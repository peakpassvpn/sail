use std::net::SocketAddr;
use std::sync::Arc;
use std::{io, pin::Pin};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use futures::stream::Stream;
use futures::task::{Context, Poll};
use futures::StreamExt;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::Semaphore;
use tokio::time::{timeout, Duration};
use tracing::{debug, trace, warn};

use crate::runtime::resource::HotResource;
use crate::transport::layers::InboundTls;
use crate::{adapter::*, session::Session, session::StreamId};

use super::super::{
    alpn_protocols, endpoint, inbound_crypto, server_config, transport_config, CongestionControl,
    QuicStream, Side,
};

struct Incoming {
    stream_rx: Receiver<AnyBaseInboundTransport>,
}

impl Stream for Incoming {
    type Item = AnyBaseInboundTransport;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.stream_rx.poll_recv(cx)
    }
}

/// Streams accepted and not yet handed on.
const ACCEPT_CHANNEL_SIZE: usize = 1024;
/// How long a connection may wait for room in the accept queue.
const ACCEPT_QUEUE_TIMEOUT: Duration = Duration::from_secs(5);

pub struct Handler {
    resource: HotResource<Resources>,
}

pub(crate) struct Resources {
    server_config: quinn::ServerConfig,
    /// How long a client has to finish its handshake.
    handshake_timeout: std::time::Duration,
    core: AnyInboundHandler,
    accept: crate::protocol::group::chain::inbound::Accept,
}

impl Handler {
    pub(crate) fn new(
        ctx: &crate::adapter::registry::InboundContext<'_>,
        tls: &InboundTls,
        core: AnyInboundHandler,
    ) -> Result<Self> {
        let tag = ctx.tag;
        let env = ctx.env;
        // tls_inbound serves REALITY without a certificate; this cannot.
        if tls.reality.as_ref().is_some_and(|r| r.enabled) {
            return Err(anyhow!(
                "[{}] inbound: tls.reality: not supported with the quic transport",
                tag
            ));
        }
        let crypto = inbound_crypto(tag, tls, env, &alpn_protocols(tls.alpn.as_ref(), &[]))?;
        let mut server_config = server_config(crypto)?;
        server_config.transport_config(Arc::new(transport_config(
            &env.options.quic,
            Side::Server,
            CongestionControl::Bbr.factory(),
        )));
        let generation = Arc::new(Resources {
            server_config,
            handshake_timeout: env.options.quic.server_handshake_timeout,
            core,
            accept: (&env.options.inbound).into(),
        });
        Ok(Self {
            resource: ctx.resource(&ctx.state.quic, generation),
        })
    }
}

async fn handle_conn(
    stream_tx: Sender<AnyBaseInboundTransport>,
    remote_addr: SocketAddr,
    conn: quinn::Connecting,
    generation: Arc<Resources>,
    handshakes: Arc<Semaphore>,
) -> Result<()> {
    // The server takes no 0-RTT data, so nothing comes before the
    // handshake is done; one not done in time is dropped.
    let conn = crate::transport::quic::server_handshake(conn, generation.handshake_timeout).await?;
    let send_timeout = ACCEPT_QUEUE_TIMEOUT;
    trace!("quic handling connection from {}", remote_addr);
    let streams = futures::stream::unfold(conn, move |conn| async move {
        let (send, recv) = conn.accept_bi().await.ok()?;
        let sess = Session {
            source: remote_addr,
            stream_id: Some(StreamId::U64(send.id().index())),
            ..Default::default()
        };
        Some((
            AnyBaseInboundTransport::Stream(Box::new(QuicStream::new(send, recv)), sess),
            conn,
        ))
    });
    let core: AnyInboundHandler = Arc::new(crate::adapter::inbound::Handler::new(
        generation.core.tag().clone(),
        Some(Arc::new(LimitedHandshake {
            core: generation.core.clone(),
            handshakes,
        })),
        None,
    ));
    let mut incoming = crate::protocol::group::chain::inbound::Incoming::new(
        Box::new(Box::pin(streams)),
        vec![core],
        generation.accept,
    );
    while let Some(transport) = incoming.next().await {
        trace!("quic accepted stream from {}", remote_addr);
        if stream_tx.capacity() == 0 {
            warn!("quic accept channel full");
        }
        match timeout(send_timeout, stream_tx.send(transport)).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => return Ok(()),
            Err(_) => {
                return Err(anyhow!(
                    "quic accept queue remained full for {:?}, dropping connection",
                    send_timeout
                ));
            }
        }
    }
    Ok(())
}

/// The old pipeline bounded authentication across the entire endpoint.
/// Keep that budget when each connection now owns a credential snapshot.
struct LimitedHandshake {
    core: AnyInboundHandler,
    handshakes: Arc<Semaphore>,
}

#[async_trait]
impl InboundStreamHandler for LimitedHandshake {
    async fn handle<'a>(
        &'a self,
        sess: Session,
        stream: AnyStream,
    ) -> io::Result<AnyInboundTransport> {
        let _permit = self
            .handshakes
            .acquire()
            .await
            .map_err(|_| io::Error::other("QUIC endpoint closed"))?;
        self.core.stream()?.handle(sess, stream).await
    }
}

#[async_trait]
impl InboundDatagramHandler for Handler {
    async fn handle<'a>(&'a self, socket: AnyInboundDatagram) -> io::Result<AnyInboundTransport> {
        tracing::trace!("handling inbound datagram");
        let (stream_tx, stream_rx) = channel(ACCEPT_CHANNEL_SIZE);
        let endpoint = endpoint(
            socket.into_std()?,
            Some(self.resource.load().server_config.clone()),
        )?;
        let resource = self.resource.clone();
        let handshakes = Arc::new(Semaphore::new(resource.load().accept.concurrency.max(1)));
        crate::runtime::scope::spawn_essential("quic accept", async move {
            loop {
                let incoming = tokio::select! {
                    incoming = endpoint.accept() => incoming,
                    _ = stream_tx.closed() => None,
                };
                let Some(incoming) = incoming else {
                    break;
                };
                let generation = resource.load();
                let stream_tx_c = stream_tx.clone();
                let handshakes = handshakes.clone();
                crate::runtime::scope::spawn("quic connection", async move {
                    let remote_addr = incoming.remote_address();
                    match incoming.accept_with(Arc::new(generation.server_config.clone())) {
                        Ok(connecting) => {
                            if let Err(e) = handle_conn(
                                stream_tx_c,
                                remote_addr,
                                connecting,
                                generation,
                                handshakes,
                            )
                            .await
                            {
                                debug!(
                                    "handle quic connection from {} failed: {}",
                                    &remote_addr, e
                                );
                            }
                        }
                        Err(e) => {
                            debug!("accept quic connection from {} failed: {}", &remote_addr, e);
                        }
                    }
                });
            }
            endpoint.close(0u32.into(), b"");
        });
        Ok(InboundTransport::Incoming(Box::new(Incoming { stream_rx })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct Authentication;
    #[async_trait]
    impl InboundStreamHandler for Authentication {
        async fn handle<'a>(
            &'a self,
            sess: Session,
            mut stream: AnyStream,
        ) -> io::Result<AnyInboundTransport> {
            stream.read_u8().await?;
            Ok(InboundTransport::Stream(stream, sess))
        }
    }

    #[tokio::test]
    async fn connection_generations_share_and_release_handshake_budget() {
        let slots = Arc::new(Semaphore::new(1));
        let generation = |tag: &str| LimitedHandshake {
            core: Arc::new(crate::adapter::inbound::Handler::new(
                tag.into(),
                Some(Arc::new(Authentication)),
                None,
            )),
            handshakes: slots.clone(),
        };
        let first = generation("old");
        let second = generation("new");
        let (_client1, server1) = tokio::io::duplex(64);
        let (mut client2, server2) = tokio::io::duplex(64);
        let mut pending1 = first.handle(Session::default(), Box::new(server1));
        let mut pending2 = second.handle(Session::default(), Box::new(server2));
        assert!(futures::poll!(&mut pending1).is_pending());
        client2.write_u8(1).await.unwrap();
        assert!(futures::poll!(&mut pending2).is_pending());
        assert_eq!(slots.available_permits(), 0);
        drop(pending1); // a cancelled/timed out handshake returns its slot
        assert!(pending2.await.is_ok());
        assert_eq!(slots.available_permits(), 1);
    }
}
