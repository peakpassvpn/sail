use std::net::SocketAddr;
use std::sync::Arc;
use std::{io, pin::Pin};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use futures::stream::Stream;
use futures::task::{Context, Poll};
use quinn::{RecvStream, SendStream};
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::time::{timeout, Duration};
use tracing::{debug, trace, warn};

use crate::runtime::RuntimeEnv;
use crate::transport::layers::InboundTls;
use crate::{adapter::*, session::Session, session::StreamId};

use super::super::{
    alpn_protocols, endpoint, inbound_crypto, server_config, transport_config, CongestionControl,
    QuicStream, Side,
};

struct Incoming {
    stream_rx: Receiver<(SocketAddr, (SendStream, RecvStream))>,
}

impl Stream for Incoming {
    type Item = AnyBaseInboundTransport;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.stream_rx.poll_recv(cx) {
            Poll::Ready(Some((source, (send, recv)))) => {
                let mut sess = Session {
                    source,
                    ..Default::default()
                };
                sess.stream_id = Some(StreamId::U64(send.id().index()));
                Poll::Ready(Some(AnyBaseInboundTransport::Stream(
                    Box::new(QuicStream::new(send, recv)),
                    sess,
                )))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Streams accepted and not yet handed on.
const ACCEPT_CHANNEL_SIZE: usize = 1024;
/// How long a connection may wait for room in the accept queue.
const ACCEPT_QUEUE_TIMEOUT: Duration = Duration::from_secs(5);

pub struct Handler {
    server_config: quinn::ServerConfig,
}

impl Handler {
    pub fn new(tag: &str, tls: &InboundTls, env: &RuntimeEnv) -> Result<Self> {
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
        Ok(Self { server_config })
    }
}

async fn handle_conn(
    stream_tx: Sender<(SocketAddr, (SendStream, RecvStream))>,
    remote_addr: SocketAddr,
    conn: quinn::Connecting,
) -> Result<()> {
    let (conn, _) = conn
        .into_0rtt()
        .map_err(|_| anyhow!("convert 0rtt failed"))?;
    let send_timeout = ACCEPT_QUEUE_TIMEOUT;
    trace!("quic handling connection from {}", remote_addr);
    loop {
        let s = conn.accept_bi().await?;
        trace!("quic accepted stream from {}", remote_addr);
        if stream_tx.capacity() == 0 {
            warn!("quic accept channel full");
        }
        match timeout(send_timeout, stream_tx.send((remote_addr, s))).await {
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
}

#[async_trait]
impl InboundDatagramHandler for Handler {
    async fn handle<'a>(&'a self, socket: AnyInboundDatagram) -> io::Result<AnyInboundTransport> {
        tracing::trace!("handling inbound datagram");
        let (stream_tx, stream_rx) = channel(ACCEPT_CHANNEL_SIZE);
        let endpoint = endpoint(socket.into_std()?, Some(self.server_config.clone()))?;
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let stream_tx_c = stream_tx.clone();
                tokio::spawn(async move {
                    let remote_addr = incoming.remote_address();
                    match incoming.accept() {
                        Ok(connecting) => {
                            if let Err(e) = handle_conn(stream_tx_c, remote_addr, connecting).await
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
        });
        Ok(InboundTransport::Incoming(Box::new(Incoming { stream_rx })))
    }
}
