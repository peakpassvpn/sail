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

use crate::{adapter::*, session::Session, session::StreamId};

use super::QuicProxyStream;

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
                    Box::new(QuicProxyStream { recv, send }),
                    sess,
                )))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

fn quic_err<E>(error: E) -> io::Error
where
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    io::Error::other(error)
}

/// Streams accepted and not yet handed on.
const ACCEPT_CHANNEL_SIZE: usize = 1024;
/// How long a connection may wait for room in the accept queue.
const ACCEPT_QUEUE_TIMEOUT: Duration = Duration::from_secs(5);

pub struct Handler {
    server_config: quinn::ServerConfig,
}

impl Handler {
    pub fn new(
        certificate: String,
        certificate_key: String,
        alpns: Vec<String>,
        tuning: &crate::runtime::options::Quic,
    ) -> Result<Self> {
        use crate::transport::tls::client::{load_certificates, load_private_key};
        use quinn_btls::QuicSslContext;
        let mut certs = load_certificates(&certificate)?.into_iter();
        let key = load_private_key(&certificate_key)?;

        let mut crypto =
            quinn_btls::ServerConfig::new().map_err(|e| anyhow!("quic server config: {}", e))?;
        let ctx = crypto.ctx_mut();
        ctx.set_certificate(certs.next().expect("load_certificates returns one or more"))?;
        for cert in certs {
            ctx.add_to_cert_chain(cert)?;
        }
        ctx.set_private_key(key)?;
        ctx.check_private_key()
            .map_err(|e| anyhow!("private key does not match the certificate: {}", e))?;
        if !alpns.is_empty() {
            let alpns: Vec<Vec<u8>> = alpns.into_iter().map(String::into_bytes).collect();
            crypto
                .set_alpn(&alpns)
                .map_err(|e| anyhow!("quic alpn: {}", e))?;
        }

        let mut server_config = quinn_btls::helpers::server_config(Arc::new(crypto))
            .map_err(|e| anyhow!("quic server config: {}", e))?;
        let mut transport_config = quinn::TransportConfig::default();
        transport_config
            .max_concurrent_bidi_streams(quinn::VarInt::from_u32(tuning.max_concurrent_streams));
        transport_config
            .max_idle_timeout(quinn::IdleTimeout::try_from(tuning.server_idle_timeout).ok());
        transport_config.keep_alive_interval(
            (!tuning.server_keep_alive_interval.is_zero())
                .then_some(tuning.server_keep_alive_interval),
        );
        transport_config
            .congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
        server_config.transport_config(Arc::new(transport_config));

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
        let endpoint = quinn::Endpoint::new(
            quinn_btls::helpers::default_endpoint_config(),
            Some(self.server_config.clone()),
            socket.into_std()?,
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(quic_err)?;
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
