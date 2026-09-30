use std::io;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use tokio::sync::RwLock;
use tokio::time::timeout;
use tracing::{debug, trace, Instrument};

use crate::runtime::RuntimeEnv;
use crate::transport::layers::OutboundTls;
use crate::{adapter::*, app::SyncDnsClient, net::*, session::Session};

use super::super::{endpoint_on, transport_config, ClientTls, CongestionControl, QuicStream, Side};

struct Manager {
    address: String,
    port: u16,
    server_name: String,
    dns_client: SyncDnsClient,
    dialer: Dialer,
    client_config: quinn::ClientConfig,
    connections: RwLock<Vec<quinn::Connection>>,
}

impl Manager {
    pub async fn new_stream(&self) -> Result<QuicStream> {
        let dial_timeout = self.dialer.connect_timeout();
        let start = std::time::Instant::now();
        loop {
            let conn = {
                let mut conns = self.connections.write().await;
                if conns.is_empty() {
                    None
                } else {
                    Some(conns.swap_remove(0))
                }
            };

            let Some(conn) = conn else {
                break;
            };

            match timeout(dial_timeout, conn.open_bi()).await {
                Ok(Ok((send, recv))) => {
                    let rtt = conn.rtt();
                    let mut conns = self.connections.write().await;
                    conns.insert(0, conn);
                    trace!(
                        "opened stream on existing connection (rtt {} ms) in {} ms",
                        rtt.as_millis(),
                        start.elapsed().as_millis(),
                    );
                    return Ok(QuicStream::new(send, recv));
                }
                Ok(Err(e)) => {
                    debug!("open stream failed: {}", e);
                }
                Err(_) => {
                    debug!("open stream timed out");
                }
            }
        }

        let targets = self
            .dialer
            .targets(&self.dns_client, &self.address, self.port)
            .instrument(tracing::Span::current())
            .await?;
        let mut last_err: Option<anyhow::Error> = None;
        for to in targets {
            // A socket of its own for each address, or the detour's
            // datagrams.
            let (socket, remote) = match self
                .dialer
                .quic_socket(&self.dns_client, None, &to)
                .instrument(tracing::Span::current())
                .await
            {
                Ok(s) => s,
                Err(e) => {
                    last_err = Some(e.into());
                    continue;
                }
            };
            let mut endpoint = endpoint_on(socket, None)?;
            endpoint.set_default_client_config(self.client_config.clone());
            let connecting = match endpoint.connect(remote, &self.server_name) {
                Ok(c) => c,
                Err(e) => {
                    last_err = Some(e.into());
                    continue;
                }
            };
            let conn = match timeout(dial_timeout, connecting).await {
                Ok(Ok(c)) => c,
                Ok(Err(e)) => {
                    last_err = Some(e.into());
                    continue;
                }
                Err(_) => {
                    last_err = Some(anyhow!("connect quic timed out"));
                    continue;
                }
            };
            let (send, recv) = match timeout(dial_timeout, conn.open_bi()).await {
                Ok(Ok(x)) => x,
                Ok(Err(e)) => {
                    last_err = Some(e.into());
                    continue;
                }
                Err(_) => {
                    last_err = Some(anyhow!("open quic stream timed out"));
                    continue;
                }
            };

            let mut conns = self.connections.write().await;
            if conns.len() >= 4 {
                conns.swap_remove(0);
            }
            conns.push(conn);

            trace!("opened quic stream on new connection",);

            return Ok(QuicStream::new(send, recv));
        }

        Err(last_err.unwrap_or_else(|| anyhow!("connect quic failed")))
    }
}

pub struct Handler {
    manager: Manager,
}

impl Handler {
    pub fn new(
        tls: &OutboundTls,
        address: String,
        port: u16,
        dns_client: SyncDnsClient,
        dialer: Dialer,
        env: &RuntimeEnv,
    ) -> Result<Self> {
        // As the tls transport: `certificate` replaces the bundled roots,
        // and no ALPN is offered unless set.
        let tls = ClientTls::new(tls, &address, &[], env)?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(tls.crypto));
        client_config.transport_config(Arc::new(transport_config(
            &env.options.quic,
            Side::Client,
            CongestionControl::Bbr.factory(),
        )));
        Ok(Self {
            manager: Manager {
                address,
                port,
                server_name: tls.server_name,
                dns_client,
                dialer,
                client_config,
                connections: RwLock::new(Vec::new()),
            },
        })
    }

    pub async fn new_stream(&self) -> io::Result<QuicStream> {
        self.manager
            .new_stream()
            .await
            .map_err(|e| io::Error::other(format!("new quic stream failed: {}", e)))
    }
}

#[async_trait]
impl OutboundStreamHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Unknown
    }

    async fn handle<'a>(
        &'a self,
        _sess: &'a Session,
        _lhs: Option<&mut AnyStream>,
        _stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        tracing::trace!("handling outbound stream");
        Ok(Box::new(
            self.new_stream()
                .instrument(tracing::Span::current())
                .await?,
        ))
    }
}
