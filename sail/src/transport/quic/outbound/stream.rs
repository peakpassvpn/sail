use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use futures::TryFutureExt;
use tokio::sync::RwLock;
use tokio::time::timeout;
use tracing::{debug, trace, Instrument};

use crate::runtime::RuntimeEnv;
use crate::transport::layers::OutboundTls;
use crate::{adapter::*, app::SyncDnsClient, net::*, session::Session};

use super::super::{endpoint, transport_config, ClientTls, CongestionControl, QuicStream, Side};

struct Manager {
    address: String,
    port: u16,
    server_name: String,
    dns_client: SyncDnsClient,
    dial: Arc<crate::net::DialOptions>,
    client_config: quinn::ClientConfig,
    connections: RwLock<Vec<quinn::Connection>>,
}

impl Manager {
    pub async fn new_stream(&self) -> Result<QuicStream> {
        let dial_timeout = self.dial.connect_timeout;
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

        // FIXME A better indicator.
        let socket = self
            .new_udp_socket(&self.dial.unspecified(), &self.dial)
            .instrument(tracing::Span::current())
            .await?;
        let mut endpoint = endpoint(socket.into_std()?, None)?;
        endpoint.set_default_client_config(self.client_config.clone());
        let ips = {
            self.dns_client
                .load_full()
                .direct_lookup(&self.address)
                .map_err(|e| io::Error::other(format!("lookup {} failed: {}", &self.address, e)))
                .instrument(tracing::Span::current())
                .await?
        };
        if ips.is_empty() {
            return Err(anyhow!("could not resolve to any address",));
        }
        let mut last_err: Option<anyhow::Error> = None;
        for ip in ips {
            let connect_addr = SocketAddr::new(ip, self.port);
            let connecting = match endpoint.connect(connect_addr, &self.server_name) {
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

impl UdpConnector for Manager {}

pub struct Handler {
    manager: Manager,
}

impl Handler {
    pub fn new(
        tls: &OutboundTls,
        address: String,
        port: u16,
        dns_client: SyncDnsClient,
        dial: Arc<crate::net::DialOptions>,
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
                dial,
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

impl UdpConnector for Handler {}

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
