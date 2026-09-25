use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use futures::TryFutureExt;
use tokio::sync::RwLock;
use tokio::time::timeout;
use tracing::{debug, trace, Instrument};

use crate::{adapter::*, app::SyncDnsClient, net::*, session::Session};

use super::QuicProxyStream;

struct Manager {
    address: String,
    port: u16,
    server_name: Option<String>,
    dns_client: SyncDnsClient,
    dial: Arc<crate::net::DialOptions>,
    client_config: quinn::ClientConfig,
    connections: RwLock<Vec<quinn::Connection>>,
}

impl Manager {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        address: String,
        port: u16,
        server_name: Option<String>,
        alpns: Vec<String>,
        certificate: Option<String>,
        dns_client: SyncDnsClient,
        dial: Arc<crate::net::DialOptions>,
        tuning: &crate::runtime::options::Quic,
    ) -> Result<Self> {
        use quinn_btls::QuicSslContext;
        let mut crypto =
            quinn_btls::ClientConfig::new().map_err(|e| anyhow!("quic client config: {}", e))?;
        // `certificate` replaces the bundled roots, as for TLS.
        let certs = match certificate.as_deref() {
            Some(certificate) => crate::transport::tls::client::load_certificates(certificate)?,
            None => crate::transport::tls::client::bundled_root_certs()?.to_vec(),
        };
        let store = crypto.ctx_mut().cert_store_mut();
        for cert in certs {
            store.add_cert(cert)?;
        }
        if !alpns.is_empty() {
            let alpns: Vec<Vec<u8>> = alpns.into_iter().map(String::into_bytes).collect();
            crypto
                .set_alpn(&alpns)
                .map_err(|e| anyhow!("quic alpn: {}", e))?;
        }

        let mut client_config = quinn::ClientConfig::new(Arc::new(crypto));
        let mut transport_config = quinn::TransportConfig::default();
        transport_config
            .max_concurrent_bidi_streams(quinn::VarInt::from_u32(tuning.max_concurrent_streams));
        transport_config
            .max_idle_timeout(quinn::IdleTimeout::try_from(tuning.client_idle_timeout).ok());
        transport_config.keep_alive_interval(
            (!tuning.client_keep_alive_interval.is_zero())
                .then_some(tuning.client_keep_alive_interval),
        );
        transport_config
            .congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
        client_config.transport_config(Arc::new(transport_config));

        Ok(Manager {
            address,
            port,
            server_name,
            dns_client,
            dial,
            client_config,
            connections: RwLock::new(Vec::new()),
        })
    }
}

impl Manager {
    pub async fn new_stream(
        &self,
    ) -> Result<QuicProxyStream<quinn::RecvStream, quinn::SendStream>> {
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
                    return Ok(QuicProxyStream { recv, send });
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
        let mut endpoint = quinn::Endpoint::new(
            quinn_btls::helpers::default_endpoint_config(),
            None,
            socket.into_std()?,
            Arc::new(quinn::TokioRuntime),
        )?;
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
        let server_name = self.server_name.as_ref().unwrap_or(&self.address);
        let mut last_err: Option<anyhow::Error> = None;
        for ip in ips {
            let connect_addr = SocketAddr::new(ip, self.port);
            let connecting = match endpoint.connect(connect_addr, server_name) {
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

            return Ok(QuicProxyStream { recv, send });
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
        address: String,
        port: u16,
        server_name: Option<String>,
        alpns: Vec<String>,
        certificate: Option<String>,
        dns_client: SyncDnsClient,
        dial: Arc<crate::net::DialOptions>,
        tuning: &crate::runtime::options::Quic,
    ) -> Result<Self> {
        Ok(Self {
            manager: Manager::new(
                address,
                port,
                server_name,
                alpns,
                certificate,
                dns_client,
                dial,
                tuning,
            )?,
        })
    }

    pub async fn new_stream(
        &self,
    ) -> io::Result<QuicProxyStream<quinn::RecvStream, quinn::SendStream>> {
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
