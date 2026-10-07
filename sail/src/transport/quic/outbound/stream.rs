use std::io;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use tokio::sync::RwLock;
use tokio::time::timeout;
use tracing::{debug, trace, Instrument};

use crate::net::dial::BoundInterface;
use crate::runtime::RuntimeEnv;
use crate::transport::layers::OutboundTls;
use crate::{adapter::*, app::SyncDnsClient, net::*, session::Session};

use super::super::{
    endpoint_on, transport_config, ClientConfigs, ClientTls, CongestionControl, QuicStream, Side,
};

struct Manager {
    address: String,
    port: u16,
    dns_client: SyncDnsClient,
    dialer: Dialer,
    configs: ClientConfigs,
    connections: Arc<RwLock<Vec<Pooled>>>,
}

/// A connection, and where it went out, which every stream on it is given.
struct Pooled {
    conn: quinn::Connection,
    bound: BoundInterface,
}

impl Manager {
    /// A stream for `sess`, on which where its connection went out is
    /// recorded.
    pub async fn new_stream(&self, sess: &Session) -> Result<QuicStream> {
        let dial_timeout = self.dialer.connect_timeout();
        let start = std::time::Instant::now();
        loop {
            let pooled = {
                let mut conns = self.connections.write().await;
                if conns.is_empty() {
                    None
                } else {
                    Some(conns.swap_remove(0))
                }
            };

            let Some(pooled) = pooled else {
                break;
            };

            match timeout(dial_timeout, pooled.conn.open_bi()).await {
                Ok(Ok((send, recv))) => {
                    let rtt = pooled.conn.rtt();
                    pooled.bound.onto(sess);
                    let mut conns = self.connections.write().await;
                    conns.insert(0, pooled);
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
        let config = self.configs.connection(&self.dns_client).await?;
        let mut last_err: Option<anyhow::Error> = None;
        for to in targets {
            // A socket of its own for each address, or the detour's
            // datagrams.
            let (socket, remote, bound) = match self
                .dialer
                .quic_socket(&self.dns_client, &to)
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
            endpoint.set_default_client_config(config.clone());
            let connecting = match endpoint.connect(remote, self.configs.server_name()) {
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

            bound.onto(sess);
            let mut conns = self.connections.write().await;
            if conns.len() >= 4 {
                conns.swap_remove(0);
            }
            conns.push(Pooled { conn, bound });

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
        let configs = ClientConfigs::new(
            tls,
            transport_config(
                &env.options.quic,
                Side::Client,
                CongestionControl::Bbr.factory(),
            ),
        );
        Ok(Self {
            manager: Manager {
                address,
                port,
                dns_client,
                dialer,
                configs,
                connections: Arc::new(RwLock::new(Vec::new())),
            },
        })
    }

    pub async fn new_stream(&self, sess: &Session) -> io::Result<QuicStream> {
        self.manager
            .new_stream(sess)
            .await
            .map_err(|e| io::Error::other(format!("new quic stream failed: {}", e)))
    }
}

#[async_trait]
impl OutboundStreamHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Unknown
    }

    /// Its connections close, as sing-box closes its transport when the
    /// network changes; the next stream dials anew.
    fn network_changed(&self, _change: &crate::net::network::NetworkChange) {
        fn close(connections: &mut Vec<Pooled>) {
            for pooled in connections.drain(..) {
                pooled.conn.close(0u32.into(), b"network changed");
            }
        }
        match self.manager.connections.try_write() {
            Ok(mut connections) => close(&mut connections),
            Err(_) => {
                // A stream is being opened: close them once it is.
                let connections = self.manager.connections.clone();
                if tokio::runtime::Handle::try_current().is_ok() {
                    crate::runtime::scope::spawn("quic reset", async move {
                        close(&mut *connections.write().await)
                    });
                }
            }
        }
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _lhs: Option<&mut AnyStream>,
        _stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        tracing::trace!("handling outbound stream");
        Ok(Box::new(
            self.new_stream(sess)
                .instrument(tracing::Span::current())
                .await?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::dial::Egress;
    use crate::transport::quic::{
        alpn_protocols, client_crypto, endpoint, server_config, server_crypto,
    };

    /// Every stream on a connection, which none of them dialled, goes out
    /// where it does.
    #[tokio::test]
    async fn the_streams_on_a_connection_go_out_where_it_does() {
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let alpns = alpn_protocols(None, &["test"]);
        let crypto = server_crypto(&cert.pem(), &key_pair.serialize_pem(), &alpns).unwrap();
        let server = endpoint(
            std::net::UdpSocket::bind("127.0.0.1:0").unwrap(),
            Some(server_config(crypto).unwrap()),
        )
        .unwrap();
        let port = server.local_addr().unwrap().port();
        // Takes the connections, and keeps them.
        tokio::spawn(async move {
            let mut kept = Vec::new();
            while let Some(incoming) = server.accept().await {
                if let Ok(conn) = incoming.await {
                    kept.push(conn);
                }
            }
        });
        let crypto = client_crypto(
            Some(&cert.pem()),
            false,
            &alpns,
            &crate::transport::tls::tests::test_roots(),
        )
        .unwrap();
        let dns = crate::app::dns::DnsClient::new(
            &Default::default(),
            Default::default(),
            &Default::default(),
        )
        .unwrap()
        .into_shared();
        let manager = Manager {
            address: "127.0.0.1".into(),
            port,
            dns_client: dns,
            dialer: Dialer::system(),
            configs: ClientConfigs::new(
                ClientTls {
                    server_name: "localhost".into(),
                    crypto,
                    ech_lookup: false,
                },
                quinn::TransportConfig::default(),
            ),
            connections: Arc::default(),
        };
        let (first, second) = (Session::default(), Session::default());
        let _first = manager.new_stream(&first).await.unwrap();
        let _second = manager.new_stream(&second).await.unwrap();
        assert_eq!(manager.connections.read().await.len(), 1);
        for sess in [&first, &second] {
            assert_eq!(
                sess.state.get::<BoundInterface>().get(),
                Some(Egress::DefaultRoute)
            );
        }
    }
}
