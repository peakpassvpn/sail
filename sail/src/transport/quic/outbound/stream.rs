use std::io;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use tokio::sync::RwLock;
use tokio::time::timeout;
use tracing::{debug, trace, Instrument};

use crate::net::dial::BoundInterface;
use crate::runtime::RuntimeEnv;
use crate::transport::idle::{self, Count, Idle};
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
    /// How long a connection is kept with no stream open: the keep-alive
    /// would hold it up for good.
    idle_timeout: Duration,
    /// The idle check, which the first dial starts.
    checking: OnceLock<idle::Check>,
}

/// A connection, and where it went out, which every stream on it is given.
struct Pooled {
    conn: quinn::Connection,
    bound: BoundInterface,
    /// The streams open on it.
    open: Count,
    /// Since when it has had none, as last checked.
    idle: Idle,
}

/// Closes the connections without a stream open for `idle_timeout`; the
/// next stream dials anew. Not while a stream is being opened: the next
/// check will do.
fn check_idle(
    connections: &RwLock<Vec<Pooled>>,
    idle_timeout: Duration,
    now: tokio::time::Instant,
) {
    if let Ok(mut connections) = connections.try_write() {
        close_idle(&mut connections, idle_timeout, now);
    }
}

fn close_idle(connections: &mut Vec<Pooled>, idle_timeout: Duration, now: tokio::time::Instant) {
    connections.retain_mut(|pooled| {
        if !pooled.idle.expired(pooled.open.get(), now, idle_timeout) {
            return true;
        }
        debug!("closing an idle quic connection");
        pooled.conn.close(0u32.into(), b"idle");
        false
    });
}

impl Manager {
    /// A stream for `sess`, on which where its connection went out is
    /// recorded.
    pub async fn new_stream(&self, sess: &Session) -> Result<QuicStream<idle::Open>> {
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
            // Taken out of the pool, which the idle check sees no more.
            let open = pooled.open.open();

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
                    return Ok(QuicStream::guarded(send, recv, open));
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
            let count = Count::default();
            let open = count.open();
            let mut conns = self.connections.write().await;
            if conns.len() >= 4 {
                conns.swap_remove(0);
            }
            conns.push(Pooled {
                conn,
                bound,
                open: count,
                idle: Idle::default(),
            });
            drop(conns);
            self.checking.get_or_init(|| {
                let idle_timeout = self.idle_timeout;
                idle::spawn_check(
                    "quic idle check",
                    Arc::downgrade(&self.connections),
                    idle_timeout,
                    move |connections, now| check_idle(connections, idle_timeout, now),
                )
            });

            trace!("opened quic stream on new connection",);

            return Ok(QuicStream::guarded(send, recv, open));
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
                idle_timeout: env.options.profile.carrier_idle_timeout(),
                checking: OnceLock::new(),
            },
        })
    }

    pub async fn new_stream(&self, sess: &Session) -> io::Result<QuicStream<idle::Open>> {
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

    /// The connections with no stream open close.
    fn close_idle(&self) {
        let now = tokio::time::Instant::now();
        match self.manager.connections.try_write() {
            Ok(mut connections) => close_idle(&mut connections, Duration::ZERO, now),
            Err(_) => {
                // A stream is being opened: once it is.
                let connections = self.manager.connections.clone();
                if tokio::runtime::Handle::try_current().is_ok() {
                    crate::runtime::scope::spawn("quic close idle", async move {
                        close_idle(&mut *connections.write().await, Duration::ZERO, now)
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
    use tokio::sync::mpsc;

    use super::*;
    use crate::net::dial::Egress;
    use crate::transport::quic::{
        alpn_protocols, client_crypto, endpoint, server_config, server_crypto,
    };

    /// A server on 127.0.0.1 that takes connections and keeps them: its
    /// port and certificate, and the reasons of the connections the client
    /// closed, as they close.
    fn server() -> (u16, String, mpsc::UnboundedReceiver<bytes::Bytes>) {
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let alpns = alpn_protocols(None, &["test"]);
        let crypto = server_crypto(&cert.pem(), &key_pair.serialize_pem(), &alpns).unwrap();
        let server = endpoint(
            std::net::UdpSocket::bind("127.0.0.1:0").unwrap(),
            Some(server_config(crypto).unwrap()),
            Default::default(),
        )
        .unwrap();
        let port = server.local_addr().unwrap().port();
        let (closed, closes) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Some(incoming) = server.accept().await {
                let Ok(conn) = incoming.await else {
                    continue;
                };
                let closed = closed.clone();
                tokio::spawn(async move {
                    // Takes its streams, and keeps them.
                    let mut kept = Vec::new();
                    loop {
                        match conn.accept_bi().await {
                            Ok(stream) => kept.push(stream),
                            Err(quinn::ConnectionError::ApplicationClosed(close)) => {
                                let _ = closed.send(close.reason);
                                return;
                            }
                            Err(_) => return,
                        }
                    }
                });
            }
        });
        (port, cert.pem(), closes)
    }

    /// A pool of connections to the server on `port`, with `cert`, kept
    /// with no stream open for `idle_timeout`.
    fn manager(port: u16, cert: &str, idle_timeout: Duration) -> Manager {
        let alpns = alpn_protocols(None, &["test"]);
        let crypto = client_crypto(
            Some(cert),
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
        Manager {
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
            idle_timeout,
            checking: OnceLock::new(),
        }
    }

    /// Every stream on a connection, which none of them dialled, goes out
    /// where it does.
    #[tokio::test]
    async fn the_streams_on_a_connection_go_out_where_it_does() {
        let (port, cert, _) = server();
        let manager = manager(port, &cert, Duration::from_secs(60));
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

    /// What the idle tests keep a connection with no stream for: short, as
    /// quinn's timers run in real time.
    const IDLE: Duration = Duration::from_millis(200);

    /// A connection whose streams have ended is closed once the idle
    /// timeout has passed, which the server sees; the next stream dials
    /// anew.
    #[tokio::test]
    async fn a_connection_with_no_stream_open_is_closed() {
        use tokio::io::AsyncWriteExt;
        let (port, cert, mut closes) = server();
        let manager = manager(port, &cert, IDLE);
        let mut stream = manager.new_stream(&Session::default()).await.unwrap();
        // A stream the server hears of.
        stream.write_all(b"ping").await.unwrap();
        let old = manager.connections.read().await[0].conn.stable_id();
        drop(stream);

        let closed = timeout(IDLE * 25, closes.recv()).await;
        assert!(
            matches!(&closed, Ok(Some(reason)) if &reason[..] == b"idle"),
            "not closed with no stream open: {:?}",
            closed
        );
        assert!(manager.connections.read().await.is_empty());
        let _stream = manager.new_stream(&Session::default()).await.unwrap();
        let connections = manager.connections.read().await;
        assert_eq!(connections.len(), 1);
        assert_ne!(connections[0].conn.stable_id(), old);
    }

    /// An open stream keeps its connection past the idle timeout.
    #[tokio::test]
    async fn an_open_stream_keeps_the_connection() {
        use tokio::io::AsyncWriteExt;
        let (port, cert, mut closes) = server();
        let manager = manager(port, &cert, IDLE);
        let mut stream = manager.new_stream(&Session::default()).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        tokio::time::sleep(IDLE * 4).await;
        assert!(closes.try_recv().is_err(), "closed with a stream open");
        let connections = manager.connections.read().await;
        assert_eq!(connections.len(), 1);
        assert!(connections[0].conn.close_reason().is_none());
        drop(connections);
        stream.write_all(b"pong").await.unwrap();
    }
}
