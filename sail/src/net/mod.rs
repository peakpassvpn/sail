use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use socket2::{Domain, SockRef, Socket, Type};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, trace};

use crate::{
    adapter::*,
    app::SyncDnsClient,
    session::{Network, Session, SocksAddr},
};

pub mod accept;
pub mod datagram;
pub mod dial;
pub mod interface;
#[cfg(feature = "netstack")]
pub mod netstack;
pub mod network;
pub mod relay;
pub mod resolver;

pub use datagram::*;
pub use dial::{DialDefaults, Dialer, InboundDialer, InstanceDial, SharedDialDefaults};

pub struct TcpListener {
    inner: tokio::net::TcpListener,
    abort_on_close: bool,
    keepalive: Option<TcpKeepAlive>,
    send_buffer: usize,
}

impl TcpListener {
    pub async fn bind(addr: &SocketAddr) -> io::Result<Self> {
        Self::bind_now(addr)
    }

    /// Binds right away, so that a failure is known before anything starts.
    /// Must be called from within a Tokio runtime.
    pub fn bind_now(addr: &SocketAddr) -> io::Result<Self> {
        let socket = Socket::new(Domain::for_address(*addr), Type::STREAM, None)?;
        // As tokio's own bind does: lets a restarted process listen again
        // while connections of the last one are still in TIME_WAIT.
        #[cfg(not(windows))]
        socket.set_reuse_address(true)?;
        socket.bind(&(*addr).into())?;
        socket.listen(1024)?;
        socket.set_nonblocking(true)?;
        Ok(Self {
            inner: tokio::net::TcpListener::from_std(socket.into())?,
            abort_on_close: false,
            keepalive: Some(TcpKeepAlive::DEFAULT),
            send_buffer: 0,
        })
    }

    /// Keepalive for accepted connections, none if unset.
    pub fn keepalive(mut self, keepalive: Option<TcpKeepAlive>) -> Self {
        self.keepalive = keepalive;
        self
    }

    /// Resets accepted connections on close instead of closing them
    /// gracefully: sockets are reclaimed at once, and whatever is still
    /// queued for the peer is lost.
    pub fn abort_on_close(mut self, abort: bool) -> Self {
        self.abort_on_close = abort;
        self
    }

    /// The send buffer of accepted connections, in bytes; zero leaves it to
    /// the system.
    pub fn send_buffer(mut self, bytes: usize) -> Self {
        self.send_buffer = bytes;
        self
    }

    pub fn io(&self) -> &tokio::net::TcpListener {
        &self.inner
    }

    /// The next connection. An error is the listener's own: a connection
    /// whose options cannot be set, one the peer has already reset say, is
    /// dropped here and the next one taken.
    pub async fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        loop {
            let (stream, addr) = self.inner.accept().await?;
            match self.configure(&stream) {
                Ok(()) => return Ok((stream, addr)),
                Err(e) => debug!("accepted connection from {} dropped: {}", addr, e),
            }
        }
    }

    fn configure(&self, stream: &TcpStream) -> io::Result<()> {
        apply_socket_opts(SockRef::from(stream), self.keepalive)?;
        if self.abort_on_close {
            // Reclaims the socket the moment it is closed, and discards
            // anything still queued for the peer along with it. See the
            // option's own documentation for when that trade is the right one.
            SockRef::from(stream).set_linger(Some(Duration::ZERO))?;
        }
        if self.send_buffer > 0 {
            SockRef::from(stream).set_send_buffer_size(self.send_buffer)?;
        }
        Ok(())
    }
}

/// The largest UDP payload: what a socket must be able to send.
pub const MAX_DATAGRAM: usize = 65535;

/// Marks a socket sail listens with by `env.listen_mark`, if there is one.
pub fn mark_listener(socket: SockRef, env: &crate::runtime::RuntimeEnv) -> io::Result<()> {
    match env.listen_mark {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        Some(mark) => socket.set_mark(mark),
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        Some(_) => {
            let _ = socket;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "socket marks are only supported on Linux",
            ))
        }
        None => Ok(()),
    }
}

/// Lets `socket` send a datagram of [`MAX_DATAGRAM`] bytes. macOS caps a
/// datagram at the send buffer, which starts at 9 KiB
/// (`net.inet.udp.maxdgram`), and fails a larger one with EMSGSIZE; other
/// systems start above it, and this leaves them alone.
pub fn fit_largest_datagram(socket: SockRef) -> io::Result<()> {
    if socket.send_buffer_size()? < MAX_DATAGRAM + 1 {
        socket.set_send_buffer_size(MAX_DATAGRAM + 1)?;
    }
    Ok(())
}

/// TCP keepalive: probes once a connection has carried nothing for `idle`,
/// then every `interval` until the peer answers or the system gives up on
/// it (after 9 probes on Linux, 8 on macOS, 10 on Windows).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpKeepAlive {
    pub idle: Duration,
    pub interval: Duration,
}

impl TcpKeepAlive {
    /// sing-box's: a dead peer is found within about 15 minutes, where the
    /// systems' own two hours find it practically never.
    pub const DEFAULT: TcpKeepAlive = TcpKeepAlive {
        idle: Duration::from_secs(5 * 60),
        interval: Duration::from_secs(75),
    };

    fn apply(&self, s: &SockRef) -> io::Result<()> {
        let keepalive = socket2::TcpKeepalive::new().with_time(self.idle);
        #[cfg(any(
            target_os = "android",
            target_os = "freebsd",
            target_os = "ios",
            target_os = "linux",
            target_os = "macos",
            target_os = "netbsd",
            target_os = "tvos",
            target_os = "visionos",
            target_os = "watchos",
            target_os = "windows",
        ))]
        let keepalive = keepalive.with_interval(self.interval);
        s.set_tcp_keepalive(&keepalive)
    }
}

/// What every TCP connection sail makes or accepts gets: no Nagle delay,
/// and keepalive as `keepalive` says, none if unset.
pub(crate) fn apply_socket_opts(s: SockRef, keepalive: Option<TcpKeepAlive>) -> io::Result<()> {
    match keepalive {
        Some(keepalive) => keepalive.apply(&s)?,
        None => s.set_keepalive(false)?,
    }
    s.set_nodelay(true)
}

/// Dials what `handler`'s stream handler asks for, with the dialer that
/// comes with the request: `None` when it asks for nothing.
pub async fn connect_stream_outbound(
    sess: &Session,
    dns_client: SyncDnsClient,
    handler: &AnyOutboundHandler,
) -> io::Result<Option<AnyStream>> {
    match handler.stream()?.connect_addr() {
        OutboundConnect::Proxy(Network::Tcp, addr, port, dialer) => {
            trace!("connect stream proxy outbound addr={} port={}", &addr, port);
            let to = SocksAddr::try_from((addr, port))?;
            Ok(Some(dialer.stream(&dns_client, Some(sess), &to).await?))
        }
        OutboundConnect::Direct(dialer) => {
            trace!("connect stream direct dst={}", &sess.destination);
            Ok(Some(
                dialer
                    .stream(&dns_client, Some(sess), &sess.destination)
                    .await?,
            ))
        }
        _ => {
            trace!("connect stream None");
            Ok(None)
        }
    }
}

/// Dials what `handler`'s datagram handler asks for, with the dialer that
/// comes with the request: `None` when it asks for nothing.
pub async fn connect_datagram_outbound(
    sess: &Session,
    dns_client: SyncDnsClient,
    handler: &AnyOutboundHandler,
) -> io::Result<Option<AnyOutboundTransport>> {
    match handler.datagram()?.connect_addr() {
        OutboundConnect::Proxy(network, addr, port, dialer) => {
            let to = SocksAddr::try_from((addr, port))?;
            match network {
                Network::Udp => Ok(Some(OutboundTransport::Datagram(
                    dialer.datagram(&dns_client, Some(sess), &to).await?,
                ))),
                Network::Tcp => Ok(Some(OutboundTransport::Stream(
                    dialer.stream(&dns_client, Some(sess), &to).await?,
                ))),
            }
        }
        // Through a detour, the session's destination is the detour's to
        // reach.
        OutboundConnect::Direct(dialer) if dialer.detour().is_some() => {
            Ok(Some(OutboundTransport::Datagram(
                dialer
                    .datagram(&dns_client, Some(sess), &sess.destination)
                    .await?,
            )))
        }
        OutboundConnect::Direct(dialer) if sess.route.udp_connect => {
            let addr = match &sess.destination {
                SocksAddr::Ip(addr) => *addr,
                SocksAddr::Domain(domain, port) => {
                    let ips = dialer.lookup(&dns_client, domain).await?;
                    let ip = ips.first().ok_or_else(|| {
                        io::Error::other(format!("{} resolves to nothing", domain))
                    })?;
                    SocketAddr::new(*ip, *port)
                }
            };
            let socket = dialer.udp_socket(&addr).await?;
            socket.connect(addr).await?;
            let from = match &sess.destination {
                SocksAddr::Domain(..) if !sess.route.udp_disable_domain_unmapping => {
                    sess.destination.clone()
                }
                _ => SocksAddr::Ip(addr),
            };
            Ok(Some(OutboundTransport::Datagram(Box::new(
                ConnectedOutboundDatagram::new(socket, from),
            ))))
        }
        OutboundConnect::Direct(dialer) => match &sess.destination {
            SocksAddr::Domain(domain, port) => {
                let socket = dialer.udp_socket(&dialer.unspecified()).await?;
                Ok(Some(OutboundTransport::Datagram(Box::new(
                    DomainAssociatedOutboundDatagram::new(
                        socket,
                        SocksAddr::Domain(domain.to_owned(), *port),
                        dns_client.clone(),
                        dialer,
                    )
                    .without_unmapping(sess.route.udp_disable_domain_unmapping),
                ))))
            }
            SocksAddr::Ip(addr) => {
                let socket = dialer.udp_socket(addr).await?;
                Ok(Some(OutboundTransport::Datagram(Box::new(
                    StdOutboundDatagram::new(socket),
                ))))
            }
        },
        _ => Ok(None),
    }
}

/// Peeks data from the local side of a stream.
pub async fn peek_tcp_one_off(lhs: Option<&mut AnyStream>) -> Vec<u8> {
    if let Some(lhs) = lhs {
        let mut read_buf = Vec::with_capacity(2 * 1024);
        match timeout(Duration::from_millis(10), lhs.read_buf(&mut read_buf)).await {
            Ok(Ok(_)) => return read_buf,
            _ => return Vec::new(),
        }
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    /// An accepted connection is closed gracefully unless the option asks for
    /// the aggressive reclaim: a reset discards whatever is still queued for
    /// the peer, including the tail of a response whose end is the close.
    #[test]
    fn accepted_socket_linger_follows_the_option() {
        for abort in [false, true] {
            runtime().block_on(async {
                let listener = TcpListener::bind(&"127.0.0.1:0".parse().unwrap())
                    .await
                    .unwrap()
                    .abort_on_close(abort);
                let addr = listener.io().local_addr().unwrap();
                let connecting = tokio::spawn(TcpStream::connect(addr));
                let (accepted, _) = listener.accept().await.unwrap();
                let _client = connecting.await.unwrap().unwrap();

                let linger = SockRef::from(&accepted).linger().unwrap();
                if abort {
                    assert_eq!(linger, Some(Duration::ZERO));
                } else {
                    assert_eq!(linger, None);
                }
            });
        }
    }

    /// Dialled and accepted connections probe a dead peer after 5 minutes
    /// idle, every 75 s, unless told otherwise.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn tcp_connections_get_keepalive() {
        let custom = TcpKeepAlive {
            idle: Duration::from_secs(40),
            interval: Duration::from_secs(7),
        };
        let check = |s: SockRef, want: Option<TcpKeepAlive>| {
            assert_eq!(s.keepalive().unwrap(), want.is_some());
            if let Some(want) = want {
                assert_eq!(s.keepalive_time().unwrap(), want.idle);
                assert_eq!(s.keepalive_interval().unwrap(), want.interval);
            }
        };
        let fields = |json| -> dial::DialFields { serde_json::from_value(json).unwrap() };
        for (listen, dial, want) in [
            (
                None,
                fields(serde_json::json!({})),
                Some(TcpKeepAlive::DEFAULT),
            ),
            (
                Some(custom),
                fields(
                    serde_json::json!({ "tcp_keep_alive": "40s", "tcp_keep_alive_interval": "7s" }),
                ),
                Some(custom),
            ),
            (
                None,
                fields(serde_json::json!({ "disable_tcp_keep_alive": true })),
                None,
            ),
        ] {
            let dialer = DialDefaults::default().dialer(&dial, None).unwrap();
            runtime().block_on(async {
                let listener = TcpListener::bind(&"127.0.0.1:0".parse().unwrap())
                    .await
                    .unwrap();
                let listener = match listen {
                    Some(k) => listener.keepalive(Some(k)),
                    None => listener,
                };
                let addr = listener.io().local_addr().unwrap();
                let dialled = tokio::spawn(async move { dialer.tcp_to(addr).await });
                let (accepted, _) = listener.accept().await.unwrap();
                let dialled = dialled.await.unwrap().unwrap();
                check(
                    SockRef::from(&accepted),
                    Some(listen.unwrap_or(TcpKeepAlive::DEFAULT)),
                );
                check(SockRef::from(&dialled), want);
            });
        }
    }

    #[test]
    fn keepalive_fields_read_as_in_sing_box() {
        use dial::tcp_keep_alive;
        assert_eq!(
            tcp_keep_alive(false, None, None),
            Some(TcpKeepAlive::DEFAULT)
        );
        // Zero is unset.
        assert_eq!(
            tcp_keep_alive(false, Some(Duration::ZERO), Some(Duration::from_secs(9))),
            Some(TcpKeepAlive {
                idle: TcpKeepAlive::DEFAULT.idle,
                interval: Duration::from_secs(9),
            })
        );
        assert_eq!(
            tcp_keep_alive(true, Some(Duration::from_secs(9)), None),
            None
        );
        assert_eq!(TcpKeepAlive::DEFAULT.idle, Duration::from_secs(300));
        assert_eq!(TcpKeepAlive::DEFAULT.interval, Duration::from_secs(75));
    }

    /// Accepted connections get the send buffer asked for, which Linux
    /// doubles; unasked, the system's own.
    #[tokio::test]
    async fn accepted_connections_get_the_send_buffer_asked_for() {
        const ASKED: usize = 48 << 10;
        let listener = TcpListener::bind_now(&"127.0.0.1:0".parse().unwrap())
            .unwrap()
            .send_buffer(ASKED);
        let addr = listener.io().local_addr().unwrap();
        let _client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (accepted, _) = listener.accept().await.unwrap();
        let size = SockRef::from(&accepted).send_buffer_size().unwrap();
        assert!((ASKED..=2 * ASKED).contains(&size), "{}", size);
    }

    #[test]
    fn only_the_router_profile_caps_the_send_buffer() {
        use crate::runtime::options::{Profile, RuntimeOptions};
        for profile in [Profile::Desktop, Profile::Mobile, Profile::Server] {
            assert_eq!(RuntimeOptions::profile(profile).inbound.tcp_send_buffer, 0);
        }
        assert_eq!(
            RuntimeOptions::profile(Profile::Router)
                .inbound
                .tcp_send_buffer,
            256
        );
    }

    #[test]
    fn abort_on_close_is_off_unless_asked_for() {
        assert!(
            !crate::runtime::RuntimeOptions::default()
                .inbound
                .tcp_abort_on_close
        );
    }

    /// What an outbound asks to have dialled is dialled by the dialer that
    /// comes with the request, and no other.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_request_is_dialled_by_its_own_dialer() {
        use crate::adapter::outbound::HandlerBuilder;
        use crate::adapter::{
            AnyOutboundDatagram, AnyOutboundTransport, DatagramTransportType,
            OutboundDatagramHandler, OutboundStreamHandler,
        };

        struct Asks(OutboundConnect);

        #[async_trait::async_trait]
        impl OutboundStreamHandler for Asks {
            fn connect_addr(&self) -> OutboundConnect {
                self.0.clone()
            }

            async fn handle<'a>(
                &'a self,
                _sess: &'a Session,
                _lhs: Option<&mut AnyStream>,
                _stream: Option<AnyStream>,
            ) -> io::Result<AnyStream> {
                unreachable!("only dialled")
            }
        }

        #[async_trait::async_trait]
        impl OutboundDatagramHandler for Asks {
            fn connect_addr(&self) -> OutboundConnect {
                self.0.clone()
            }

            fn transport_type(&self) -> DatagramTransportType {
                DatagramTransportType::Unreliable
            }

            async fn handle<'a>(
                &'a self,
                _sess: &'a Session,
                _transport: Option<AnyOutboundTransport>,
            ) -> io::Result<AnyOutboundDatagram> {
                unreachable!("only dialled")
            }
        }

        let handler = |connect: OutboundConnect| {
            let asks = std::sync::Arc::new(Asks(connect));
            HandlerBuilder::default()
                .tag("asks".to_string())
                .stream_handler(asks.clone())
                .datagram_handler(asks)
                .build()
        };
        let dns = crate::app::dns::DnsClient::new(
            &Default::default(),
            std::sync::Arc::new(DialDefaults::default()),
            &Default::default(),
        )
        .unwrap()
        .into_shared();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepting = tokio::spawn(async move {
            loop {
                let _ = listener.accept().await;
            }
        });
        let sess = Session {
            destination: SocksAddr::Ip(addr),
            ..Default::default()
        };

        let (proxy, by_proxy) = dial::recording::dialer();
        let proxy = handler(OutboundConnect::Proxy(
            Network::Tcp,
            addr.ip().to_string(),
            addr.port(),
            proxy,
        ));
        let (direct, by_direct) = dial::recording::dialer();
        let direct = handler(OutboundConnect::Direct(direct));

        connect_stream_outbound(&sess, dns.clone(), &proxy)
            .await
            .unwrap()
            .unwrap();
        connect_datagram_outbound(&sess, dns.clone(), &proxy)
            .await
            .unwrap()
            .unwrap();
        assert_eq!((by_proxy.count(), by_direct.count()), (2, 0));
        connect_stream_outbound(&sess, dns.clone(), &direct)
            .await
            .unwrap()
            .unwrap();
        connect_datagram_outbound(&sess, dns.clone(), &direct)
            .await
            .unwrap()
            .unwrap();
        assert_eq!((by_proxy.count(), by_direct.count()), (2, 2));
        // Asking for nothing, nothing is dialled.
        assert!(
            connect_stream_outbound(&sess, dns, &handler(OutboundConnect::Unknown))
                .await
                .unwrap()
                .is_none()
        );
        accepting.abort();
    }

    /// Every outbound built asks to be dialled by its own dialer, built
    /// over the instance's defaults, and so protected by the host.
    #[cfg(all(unix, feature = "outbound-direct"))]
    #[tokio::test]
    async fn every_outbound_built_dials_with_its_dialer() {
        let (defaults, protected) = dial::recording::defaults();
        let config = crate::config::Config::from_json(
            r#"{ "outbounds": [
                { "type": "direct", "tag": "own", "connect_timeout": "3s" },
                { "type": "direct", "tag": "plain" }
            ] }"#,
        )
        .unwrap();
        let dns = crate::app::dns::DnsClient::new(
            &config.dns,
            std::sync::Arc::new(defaults.clone()),
            &Default::default(),
        )
        .unwrap()
        .into_shared();
        let manager = crate::app::outbound::manager::OutboundManager::new(
            &config.outbounds,
            &defaults,
            &Default::default(),
            dns.clone(),
        )
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let sess = Session {
            destination: SocksAddr::Ip(addr),
            ..Default::default()
        };
        for (tag, timeout) in [("own", 3), ("plain", 5)] {
            let handler = manager.get(tag).unwrap();
            let OutboundConnect::Direct(dialer) = handler.stream().unwrap().connect_addr() else {
                panic!("[{}] asks for no direct connection", tag);
            };
            assert_eq!(dialer.connect_timeout(), Duration::from_secs(timeout));
            let (dialled, accepted) = tokio::join!(
                connect_stream_outbound(&sess, dns.clone(), &handler),
                listener.accept()
            );
            dialled.unwrap().unwrap();
            accepted.unwrap();
        }
        assert_eq!(protected.count(), 2);
    }
}
