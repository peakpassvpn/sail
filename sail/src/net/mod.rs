use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use async_trait::async_trait;
use futures::TryFutureExt;
use socket2::{Domain, SockRef, Socket, Type};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use tokio::time::timeout;
use tracing::{debug, trace};

#[cfg(unix)]
use {
    std::os::unix::io::{AsRawFd, RawFd},
    tokio::io::AsyncWriteExt,
    tokio::net::UnixStream,
};

use crate::{
    adapter::*,
    app::SyncDnsClient,
    session::{Network, Session, SocksAddr},
};

use resolver::Resolver;

pub mod datagram;
pub mod dial;
pub mod interface;
#[cfg(feature = "netstack")]
pub mod netstack;
pub mod relay;
pub mod resolver;

pub use datagram::*;
pub use dial::DialOptions;

/// Keeps an outbound socket out of the host's VPN, as `dial.protect` says.
#[cfg(unix)]
async fn protect_socket(fd: RawFd, dial: &DialOptions) -> io::Result<()> {
    let answer = match &dial.protect {
        None => return Ok(()),
        Some(dial::SocketProtect::Platform(platform)) => {
            let start = std::time::Instant::now();
            platform.protect_socket(fd).map_err(|e| {
                io::Error::other(format!("failed to protect outbound socket {}: {}", fd, e))
            })?;
            trace!(
                "protected socket {} in {} µs",
                fd,
                start.elapsed().as_micros()
            );
            return Ok(());
        }
        Some(dial::SocketProtect::Tcp(addr)) => {
            let mut stream = TcpStream::connect(addr).await?;
            stream.write_i32(fd).await?;
            stream.read_i32().await?
        }
        Some(dial::SocketProtect::Unix(path)) => {
            let mut stream = UnixStream::connect(path).await?;
            stream.write_i32(fd).await?;
            stream.read_i32().await?
        }
    };
    if answer != 0 {
        return Err(io::Error::other(format!(
            "failed to protect outbound socket {}",
            fd
        )));
    }
    Ok(())
}

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

    pub async fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        let (stream, addr) = self.inner.accept().await?;
        apply_socket_opts(SockRef::from(&stream), self.keepalive)?;
        if self.abort_on_close {
            // Reclaims the socket the moment it is closed, and discards
            // anything still queued for the peer along with it. See the
            // option's own documentation for when that trade is the right one.
            SockRef::from(&stream).set_linger(Some(Duration::ZERO))?;
        }
        if self.send_buffer > 0 {
            SockRef::from(&stream).set_send_buffer_size(self.send_buffer)?;
        }
        Ok((stream, addr))
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

/// A UDP socket for talking to `indicator`'s address family, opened as
/// `dial` says.
pub async fn new_udp_socket(indicator: &SocketAddr, dial: &DialOptions) -> io::Result<UdpSocket> {
    let socket = Socket::new(Domain::for_address(*indicator), Type::DGRAM, None)?;
    socket.set_nonblocking(true)?;
    fit_largest_datagram(SockRef::from(&socket))?;
    let bound = dial::bind(&socket, indicator, dial)?;
    if !bound && indicator.ip().is_unspecified() {
        socket.bind(&(*indicator).into())?;
    }

    #[cfg(unix)]
    protect_socket(socket.as_raw_fd(), dial).await?;

    UdpSocket::from_std(socket.into())
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
fn apply_socket_opts(s: SockRef, keepalive: Option<TcpKeepAlive>) -> io::Result<()> {
    match keepalive {
        Some(keepalive) => keepalive.apply(&s)?,
        None => s.set_keepalive(false)?,
    }
    s.set_nodelay(true)
}

/// A TCP connection to `addr`, opened as `dial` says.
pub async fn tcp_connect(addr: SocketAddr, dial: &DialOptions) -> io::Result<TcpStream> {
    let socket = match addr {
        SocketAddr::V4(..) => TcpSocket::new_v4()?,
        SocketAddr::V6(..) => TcpSocket::new_v6()?,
    };

    dial::bind(&SockRef::from(&socket), &addr, dial)?;

    #[cfg(unix)]
    protect_socket(socket.as_raw_fd(), dial).await?;

    debug!("tcp dialing {}", &addr);
    let start = tokio::time::Instant::now();
    let stream = timeout(dial.connect_timeout, socket.connect(addr))
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!("connect {} timed out", addr),
            )
        })??;
    let elapsed = tokio::time::Instant::now().duration_since(start);

    apply_socket_opts(SockRef::from(&stream), dial.tcp_keep_alive())?;

    debug!(
        "tcp {} <-> {} connected in {}ms",
        stream.local_addr()?,
        &addr,
        elapsed.as_millis()
    );
    Ok(stream)
}

pub async fn connect_stream_outbound(
    sess: &Session,
    dns_client: SyncDnsClient,
    handler: &AnyOutboundHandler,
) -> io::Result<Option<AnyStream>> {
    let (connect, dial) = handler.stream()?.connect_addr().with_dial();
    match connect {
        OutboundConnect::Proxy(Network::Tcp, addr, port) => {
            trace!("connect stream proxy outbound addr={} port={}", &addr, port);
            Ok(Some(new_tcp_stream(dns_client, &addr, &port, &dial).await?))
        }
        OutboundConnect::Direct => {
            let dest = &sess.destination;
            trace!("connect stream direct dst={}", &dest);
            Ok(Some(
                new_tcp_stream(dns_client, &dest.host(), &dest.port(), &dial).await?,
            ))
        }
        _ => {
            trace!("connect stream None");
            Ok(None)
        }
    }
}

pub async fn connect_datagram_outbound(
    sess: &Session,
    dns_client: SyncDnsClient,
    handler: &AnyOutboundHandler,
) -> io::Result<Option<AnyOutboundTransport>> {
    let (connect, dial) = handler.datagram()?.connect_addr().with_dial();
    match connect {
        OutboundConnect::Proxy(network, addr, port) => match network {
            Network::Udp => {
                let socket = match addr.parse::<IpAddr>() {
                    Ok(ip) if ip.is_loopback() => {
                        new_udp_socket(&SocketAddr::new(ip, 0), &dial).await?
                    }
                    _ => new_udp_socket(&dial.unspecified(), &dial).await?,
                };
                Ok(Some(OutboundTransport::Datagram(Box::new(
                    DomainResolveOutboundDatagram::new(socket, dns_client.clone(), dial.clone()),
                ))))
            }
            Network::Tcp => {
                let stream = new_tcp_stream(dns_client.clone(), &addr, &port, &dial).await?;
                Ok(Some(OutboundTransport::Stream(stream)))
            }
        },
        OutboundConnect::Direct if sess.route.udp_connect => {
            let addr = match &sess.destination {
                SocksAddr::Ip(addr) => *addr,
                SocksAddr::Domain(domain, port) => {
                    let ips = dns_client
                        .load_full()
                        .lookup_dial(domain, &dial)
                        .await
                        .map_err(|e| {
                            io::Error::other(format!("lookup {} failed: {}", domain, e))
                        })?;
                    let ip = ips.first().ok_or_else(|| {
                        io::Error::other(format!("{} resolves to nothing", domain))
                    })?;
                    SocketAddr::new(*ip, *port)
                }
            };
            let socket = new_udp_socket(&addr, &dial).await?;
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
        OutboundConnect::Direct => match &sess.destination {
            SocksAddr::Domain(domain, port) => {
                let socket = new_udp_socket(&dial.unspecified(), &dial).await?;
                Ok(Some(OutboundTransport::Datagram(Box::new(
                    DomainAssociatedOutboundDatagram::new(
                        socket,
                        SocksAddr::Domain(domain.to_owned(), *port),
                        dns_client.clone(),
                        dial.clone(),
                    )
                    .without_unmapping(sess.route.udp_disable_domain_unmapping),
                ))))
            }
            SocksAddr::Ip(addr) => {
                let socket = new_udp_socket(addr, &dial).await?;
                Ok(Some(OutboundTransport::Datagram(Box::new(
                    StdOutboundDatagram::new(socket),
                ))))
            }
        },
        _ => Ok(None),
    }
}

/// Dials a TCP stream to `address`, trying its addresses one by one.
pub async fn new_tcp_stream(
    dns_client: SyncDnsClient,
    address: &String,
    port: &u16,
    dial: &DialOptions,
) -> io::Result<AnyStream> {
    Ok(Box::new(dial_tcp(dns_client, address, port, dial).await?))
}

/// `new_tcp_stream`, the TCP stream itself.
pub async fn dial_tcp(
    dns_client: SyncDnsClient,
    address: &String,
    port: &u16,
    dial: &DialOptions,
) -> io::Result<TcpStream> {
    let resolver = Resolver::new(dns_client.clone(), address, port, dial)
        .map_err(|e| io::Error::other(format!("resolve address failed: {}", e)))
        .await?;

    let mut last_err = None;
    for dial_addr in resolver {
        match tcp_connect(dial_addr, dial).await {
            Ok(stream) => return Ok(stream),
            Err(e) => last_err = Some(e),
        }
    }

    Err(match last_err {
        Some(e) => io::Error::other(format!("all attempts failed, last error: {}", e)),
        None => io::Error::new(
            io::ErrorKind::InvalidInput,
            "could not resolve to any address",
        ),
    })
}

/// An interface with the ability to dial TCP connections.
#[async_trait]
pub trait TcpConnector: Send + Sync + Unpin {
    /// Dials a TCP connection.
    async fn new_tcp_stream(
        &self,
        dns_client: SyncDnsClient,
        address: &String,
        port: &u16,
        dial: &DialOptions,
    ) -> io::Result<AnyStream> {
        new_tcp_stream(dns_client, address, port, dial).await
    }
}

/// An interface with the ability to create UDP sockets.
#[async_trait]
pub trait UdpConnector: Send + Sync + Unpin {
    /// Creates a UDP socket.
    async fn new_udp_socket(
        &self,
        indicator: &SocketAddr,
        dial: &DialOptions,
    ) -> io::Result<UdpSocket> {
        new_udp_socket(indicator, dial).await
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
        for (listen, dial) in [
            (None, DialOptions::default()),
            (
                Some(custom),
                DialOptions {
                    tcp_keep_alive: Some(custom.idle),
                    tcp_keep_alive_interval: Some(custom.interval),
                    ..Default::default()
                },
            ),
            (
                None,
                DialOptions {
                    disable_tcp_keep_alive: true,
                    ..Default::default()
                },
            ),
        ] {
            runtime().block_on(async {
                let listener = TcpListener::bind(&"127.0.0.1:0".parse().unwrap())
                    .await
                    .unwrap();
                let listener = match listen {
                    Some(k) => listener.keepalive(Some(k)),
                    None => listener,
                };
                let addr = listener.io().local_addr().unwrap();
                let dialling = dial.clone();
                let dialled = tokio::spawn(async move { tcp_connect(addr, &dialling).await });
                let (accepted, _) = listener.accept().await.unwrap();
                let dialled = dialled.await.unwrap().unwrap();
                check(
                    SockRef::from(&accepted),
                    Some(listen.unwrap_or(TcpKeepAlive::DEFAULT)),
                );
                let want = if dial.disable_tcp_keep_alive {
                    None
                } else if dial.tcp_keep_alive.is_some() {
                    Some(custom)
                } else {
                    Some(TcpKeepAlive::DEFAULT)
                };
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
}
