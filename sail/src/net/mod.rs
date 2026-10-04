use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use socket2::{Domain, SockRef, Socket, Type};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, trace};

use crate::{
    adapter::*,
    app::SyncDnsClient,
    session::{Network, Session, SocksAddr},
};

pub mod accept;
pub mod backlog;
pub mod datagram;
pub mod dial;
pub mod dial_domain;
pub mod interface;
pub mod nat64;
pub(crate) mod neighbor;
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
        dual_stack(SockRef::from(&socket), addr)?;
        // As tokio's own bind does: lets a restarted process listen again
        // while connections of the last one are still in TIME_WAIT.
        #[cfg(not(windows))]
        socket.set_reuse_address(true)?;
        socket.bind(&(*addr).into())?;
        socket.listen(backlog::max_listener_backlog())?;
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

/// Makes `socket`, about to be bound to `addr`, carry IPv4 as well when
/// `addr` is IPv6's unspecified address, `::`: a listener there accepts
/// IPv4, and a socket there sends to IPv4 addresses, IPv4-mapped. Go does
/// the same on every system for a wildcard listen. The systems' defaults
/// differ: Windows makes every IPv6 socket IPv6-only, and Linux does with
/// `net.ipv6.bindv6only` set. A socket on any other address is left as it
/// is. Call it before the bind.
pub fn dual_stack(socket: SockRef, addr: &SocketAddr) -> io::Result<()> {
    match addr {
        SocketAddr::V6(v6) if v6.ip().is_unspecified() => socket.set_only_v6(false),
        _ => Ok(()),
    }
}

/// Has Windows stop failing a UDP socket's next receive or send with
/// WSAECONNRESET for an ICMP port unreachable that a datagram sent earlier
/// to any peer drew (SIO_UDP_CONNRESET off), which it does on an
/// unconnected socket too, as no other system does; a socket that relays
/// for many peers would stall, or a connected one end, for one peer gone.
/// Elsewhere nothing. Should the system refuse, the socket works as it
/// did before: said once, at debug.
pub fn no_udp_connreset(socket: SockRef) {
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        use windows_sys::Win32::Networking::WinSock::{WSAIoctl, SIO_UDP_CONNRESET, SOCKET};
        let off: u32 = 0;
        let mut returned = 0u32;
        // SAFETY: a socket, a 4-byte BOOL in, nothing out, no overlapped
        // call.
        let failed = unsafe {
            WSAIoctl(
                socket.as_raw_socket() as SOCKET,
                SIO_UDP_CONNRESET,
                &off as *const u32 as *const core::ffi::c_void,
                std::mem::size_of::<u32>() as u32,
                std::ptr::null_mut(),
                0,
                &mut returned,
                std::ptr::null_mut(),
                None,
            )
        } != 0;
        if failed {
            static SAID: std::sync::Once = std::sync::Once::new();
            let e = io::Error::last_os_error();
            SAID.call_once(|| {
                debug!("udp: SIO_UDP_CONNRESET not set ({}): an ICMP port unreachable may fail a later receive", e)
            });
        }
    }
    #[cfg(not(windows))]
    let _ = socket;
}

/// A UDP socket bound to `addr`, as `std::net::UdpSocket::bind` binds it,
/// but [`dual_stack`] on `::`, and with [`no_udp_connreset`].
pub fn bind_udp(addr: &SocketAddr) -> io::Result<std::net::UdpSocket> {
    let socket = Socket::new(Domain::for_address(*addr), Type::DGRAM, None)?;
    no_udp_connreset(SockRef::from(&socket));
    dual_stack(SockRef::from(&socket), addr)?;
    socket.bind(&(*addr).into())?;
    Ok(socket.into())
}

/// A TCP listener on `addr`, as `std::net::TcpListener::bind` makes it,
/// but [`dual_stack`] on `::`.
pub fn listen_tcp(addr: &SocketAddr) -> io::Result<std::net::TcpListener> {
    let socket = Socket::new(Domain::for_address(*addr), Type::STREAM, None)?;
    dual_stack(SockRef::from(&socket), addr)?;
    #[cfg(not(windows))]
    socket.set_reuse_address(true)?;
    socket.bind(&(*addr).into())?;
    socket.listen(128)?;
    Ok(socket.into())
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
    let th = handler.stream()?;
    th.dialing(sess);
    connect_stream(sess, dns_client, th.connect_addr()).await
}

/// `connect_stream_outbound`, for `handler`, the outbound the rules routed
/// `sess` to: see [`routed`].
pub async fn connect_stream_routed(
    sess: &Session,
    dns_client: SyncDnsClient,
    handler: &AnyOutboundHandler,
) -> io::Result<Option<AnyStream>> {
    let th = handler.stream()?;
    th.dialing(sess);
    let connect = routed(sess, handler, th.connect_addr(), false);
    connect_stream(sess, dns_client, connect).await
}

/// `connect_datagram_outbound`, for `handler`, the outbound the rules
/// routed `sess` to: see [`routed`].
pub async fn connect_datagram_routed(
    sess: &Session,
    dns_client: SyncDnsClient,
    handler: &AnyOutboundHandler,
) -> io::Result<Option<AnyOutboundTransport>> {
    let dh = handler.datagram()?;
    dh.dialing(sess);
    let connect = routed(sess, handler, dh.connect_addr(), true);
    connect_datagram(sess, dns_client, connect).await
}

/// What `handler`, the outbound the rules routed `sess` to, has dialled:
/// what it asks for, `connect`, for datagrams if `datagram`, with the
/// `network_strategy` and `fallback_delay` the rules set where it is a
/// direct outbound (`Dialer::routed`). Only a direct outbound the rules
/// route to takes them, as only sing-box's direct outbound takes the
/// router's (protocol/direct/outbound.go:33, 232-262): neither a group
/// whose pick is one, nor an outbound dialing its server. And only where
/// the destination's addresses are known before it is dialled, as sing-box
/// hands them over only then (route/conn.go:101-105, 162-175, 203-205): a
/// `resolve` rule resolved its domain, or it is an address, but for UDP
/// that is not connected. A domain the direct outbound resolves itself it
/// dials as its own fields say.
pub(crate) fn routed(
    sess: &Session,
    handler: &AnyOutboundHandler,
    connect: OutboundConnect,
    datagram: bool,
) -> OutboundConnect {
    let known = !sess.route.resolved.is_empty()
        || (sess.destination.ip().is_some() && (!datagram || sess.route.udp_connect));
    match connect {
        OutboundConnect::Direct(dialer) if handler.is_direct() && known => OutboundConnect::Direct(
            dialer.routed(sess.route.network_strategy, sess.route.fallback_delay),
        ),
        connect => connect,
    }
}

async fn connect_stream(
    sess: &Session,
    dns_client: SyncDnsClient,
    connect: OutboundConnect,
) -> io::Result<Option<AnyStream>> {
    match connect {
        OutboundConnect::Proxy(Network::Tcp, addr, port, dialer) => {
            trace!("connect stream proxy outbound addr={} port={}", &addr, port);
            let to = SocksAddr::try_from((addr, port))?;
            Ok(Some(dialer.stream(&dns_client, Some(sess), &to).await?))
        }
        OutboundConnect::Direct(dialer) => {
            trace!("connect stream direct dst={}", &sess.destination);
            if let Some(ips) = resolved(sess, &dialer) {
                return Ok(Some(
                    dialer
                        .stream_to_resolved(Some(sess), ips, sess.destination.port())
                        .await?,
                ));
            }
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
    let dh = handler.datagram()?;
    dh.dialing(sess);
    connect_datagram(sess, dns_client, dh.connect_addr()).await
}

async fn connect_datagram(
    sess: &Session,
    dns_client: SyncDnsClient,
    connect: OutboundConnect,
) -> io::Result<Option<AnyOutboundTransport>> {
    match connect {
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
                    let ips = match resolved(sess, &dialer) {
                        Some(ips) => ips.to_vec(),
                        None => dialer.lookup(&dns_client, domain).await?,
                    };
                    let ip = ips.first().ok_or_else(|| {
                        io::Error::other(format!("{} resolves to nothing", domain))
                    })?;
                    SocketAddr::new(*ip, *port)
                }
            };
            let socket = dialer.udp_socket_for(sess, &addr).await?;
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
                let socket = dialer.udp_socket_for(sess, &dialer.unspecified()).await?;
                Ok(Some(OutboundTransport::Datagram(Box::new(
                    DomainAssociatedOutboundDatagram::new(
                        socket,
                        SocksAddr::Domain(domain.to_owned(), *port),
                        dns_client.clone(),
                        dialer,
                    )
                    .without_unmapping(sess.route.udp_disable_domain_unmapping)
                    .resolved(sess.route.resolved.clone()),
                ))))
            }
            SocksAddr::Ip(addr) => {
                let socket = dialer.udp_socket_for(sess, addr).await?;
                Ok(Some(OutboundTransport::Datagram(Box::new(
                    StdOutboundDatagram::new(socket),
                ))))
            }
        },
        _ => Ok(None),
    }
}

/// The addresses a `resolve` rule resolved `sess`'s domain to, which
/// `dialer` dials instead of resolving the domain again, as sing-box dials
/// its `DestinationAddresses` (route/conn.go:101-104, 166-170, 203-205):
/// none for an address, or for a dialer with a detour, which hands the
/// domain on.
fn resolved<'a>(sess: &'a Session, dialer: &Dialer) -> Option<&'a [std::net::IpAddr]> {
    (sess.destination.domain().is_some()
        && !sess.route.resolved.is_empty()
        && dialer.detour().is_none())
    .then_some(sess.route.resolved.as_slice())
}

/// Where an outbound asking for `connect` is to take `sess`, each in turn
/// until one connects: its destination; or, after a sing-box `resolve`
/// rule, each address it resolved the domain to, as sing-box hands them to
/// every outbound, a proxy's server then told the address
/// (route/conn.go:101-104, 166-175, 203-205;
/// common/dialer/default_parallel_network.go:16-45). Not to a direct dial
/// of its own, which races them itself, nor after an `on_demand` resolve,
/// whose addresses, as Mihomo's, only a direct dial takes. Nor where
/// `override_destination` asks that a proxy be told the name: it wins.
pub(crate) fn destinations(sess: &Session, connect: &OutboundConnect) -> Vec<SocksAddr> {
    let self_dialing =
        matches!(connect, OutboundConnect::Direct(dialer) if dialer.detour().is_none());
    match &sess.destination {
        SocksAddr::Domain(_, port)
            if sess.route.resolved_for_every_outbound
                && !sess.route.resolved.is_empty()
                && !self_dialing
                && sess.route.override_destination.is_none() =>
        {
            sess.route
                .resolved
                .iter()
                .map(|ip| SocksAddr::Ip(SocketAddr::new(*ip, *port)))
                .collect()
        }
        _ => vec![sess.destination.clone()],
    }
}

/// How much of what a refused client sent [`refuse`] reads and drops, at
/// most: a judgment value, as sing-box sets none.
const REFUSAL_DRAIN_LIMIT: u64 = 64 * 1024;
/// How long [`refuse`] waits, in all, for the client to stop sending: a
/// judgment value.
const REFUSAL_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

/// Writes a refusal, `reply`, and closes the write side, then reads and drops
/// what the client sent but was not read, up to its end or a bound. A
/// connection closed with data left unread is reset, not closed in order,
/// and the reset can discard the refusal before the client reads it (on
/// Windows, most of all). Fails only when the reply cannot be written.
pub async fn refuse<S>(stream: &mut S, reply: &[u8]) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    stream.write_all(reply).await?;
    stream.flush().await?;
    let _ = stream.shutdown().await;
    let mut unread = (&mut *stream).take(REFUSAL_DRAIN_LIMIT);
    let _ = timeout(
        REFUSAL_DRAIN_TIMEOUT,
        tokio::io::copy(&mut unread, &mut tokio::io::sink()),
    )
    .await;
    Ok(())
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

    /// An address nothing listens on: a port bound, then let go.
    fn closed_port() -> SocketAddr {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.local_addr().unwrap()
    }

    /// What `no_udp_connreset` is for: on Windows a socket that sent to a
    /// closed port fails its next receive, unconnected as it is.
    #[cfg(windows)]
    #[test]
    fn windows_fails_the_next_receive_after_a_port_unreachable() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        socket.send_to(b"x", closed_port()).unwrap();
        let mut buf = [0u8; 8];
        let e = socket.recv_from(&mut buf).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::ConnectionReset, "{}", e);
    }

    /// A socket of `bind_udp`, which relays for many peers, sends to a
    /// closed port and goes on: its next receive waits for a datagram
    /// rather than fails, and it sends to and hears from an open one.
    #[test]
    fn a_port_unreachable_fails_neither_receive_nor_send() {
        let socket = bind_udp(&"127.0.0.1:0".parse().unwrap()).unwrap();
        let open = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        open.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        socket.send_to(b"x", closed_port()).unwrap();
        let mut buf = [0u8; 8];
        let e = socket.recv_from(&mut buf).unwrap_err();
        assert!(
            matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ),
            "{}",
            e
        );
        socket.send_to(b"x", closed_port()).unwrap();
        socket.send_to(b"y", open.local_addr().unwrap()).unwrap();
        let (n, from) = open.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"y");
        open.send_to(b"z", from).unwrap();
        let (n, _) = socket.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"z");
    }

    /// A dialer's socket for a peer of a known address is not bound until
    /// it first sends; a receive on it before then, as a NAT session's
    /// downlink starts before its uplink sends, waits rather than fails.
    #[tokio::test]
    async fn a_receive_before_the_first_send_waits() {
        let socket = Dialer::system()
            .udp_socket(&"127.0.0.1:9".parse().unwrap())
            .await
            .unwrap();
        let mut buf = [0u8; 8];
        let waited =
            tokio::time::timeout(Duration::from_millis(300), socket.recv_from(&mut buf)).await;
        assert!(waited.is_err(), "the receive answered: {:?}", waited);
    }

    /// The same of a dialer's socket, which every outbound, DNS server and
    /// QUIC endpoint takes.
    #[tokio::test]
    async fn a_dialer_s_socket_goes_on_after_a_port_unreachable() {
        let socket = Dialer::system()
            .udp_socket(&"0.0.0.0:0".parse().unwrap())
            .await
            .unwrap();
        let open = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.send_to(b"x", closed_port()).await.unwrap();
        let mut buf = [0u8; 8];
        let waited =
            tokio::time::timeout(Duration::from_millis(500), socket.recv_from(&mut buf)).await;
        assert!(waited.is_err(), "the receive answered: {:?}", waited);
        socket
            .send_to(b"y", open.local_addr().unwrap())
            .await
            .unwrap();
        let (n, from) = open.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"y");
        open.send_to(b"z", from).await.unwrap();
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buf))
            .await
            .expect("the answer in time")
            .unwrap();
        assert_eq!(&buf[..n], b"z");
    }

    const ANY_V6: &str = "[::]:0";

    /// A socket on `::` is made dual-stack whatever the system's default,
    /// here IPv6-only as on Windows; one on another address is left alone.
    /// Told by what the socket can send where the option cannot be read
    /// back: socket2's getter fails on Windows, which answers with one byte.
    #[test]
    fn a_socket_on_the_ipv6_unspecified_address_is_made_dual_stack() {
        let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let to: SocketAddr = (
            std::net::Ipv4Addr::LOCALHOST.to_ipv6_mapped(),
            peer.local_addr().unwrap().port(),
        )
            .into();
        let v6_only = || {
            let socket = Socket::new(Domain::IPV6, Type::DGRAM, None).unwrap();
            socket.set_only_v6(true).unwrap();
            socket
        };
        let socket = v6_only();
        dual_stack(SockRef::from(&socket), &ANY_V6.parse().unwrap()).unwrap();
        // macOS lets an IPv6-only socket send to an IPv4-mapped address, so
        // the send alone tells only on Windows.
        #[cfg(not(windows))]
        assert!(!socket.only_v6().unwrap());
        socket
            .bind(&ANY_V6.parse::<SocketAddr>().unwrap().into())
            .unwrap();
        socket.send_to(b"ping", &to.into()).unwrap();
        let mut buf = [0u8; 8];
        let (n, _) = peer.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"ping");

        let socket = v6_only();
        dual_stack(SockRef::from(&socket), &"[::1]:0".parse().unwrap()).unwrap();
        #[cfg(not(windows))]
        assert!(socket.only_v6().unwrap());
    }

    /// A UDP socket and the TCP listeners on `::` take IPv4 from 127.0.0.1.
    #[tokio::test]
    async fn listeners_on_the_ipv6_unspecified_address_take_ipv4() {
        let any: SocketAddr = ANY_V6.parse().unwrap();
        let udp = bind_udp(&any).unwrap();
        udp.set_nonblocking(true).unwrap();
        let udp = tokio::net::UdpSocket::from_std(udp).unwrap();
        let port = udp.local_addr().unwrap().port();
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        peer.send_to(b"ping", ("127.0.0.1", port)).await.unwrap();
        let mut buf = [0u8; 8];
        let (n, _) = timeout(Duration::from_secs(5), udp.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"ping");

        let listener = TcpListener::bind_now(&any).unwrap();
        let port = listener.io().local_addr().unwrap().port();
        let (connected, accepted) = tokio::join!(
            TcpStream::connect(("127.0.0.1", port)),
            timeout(Duration::from_secs(5), listener.accept())
        );
        connected.unwrap();
        accepted.unwrap().unwrap();

        let listener = listen_tcp(&any).unwrap();
        let port = listener.local_addr().unwrap().port();
        std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        listener.accept().unwrap();
    }

    /// A dialer's UDP socket on `::` sends to an IPv4 address, IPv4-mapped.
    #[tokio::test]
    async fn a_dialer_udp_socket_on_the_ipv6_unspecified_address_sends_to_ipv4() {
        let socket = Dialer::system()
            .udp_socket(&ANY_V6.parse().unwrap())
            .await
            .unwrap();
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = peer.local_addr().unwrap().port();
        let mapped = std::net::Ipv4Addr::LOCALHOST.to_ipv6_mapped();
        socket.send_to(b"ping", (mapped, port)).await.unwrap();
        let mut buf = [0u8; 8];
        let (n, _) = timeout(Duration::from_secs(5), peer.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"ping");
    }

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

    /// A direct dial to a domain a `resolve` rule resolved goes to the
    /// addresses it resolved to, not to what its own resolver answers, as
    /// sing-box dials `DestinationAddresses` (route/conn.go:101-104,
    /// 166-170, 203-205): over TCP, connected UDP, and UDP that is not.
    /// Here the default server answers `::1`, the rule's `127.0.0.1`.
    #[tokio::test]
    async fn a_direct_dial_goes_to_the_addresses_a_resolve_rule_resolved() {
        use tokio::io::AsyncWriteExt;

        let config = crate::config::Config::from_json(
            r#"{ "dns": { "servers": [
                { "type": "hosts", "predefined": { "test.sail": "::1" } }
            ] } }"#,
        )
        .unwrap();
        let dns = crate::app::dns::DnsClient::new(
            &config.dns,
            std::sync::Arc::new(DialDefaults::default()),
            &Default::default(),
        )
        .unwrap()
        .into_shared();
        // One port on both loopbacks, for TCP and UDP.
        let (tcp, udp, port) = loop {
            let v4 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = v4.local_addr().unwrap().port();
            let at = |ip: &str| SocketAddr::new(ip.parse().unwrap(), port);
            let (Ok(v6), Ok(u4), Ok(u6)) = (
                tokio::net::TcpListener::bind(at("::1")).await,
                tokio::net::UdpSocket::bind(at("127.0.0.1")).await,
                tokio::net::UdpSocket::bind(at("::1")).await,
            ) else {
                continue;
            };
            break ((v4, v6), (u4, u6), port);
        };
        let resolved = |udp_connect: bool| {
            let mut sess = Session {
                destination: SocksAddr::Domain("test.sail".into(), port),
                ..Default::default()
            };
            sess.route.resolved = vec!["127.0.0.1".parse().unwrap()];
            sess.route.udp_connect = udp_connect;
            sess
        };
        let direct = || OutboundConnect::Direct(Dialer::system());

        let sess = resolved(false);
        let mut stream = connect_stream(&sess, dns.clone(), direct())
            .await
            .unwrap()
            .unwrap();
        stream.write_all(b"x").await.unwrap();
        let accepted = tokio::select! {
            _ = tcp.0.accept() => "127.0.0.1",
            _ = tcp.1.accept() => "::1",
        };
        assert_eq!(accepted, "127.0.0.1");

        let (mut buf4, mut buf6) = ([0u8; 8], [0u8; 8]);
        for udp_connect in [false, true] {
            let sess = resolved(udp_connect);
            let Some(OutboundTransport::Datagram(datagram)) =
                connect_datagram(&sess, dns.clone(), direct())
                    .await
                    .unwrap()
            else {
                panic!("no datagrams");
            };
            let (_recv, mut send) = datagram.split();
            send.send_to(b"x", &sess.destination).await.unwrap();
            let heard = tokio::select! {
                _ = udp.0.recv_from(&mut buf4) => "127.0.0.1",
                _ = udp.1.recv_from(&mut buf6) => "::1",
            };
            assert_eq!(heard, "127.0.0.1", "udp_connect: {}", udp_connect);
        }
    }

    /// Only a direct outbound the rules route to dials with what they set:
    /// neither an outbound that dials its server, nor a group passing on a
    /// direct pick's request, which says it is no direct outbound, as only
    /// sing-box's direct outbound takes the router's `network_strategy`.
    /// And only to addresses known before it dials: an address, but not
    /// for UDP that is not connected, or a domain a `resolve` rule
    /// resolved (route/conn.go:101-105, 162-175, 203-205).
    #[test]
    fn only_a_routed_direct_outbound_to_known_addresses_takes_the_rules_network() {
        use crate::adapter::outbound::HandlerBuilder;
        use crate::net::dial::NetworkStrategy;

        let handler = |direct: bool| HandlerBuilder::default().is_direct(direct).build();
        let at = |destination: &str| {
            let mut sess = Session {
                destination: match destination.parse::<SocketAddr>() {
                    Ok(addr) => SocksAddr::Ip(addr),
                    Err(_) => SocksAddr::Domain(destination.into(), 443),
                },
                ..Default::default()
            };
            sess.route.network_strategy = Some(NetworkStrategy::Hybrid);
            sess.route.fallback_delay = Some(Duration::from_millis(40));
            sess
        };
        let own = Dialer::system();
        let taken = (Some(NetworkStrategy::Hybrid), Duration::from_millis(40));
        let not = (None, dial::DEFAULT_FALLBACK_DELAY);
        let strategy =
            |sess: &Session, direct: bool, connect: OutboundConnect, datagram| match routed(
                sess,
                &handler(direct),
                connect,
                datagram,
            ) {
                OutboundConnect::Direct(dialer) | OutboundConnect::Proxy(.., dialer) => (
                    dialer.spec().networks.as_ref().map(|n| n.strategy),
                    dialer.spec().fallback_delay,
                ),
                _ => unreachable!(),
            };
        let direct = || OutboundConnect::Direct(own.clone());

        let addr = at("192.0.2.1:443");
        assert_eq!(strategy(&addr, true, direct(), false), taken);
        assert_eq!(strategy(&addr, false, direct(), false), not);
        let proxy = OutboundConnect::Proxy(Network::Tcp, "192.0.2.1".into(), 443, own.clone());
        assert_eq!(strategy(&addr, true, proxy, false), not);
        // UDP to an address, connected only.
        assert_eq!(strategy(&addr, true, direct(), true), not);
        let mut connected = at("192.0.2.1:443");
        connected.route.udp_connect = true;
        assert_eq!(strategy(&connected, true, direct(), true), taken);

        // A domain, once a resolve rule resolved it.
        let mut domain = at("x.test");
        assert_eq!(strategy(&domain, true, direct(), false), not);
        assert_eq!(strategy(&domain, true, direct(), true), not);
        domain.route.resolved = vec!["192.0.2.1".parse().unwrap()];
        assert_eq!(strategy(&domain, true, direct(), false), taken);
        assert_eq!(strategy(&domain, true, direct(), true), taken);
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
