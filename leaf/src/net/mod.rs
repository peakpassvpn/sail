#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::ffi::CString;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::Duration;

use async_trait::async_trait;
use futures::future::select_ok;
use futures::TryFutureExt;
use socket2::{Domain, SockRef, Socket, Type};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use tokio::time::timeout;
use tracing::{debug, trace};

#[cfg(unix)]
use std::os::unix::io::AsFd;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::os::unix::io::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsSocket;
#[cfg(target_os = "android")]
use {
    std::os::unix::io::{AsRawFd, RawFd},
    tokio::io::AsyncWriteExt,
    tokio::net::UnixStream,
};

use crate::{
    adapter::*,
    app::SyncDnsClient,
    option,
    session::{Network, Session, SocksAddr},
};

use resolver::Resolver;

pub mod addr;
pub mod datagram;
pub mod relay;
pub mod resolver;

pub use datagram::*;

#[derive(Debug)]
pub enum OutboundBind {
    Ip(SocketAddr),
    Interface(String),
}

#[cfg(target_os = "android")]
async fn protect_socket(fd: RawFd) -> io::Result<()> {
    if crate::mobile::callback::android::is_protect_socket_callback_set() {
        let start = std::time::Instant::now();
        crate::mobile::callback::android::protect_socket(fd).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("failed to protect outbound socket {}: {:?}", fd, e),
            )
        })?;
        trace!(
            "protected socket {} in {} µs",
            fd,
            start.elapsed().as_micros()
        );
        return Ok(());
    }
    if let Some(addr) = &*option::SOCKET_PROTECT_SERVER {
        let mut stream = TcpStream::connect(addr).await?;
        stream.write_i32(fd as i32).await?;
        if stream.read_i32().await? != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("failed to protect outbound socket {}", fd),
            ));
        }
        return Ok(());
    }
    if !option::SOCKET_PROTECT_PATH.is_empty() {
        let mut stream = UnixStream::connect(&*option::SOCKET_PROTECT_PATH).await?;
        stream.write_i32(fd as i32).await?;
        if stream.read_i32().await? != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("failed to protect outbound socket {}", fd),
            ));
        }
        return Ok(());
    }
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
trait BindSocket: AsFd {
    fn bind(&self, bind_addr: &SocketAddr) -> io::Result<()>;
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
trait BindSocket {
    fn bind(&self, bind_addr: &SocketAddr) -> io::Result<()>;
}

impl BindSocket for TcpSocket {
    fn bind(&self, bind_addr: &SocketAddr) -> io::Result<()> {
        self.bind(bind_addr.to_owned())
    }
}

impl BindSocket for socket2::Socket {
    fn bind(&self, bind_addr: &SocketAddr) -> io::Result<()> {
        self.bind(&bind_addr.to_owned().into())
    }
}

pub struct TcpListener {
    inner: tokio::net::TcpListener,
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
        })
    }

    pub fn io(&self) -> &tokio::net::TcpListener {
        &self.inner
    }

    pub async fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        let (stream, addr) = self.inner.accept().await?;
        apply_socket_opts(&stream)?;
        if *option::TCP_INBOUND_ABORT_ON_CLOSE {
            // Reclaims the socket the moment it is closed, and discards
            // anything still queued for the peer along with it. See the
            // option's own documentation for when that trade is the right one.
            SockRef::from(&stream).set_linger(Some(Duration::ZERO))?;
        }
        Ok((stream, addr))
    }
}

async fn bind_socket<T: BindSocket>(socket: &T, indicator: &SocketAddr) -> io::Result<()> {
    match indicator.ip() {
        IpAddr::V4(v4) if v4.is_loopback() => {
            socket.bind(&SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 0).into())?;
            debug!("socket bind loopback v4");
            return Ok(());
        }
        IpAddr::V6(v6) if v6.is_loopback() => {
            socket.bind(&SocketAddrV6::new("::1".parse().unwrap(), 0, 0, 0).into())?;
            debug!("socket bind loopback v6");
            return Ok(());
        }
        _ => {}
    }
    if option::OUTBOUND_BINDS.is_empty() {
        return Ok(());
    }
    let mut last_err = None;
    for bind in option::OUTBOUND_BINDS.iter() {
        match bind {
            OutboundBind::Interface(iface) => {
                #[cfg(target_os = "macos")]
                unsafe {
                    let ifa = CString::new(iface.as_bytes()).unwrap();
                    let ifidx: libc::c_uint = libc::if_nametoindex(ifa.as_ptr());
                    if ifidx == 0 {
                        last_err = Some(io::Error::last_os_error());
                        continue;
                    }

                    let ret = match indicator {
                        SocketAddr::V4(..) => libc::setsockopt(
                            socket.as_fd().as_raw_fd(),
                            libc::IPPROTO_IP,
                            libc::IP_BOUND_IF,
                            &ifidx as *const _ as *const libc::c_void,
                            std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
                        ),
                        SocketAddr::V6(..) => libc::setsockopt(
                            socket.as_fd().as_raw_fd(),
                            libc::IPPROTO_IPV6,
                            libc::IPV6_BOUND_IF,
                            &ifidx as *const _ as *const libc::c_void,
                            std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
                        ),
                    };
                    if ret == -1 {
                        last_err = Some(io::Error::last_os_error());
                        continue;
                    }
                    debug!("socket bind {}", iface);
                    return Ok(());
                }
                #[cfg(target_os = "linux")]
                unsafe {
                    let ifa = CString::new(iface.as_bytes()).unwrap();
                    let ret = libc::setsockopt(
                        socket.as_fd().as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_BINDTODEVICE,
                        ifa.as_ptr() as *const libc::c_void,
                        ifa.as_bytes().len() as libc::socklen_t,
                    );
                    if ret == -1 {
                        last_err = Some(io::Error::last_os_error());
                        continue;
                    }
                    debug!("socket bind {}", iface);
                    return Ok(());
                }
                #[cfg(not(any(target_os = "macos", target_os = "linux")))]
                {
                    let _ = iface;
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "binding to interface is not supported on this platform",
                    ));
                }
            }
            OutboundBind::Ip(addr) => {
                if (addr.is_ipv4() && indicator.is_ipv4())
                    || (addr.is_ipv6() && indicator.is_ipv6())
                {
                    if let Err(e) = socket.bind(addr) {
                        last_err = Some(e);
                        continue;
                    }
                    debug!("socket bind {}", addr);
                    return Ok(());
                }
            }
        }
    }
    Err(last_err.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "could not bind to any address or interface",
        )
    }))
}

// New UDP socket.
pub async fn new_udp_socket(indicator: &SocketAddr) -> io::Result<UdpSocket> {
    let socket = match indicator {
        SocketAddr::V4(..) => Socket::new(Domain::IPV4, Type::DGRAM, None)?,
        SocketAddr::V6(..) => Socket::new(Domain::IPV6, Type::DGRAM, None)?,
    };

    socket.set_nonblocking(true)?;

    bind_socket(&socket, indicator).await?;

    if option::OUTBOUND_BINDS.is_empty() && indicator.ip().is_unspecified() {
        BindSocket::bind(&socket, indicator)?;
    }

    #[cfg(target_os = "android")]
    protect_socket(socket.as_raw_fd()).await?;

    UdpSocket::from_std(socket.into())
}

fn apply_socket_opts_internal(s: SockRef) -> io::Result<()> {
    s.set_keepalive(true)?;
    s.set_nodelay(true)
}

#[cfg(unix)]
fn apply_socket_opts<S: AsFd>(socket: &S) -> io::Result<()> {
    let sock_ref = SockRef::from(socket);
    apply_socket_opts_internal(sock_ref)
}
#[cfg(windows)]
fn apply_socket_opts<S: AsSocket>(socket: &S) -> io::Result<()> {
    let sock_ref = SockRef::from(socket);
    apply_socket_opts_internal(sock_ref)
}

// TCP dial order.
#[derive(PartialEq)]
pub enum DialOrder {
    // Leave the order of IPs untouched.
    Ordered,
    // Randomize the IPs.
    Random,
    // Randomize the IPs except the first one. We have a little optimization in
    // the DNS client that moves the previously connected IP to the head, we want
    // that IP always tried first.
    PartialRandom,
}

// A single TCP dial.
async fn tcp_dial_task(dial_addr: SocketAddr) -> io::Result<DialResult> {
    let socket = match dial_addr {
        SocketAddr::V4(..) => TcpSocket::new_v4()?,
        SocketAddr::V6(..) => TcpSocket::new_v6()?,
    };

    bind_socket(&socket, &dial_addr).await?;

    #[cfg(target_os = "android")]
    protect_socket(socket.as_raw_fd()).await?;

    debug!("tcp dialing {}", &dial_addr);
    let start = tokio::time::Instant::now();
    let stream = timeout(
        Duration::from_secs(*option::OUTBOUND_DIAL_TIMEOUT),
        socket.connect(dial_addr),
    )
    .await??;
    let elapsed = tokio::time::Instant::now().duration_since(start);

    apply_socket_opts(&stream)?;

    debug!(
        "tcp {} <-> {} connected in {}ms",
        stream.local_addr()?,
        &dial_addr,
        elapsed.as_millis()
    );
    Ok(DialResult {
        stream: Box::new(stream),
        addr: dial_addr,
    })
}

pub async fn connect_stream_outbound(
    sess: &Session,
    dns_client: SyncDnsClient,
    handler: &AnyOutboundHandler,
) -> io::Result<Option<AnyStream>> {
    match handler.stream()?.connect_addr() {
        OutboundConnect::Proxy(Network::Tcp, addr, port) => {
            trace!("connect stream proxy outbound addr={} port={}", &addr, port);
            Ok(Some(new_tcp_stream(dns_client, &addr, &port).await?))
        }
        OutboundConnect::Direct => {
            let dest = &sess.destination;
            trace!("connect stream direct dst={}", &dest);
            Ok(Some(
                new_tcp_stream(dns_client, &dest.host(), &dest.port()).await?,
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
    match handler.datagram()?.connect_addr() {
        OutboundConnect::Proxy(network, addr, port) => match network {
            Network::Udp => {
                let socket = match addr.parse::<IpAddr>() {
                    Ok(ip) if ip.is_loopback() => new_udp_socket(&SocketAddr::new(ip, 0)).await?,
                    _ => new_udp_socket(&crate::option::UNSPECIFIED_BIND_ADDR).await?,
                };
                Ok(Some(OutboundTransport::Datagram(Box::new(
                    DomainResolveOutboundDatagram::new(socket, dns_client.clone()),
                ))))
            }
            Network::Tcp => {
                let stream = new_tcp_stream(dns_client.clone(), &addr, &port).await?;
                Ok(Some(OutboundTransport::Stream(stream)))
            }
        },
        OutboundConnect::Direct => match &sess.destination {
            SocksAddr::Domain(domain, port) => {
                let socket = new_udp_socket(&crate::option::UNSPECIFIED_BIND_ADDR).await?;
                Ok(Some(OutboundTransport::Datagram(Box::new(
                    DomainAssociatedOutboundDatagram::new(
                        socket,
                        sess.source,
                        SocksAddr::Domain(domain.to_owned(), *port),
                        dns_client.clone(),
                    ),
                ))))
            }
            SocksAddr::Ip(addr) => {
                let socket = new_udp_socket(addr).await?;
                Ok(Some(OutboundTransport::Datagram(Box::new(
                    StdOutboundDatagram::new(socket),
                ))))
            }
        },
        _ => Ok(None),
    }
}

struct DialResult {
    stream: AnyStream,
    addr: SocketAddr,
}

// Dials a TCP stream.
pub async fn new_tcp_stream(
    dns_client: SyncDnsClient,
    address: &String,
    port: &u16,
) -> io::Result<AnyStream> {
    let mut resolver = Resolver::new(dns_client.clone(), address, port)
        .map_err(|e| io::Error::other(format!("resolve address failed: {}", e)))
        .await?;

    let mut last_err = None;

    let mut done = false;

    while !done {
        let mut tasks = Vec::new();
        for _ in 0..*option::OUTBOUND_DIAL_CONCURRENCY {
            let dial_addr = match resolver.next() {
                Some(a) => a,
                None => {
                    done = true; // run out
                    break; // break and execute tasks if there're any
                }
            };
            let t = tcp_dial_task(dial_addr);
            tasks.push(Box::pin(t));
        }
        if !tasks.is_empty() {
            match select_ok(tasks.into_iter()).await {
                Ok(v) => {
                    dns_client
                        .read()
                        .await
                        .optimize_cache(address.to_owned(), v.0.addr.ip())
                        .await;
                    return Ok(v.0.stream);
                }
                Err(e) => {
                    last_err = Some(io::Error::other(format!(
                        "all attempts failed, last error: {}",
                        e
                    )));
                }
            }
        }
    }

    Err(last_err.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "could not resolve to any address",
        )
    }))
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
    ) -> io::Result<AnyStream> {
        new_tcp_stream(dns_client, address, port).await
    }
}

/// An interface with the ability to create UDP sockets.
#[async_trait]
pub trait UdpConnector: Send + Sync + Unpin {
    /// Creates a UDP socket.
    async fn new_udp_socket(&self, indicator: &SocketAddr) -> io::Result<UdpSocket> {
        new_udp_socket(indicator).await
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
        runtime().block_on(async {
            let listener = TcpListener::bind(&"127.0.0.1:0".parse().unwrap())
                .await
                .unwrap();
            let addr = listener.io().local_addr().unwrap();
            let connecting = tokio::spawn(TcpStream::connect(addr));
            let (accepted, _) = listener.accept().await.unwrap();
            let _client = connecting.await.unwrap().unwrap();

            let linger = SockRef::from(&accepted).linger().unwrap();
            if *option::TCP_INBOUND_ABORT_ON_CLOSE {
                assert_eq!(linger, Some(Duration::ZERO));
            } else {
                assert_eq!(linger, None);
            }
        });
    }

    #[test]
    fn abort_on_close_is_off_unless_asked_for() {
        if std::env::var("TCP_INBOUND_ABORT_ON_CLOSE").is_ok() {
            // The environment chose; the case above covers the wiring.
            return;
        }
        assert!(!*option::TCP_INBOUND_ABORT_ON_CLOSE);
    }
}
