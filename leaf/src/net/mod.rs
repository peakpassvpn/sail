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
use std::os::unix::io::AsFd;
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

pub mod datagram;
pub mod dial;
pub mod relay;
pub mod resolver;

pub use datagram::*;
pub use dial::DialOptions;

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

/// A UDP socket for talking to `indicator`'s address family, opened as
/// `dial` says.
pub async fn new_udp_socket(indicator: &SocketAddr, dial: &DialOptions) -> io::Result<UdpSocket> {
    let socket = Socket::new(Domain::for_address(*indicator), Type::DGRAM, None)?;
    socket.set_nonblocking(true)?;
    let bound = dial::bind(&socket, indicator, dial)?;
    if !bound && indicator.ip().is_unspecified() {
        socket.bind(&(*indicator).into())?;
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

/// A TCP connection to `addr`, opened as `dial` says.
pub async fn tcp_connect(addr: SocketAddr, dial: &DialOptions) -> io::Result<TcpStream> {
    let socket = match addr {
        SocketAddr::V4(..) => TcpSocket::new_v4()?,
        SocketAddr::V6(..) => TcpSocket::new_v6()?,
    };

    dial::bind(&SockRef::from(&socket), &addr, dial)?;

    #[cfg(target_os = "android")]
    protect_socket(socket.as_raw_fd()).await?;

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

    apply_socket_opts(&stream)?;

    debug!(
        "tcp {} <-> {} connected in {}ms",
        stream.local_addr()?,
        &addr,
        elapsed.as_millis()
    );
    Ok(stream)
}

// A single TCP dial.
async fn tcp_dial_task(dial_addr: SocketAddr, dial: &DialOptions) -> io::Result<DialResult> {
    Ok(DialResult {
        stream: Box::new(tcp_connect(dial_addr, dial).await?),
        addr: dial_addr,
    })
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
                    _ => new_udp_socket(&crate::option::UNSPECIFIED_BIND_ADDR, &dial).await?,
                };
                Ok(Some(OutboundTransport::Datagram(Box::new(
                    DomainResolveOutboundDatagram::new(socket, dns_client.clone()),
                ))))
            }
            Network::Tcp => {
                let stream = new_tcp_stream(dns_client.clone(), &addr, &port, &dial).await?;
                Ok(Some(OutboundTransport::Stream(stream)))
            }
        },
        OutboundConnect::Direct => match &sess.destination {
            SocksAddr::Domain(domain, port) => {
                let socket = new_udp_socket(&crate::option::UNSPECIFIED_BIND_ADDR, &dial).await?;
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
                let socket = new_udp_socket(addr, &dial).await?;
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

/// Dials a TCP stream to `address`, trying its addresses one by one.
pub async fn new_tcp_stream(
    dns_client: SyncDnsClient,
    address: &String,
    port: &u16,
    dial: &DialOptions,
) -> io::Result<AnyStream> {
    let resolver = Resolver::new(dns_client.clone(), address, port)
        .map_err(|e| io::Error::other(format!("resolve address failed: {}", e)))
        .await?;

    let mut last_err = None;
    for dial_addr in resolver {
        match tcp_dial_task(dial_addr, dial).await {
            Ok(v) => {
                dns_client
                    .read()
                    .await
                    .optimize_cache(address.to_owned(), v.addr.ip())
                    .await;
                return Ok(v.stream);
            }
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
