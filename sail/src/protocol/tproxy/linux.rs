use std::io;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::anyhow;
use async_trait::async_trait;
use lru::LruCache;
use socket2::SockRef;
use tokio::io::Interest;
use tokio::net::UdpSocket;
use tracing::debug;

use super::sys;
use crate::adapter::*;
use crate::session::{DatagramSource, Network, Session, SocksAddr};

/// A tproxy inbound, on TCP, UDP, or both.
pub struct Handler {
    tag: String,
    stream: Option<AnyInboundStreamHandler>,
    datagram: Option<AnyInboundDatagramHandler>,
}

impl Handler {
    pub fn new(tag: String, tcp: bool, udp: bool) -> Self {
        Self {
            tag,
            stream: tcp.then(|| Arc::new(StreamHandler) as AnyInboundStreamHandler),
            datagram: udp.then(|| Arc::new(DatagramHandler) as AnyInboundDatagramHandler),
        }
    }
}

impl Tag for Handler {
    fn tag(&self) -> &String {
        &self.tag
    }
}

impl BaseHandler for Handler {}

impl InboundHandler for Handler {
    fn stream(&self) -> io::Result<&AnyInboundStreamHandler> {
        self.stream
            .as_ref()
            .ok_or_else(|| io::Error::other("tproxy: not on tcp"))
    }

    fn datagram(&self) -> io::Result<&AnyInboundDatagramHandler> {
        self.datagram
            .as_ref()
            .ok_or_else(|| io::Error::other("tproxy: not on udp"))
    }

    fn prepare_listener(&self, socket: SockRef<'_>, network: Network) -> io::Result<()> {
        let ipv6 = socket
            .local_addr()?
            .as_socket()
            .is_some_and(|a| a.is_ipv6());
        sys::set_transparent(&socket, ipv6)?;
        if network == Network::Udp {
            sys::set_recv_original_destination(&socket, ipv6)?;
        }
        Ok(())
    }
}

/// `addr`, as IPv4 if it is an IPv4-mapped IPv6 address, as a dual-stack
/// listener reports IPv4 peers.
fn unmapped(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(v4.into(), v6.port()),
            None => addr,
        },
        v4 => v4,
    }
}

/// A TPROXY'd connection is accepted on the address it was sent to, so its
/// local address is its destination. Addresses are unmapped, as for a
/// datagram.
struct StreamHandler;

#[async_trait]
impl InboundStreamHandler for StreamHandler {
    async fn handle<'a>(
        &'a self,
        mut sess: Session,
        stream: AnyStream,
    ) -> io::Result<AnyInboundTransport> {
        sess.source = unmapped(sess.source);
        sess.local_addr = unmapped(sess.local_addr);
        sess.destination = SocksAddr::from(sess.local_addr);
        Ok(InboundTransport::Stream(stream, sess))
    }
}

struct DatagramHandler;

#[async_trait]
impl InboundDatagramHandler for DatagramHandler {
    async fn handle<'a>(&'a self, socket: AnyInboundDatagram) -> io::Result<AnyInboundTransport> {
        // The listener's plain socket, taken back to read the original
        // destination off each datagram, which it cannot.
        let socket = UdpSocket::from_std(socket.into_std()?)?;
        Ok(InboundTransport::Datagram(
            Box::new(Datagram(Arc::new(socket))),
            None,
        ))
    }
}

struct Datagram(Arc<UdpSocket>);

impl InboundDatagram for Datagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn InboundDatagramRecvHalf>,
        Box<dyn InboundDatagramSendHalf>,
    ) {
        (
            Box::new(DatagramRecvHalf(self.0)),
            Box::new(DatagramSendHalf {
                replies: ReplySockets::new(),
            }),
        )
    }

    fn into_std(self: Box<Self>) -> io::Result<std::net::UdpSocket> {
        Arc::try_unwrap(self.0)
            .map_err(|_| io::Error::other("tproxy: socket is shared"))?
            .into_std()
    }
}

struct DatagramRecvHalf(Arc<UdpSocket>);

#[async_trait]
impl InboundDatagramRecvHalf for DatagramRecvHalf {
    async fn recv_from(
        &mut self,
        buf: &mut [u8],
    ) -> ProxyResult<(usize, DatagramSource, SocksAddr)> {
        let fd = self.0.as_raw_fd();
        let (n, source, destination) = self
            .0
            .async_io(Interest::READABLE, || {
                sys::recv_with_original_destination(fd, buf)
            })
            .await
            .map_err(|e| ProxyError::DatagramFatal(e.into()))?;
        let source = unmapped(source);
        let destination = destination.map(unmapped).ok_or_else(|| {
            ProxyError::DatagramWarn(anyhow!(
                "tproxy: datagram from {} came without its original destination",
                source
            ))
        })?;
        Ok((
            n,
            DatagramSource::new(source, None),
            SocksAddr::from(destination),
        ))
    }
}

/// Sends each reply from a socket bound to the address it comes from,
/// the destination the client sent to.
struct DatagramSendHalf {
    replies: ReplySockets,
}

#[async_trait]
impl InboundDatagramSendHalf for DatagramSendHalf {
    async fn send_to(
        &mut self,
        buf: &[u8],
        src_addr: &SocksAddr,
        dst_addr: &SocketAddr,
    ) -> io::Result<usize> {
        let SocksAddr::Ip(from) = src_addr else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "tproxy: a reply from {} cannot be sent from a domain",
                    src_addr
                ),
            ));
        };
        let (from, to) = (unmapped(*from), unmapped(*dst_addr));
        if from.is_ipv4() != to.is_ipv4() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("tproxy: a reply from {} cannot go to {}", from, to),
            ));
        }
        self.replies.get(from)?.send_to(buf, to).await
    }

    async fn close(&mut self) -> io::Result<()> {
        self.replies.clear();
        Ok(())
    }
}

/// At most this many reply sockets are kept open, the least recently used
/// closed first.
const REPLY_SOCKETS: usize = 256;

/// A reply socket unused this long is closed.
const REPLY_SOCKET_IDLE: Duration = Duration::from_secs(60);

/// The sockets replies are sent from, by the address each is bound to.
/// Bounded, as every destination a client sends to would otherwise keep
/// one open.
struct ReplySockets {
    sockets: LruCache<SocketAddr, (UdpSocket, Instant)>,
}

impl ReplySockets {
    fn new() -> Self {
        Self {
            sockets: LruCache::new(
                NonZeroUsize::new(REPLY_SOCKETS).expect("REPLY_SOCKETS is not zero"),
            ),
        }
    }

    /// The socket bound to `from`, opened if there is none.
    fn get(&mut self, from: SocketAddr) -> io::Result<&UdpSocket> {
        let now = Instant::now();
        while let Some((_, (_, used))) = self.sockets.peek_lru() {
            if now.duration_since(*used) < REPLY_SOCKET_IDLE {
                break;
            }
            self.sockets.pop_lru();
        }
        if !self.sockets.contains(&from) {
            let socket = sys::bind_transparent_udp(from).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("tproxy: bind reply socket {}: {}", from, e),
                )
            })?;
            debug!("tproxy: opened reply socket {}", from);
            self.sockets.put(from, (socket, now));
        }
        let (socket, used) = self
            .sockets
            .get_mut(&from)
            .ok_or_else(|| io::Error::other("tproxy: reply socket vanished"))?;
        *used = now;
        Ok(socket)
    }

    fn clear(&mut self) {
        self.sockets.clear();
    }
}
