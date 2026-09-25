use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use socket2::SockRef;

use crate::adapter::*;
use crate::session::{Session, SocksAddr};

/// A redirect inbound: a TCP listener only, as REDIRECT is for TCP.
pub struct Handler {
    tag: String,
    stream: AnyInboundStreamHandler,
}

impl Handler {
    pub fn new(tag: String) -> Self {
        Self {
            tag,
            stream: Arc::new(StreamHandler),
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
        Ok(&self.stream)
    }

    fn datagram(&self) -> io::Result<&AnyInboundDatagramHandler> {
        Err(io::Error::other("redirect takes no udp"))
    }

    fn accepted(&self, socket: SockRef<'_>, sess: &mut Session) -> io::Result<()> {
        // A dual-stack listener reports IPv4 peers as mapped IPv6 addresses,
        // which rules on IPv4 addresses would not match.
        sess.source = unmapped(sess.source);
        sess.local_addr = unmapped(sess.local_addr);
        sess.destination = SocksAddr::from(original_destination(&socket, sess.source)?);
        Ok(())
    }
}

/// Where the connection on `socket`, from `peer`, was going before REDIRECT
/// sent it here. An IPv4 connection accepted on a dual-stack IPv6 listener
/// is tracked, and asked for, as IPv4.
fn original_destination(socket: &SockRef<'_>, peer: SocketAddr) -> io::Result<SocketAddr> {
    let original = match unmapped(peer) {
        SocketAddr::V4(_) => socket.original_dst(),
        SocketAddr::V6(_) => socket.original_dst_ipv6(),
    }
    .map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("no original destination (not redirected?): {}", e),
        )
    })?;
    original
        .as_socket()
        .map(unmapped)
        .ok_or_else(|| io::Error::other("original destination is not an IP address"))
}

/// `addr`, as IPv4 if it is an IPv4-mapped IPv6 address.
fn unmapped(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(v4.into(), v6.port()),
            None => addr,
        },
        v4 => v4,
    }
}

/// Passes the connection on as it is: `Handler::accepted` has put its
/// destination in the session already.
struct StreamHandler;

#[async_trait]
impl InboundStreamHandler for StreamHandler {
    async fn handle<'a>(
        &'a self,
        sess: Session,
        stream: AnyStream,
    ) -> io::Result<AnyInboundTransport> {
        // Reached without its own listener, as a part of another inbound,
        // there is no socket to read a destination from.
        if sess.destination == SocksAddr::any() {
            return Err(io::Error::other(
                "redirect: no original destination, the connection did not come through its own listener",
            ));
        }
        Ok(InboundTransport::Stream(stream, sess))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mapped_address_is_unmapped() {
        let mapped: SocketAddr = "[::ffff:10.0.0.1]:80".parse().unwrap();
        assert_eq!(unmapped(mapped), "10.0.0.1:80".parse().unwrap());
        let v6: SocketAddr = "[fd00::1]:80".parse().unwrap();
        assert_eq!(unmapped(v6), v6);
    }
}
