use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use socket2::SockRef;

use crate::adapter::*;
use crate::platform::original_dst::{original_destination, unmapped};
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
