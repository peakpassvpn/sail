use std::io;

use async_trait::async_trait;

use crate::{adapter::*, session::Session};

/// Dials the session's destination with the outbound's dialer.
pub struct Handler(pub crate::net::Dialer);

#[async_trait]
impl OutboundStreamHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Direct(self.0.clone())
    }

    async fn handle<'a>(
        &'a self,
        _sess: &'a Session,
        _lhs: Option<&mut AnyStream>,
        stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        tracing::trace!("handling outbound stream");
        stream.ok_or_else(|| io::Error::other("invalid input"))
    }
}
