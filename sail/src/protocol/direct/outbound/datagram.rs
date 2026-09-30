use std::io;

use async_trait::async_trait;

use crate::{adapter::*, session::Session};

/// Dials the session's destination with the outbound's dialer.
pub struct Handler(pub crate::net::Dialer);

#[async_trait]
impl OutboundDatagramHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Direct(self.0.clone())
    }

    fn transport_type(&self) -> DatagramTransportType {
        DatagramTransportType::Unreliable
    }

    async fn handle<'a>(
        &'a self,
        _sess: &'a Session,
        transport: Option<AnyOutboundTransport>,
    ) -> io::Result<AnyOutboundDatagram> {
        tracing::trace!("handling outbound datagram");
        if let Some(OutboundTransport::Datagram(dgram)) = transport {
            Ok(dgram)
        } else {
            Err(io::Error::other("invalid input"))
        }
    }
}
