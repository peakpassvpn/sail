//! UDP through the outbound: a stream to `sp.v2.udp-over-tcp.arpa`, each
//! packet with its address.

use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::BytesMut;

use crate::adapter::*;
use crate::session::{Session, SocksAddrWireType};
use crate::transport::uot;

use super::client::Client;

pub struct Handler {
    pub client: Arc<Client>,
}

#[async_trait]
impl OutboundDatagramHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Unknown
    }

    fn transport_type(&self) -> DatagramTransportType {
        DatagramTransportType::Reliable
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _transport: Option<AnyOutboundTransport>,
    ) -> io::Result<AnyOutboundDatagram> {
        tracing::trace!("handling outbound datagram");
        let mut first = BytesMut::new();
        uot::magic_destination().write_buf(&mut first, SocksAddrWireType::PortLast);
        // Not connected: every packet names its address, so that one
        // session can reach any.
        uot::put_request(&mut first, false, &sess.destination);
        let stream = self.client.open_stream(sess, &first).await?;
        Ok(Box::new(uot::OutboundDatagram::new(
            stream,
            &sess.destination,
        )))
    }
}
