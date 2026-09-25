//! UDP through the outbound: a stream to `sp.v2.udp-over-tcp.arpa`, each
//! packet with its address.

use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::BytesMut;
use tokio::io::{AsyncWriteExt, ReadHalf, WriteHalf};

use crate::adapter::*;
use crate::session::{Session, SocksAddr, SocksAddrWireType};

use super::super::frame::UOT_MAGIC_ADDRESS;
use super::super::session::Stream;
use super::super::uot;
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
        SocksAddr::Domain(UOT_MAGIC_ADDRESS.to_string(), 0)
            .write_buf(&mut first, SocksAddrWireType::PortLast);
        // Not connected: every packet names its address, so that one
        // session can reach any.
        uot::put_request(&mut first, false, &sess.destination);
        let stream = self.client.open_stream(sess, &first).await?;
        let destination = match &sess.destination {
            SocksAddr::Domain(..) => Some(sess.destination.clone()),
            SocksAddr::Ip(_) => None,
        };
        Ok(Box::new(Datagram {
            stream,
            destination,
        }))
    }
}

struct Datagram {
    stream: Stream,
    /// A domain destination, which replies are reported as coming from, as
    /// the trojan outbound does: the server answers from the address it
    /// resolved.
    destination: Option<SocksAddr>,
}

impl OutboundDatagram for Datagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        let (r, w) = tokio::io::split(self.stream);
        (
            Box::new(RecvHalf {
                r,
                destination: self.destination,
            }),
            Box::new(SendHalf(w)),
        )
    }
}

struct RecvHalf {
    r: ReadHalf<Stream>,
    destination: Option<SocksAddr>,
}

#[async_trait]
impl OutboundDatagramRecvHalf for RecvHalf {
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
        loop {
            let addr = uot::read_addr(&mut self.r).await?;
            match uot::read_payload(&mut self.r, buf).await? {
                Some(n) => return Ok((n, self.destination.clone().unwrap_or(addr))),
                None => tracing::debug!("anytls outbound dropped a UDP packet too large"),
            }
        }
    }
}

struct SendHalf(WriteHalf<Stream>);

#[async_trait]
impl OutboundDatagramSendHalf for SendHalf {
    async fn send_to(&mut self, buf: &[u8], target: &SocksAddr) -> io::Result<usize> {
        let packet = uot::encode_packet(Some(target), buf)?;
        self.0.write_all(&packet).await?;
        Ok(buf.len())
    }

    async fn close(&mut self) -> io::Result<()> {
        self.0.shutdown().await
    }
}
