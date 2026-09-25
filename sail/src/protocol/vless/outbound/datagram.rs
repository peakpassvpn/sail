use std::io;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};

use super::super::request::{read_packet, write_packet, Flow, COMMAND_MUX, COMMAND_UDP};
use super::stream::open;
use super::PacketEncoding;
use crate::protocol::vmess::xudp;
use crate::{adapter::*, session::*};

pub struct Handler {
    pub address: String,
    pub port: u16,
    pub uuid: [u8; 16],
    pub flow: Flow,
    pub packet_encoding: PacketEncoding,
}

#[async_trait]
impl OutboundDatagramHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Proxy(Network::Tcp, self.address.clone(), self.port)
    }

    fn transport_type(&self) -> DatagramTransportType {
        DatagramTransportType::Reliable
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        transport: Option<AnyOutboundTransport>,
    ) -> io::Result<AnyOutboundDatagram> {
        tracing::trace!("handling outbound datagram");
        let Some(OutboundTransport::Stream(stream)) = transport else {
            return Err(io::Error::other("invalid input"));
        };
        match self.packet_encoding {
            PacketEncoding::Xudp => {
                let stream = open(sess, stream, &self.uuid, self.flow, COMMAND_MUX, None).await?;
                Ok(Box::new(xudp::ClientDatagram::new(
                    stream,
                    sess.destination.clone(),
                )))
            }
            PacketEncoding::Plain => {
                // UDP requests carry no flow, as sing-box and Xray send them.
                let stream = open(
                    sess,
                    stream,
                    &self.uuid,
                    Flow::None,
                    COMMAND_UDP,
                    Some(&sess.destination),
                )
                .await?;
                Ok(Box::new(Datagram {
                    stream,
                    destination: sess.destination.clone(),
                }))
            }
        }
    }
}

/// VLESS's own UDP: packets, each behind its two-byte length, to and from
/// the one destination of the request.
pub struct Datagram<S> {
    stream: S,
    destination: SocksAddr,
}

impl<S> OutboundDatagram for Datagram<S>
where
    S: 'static + AsyncRead + AsyncWrite + Unpin + Send + Sync,
{
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        let (r, w) = tokio::io::split(self.stream);
        (
            Box::new(DatagramRecvHalf {
                reader: r,
                destination: self.destination,
            }),
            Box::new(DatagramSendHalf { writer: w }),
        )
    }
}

struct DatagramRecvHalf<T> {
    reader: ReadHalf<T>,
    destination: SocksAddr,
}

#[async_trait]
impl<T> OutboundDatagramRecvHalf for DatagramRecvHalf<T>
where
    T: AsyncRead + AsyncWrite + Send + Sync,
{
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
        let n = read_packet(&mut self.reader, buf).await?;
        Ok((n, self.destination.clone()))
    }
}

struct DatagramSendHalf<T> {
    writer: WriteHalf<T>,
}

#[async_trait]
impl<T> OutboundDatagramSendHalf for DatagramSendHalf<T>
where
    T: AsyncRead + AsyncWrite + Send + Sync,
{
    async fn send_to(&mut self, buf: &[u8], _target: &SocksAddr) -> io::Result<usize> {
        write_packet(&mut self.writer, buf).await?;
        Ok(buf.len())
    }

    async fn close(&mut self) -> io::Result<()> {
        self.writer.shutdown().await
    }
}
