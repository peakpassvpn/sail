use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};

use super::super::header::*;
use super::super::xudp;
use super::stream::Client;
use crate::{adapter::*, session::*};

pub struct Handler {
    pub address: String,
    pub port: u16,
    pub client: Arc<Client>,
    pub xudp: bool,
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
        if self.xudp {
            let stream = self.client.open(stream, COMMAND_MUX, None).await?;
            return Ok(Box::new(xudp::ClientDatagram::new(
                stream,
                sess.destination.clone(),
            )));
        }
        let stream = self
            .client
            .open(stream, COMMAND_UDP, Some(sess.destination.clone()))
            .await?;
        Ok(Box::new(Datagram {
            stream,
            destination: sess.destination.clone(),
        }))
    }
}

/// VMess's own UDP: a chunk per packet, to and from the request's one
/// destination.
struct Datagram<S> {
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
            Box::new(DatagramRecvHalf(r, self.destination)),
            Box::new(DatagramSendHalf(w)),
        )
    }
}

struct DatagramRecvHalf<T>(ReadHalf<T>, SocksAddr);

#[async_trait]
impl<T> OutboundDatagramRecvHalf for DatagramRecvHalf<T>
where
    T: AsyncRead + AsyncWrite + Send + Sync,
{
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
        let n = self.0.read(buf).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "vmess: UDP session ended",
            ));
        }
        Ok((n, self.1.clone()))
    }
}

struct DatagramSendHalf<T>(WriteHalf<T>);

#[async_trait]
impl<T> OutboundDatagramSendHalf for DatagramSendHalf<T>
where
    T: AsyncRead + AsyncWrite + Send + Sync,
{
    async fn send_to(&mut self, buf: &[u8], _target: &SocksAddr) -> io::Result<usize> {
        if buf.is_empty() {
            // An empty chunk would end the session.
            return Ok(0);
        }
        self.0.write_all(buf).await?;
        self.0.flush().await?;
        Ok(buf.len())
    }

    async fn close(&mut self) -> io::Result<()> {
        self.0.shutdown().await
    }
}
