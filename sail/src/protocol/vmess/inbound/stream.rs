use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rand::Rng;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};

use super::super::body::VmessStream;
use super::super::header::*;
use super::super::xudp;
use crate::{
    adapter::*,
    session::{DatagramSource, Network, Session, SocksAddr},
};

pub struct Handler {
    auth: Authenticator<Option<Arc<str>>>,
}

impl Handler {
    /// Takes the users, each with their name.
    pub fn new(users: Vec<User<Option<Arc<str>>>>) -> Self {
        Handler {
            auth: Authenticator::new(users),
        }
    }
}

/// Reads and drops what a refused client sends, for a while, as Xray
/// does: closing right after a bad header would tell a prober where the
/// header ended.
async fn drain(stream: &mut AnyStream) {
    let (limit, secs) = {
        let mut rng = rand::thread_rng();
        (rng.gen_range(1024..16 * 1024), rng.gen_range(2..8))
    };
    let mut rest = stream.take(limit);
    let _ = tokio::time::timeout(
        Duration::from_secs(secs),
        tokio::io::copy(&mut rest, &mut tokio::io::sink()),
    )
    .await;
}

#[async_trait]
impl InboundStreamHandler for Handler {
    async fn handle<'a>(
        &'a self,
        mut sess: Session,
        mut stream: AnyStream,
    ) -> io::Result<AnyInboundTransport> {
        tracing::trace!("handling inbound stream");
        let (user, request) = match self.auth.read_request(&mut stream).await {
            Ok(request) => request,
            Err(e) => {
                if e.kind() != io::ErrorKind::UnexpectedEof {
                    drain(&mut stream).await;
                }
                return Err(e);
            }
        };
        sess.user = user.data.clone();
        let source = DatagramSource::new(sess.source, sess.stream_id).with_user(sess.user.clone());
        match (request.command, request.address.clone()) {
            (COMMAND_TCP, Some(destination)) => {
                sess.destination = destination;
                let stream = VmessStream::server(stream, &request, false)?;
                Ok(InboundTransport::Stream(Box::new(stream), sess))
            }
            (COMMAND_UDP, Some(destination)) => {
                sess.network = Network::Udp;
                sess.destination = destination.clone();
                let stream = VmessStream::server(stream, &request, true)?;
                Ok(InboundTransport::Datagram(
                    Box::new(Datagram {
                        stream,
                        source,
                        destination,
                    }),
                    Some(sess),
                ))
            }
            (COMMAND_MUX, _) => {
                sess.network = Network::Udp;
                let stream = VmessStream::server(stream, &request, false)?;
                Ok(InboundTransport::Datagram(
                    Box::new(xudp::ServerDatagram::new(stream, source)),
                    Some(sess),
                ))
            }
            _ => Err(io::Error::other("vmess: invalid request")),
        }
    }
}

/// VMess's own UDP: a chunk per packet, to the request's destination.
struct Datagram<S> {
    stream: S,
    source: DatagramSource,
    destination: SocksAddr,
}

impl<S> InboundDatagram for Datagram<S>
where
    S: 'static + AsyncRead + AsyncWrite + Unpin + Send + Sync,
{
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn InboundDatagramRecvHalf>,
        Box<dyn InboundDatagramSendHalf>,
    ) {
        let (r, w) = tokio::io::split(self.stream);
        (
            Box::new(DatagramRecvHalf {
                reader: r,
                source: self.source,
                destination: self.destination,
            }),
            Box::new(DatagramSendHalf(w)),
        )
    }

    fn into_std(self: Box<Self>) -> io::Result<std::net::UdpSocket> {
        Err(io::Error::other("stream transport"))
    }
}

struct DatagramRecvHalf<T> {
    reader: ReadHalf<T>,
    source: DatagramSource,
    destination: SocksAddr,
}

#[async_trait]
impl<T> InboundDatagramRecvHalf for DatagramRecvHalf<T>
where
    T: AsyncRead + AsyncWrite + Send + Sync,
{
    async fn recv_from(
        &mut self,
        buf: &mut [u8],
    ) -> ProxyResult<(usize, DatagramSource, SocksAddr)> {
        let n = self
            .reader
            .read(buf)
            .await
            .map_err(|e| ProxyError::DatagramFatal(e.into()))?;
        if n == 0 {
            return Err(ProxyError::DatagramFatal(anyhow::anyhow!(
                "vmess: UDP session ended"
            )));
        }
        Ok((n, self.source.clone(), self.destination.clone()))
    }
}

struct DatagramSendHalf<T>(WriteHalf<T>);

#[async_trait]
impl<T> InboundDatagramSendHalf for DatagramSendHalf<T>
where
    T: AsyncRead + AsyncWrite + Send + Sync,
{
    async fn send_to(
        &mut self,
        buf: &[u8],
        _src_addr: &SocksAddr,
        _dst_addr: &SocketAddr,
    ) -> io::Result<usize> {
        if buf.is_empty() {
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
