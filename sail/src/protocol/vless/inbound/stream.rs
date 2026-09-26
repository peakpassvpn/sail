use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf};
use tokio::time::timeout;

use super::super::request::{
    read_packet, read_request, write_packet, Flow, Request, ServerStream, COMMAND_MUX, COMMAND_TCP,
    COMMAND_UDP,
};
use super::super::stream::VlessStream;
use crate::protocol::fallback::{Fallback, HEADER_TIMEOUT};
use crate::protocol::vmess::xudp;
use crate::transport::vision::VisionState;
use crate::{
    adapter::*,
    session::{DatagramSource, Network, Session, SocksAddr},
};

/// A VLESS user.
pub struct User {
    pub name: Option<Arc<str>>,
    pub flow: Flow,
}

pub struct Handler {
    users: HashMap<[u8; 16], User>,
    /// Where what fails to authenticate goes; closed without one.
    fallback: Option<Fallback>,
}

impl Handler {
    /// Takes the users by UUID.
    pub fn new(users: HashMap<[u8; 16], User>, fallback: Option<Fallback>) -> Self {
        Handler { users, fallback }
    }

    /// The user of `request` and the flow it asks for, or why it is refused.
    fn authorize(&self, request: &Request) -> Result<(&User, Flow), String> {
        let user = self
            .users
            .get(&request.uuid)
            .ok_or_else(|| "unknown user".to_string())?;
        let flow = Flow::parse(&request.flow)?;
        // As Xray has it: a Vision user may leave the flow out only for UDP,
        // which Vision cannot carry itself.
        match (flow, user.flow) {
            (Flow::Vision, Flow::Vision) if request.command == COMMAND_UDP => {
                Err("xtls-rprx-vision does not carry UDP; use xudp".to_string())
            }
            (Flow::Vision, Flow::Vision) | (Flow::None, Flow::None) => Ok((user, flow)),
            (Flow::None, Flow::Vision) if request.command != COMMAND_TCP => Ok((user, flow)),
            (flow, expected) => Err(format!(
                "flow mismatch: the user has \"{}\", the request \"{}\"",
                expected.as_str(),
                flow.as_str()
            )),
        }
    }
}

fn refused(what: String) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, what)
}

/// A reader that keeps what is read through it: the bytes the fallback is
/// given. It holds no more than the request header, which is all that is
/// read through it and is bounded by its format.
struct Recording<'a> {
    inner: &'a mut AnyStream,
    seen: Vec<u8>,
}

impl AsyncRead for Recording<'_> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        ready!(Pin::new(&mut *this.inner).poll_read(cx, buf))?;
        this.seen.extend_from_slice(&buf.filled()[before..]);
        Poll::Ready(Ok(()))
    }
}

#[async_trait]
impl InboundStreamHandler for Handler {
    async fn handle<'a>(
        &'a self,
        mut sess: Session,
        mut stream: AnyStream,
    ) -> io::Result<AnyInboundTransport> {
        tracing::trace!("handling inbound stream");
        let mut recording = Recording {
            inner: &mut stream,
            seen: Vec::new(),
        };
        let reading = read_request(&mut recording, |uuid| self.users.contains_key(uuid));
        let request = match self.fallback {
            // A peer that sends part of a header and waits is not a client.
            Some(_) => timeout(HEADER_TIMEOUT, reading).await.unwrap_or_else(|_| {
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "no request header in time",
                ))
            }),
            None => reading.await,
        };
        let consumed = recording.seen;
        let authorized = match request {
            Ok(request) => self
                .authorize(&request)
                .map(|(user, flow)| (request, user, flow)),
            // What is not a VLESS request from a user; the other errors are
            // the connection failing, and there is nothing to relay.
            Err(e) => match e.kind() {
                io::ErrorKind::InvalidData
                | io::ErrorKind::UnexpectedEof
                | io::ErrorKind::TimedOut => Err(e.to_string()),
                _ => return Err(e),
            },
        };
        let (request, user, flow) = match authorized {
            Ok(authorized) => authorized,
            Err(why) => {
                return Err(match &self.fallback {
                    Some(fallback) => fallback.relay(&sess, stream, consumed, &why),
                    None => refused(why),
                })
            }
        };
        sess.user = user.name.clone();

        let stream: AnyStream = Box::new(ServerStream::new(stream));
        let stream: AnyStream = match flow {
            Flow::Vision => {
                // From here the TLS layer must stop reads at record
                // boundaries until Vision settles.
                let vision = VisionState::of(&sess);
                vision.start();
                Box::new(VlessStream::server(stream, request.uuid, Some(vision)))
            }
            Flow::None => stream,
        };

        let source = DatagramSource::new(sess.source, sess.stream_id).with_user(sess.user.clone());
        match (request.command, request.destination) {
            (COMMAND_TCP, Some(destination)) => {
                sess.destination = destination;
                Ok(InboundTransport::Stream(stream, sess))
            }
            (COMMAND_UDP, Some(destination)) => {
                sess.network = Network::Udp;
                sess.destination = destination.clone();
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
                Ok(InboundTransport::Datagram(
                    Box::new(xudp::ServerDatagram::new(stream, source)),
                    Some(sess),
                ))
            }
            _ => Err(io::Error::other("invalid request")),
        }
    }
}

/// VLESS's own UDP: length-prefixed packets to the request's destination.
struct Datagram {
    stream: AnyStream,
    source: DatagramSource,
    destination: SocksAddr,
}

impl InboundDatagram for Datagram {
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
            Box::new(DatagramSendHalf { writer: w }),
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
        let n = read_packet(&mut self.reader, buf)
            .await
            .map_err(|e| ProxyError::DatagramFatal(e.into()))?;
        Ok((n, self.source.clone(), self.destination.clone()))
    }
}

struct DatagramSendHalf<T> {
    writer: WriteHalf<T>,
}

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
        write_packet(&mut self.writer, buf).await?;
        Ok(buf.len())
    }

    async fn close(&mut self) -> io::Result<()> {
        self.writer.shutdown().await
    }
}
