//! What an inbound's `multiplex` block makes of the sing-mux connections
//! that come in through it, as sing-box's inbound `multiplex` does: with no
//! block, or `enabled: false`, a connection to the magic destination is
//! refused; with `padding: true`, one that is not padded is.
//!
//! The connections themselves are served in `app::inbound`, whatever
//! inbound they came in through; this sits around the inbound's handler,
//! where its configuration is known, and lets through only what it allows.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use async_trait::async_trait;
use futures::{future, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::debug;

use crate::adapter::{
    AnyBaseInboundTransport, AnyInboundDatagramHandler, AnyInboundHandler, AnyInboundStreamHandler,
    AnyInboundTransport, AnyStream, BaseHandler, BaseInboundTransport, InboundHandler,
    InboundStreamHandler, InboundTransport, Tag,
};
use crate::session::{Network, Session};

use super::{is_magic, VERSION_1};

/// How an inbound serves sing-mux.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// Not at all, as sing-box's inbounds do unless `multiplex` is enabled.
    Refuse,
    /// Padded or not, as the client likes.
    Serve,
    /// Only padded connections (`padding: true`).
    ServePadded,
}

/// `handler`, letting through the sing-mux connections `policy` allows.
pub fn with_policy(handler: AnyInboundHandler, policy: Policy) -> AnyInboundHandler {
    let stream = handler.stream().ok().map(|inner| {
        Arc::new(PolicyStreamHandler {
            inner: inner.clone(),
            policy,
        }) as AnyInboundStreamHandler
    });
    Arc::new(PolicyHandler {
        inner: handler,
        stream,
    })
}

struct PolicyHandler {
    inner: AnyInboundHandler,
    stream: Option<AnyInboundStreamHandler>,
}

impl Tag for PolicyHandler {
    fn tag(&self) -> &String {
        self.inner.tag()
    }
}

impl BaseHandler for PolicyHandler {}

impl InboundHandler for PolicyHandler {
    fn stream(&self) -> io::Result<&AnyInboundStreamHandler> {
        self.stream
            .as_ref()
            .ok_or(io::Error::other("no tcp handler"))
    }

    // A datagram is never a mux connection.
    fn datagram(&self) -> io::Result<&AnyInboundDatagramHandler> {
        self.inner.datagram()
    }

    fn prepare_listener(&self, socket: socket2::SockRef<'_>, network: Network) -> io::Result<()> {
        self.inner.prepare_listener(socket, network)
    }

    fn accepted(&self, socket: socket2::SockRef<'_>, sess: &mut Session) -> io::Result<()> {
        self.inner.accepted(socket, sess)
    }
}

struct PolicyStreamHandler {
    inner: AnyInboundStreamHandler,
    policy: Policy,
}

#[async_trait]
impl InboundStreamHandler for PolicyStreamHandler {
    async fn handle<'a>(
        &'a self,
        sess: Session,
        stream: AnyStream,
    ) -> io::Result<AnyInboundTransport> {
        let policy = self.policy;
        Ok(match self.inner.handle(sess, stream).await? {
            InboundTransport::Stream(stream, sess) => {
                InboundTransport::Stream(admit(policy, stream, &sess)?, sess)
            }
            // Streams of a connection that carries many (AnyTLS, amux): a
            // mux connection among them is refused alone.
            InboundTransport::Incoming(incoming) => InboundTransport::Incoming(Box::new(
                incoming.filter_map(move |transport: AnyBaseInboundTransport| {
                    future::ready(match transport {
                        BaseInboundTransport::Stream(stream, sess) => {
                            match admit(policy, stream, &sess) {
                                Ok(stream) => Some(BaseInboundTransport::Stream(stream, sess)),
                                Err(e) => {
                                    debug!("stream from {}: {}", sess.source, e);
                                    None
                                }
                            }
                        }
                        other => Some(other),
                    })
                }),
            )),
            other => other,
        })
    }
}

/// `stream`, if `policy` lets it through: as it is, or, where only padded
/// mux connections are, checked for padding as its first bytes are read.
fn admit(policy: Policy, stream: AnyStream, sess: &Session) -> io::Result<AnyStream> {
    if !is_magic(&sess.destination) {
        return Ok(stream);
    }
    match policy {
        Policy::Refuse => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "mux: not enabled on this inbound (multiplex.enabled)",
        )),
        Policy::Serve => Ok(stream),
        Policy::ServePadded => Ok(Box::new(RequirePadding::new(stream))),
    }
}

/// The bytes of a mux request that say whether it is padded: `version`,
/// then `protocol`, then with version 1 `padding`.
const PADDING_FLAG_AT: usize = 2;

/// A mux connection that fails as it is read unless its request asks for
/// padding, as sing-mux's server with `padding` refuses the others.
struct RequirePadding<S> {
    inner: S,
    /// How many of the request's first bytes have been checked.
    checked: usize,
}

impl<S> RequirePadding<S> {
    fn new(inner: S) -> Self {
        RequirePadding { inner, checked: 0 }
    }

    /// Checks the request's bytes in `read`, which follow the ones
    /// checked so far.
    fn check(&mut self, read: &[u8]) -> io::Result<()> {
        for &b in read {
            let ok = match self.checked {
                0 => b == VERSION_1,
                PADDING_FLAG_AT => b == 1,
                _ => true,
            };
            if !ok {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "mux: a connection that is not padded is refused (multiplex.padding)",
                ));
            }
            self.checked += 1;
            if self.checked > PADDING_FLAG_AT {
                break;
            }
        }
        Ok(())
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for RequirePadding<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        let before = buf.filled().len();
        ready!(Pin::new(&mut me.inner).poll_read(cx, buf))?;
        if me.checked <= PADDING_FLAG_AT {
            me.check(&buf.filled()[before..])?;
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for RequirePadding<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{encode_request, read_request, Protocol};
    use super::*;

    async fn read_through(request: &[u8]) -> io::Result<(Protocol, bool)> {
        let (mut client, server) = tokio::io::duplex(4096);
        tokio::io::AsyncWriteExt::write_all(&mut client, request).await?;
        let mut server = RequirePadding::new(server);
        read_request(&mut server).await
    }

    #[test]
    fn only_padded_requests_get_through() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(async {
            for protocol in [Protocol::Smux, Protocol::Yamux, Protocol::H2Mux] {
                let padded = encode_request(protocol, true);
                assert_eq!(read_through(&padded).await.unwrap(), (protocol, true));
                // Version 0, which has no padding flag.
                let unpadded = encode_request(protocol, false);
                assert_eq!(
                    read_through(&unpadded).await.unwrap_err().kind(),
                    io::ErrorKind::PermissionDenied
                );
                // Version 1 with the flag off.
                let off = [VERSION_1, protocol as u8, 0];
                assert_eq!(
                    read_through(&off).await.unwrap_err().kind(),
                    io::ErrorKind::PermissionDenied
                );
            }
        });
    }

    #[test]
    fn a_request_checked_a_byte_at_a_time() {
        let mut stream = RequirePadding::new(());
        for b in [VERSION_1, 0, 1, 0, 0] {
            stream.check(&[b]).unwrap();
        }
        let mut stream = RequirePadding::new(());
        stream.check(&[VERSION_1]).unwrap();
        stream.check(&[0]).unwrap();
        assert!(stream.check(&[0]).is_err());
    }
}
