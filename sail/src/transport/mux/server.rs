//! The server side: a connection to the magic destination, and the
//! streams on it.

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use futures::future::AbortHandle;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

use crate::adapter::AnyStream;

use super::h2mux::{self, H2Stream};
use super::padding::PaddingStream;
use super::session::{Flavor, FrameSession, MuxStream};
use super::{read_request, Protocol, StreamRequest, STATUS_SUCCESS};

enum Inner {
    /// The session is kept for as long as streams may come.
    Frames {
        _session: FrameSession,
        accept: mpsc::Receiver<MuxStream>,
    },
    H2(AbortHandle, mpsc::Receiver<H2Stream>),
}

/// A mux connection being served. Dropping it closes the connection and
/// every stream on it.
pub struct Server {
    inner: Inner,
}

impl Server {
    /// Reads the request that opens `conn`, and starts serving it.
    pub async fn start(mut conn: AnyStream) -> io::Result<Server> {
        let (protocol, padding) = read_request(&mut conn).await?;
        let conn: AnyStream = if padding {
            Box::new(PaddingStream::new(conn))
        } else {
            conn
        };
        let inner = match protocol {
            Protocol::Smux | Protocol::Yamux => {
                let flavor = if protocol == Protocol::Smux {
                    Flavor::Smux
                } else {
                    Flavor::Yamux
                };
                let (session, accept) = FrameSession::new(conn, flavor, true);
                let accept = accept.ok_or_else(|| io::Error::other("mux: not a server"))?;
                Inner::Frames {
                    _session: session,
                    accept,
                }
            }
            Protocol::H2Mux => {
                let (handle, accept) = h2mux::serve(conn);
                Inner::H2(handle, accept)
            }
        };
        Ok(Server { inner })
    }

    /// The next stream the client opens; `None` once the connection is
    /// done.
    pub async fn accept(&mut self) -> Option<AnyStream> {
        match &mut self.inner {
            Inner::Frames { accept, .. } => accept.recv().await.map(|s| Box::new(s) as AnyStream),
            Inner::H2(_, accept) => accept.recv().await.map(|s| Box::new(s) as AnyStream),
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        if let Inner::H2(handle, _) = &self.inner {
            handle.abort();
        }
    }
}

/// Reads what a stream asks for. A TCP stream comes back ready to relay;
/// a UDP one is for `packet::ServerDatagram`.
pub async fn read_stream(mut stream: AnyStream) -> io::Result<(StreamRequest, AnyStream)> {
    let request = StreamRequest::read(&mut stream).await?;
    let stream: AnyStream = match request {
        StreamRequest::Tcp(_) => Box::new(ServerStream {
            inner: stream,
            status_written: false,
        }),
        _ => stream,
    };
    Ok((request, stream))
}

/// A TCP stream on the server, which sends its status before its first
/// data, as sing-mux does: had the destination failed, the stream would
/// have been closed before.
struct ServerStream {
    inner: AnyStream,
    status_written: bool,
}

impl ServerStream {
    fn poll_status(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.status_written {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &[STATUS_SUCCESS]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.status_written = true;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for ServerStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for ServerStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        ready!(me.poll_status(cx))?;
        Pin::new(&mut me.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        // A client reads the status before it can see the end.
        ready!(me.poll_status(cx))?;
        Pin::new(&mut me.inner).poll_shutdown(cx)
    }
}
