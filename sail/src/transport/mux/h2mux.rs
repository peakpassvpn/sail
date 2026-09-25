//! h2mux: every stream is an HTTP/2 CONNECT request, its body one way and
//! the response's the other, as sing-mux carries streams over HTTP/2.
//!
//! HTTP/2 flow control bounds what waits unread: `STREAM_WINDOW` a stream,
//! `CONNECTION_WINDOW` a connection.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use bytes::{Buf, Bytes};
use futures::future::{abortable, AbortHandle};
use futures::FutureExt;
use h2::{client::ResponseFuture, RecvStream, SendStream};
use http::{Method, Request, Response, StatusCode, Uri};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tracing::debug;

use super::session::MAX_STREAMS;

const STREAM_WINDOW: u32 = 1 << 20;
const CONNECTION_WINDOW: u32 = 4 << 20;
/// Written into one stream's send buffer at once.
const MAX_WRITE: usize = 32 << 10;
/// Streams accepted and not yet taken by the server.
const ACCEPT_QUEUE: usize = 256;

fn h2_error(e: h2::Error) -> io::Error {
    if e.is_io() {
        return e.into_io().unwrap_or_else(|| io::Error::other("h2mux: io"));
    }
    io::Error::other(format!("h2mux: {}", e))
}

/// Counts the streams open on a connection.
struct Active(Arc<AtomicUsize>);

impl Active {
    fn new(count: &Arc<AtomicUsize>) -> Self {
        count.fetch_add(1, Ordering::Relaxed);
        Active(count.clone())
    }
}

impl Drop for Active {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

pub struct H2Client {
    send: h2::client::SendRequest<Bytes>,
    closed: Arc<AtomicBool>,
    active: Arc<AtomicUsize>,
    task: AbortHandle,
}

impl H2Client {
    pub async fn new<S>(conn: S) -> io::Result<Self>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (send, connection) = h2::client::Builder::new()
            .initial_window_size(STREAM_WINDOW)
            .initial_connection_window_size(CONNECTION_WINDOW)
            .max_concurrent_streams(0)
            .handshake(conn)
            .await
            .map_err(h2_error)?;
        let closed = Arc::new(AtomicBool::new(false));
        let (driver, task) = abortable({
            let closed = closed.clone();
            connection.map(move |result| {
                if let Err(e) = result {
                    debug!("h2mux connection: {}", e);
                }
                closed.store(true, Ordering::Relaxed);
            })
        });
        tokio::spawn(driver);
        Ok(H2Client {
            send,
            closed,
            active: Arc::new(AtomicUsize::new(0)),
            task,
        })
    }

    pub async fn open(&self) -> io::Result<H2Stream> {
        let mut send = self.send.clone().ready().await.map_err(h2_error)?;
        let request = Request::builder()
            .method(Method::CONNECT)
            .uri(Uri::from_static("localhost:443"))
            .body(())
            .map_err(io::Error::other)?;
        let (response, stream) = send.send_request(request, false).map_err(h2_error)?;
        Ok(H2Stream {
            response: Some(response),
            recv: None,
            send: stream,
            received: Bytes::new(),
            ended: false,
            _active: Active::new(&self.active),
        })
    }

    pub fn num_streams(&self) -> usize {
        self.active.load(Ordering::Relaxed)
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    /// Whether the server takes another stream now.
    pub fn can_take_new_request(&self) -> bool {
        self.num_streams() < self.send.current_max_send_streams()
    }

    pub fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        self.task.abort();
    }
}

impl Drop for H2Client {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Serves HTTP/2 on `conn`: the streams come out of the receiver. The
/// handle stops serving.
pub fn serve<S>(conn: S) -> (AbortHandle, mpsc::Receiver<H2Stream>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (tx, rx) = mpsc::channel(ACCEPT_QUEUE);
    let (task, handle) = abortable(async move {
        let mut connection = match h2::server::Builder::new()
            .initial_window_size(STREAM_WINDOW)
            .initial_connection_window_size(CONNECTION_WINDOW)
            .max_concurrent_streams(MAX_STREAMS as u32)
            .handshake::<_, Bytes>(conn)
            .await
        {
            Ok(c) => c,
            Err(e) => {
                debug!("h2mux handshake: {}", e);
                return;
            }
        };
        let active = Arc::new(AtomicUsize::new(0));
        // Accepting drives the connection too, so it never waits on the
        // receiver: a stream that finds the queue full is refused.
        while let Some(accepted) = connection.accept().await {
            let (request, mut respond) = match accepted {
                Ok(v) => v,
                Err(e) => {
                    debug!("h2mux accept: {}", e);
                    break;
                }
            };
            let status = if request.method() == Method::CONNECT {
                StatusCode::OK
            } else {
                StatusCode::NOT_FOUND
            };
            let response = Response::builder()
                .status(status)
                .body(())
                .unwrap_or_default();
            let send = match respond.send_response(response, status != StatusCode::OK) {
                Ok(send) => send,
                Err(e) => {
                    debug!("h2mux respond: {}", e);
                    continue;
                }
            };
            if status != StatusCode::OK {
                continue;
            }
            let stream = H2Stream {
                response: None,
                recv: Some(request.into_body()),
                send,
                received: Bytes::new(),
                ended: false,
                _active: Active::new(&active),
            };
            if tx.try_send(stream).is_err() {
                debug!("h2mux: too many streams waiting, one refused");
            }
        }
    });
    tokio::spawn(task);
    (handle, rx)
}

/// One stream: a CONNECT request, from either end.
pub struct H2Stream {
    /// On a client, until the response comes.
    response: Option<ResponseFuture>,
    recv: Option<RecvStream>,
    send: SendStream<Bytes>,
    /// Received and not yet read.
    received: Bytes,
    ended: bool,
    _active: Active,
}

impl AsyncRead for H2Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        loop {
            if !me.received.is_empty() {
                let n = me.received.len().min(buf.remaining());
                buf.put_slice(&me.received[..n]);
                me.received.advance(n);
                return Poll::Ready(Ok(()));
            }
            if let Some(response) = me.response.as_mut() {
                let response = ready!(response.poll_unpin(cx)).map_err(h2_error)?;
                me.response = None;
                if response.status() != StatusCode::OK {
                    return Poll::Ready(Err(io::Error::other(format!(
                        "h2mux: unexpected status {}",
                        response.status()
                    ))));
                }
                me.recv = Some(response.into_body());
            }
            let Some(recv) = me.recv.as_mut() else {
                return Poll::Ready(Ok(()));
            };
            match ready!(recv.poll_data(cx)) {
                Some(Ok(data)) => {
                    let _ = recv.flow_control().release_capacity(data.len());
                    me.received = data;
                }
                Some(Err(e)) if e.reason() == Some(h2::Reason::NO_ERROR) => {
                    return Poll::Ready(Ok(()))
                }
                Some(Err(e)) => return Poll::Ready(Err(h2_error(e))),
                None => return Poll::Ready(Ok(())),
            }
        }
    }
}

impl AsyncWrite for H2Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        if me.ended {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        me.send.reserve_capacity(buf.len().min(MAX_WRITE));
        match ready!(me.send.poll_capacity(cx)) {
            Some(Ok(n)) => {
                let n = n.min(buf.len());
                me.send
                    .send_data(Bytes::copy_from_slice(&buf[..n]), false)
                    .map_err(h2_error)?;
                Poll::Ready(Ok(n))
            }
            Some(Err(e)) => Poll::Ready(Err(h2_error(e))),
            None => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        if !me.ended {
            me.ended = true;
            me.send.reserve_capacity(0);
            me.send.send_data(Bytes::new(), true).map_err(h2_error)?;
        }
        Poll::Ready(Ok(()))
    }
}
