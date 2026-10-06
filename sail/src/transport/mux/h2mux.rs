//! h2mux: every stream is an HTTP/2 CONNECT request, its body one way and
//! the response's the other, as sing-mux carries streams over HTTP/2.
//!
//! HTTP/2 flow control bounds what waits unread: `Tuning::h2_stream_window`
//! a stream, eight times that a connection. A stream whose data nothing
//! reads for the stall timeout is reset, alone (`muxcore::stall`), and
//! gives its connection its window back. A client's connection takes no
//! new streams once one ended while the server may still be sending it,
//! as a muxcore session does.

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

use crate::transport::muxcore::stall::{Guarded, Stallable};
use crate::transport::muxcore::{Tuning, MAX_STREAMS};

/// A connection's window, in stream windows.
const CONNECTION_WINDOWS: u32 = 8;
/// Written into one stream's send buffer at once.
const MAX_WRITE: usize = 32 << 10;

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
    tuning: Tuning,
    label: Arc<str>,
    closed: Arc<AtomicBool>,
    /// A stream ended before the server finished it: what it was sent is
    /// still on its way, ahead of what a new stream would get.
    retired: Arc<AtomicBool>,
    active: Arc<AtomicUsize>,
    task: AbortHandle,
}

impl H2Client {
    /// A client over `conn`; `label` says who it serves in logs.
    pub async fn new<S>(conn: S, tuning: Tuning, label: &str) -> io::Result<Self>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (send, connection) = h2::client::Builder::new()
            .initial_window_size(tuning.h2_stream_window)
            .initial_connection_window_size(CONNECTION_WINDOWS * tuning.h2_stream_window)
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
        crate::runtime::scope::spawn("h2mux connection", driver);
        Ok(H2Client {
            send,
            tuning,
            label: label.into(),
            closed,
            retired: Arc::new(AtomicBool::new(false)),
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
        let stream = H2Inner {
            response: Some(response),
            recv: None,
            send: stream,
            received: Bytes::new(),
            ended: false,
            peer_done: false,
            retire: Some(self.retired.clone()),
            _active: Active::new(&self.active),
        };
        Ok(guard(stream, &self.tuning, self.label.clone()))
    }

    pub fn num_streams(&self) -> usize {
        self.active.load(Ordering::Relaxed)
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    /// Whether a new stream may go on the connection: it is not closed,
    /// and no stream ended before the server finished it.
    pub fn is_reusable(&self) -> bool {
        !self.is_closed() && !self.retired.load(Ordering::Relaxed)
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
/// handle stops serving. `label` says who it serves in logs.
pub fn serve<S>(
    conn: S,
    tuning: Tuning,
    label: &str,
) -> (AbortHandle, mpsc::UnboundedReceiver<H2Stream>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Streams waiting to be taken are bounded by the streams the peer
    // may open at once, `MAX_STREAMS`: a burst is taken whole.
    let (tx, rx) = mpsc::unbounded_channel();
    let label: Arc<str> = label.into();
    let (task, handle) = abortable(async move {
        let mut connection = match h2::server::Builder::new()
            .initial_window_size(tuning.h2_stream_window)
            .initial_connection_window_size(CONNECTION_WINDOWS * tuning.h2_stream_window)
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
        // receiver.
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
            let stream = H2Inner {
                response: None,
                recv: Some(request.into_body()),
                send,
                received: Bytes::new(),
                ended: false,
                peer_done: false,
                retire: None,
                _active: Active::new(&active),
            };
            let stream = guard(stream, &tuning, label.clone());
            if tx.send(stream).is_err() {
                break;
            }
        }
    });
    crate::runtime::scope::spawn("h2mux accept", task);
    (handle, rx)
}

/// One stream: a CONNECT request, from either end, watched by the stall
/// timer.
pub type H2Stream = Guarded<H2Inner>;

fn guard(stream: H2Inner, tuning: &Tuning, label: Arc<str>) -> H2Stream {
    Guarded::new(stream, "h2mux", tuning.stall_timeout, label)
}

pub struct H2Inner {
    /// On a client, until the response comes.
    response: Option<ResponseFuture>,
    recv: Option<RecvStream>,
    send: SendStream<Bytes>,
    /// Received and not yet read.
    received: Bytes,
    ended: bool,
    /// The peer is done sending: it ended or reset the stream.
    peer_done: bool,
    /// On a client: marks the connection retired if the stream is dropped
    /// before the peer is done.
    retire: Option<Arc<AtomicBool>>,
    _active: Active,
}

impl Drop for H2Inner {
    fn drop(&mut self) {
        if let Some(retired) = self.retire.as_ref().filter(|_| !self.peer_done) {
            if !retired.swap(true, Ordering::Relaxed) {
                debug!(
                    "h2mux connection retired: stream {} ended before the server finished",
                    u32::from(self.send.stream_id())
                );
            }
        }
    }
}

impl Stallable for H2Inner {
    fn id(&mut self) -> u64 {
        u64::from(u32::from(self.send.stream_id()))
    }

    fn buffered(&mut self) -> Option<usize> {
        let held = self
            .recv
            .as_mut()
            .map_or(0, |recv| recv.flow_control().used_capacity());
        Some(self.received.len() + held)
    }

    /// RST_STREAM: what the stream holds is dropped, and its window goes
    /// back to the connection.
    fn reset(&mut self) {
        self.send.send_reset(h2::Reason::CANCEL);
        self.recv = None;
        self.response = None;
        self.received = Bytes::new();
        self.ended = true;
    }
}

impl AsyncRead for H2Inner {
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
                let response = match ready!(response.poll_unpin(cx)) {
                    Ok(response) => response,
                    Err(e) => {
                        me.peer_done |= e.is_remote();
                        return Poll::Ready(Err(h2_error(e)));
                    }
                };
                me.response = None;
                if response.status() != StatusCode::OK {
                    // Sent with the end of the stream.
                    me.peer_done = true;
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
                    me.peer_done = true;
                    return Poll::Ready(Ok(()));
                }
                Some(Err(e)) => {
                    me.peer_done |= e.is_remote();
                    return Poll::Ready(Err(h2_error(e)));
                }
                None => {
                    me.peer_done = true;
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl AsyncWrite for H2Inner {
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
