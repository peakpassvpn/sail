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
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use futures::future::{abortable, AbortHandle};
use futures::FutureExt;
use http::{Method, Request, Response, StatusCode, Uri};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tracing::debug;

use crate::transport::h2connect::H2Inner;
use crate::transport::muxcore::stall::Guarded;
use crate::transport::muxcore::{Tuning, MAX_STREAMS};

/// A connection's window, in stream windows.
const CONNECTION_WINDOWS: u32 = 8;

fn h2_error(e: h2::Error) -> io::Error {
    crate::transport::h2connect::h2_error("h2mux", e)
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
        let stream = H2Inner::awaiting("h2mux", stream, response)
            .retiring(self.retired.clone())
            .counted(&self.active);
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
            let stream = H2Inner::new("h2mux", send, request.into_body()).counted(&active);
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
