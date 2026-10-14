//! A stream carried by an HTTP/2 CONNECT request: the request's body one
//! way and the response's the other, as h2mux carries its streams and an
//! HTTP proxy its tunnels over HTTP/2.
//!
//! What waits unread is bounded by the stream's window. The stall guard
//! (`muxcore::stall`) resets a stream whose data nothing reads for the
//! stall timeout, alone, and gives its connection its window back.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use bytes::{Buf, Bytes};
use futures::FutureExt;
use h2::{client::ResponseFuture, RecvStream, SendStream};
use http::StatusCode;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::debug;

use crate::transport::muxcore::stall::Stallable;

/// Written into one stream's send buffer at once.
const MAX_WRITE: usize = 32 << 10;

/// `e` as an IO error, under `name`.
pub fn h2_error(name: &str, e: h2::Error) -> io::Error {
    if e.is_io() {
        return e
            .into_io()
            .unwrap_or_else(|| io::Error::other(format!("{}: io", name)));
    }
    io::Error::other(format!("{}: {}", name, e))
}

/// Counts the streams open on a connection.
pub struct Active(Arc<AtomicUsize>);

impl Active {
    pub fn new(count: &Arc<AtomicUsize>) -> Self {
        count.fetch_add(1, Ordering::Relaxed);
        Active(count.clone())
    }
}

impl Drop for Active {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

pub struct H2Inner {
    /// What errors and logs name it by.
    name: &'static str,
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
    _active: Option<Active>,
}

impl H2Inner {
    /// A stream whose peer's half is `recv`: a server's, or a client's once
    /// the response came.
    pub fn new(name: &'static str, send: SendStream<Bytes>, recv: RecvStream) -> Self {
        Self::with(name, send, None, Some(recv))
    }

    /// A client's stream whose response is read by the first read, which
    /// fails unless it is `200`.
    pub fn awaiting(name: &'static str, send: SendStream<Bytes>, response: ResponseFuture) -> Self {
        Self::with(name, send, Some(response), None)
    }

    fn with(
        name: &'static str,
        send: SendStream<Bytes>,
        response: Option<ResponseFuture>,
        recv: Option<RecvStream>,
    ) -> Self {
        H2Inner {
            name,
            response,
            recv,
            send,
            received: Bytes::new(),
            ended: false,
            peer_done: false,
            retire: None,
            _active: None,
        }
    }

    /// Marks `retired` if dropped before the peer is done.
    pub fn retiring(mut self, retired: Arc<AtomicBool>) -> Self {
        self.retire = Some(retired);
        self
    }

    /// Counted in `count` while it lives.
    pub fn counted(mut self, count: &Arc<AtomicUsize>) -> Self {
        self._active = Some(Active::new(count));
        self
    }
}

impl Drop for H2Inner {
    fn drop(&mut self) {
        if let Some(retired) = self.retire.as_ref().filter(|_| !self.peer_done) {
            if !retired.swap(true, Ordering::Relaxed) {
                debug!(
                    "{} connection retired: stream {} ended before the server finished",
                    self.name,
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
                        return Poll::Ready(Err(h2_error(me.name, e)));
                    }
                };
                me.response = None;
                if response.status() != StatusCode::OK {
                    // Sent with the end of the stream.
                    me.peer_done = true;
                    return Poll::Ready(Err(io::Error::other(format!(
                        "{}: unexpected status {}",
                        me.name,
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
                    return Poll::Ready(Err(h2_error(me.name, e)));
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
                    .map_err(|e| h2_error(me.name, e))?;
                Poll::Ready(Ok(n))
            }
            Some(Err(e)) => Poll::Ready(Err(h2_error(me.name, e))),
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
            me.send
                .send_data(Bytes::new(), true)
                .map_err(|e| h2_error(me.name, e))?;
        }
        Poll::Ready(Ok(()))
    }
}
