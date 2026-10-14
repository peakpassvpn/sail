//! HTTP/2 shared by what speaks it over connections of its own: gRPC, and
//! the HTTP proxy's CONNECT. The pool of connections an outbound's
//! requests go on (`pool`), the keepalive, and what tells it the peer is
//! alive.

#[cfg(feature = "outbound-grpc")]
mod pool;
#[cfg(feature = "outbound-grpc")]
pub use pool::*;

use std::io;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use portable_atomic::AtomicU64;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::debug;

/// What tasks are called, and the prefix of what is logged.
#[derive(Clone, Copy, Debug)]
pub struct Names {
    pub log: &'static str,
    pub connection: &'static str,
    pub idle_check: &'static str,
    pub keepalive: &'static str,
}

/// A connection's IO, under h2, counting the bytes read from the peer:
/// any at all show it alive, whatever h2 makes of them.
pub struct Counted<S> {
    inner: S,
    received: Arc<AtomicU64>,
}

impl<S> Counted<S> {
    pub fn new(inner: S) -> (Self, Arc<AtomicU64>) {
        let received = Arc::new(AtomicU64::new(0));
        let counted = Counted {
            inner,
            received: received.clone(),
        };
        (counted, received)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Counted<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let read = Pin::new(&mut self.inner).poll_read(cx, buf);
        let n = buf.filled().len() - before;
        if n > 0 {
            self.received.fetch_add(n as u64, Ordering::Relaxed);
        }
        read
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Counted<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Keepalive: every `interval`, a ping, which must be answered within
/// `timeout` or the connection is given up with `abort`. A round in which
/// `wanted` says no is skipped: a client pings a connection with no calls
/// open only if `permit_without_stream`.
///
/// A client pings every `idle_timeout` whatever the traffic; a server, as
/// sing-box's and grpc-go's, only after a whole `idle_timeout` with nothing
/// received (`quiet`). Two ends that both ping while both send can each be
/// left unable to read: h2 writes a pending PING or PONG before it reads
/// the next frame, and while each end is blocked writing its data neither
/// reads the other's. A server that pings only when nothing comes is not
/// writing then, so its PING goes at once. A window is left: the two ends
/// starting to send both ways inside the round trip of that PING; then
/// the timeout ends it. It takes a server's `idle_timeout` no shorter than
/// the client's interval: a server that waits less pings while the client's
/// own pings are all it receives.
///
/// A pong can wait behind all the peer sends before it, on a slow link
/// megabytes. So, as in grpc-go, bytes from the peer show it alive too:
/// while some arrived, `received` counting them, within the last `timeout`,
/// the pong is waited for on.
pub fn keepalive(
    names: Names,
    mut ping_pong: h2::PingPong,
    received: Arc<AtomicU64>,
    interval: Duration,
    timeout: Duration,
    wanted: impl Fn() -> bool + Send + 'static,
    abort: futures::future::AbortHandle,
) {
    crate::runtime::scope::spawn(names.keepalive, async move {
        loop {
            tokio::time::sleep(interval).await;
            if !wanted() {
                continue;
            }
            let mut seen = received.load(Ordering::Relaxed);
            let mut pong = std::pin::pin!(ping_pong.ping(h2::Ping::opaque()));
            let answered = loop {
                if let Ok(answered) = tokio::time::timeout(timeout, &mut pong).await {
                    break Some(answered);
                }
                let now = received.load(Ordering::Relaxed);
                if now == seen {
                    break None;
                }
                seen = now;
            };
            match answered {
                Some(Ok(_)) => continue,
                // The connection is gone already.
                Some(Err(_)) => break,
                None => {
                    debug!(
                        "{}: no pong nor anything else within {:?}, closing the connection",
                        names.log, timeout
                    );
                    abort.abort();
                    break;
                }
            }
        }
    });
}
