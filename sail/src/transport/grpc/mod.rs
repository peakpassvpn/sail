//! The gRPC transport, "gun", as Xray and sing-box speak it: a stream is one
//! HTTP/2 POST to `/<service_name>/Tun`, `content-type: application/grpc`,
//! its bytes gRPC messages each way. See `gun`.
//!
//! The inbound serves every call a connection carries, as many as the client
//! multiplexes onto it. The outbound multiplexes likewise: it keeps a pool
//! of connections to its server, dialled through the layers under it, and
//! makes each stream a call on one of them; see `outbound`.

pub mod gun;
#[cfg(feature = "inbound-grpc")]
pub mod inbound;
#[cfg(feature = "outbound-grpc")]
pub mod outbound;

use std::io;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use portable_atomic::AtomicU64;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::debug;

/// A stream's receive window. What one stream can have in flight towards
/// this side, and so what it can buffer here.
const STREAM_WINDOW: u32 = 1024 * 1024;

/// A connection's receive window: what all its streams together can.
const CONNECTION_WINDOW: u32 = 4 * 1024 * 1024;

/// The largest header block accepted. A gun call's headers are a few
/// hundred bytes.
const MAX_HEADER_LIST: u32 = 16 * 1024;

/// `/<service_name>/Tun`, the name escaped as a path segment, as sing-box
/// sends it.
pub fn service_path(service_name: &str) -> anyhow::Result<String> {
    let mut path = String::from("/");
    for byte in service_name.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                path.push(byte as char)
            }
            _ => path.push_str(&format!("%{:02X}", byte)),
        }
    }
    path.push_str("/Tun");
    path.parse::<http::uri::PathAndQuery>()
        .map_err(|_| anyhow::anyhow!("service_name: invalid"))?;
    Ok(path)
}

/// How long a ping may go unanswered when `ping_timeout` is not set, as in
/// sing-box.
pub const DEFAULT_PING_TIMEOUT: Duration = Duration::from_secs(15);

/// A connection's IO, under h2, counting the bytes read from the peer:
/// any at all show it alive, whatever h2 makes of them.
struct Counted<S> {
    inner: S,
    received: Arc<AtomicU64>,
}

impl<S> Counted<S> {
    fn new(inner: S) -> (Self, Arc<AtomicU64>) {
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
fn keepalive(
    mut ping_pong: h2::PingPong,
    received: Arc<AtomicU64>,
    interval: Duration,
    timeout: Duration,
    wanted: impl Fn() -> bool + Send + 'static,
    abort: futures::future::AbortHandle,
) {
    crate::runtime::scope::spawn("grpc keepalive", async move {
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
                        "gun: no pong nor anything else within {:?}, closing the connection",
                        timeout
                    );
                    abort.abort();
                    break;
                }
            }
        }
    });
}

/// Whether nothing came from the peer since the last time this was asked:
/// a server's keepalive round. `received` counts what came.
#[cfg(feature = "inbound-grpc")]
fn quiet(received: Arc<AtomicU64>) -> impl Fn() -> bool + Send + 'static {
    let seen = AtomicU64::new(received.load(Ordering::Relaxed));
    move || {
        let now = received.load(Ordering::Relaxed);
        seen.swap(now, Ordering::Relaxed) == now
    }
}

#[cfg(all(test, feature = "inbound-grpc", feature = "outbound-grpc"))]
mod stall_tests;

#[cfg(test)]
mod tests {
    /// A round is quiet only when nothing came since the one before.
    #[cfg(feature = "inbound-grpc")]
    #[test]
    fn a_server_pings_only_after_a_round_with_nothing_received() {
        use std::sync::atomic::Ordering;
        let received = std::sync::Arc::new(super::AtomicU64::new(0));
        let quiet = super::quiet(received.clone());
        assert!(quiet());
        received.fetch_add(10, Ordering::Relaxed);
        assert!(!quiet());
        assert!(quiet());
        received.fetch_add(1, Ordering::Relaxed);
        assert!(!quiet());
    }

    #[test]
    fn test_service_path() {
        assert_eq!(
            super::service_path("TunService").unwrap(),
            "/TunService/Tun"
        );
        assert_eq!(super::service_path("a b/c").unwrap(), "/a%20b%2Fc/Tun");
    }
}
