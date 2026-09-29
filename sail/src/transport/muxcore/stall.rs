//! The stall timer, for streams whose sessions are not the core's: h2mux's
//! HTTP/2 streams and QUIC's (Hysteria2, TUIC). Their windows keep one
//! stream nobody reads from holding more than its share, but the data it
//! holds still counts against its connection's window until it is read;
//! a stream that holds data nothing has read for the stall timeout is
//! reset, alone, as the core resets its own (`session`), which gives the
//! connection its credit back.
//!
//! What such a stream has received and not read is not always known:
//! HTTP/2 says, QUIC does not. There, a stream whose reader last took data
//! and has not come back for the timeout, while the stream has not ended,
//! is taken to be stuck: a relay reads again as soon as it has written
//! what it read, so one that does not is held up by where it writes.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Instant;
use tracing::warn;

use super::stats;

/// A stream is reset when data it received has waited unread this long,
/// unless the runtime options say otherwise (`mux.stall_timeout`).
pub const STALL_TIMEOUT: Duration = Duration::from_secs(60);

/// How often a stream is checked, for a stall timeout of `timeout`.
pub fn check_interval(timeout: Duration) -> Duration {
    (timeout / 4).min(Duration::from_secs(5))
}

/// Logs a stream reset for stalling, the same way for every protocol.
pub fn log(protocol: &str, label: &str, id: u64, buffered: Option<usize>, idle: Duration) {
    let buffered = buffered.map_or("unknown".to_string(), |b| b.to_string());
    warn!(
        "event=stream_stalled protocol={} {} stream={} buffered={} idle={}s",
        protocol,
        if label.is_empty() { "-" } else { label },
        id,
        buffered,
        idle.as_secs()
    );
}

/// A stream of a protocol with sessions of its own, as the stall timer
/// sees it.
pub trait Stallable: AsyncRead + AsyncWrite + Unpin + Send + 'static {
    /// The stream's id, for logs.
    fn id(&mut self) -> u64;
    /// What the stream holds received and unread: `None` if not known.
    fn buffered(&mut self) -> Option<usize>;
    /// Resets the stream both ways, dropping what it holds.
    fn reset(&mut self);
}

struct Entry<T> {
    io: T,
    /// Since when the reader has not taken data: when it last did, or
    /// last waited for it.
    progress: Instant,
    /// The reader waits for data.
    reading: bool,
    /// The stream has ended its reading side: nothing more to wait for.
    done: bool,
    stalled: bool,
}

/// A stream the stall timer watches: reset, alone, once data it holds has
/// waited unread for the timeout.
pub struct Guarded<T> {
    entry: Arc<Mutex<Entry<T>>>,
    timeout: Duration,
}

impl<T: Stallable> Guarded<T> {
    /// `io`, watched while there is a runtime to watch it on; `label` says
    /// who it serves in logs.
    pub fn new(io: T, protocol: &'static str, timeout: Duration, label: Arc<str>) -> Self {
        let entry = Arc::new(Mutex::new(Entry {
            io,
            progress: Instant::now(),
            reading: false,
            done: false,
            stalled: false,
        }));
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(watch(Arc::downgrade(&entry), protocol, timeout, label));
        }
        Guarded { entry, timeout }
    }

    fn lock(&self) -> MutexGuard<'_, Entry<T>> {
        self.entry.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn stalled(&self) -> io::Error {
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "stream reset, nothing read its data for {}s",
                self.timeout.as_secs()
            ),
        )
    }

    /// The stream, to do what only it does.
    pub fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        f(&mut self.lock().io)
    }
}

/// Checks the stream until it is gone, has ended, or is reset.
async fn watch<T: Stallable>(
    entry: Weak<Mutex<Entry<T>>>,
    protocol: &'static str,
    timeout: Duration,
    label: Arc<str>,
) {
    let every = check_interval(timeout);
    loop {
        tokio::time::sleep(every).await;
        let Some(entry) = entry.upgrade() else {
            return;
        };
        let mut e = entry.lock().unwrap_or_else(|e| e.into_inner());
        if e.done || e.stalled {
            return;
        }
        let now = Instant::now();
        let buffered = e.io.buffered();
        if e.reading || buffered == Some(0) {
            e.progress = now;
            continue;
        }
        let idle = now.saturating_duration_since(e.progress);
        if idle < timeout {
            continue;
        }
        let id = e.io.id();
        log(protocol, &label, id, buffered, idle);
        stats::counters(protocol).stalled();
        e.io.reset();
        e.stalled = true;
        return;
    }
}

impl<T: Stallable> AsyncRead for Guarded<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut e = self.lock();
        if e.stalled {
            drop(e);
            return Poll::Ready(Err(self.stalled()));
        }
        let before = buf.filled().len();
        let room = buf.remaining() > 0;
        let result = Pin::new(&mut e.io).poll_read(cx, buf);
        match &result {
            Poll::Pending => {
                if !e.reading {
                    e.reading = true;
                    e.progress = Instant::now();
                }
            }
            Poll::Ready(Ok(())) => {
                e.reading = false;
                e.progress = Instant::now();
                if room && buf.filled().len() == before {
                    e.done = true;
                }
            }
            Poll::Ready(Err(_)) => e.done = true,
        }
        result
    }
}

impl<T: Stallable> AsyncWrite for Guarded<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut e = self.lock();
        if e.stalled {
            drop(e);
            return Poll::Ready(Err(self.stalled()));
        }
        Pin::new(&mut e.io).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut e = self.lock();
        if e.stalled {
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut e.io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut e = self.lock();
        if e.stalled {
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut e.io).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    /// A pipe that says what it holds, and is reset by closing it.
    struct Pipe {
        io: Option<DuplexStream>,
        buffered: usize,
        reset: Arc<std::sync::atomic::AtomicBool>,
    }

    impl Stallable for Pipe {
        fn id(&mut self) -> u64 {
            1
        }
        fn buffered(&mut self) -> Option<usize> {
            Some(self.buffered)
        }
        fn reset(&mut self) {
            self.io = None;
            self.reset.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }

    impl AsyncRead for Pipe {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            match self.io.as_mut() {
                Some(io) => Pin::new(io).poll_read(cx, buf),
                None => Poll::Ready(Err(io::ErrorKind::ConnectionReset.into())),
            }
        }
    }

    impl AsyncWrite for Pipe {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            match self.io.as_mut() {
                Some(io) => Pin::new(io).poll_write(cx, buf),
                None => Poll::Ready(Err(io::ErrorKind::ConnectionReset.into())),
            }
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn guarded(
        buffered: usize,
    ) -> (
        Guarded<Pipe>,
        DuplexStream,
        Arc<std::sync::atomic::AtomicBool>,
    ) {
        let (a, b) = tokio::io::duplex(1024);
        let reset = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let pipe = Pipe {
            io: Some(a),
            buffered,
            reset: reset.clone(),
        };
        (
            Guarded::new(pipe, "test", STALL_TIMEOUT, "".into()),
            b,
            reset,
        )
    }

    /// Data nothing reads for the timeout: reset.
    #[tokio::test(start_paused = true)]
    async fn a_stream_nothing_reads_is_reset() {
        let (mut stream, mut peer, reset) = guarded(100);
        peer.write_all(b"x").await.unwrap();
        let mut one = [0u8; 1];
        stream.read_exact(&mut one).await.unwrap();
        tokio::time::sleep(Duration::from_secs(55)).await;
        assert!(!reset.load(std::sync::atomic::Ordering::Relaxed));
        tokio::time::sleep(Duration::from_secs(10)).await;
        assert!(reset.load(std::sync::atomic::Ordering::Relaxed));
        let err = stream.read(&mut one).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    /// A reader waiting for data, or a stream that holds none, is never
    /// reset; nor is one read slowly but steadily.
    #[tokio::test(start_paused = true)]
    async fn waiting_idle_and_slow_streams_are_not_reset() {
        let (mut waiting, _peer, reset) = guarded(100);
        let reader = tokio::spawn(async move { waiting.read(&mut [0u8; 8]).await });
        let (_idle, _peer2, idle_reset) = guarded(0);
        let (mut slow, mut peer3, slow_reset) = guarded(100);
        for _ in 0..12 {
            peer3.write_all(b"y").await.unwrap();
            slow.read_exact(&mut [0u8; 1]).await.unwrap();
            tokio::time::sleep(Duration::from_secs(10)).await;
        }
        for r in [&reset, &idle_reset, &slow_reset] {
            assert!(!r.load(std::sync::atomic::Ordering::Relaxed));
        }
        reader.abort();
    }
}
