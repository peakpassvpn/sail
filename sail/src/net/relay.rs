use std::cell::RefCell;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use futures::ready;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep};

/// Upper bound on the bytes of idle buffers cached per thread.
const BUFFER_POOL_MAX_BYTES: usize = 1024 * 1024;

struct BufferPool {
    bytes: usize,
    buffers: Vec<Box<[u8]>>,
}

thread_local! {
    // Relay buffers released by idle connections, reused by the next reader on
    // this thread instead of going back to the allocator.
    static BUFFER_POOL: RefCell<BufferPool> = const {
        RefCell::new(BufferPool { bytes: 0, buffers: Vec::new() })
    };
}

pub(crate) fn acquire_buffer(size: usize) -> io::Result<Box<[u8]>> {
    let pooled = BUFFER_POOL.with(|pool| {
        let mut pool = pool.borrow_mut();
        let i = pool.buffers.iter().rposition(|b| b.len() == size)?;
        let buf = pool.buffers.swap_remove(i);
        pool.bytes -= buf.len();
        Some(buf)
    });
    if let Some(buf) = pooled {
        return Ok(buf);
    }
    let mut buf = Vec::new();
    buf.try_reserve_exact(size)
        .map_err(|e| io::Error::other(format!("new buffer failed: {}", e)))?;
    buf.resize(size, 0);
    Ok(buf.into_boxed_slice())
}

pub(crate) fn release_buffer(buf: Box<[u8]>) {
    BUFFER_POOL.with(|pool| {
        let mut pool = pool.borrow_mut();
        if pool.bytes + buf.len() <= BUFFER_POOL_MAX_BYTES {
            pool.bytes += buf.len();
            pool.buffers.push(buf);
        }
    });
}

/// A copy buffer that only holds memory while it has data in flight: the
/// buffer is taken from a per-thread pool right before reading and given back
/// as soon as the reader has nothing to offer, so idle connections cost no
/// buffer memory.
///
/// The buffer size adapts between `min_size` and `max_size`: a read that fills
/// the whole buffer doubles the next one, cutting syscalls on bulk transfers,
/// and a read using at most a quarter of it halves the next one.
#[derive(Debug)]
pub struct CopyBuffer {
    read_done: bool,
    need_flush: bool,
    pos: usize,
    cap: usize,
    amt: u64,
    size: usize,
    min_size: usize,
    max_size: usize,
    buf: Option<Box<[u8]>>,
    /// Whether bytes were read or written since the flag was last taken.
    progressed: bool,
    /// Whether the last Pending was the writer's: data waiting to be
    /// written or flushed, rather than nothing to read.
    writer_blocked: bool,
}

impl CopyBuffer {
    pub fn new() -> Self {
        Self::with_sizes(2 * 1024, 2 * 1024)
    }

    pub fn new_with_capacity(size: usize) -> Result<Self, std::io::Error> {
        Self::new_adaptive(size, size)
    }

    pub fn new_adaptive(min_size: usize, max_size: usize) -> Result<Self, std::io::Error> {
        if min_size == 0 || max_size < min_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid buffer sizes: min={} max={}", min_size, max_size),
            ));
        }
        Ok(Self::with_sizes(min_size, max_size))
    }

    fn with_sizes(min_size: usize, max_size: usize) -> Self {
        Self {
            read_done: false,
            need_flush: false,
            pos: 0,
            cap: 0,
            amt: 0,
            size: min_size,
            min_size,
            max_size,
            buf: None,
            progressed: false,
            writer_blocked: false,
        }
    }

    /// Whether bytes moved since the last call.
    fn take_progress(&mut self) -> bool {
        std::mem::take(&mut self.progressed)
    }

    /// Whether the copy waits on its writer: it has data the writer does
    /// not take, or a flush the writer does not finish.
    fn writer_blocked(&self) -> bool {
        self.writer_blocked
    }

    fn adapt_size(&mut self, n: usize) {
        if n == self.size && self.size < self.max_size {
            self.size = (self.size * 2).min(self.max_size);
        } else if n <= self.size / 4 && self.size > self.min_size {
            self.size = (self.size / 2).max(self.min_size);
        }
    }

    pub fn amount_transferred(&self) -> u64 {
        self.amt
    }

    pub fn poll_copy<R, W>(
        &mut self,
        cx: &mut Context<'_>,
        mut reader: Pin<&mut R>,
        mut writer: Pin<&mut W>,
    ) -> Poll<io::Result<u64>>
    where
        R: AsyncRead + ?Sized,
        W: AsyncWrite + ?Sized,
    {
        loop {
            // If our buffer is empty, then we need to read some data to
            // continue.
            if self.pos == self.cap && !self.read_done {
                if self.buf.as_ref().is_some_and(|b| b.len() != self.size) {
                    release_buffer(self.buf.take().expect("checked above"));
                }
                if self.buf.is_none() {
                    self.buf = Some(acquire_buffer(self.size)?);
                }
                let me = &mut *self;
                let mut buf = ReadBuf::new(me.buf.as_deref_mut().expect("buffer acquired above"));

                match reader.as_mut().poll_read(cx, &mut buf) {
                    Poll::Ready(Ok(_)) => (),
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => {
                        // Nothing buffered and nothing to read: hand the buffer
                        // back while this direction waits. A reader returning
                        // Pending yields no data, so nothing is lost.
                        if let Some(buf) = self.buf.take() {
                            release_buffer(buf);
                        }
                        // Try flushing when the reader has no progress to avoid deadlock
                        // when the reader depends on buffered writer.
                        if self.need_flush {
                            self.writer_blocked = true;
                            ready!(writer.as_mut().poll_flush(cx))?;
                            self.need_flush = false;
                        }
                        self.writer_blocked = false;

                        return Poll::Pending;
                    }
                }

                let n = buf.filled().len();
                if n == 0 {
                    self.read_done = true;
                } else {
                    self.pos = 0;
                    self.cap = n;
                    self.adapt_size(n);
                    self.progressed = true;
                }
            }

            // If our buffer has some data, let's write it out!
            self.writer_blocked = true;
            while self.pos < self.cap {
                let me = &mut *self;
                let data = me.buf.as_deref().expect("buffer holds unwritten data");
                let i = ready!(writer.as_mut().poll_write(cx, &data[me.pos..me.cap]))?;
                if i == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write zero byte into writer",
                    )));
                } else {
                    self.pos += i;
                    self.amt += i as u64;
                    self.need_flush = true;
                    self.progressed = true;
                }
            }

            // If pos larger than cap, this loop will never stop.
            // In particular, user's wrong poll_write implementation returning
            // incorrect written length may lead to thread blocking.
            debug_assert!(
                self.pos <= self.cap,
                "writer returned length larger than input slice"
            );

            // If we've written all the data and we've seen EOF, flush out the
            // data and finish the transfer.
            if self.pos == self.cap && self.read_done {
                ready!(writer.as_mut().poll_flush(cx))?;
                return Poll::Ready(Ok(self.amt));
            }
        }
    }
}

impl Drop for CopyBuffer {
    fn drop(&mut self) {
        if let Some(buf) = self.buf.take() {
            release_buffer(buf);
        }
    }
}

impl Default for CopyBuffer {
    fn default() -> Self {
        Self::new()
    }
}

/// When a relay gives up on a direction that does not move.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayTimeouts {
    /// A direction with data its writer does not take (or a flush or a
    /// shutdown it does not finish) for this long aborts the relay, both
    /// sides closed.
    pub write_stall: Duration,
    /// Idle after half-close: once `b` closed its side, `a` to `b` is
    /// closed after this long without a byte moving, counted from the
    /// close or the last byte, whichever is later.
    pub a_to_b_idle: Duration,
    /// Idle after half-close the other way: `b` to `a` once `a` closed
    /// its side.
    pub b_to_a_idle: Duration,
}

enum TransferState {
    Running(CopyBuffer),
    ShuttingDown(u64),
    Done,
}

/// Why a direction that stood still is given up on.
enum Expired {
    WriteStall,
    Idle,
}

/// One direction of a relay, and when it last moved.
struct Direction {
    state: TransferState,
    count: u64,
    /// When bytes last moved this way, or the other direction closed,
    /// whichever is later.
    last_progress: Instant,
    /// Set once the other direction is done: how long this one may then
    /// stand still.
    idle_timeout: Option<Duration>,
    /// Wakes the relay at the earliest deadline it has, or earlier: it is
    /// reset only when it fires, not on every byte.
    timer: Option<Pin<Box<Sleep>>>,
}

impl Direction {
    fn new(buf: CopyBuffer) -> Self {
        Self {
            state: TransferState::Running(buf),
            count: 0,
            last_progress: Instant::now(),
            idle_timeout: None,
            timer: None,
        }
    }

    fn is_done(&self) -> bool {
        matches!(self.state, TransferState::Done)
    }

    /// The other direction is done: from now on, this one ends when it has
    /// stood still for `idle`.
    fn other_done(&mut self, idle: Duration) {
        if let TransferState::Running(_) = self.state {
            self.last_progress = Instant::now();
            self.idle_timeout = Some(idle);
        }
    }

    /// Copies from `reader` to `writer`, then shuts `writer` down: ready
    /// once that is done, or failed.
    fn poll_copy<R, W>(
        &mut self,
        cx: &mut Context<'_>,
        mut reader: Pin<&mut R>,
        mut writer: Pin<&mut W>,
        write_stall: Duration,
    ) -> Poll<io::Result<()>>
    where
        R: AsyncRead + ?Sized,
        W: AsyncWrite + ?Sized,
    {
        loop {
            match &mut self.state {
                TransferState::Running(buf) => {
                    let res = buf.poll_copy(cx, reader.as_mut(), writer.as_mut());
                    if buf.take_progress() {
                        self.last_progress = Instant::now();
                    }
                    match res {
                        Poll::Ready(Ok(count)) => {
                            self.state = TransferState::ShuttingDown(count);
                        }
                        Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                        Poll::Pending => {
                            let amount = buf.amount_transferred();
                            let blocked = buf.writer_blocked();
                            match ready!(self.poll_deadline(cx, blocked, write_stall)) {
                                Expired::WriteStall => return Poll::Ready(Err(write_stalled())),
                                Expired::Idle => {
                                    self.state = TransferState::ShuttingDown(amount);
                                }
                            }
                        }
                    }
                    // Shutting down, only a stalled writer is given up on.
                    self.idle_timeout = None;
                }
                TransferState::ShuttingDown(count) => {
                    let count = *count;
                    match writer.as_mut().poll_shutdown(cx) {
                        Poll::Ready(Ok(())) => {
                            self.count = count;
                            self.state = TransferState::Done;
                        }
                        Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                        Poll::Pending => {
                            ready!(self.poll_deadline(cx, true, write_stall));
                            return Poll::Ready(Err(write_stalled()));
                        }
                    }
                }
                TransferState::Done => return Poll::Ready(Ok(())),
            }
        }
    }

    /// Pending until the direction has stood still for longer than it may:
    /// `write_stall` while `writer_blocked`, the idle timeout once the other
    /// direction is done.
    fn poll_deadline(
        &mut self,
        cx: &mut Context<'_>,
        writer_blocked: bool,
        write_stall: Duration,
    ) -> Poll<Expired> {
        let stall = writer_blocked.then(|| (self.last_progress + write_stall, Expired::WriteStall));
        let idle = self
            .idle_timeout
            .map(|idle| (self.last_progress + idle, Expired::Idle));
        let (deadline, expired) = match (stall, idle) {
            (Some(s), Some(i)) => {
                if s.0 <= i.0 {
                    s
                } else {
                    i
                }
            }
            (Some(d), None) | (None, Some(d)) => d,
            (None, None) => return Poll::Pending,
        };
        let timer = self
            .timer
            .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(deadline)));
        if timer.deadline() > deadline {
            timer.as_mut().reset(deadline);
        }
        loop {
            ready!(timer.as_mut().poll(cx));
            if Instant::now() >= deadline {
                return Poll::Ready(expired);
            }
            // Bytes moved since the timer was set: wait out the rest.
            timer.as_mut().reset(deadline);
        }
    }
}

fn write_stalled() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "relay write stalled")
}

struct CopyBidirectional<'a, A: ?Sized, B: ?Sized> {
    a: &'a mut A,
    b: &'a mut B,
    a_to_b: Direction,
    b_to_a: Direction,
    timeouts: RelayTimeouts,
}

impl<'a, A, B> Future for CopyBidirectional<'a, A, B>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    type Output = io::Result<(u64, u64)>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Unpack self into mut refs to each field to avoid borrow check issues.
        let CopyBidirectional {
            a,
            b,
            a_to_b,
            b_to_a,
            timeouts,
        } = &mut *self;

        let mut a = Pin::new(a);
        let mut b = Pin::new(b);

        loop {
            let a_to_b_open = !a_to_b.is_done();
            let b_to_a_open = !b_to_a.is_done();
            if a_to_b_open {
                if let Poll::Ready(Err(err)) =
                    a_to_b.poll_copy(cx, a.as_mut(), b.as_mut(), timeouts.write_stall)
                {
                    return Poll::Ready(Err(err));
                }
            }
            if b_to_a_open {
                if let Poll::Ready(Err(err)) =
                    b_to_a.poll_copy(cx, b.as_mut(), a.as_mut(), timeouts.write_stall)
                {
                    return Poll::Ready(Err(err));
                }
            }
            if a_to_b.is_done() && b_to_a.is_done() {
                return Poll::Ready(Ok((a_to_b.count, b_to_a.count)));
            }
            // A direction just done leaves the other on its idle timeout,
            // which it must be polled again to arm.
            if a_to_b_open && a_to_b.is_done() {
                b_to_a.other_done(timeouts.b_to_a_idle);
            } else if b_to_a_open && b_to_a.is_done() {
                a_to_b.other_done(timeouts.a_to_b_idle);
            } else {
                return Poll::Pending;
            }
        }
    }
}

pub async fn copy_buf_bidirectional_with_timeout<A, B>(
    a: &mut A,
    b: &mut B,
    min_size: usize,
    max_size: usize,
    timeouts: RelayTimeouts,
) -> Result<(u64, u64), std::io::Error>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    CopyBidirectional {
        a,
        b,
        a_to_b: Direction::new(CopyBuffer::new_adaptive(min_size, max_size)?),
        b_to_a: Direction::new(CopyBuffer::new_adaptive(min_size, max_size)?),
        timeouts,
    }
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt, DuplexStream};
    use tokio::task::JoinHandle;
    use tokio::time::sleep;

    const STALL: Duration = Duration::from_secs(300);

    fn timeouts() -> RelayTimeouts {
        let relay = crate::runtime::options::Relay::default();
        RelayTimeouts {
            write_stall: relay.write_stall_timeout,
            a_to_b_idle: relay.uplink_idle_timeout,
            b_to_a_idle: relay.downlink_idle_timeout,
        }
    }

    /// A relay between a client and a server, each end a pipe of `size`
    /// bytes: the client's end, the relay, and the server's end.
    fn relay(
        size: usize,
    ) -> (
        DuplexStream,
        JoinHandle<io::Result<(u64, u64)>>,
        DuplexStream,
    ) {
        let (client, mut a) = duplex(size);
        let (mut b, server) = duplex(size);
        let relay = tokio::spawn(async move {
            copy_buf_bidirectional_with_timeout(&mut a, &mut b, 1024, 1024, timeouts()).await
        });
        (client, relay, server)
    }

    #[test]
    fn the_defaults_are_the_measured_ones() {
        let t = timeouts();
        assert_eq!(t.write_stall, STALL);
        assert_eq!(t.a_to_b_idle, Duration::from_secs(300));
        assert_eq!(t.b_to_a_idle, Duration::from_secs(300));
    }

    /// A server that takes nothing for the write-stall timeout ends the
    /// relay, both sides closed.
    #[tokio::test(start_paused = true)]
    async fn a_stalled_write_aborts_the_relay() {
        let (mut client, relay, mut server) = relay(64);
        let writer = tokio::spawn(async move {
            let _ = client.write_all(&[7u8; 4096]).await;
            client
        });
        sleep(STALL - Duration::from_secs(1)).await;
        assert!(!relay.is_finished(), "cut before the timeout");
        sleep(Duration::from_secs(2)).await;
        let err = relay.await.unwrap().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        // The relay's ends are gone: both sides see the connection close.
        let mut client = writer.await.unwrap();
        let mut buf = [0u8; 64];
        assert_eq!(client.read(&mut buf).await.unwrap(), 0);
        let mut seen = 0;
        loop {
            match server.read(&mut buf).await.unwrap() {
                0 => break,
                n => seen += n,
            }
        }
        assert!(seen < 4096);
    }

    /// A writer that takes a little now and then is slow, not stalled.
    #[tokio::test(start_paused = true)]
    async fn a_slow_writer_is_not_a_stalled_one() {
        let (mut client, relay, mut server) = relay(64);
        tokio::spawn(async move {
            let _ = client.write_all(&[7u8; 4096]).await;
            // Kept open: the relay is to end only by the stall.
            std::future::pending::<()>().await;
            drop(client);
        });
        for _ in 0..10 {
            sleep(STALL * 2 / 3).await;
            let mut buf = [0u8; 16];
            assert!(server.read(&mut buf).await.unwrap() > 0);
            assert!(!relay.is_finished(), "a moving direction cut");
        }
        // Then nothing is taken any more.
        sleep(STALL + Duration::from_secs(1)).await;
        assert_eq!(
            relay.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }

    /// Slow upload: the client sent everything and closed its side, and
    /// the server answers only once what it was sent has made its way to
    /// it, longer after than the old half-close timeout of 10 s. The answer
    /// still arrives.
    #[tokio::test(start_paused = true)]
    async fn a_response_after_a_slow_upload_is_delivered() {
        let (mut client, relay, mut server) = relay(1 << 16);
        client.write_all(b"upload").await.unwrap();
        client.shutdown().await.unwrap();
        let mut upload = Vec::new();
        server.read_to_end(&mut upload).await.unwrap();
        assert_eq!(upload, b"upload");
        // What the server does with it takes a minute.
        sleep(Duration::from_secs(60)).await;
        server.write_all(b"OK 6").await.unwrap();
        server.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"OK 6");
        assert_eq!(relay.await.unwrap().unwrap(), (6, 4));
    }

    /// Once the client closed its side, a server that neither answers nor
    /// closes has its connection reclaimed at the idle timeout, counted
    /// from the last byte it sent.
    #[tokio::test(start_paused = true)]
    async fn a_half_closed_idle_connection_is_reclaimed() {
        let idle = timeouts().b_to_a_idle;
        let (mut client, relay, mut server) = relay(1 << 16);
        client.shutdown().await.unwrap();
        let mut buf = [0u8; 16];
        assert_eq!(server.read(&mut buf).await.unwrap(), 0);
        // A byte now and then keeps it open, however long.
        for _ in 0..5 {
            sleep(idle - Duration::from_secs(1)).await;
            server.write_all(b"x").await.unwrap();
            assert_eq!(client.read(&mut buf).await.unwrap(), 1);
        }
        assert!(!relay.is_finished(), "a moving direction cut");
        sleep(idle - Duration::from_secs(1)).await;
        assert!(!relay.is_finished(), "cut before the timeout");
        sleep(Duration::from_secs(2)).await;
        assert!(relay.is_finished());
        assert_eq!(relay.await.unwrap().unwrap(), (0, 5));
        assert_eq!(client.read(&mut buf).await.unwrap(), 0);
        drop(server);
    }

    /// A connection nobody half-closed has no idle timeout.
    #[tokio::test(start_paused = true)]
    async fn an_idle_connection_stays() {
        let (_client, relay, _server) = relay(1 << 16);
        sleep(Duration::from_secs(24 * 3600)).await;
        assert!(!relay.is_finished());
    }
}
