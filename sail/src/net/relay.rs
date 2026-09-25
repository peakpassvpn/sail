use std::cell::RefCell;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use futures::ready;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

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
        }
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
                            ready!(writer.as_mut().poll_flush(cx))?;
                            self.need_flush = false;
                        }

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
                }
            }

            // If our buffer has some data, let's write it out!
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

enum TransferState {
    Running(CopyBuffer),
    ShuttingDown(u64),
    Done,
}

struct CopyBidirectional<'a, A: ?Sized, B: ?Sized> {
    a: &'a mut A,
    b: &'a mut B,
    a_to_b: TransferState,
    b_to_a: TransferState,
    a_to_b_count: u64,
    b_to_a_count: u64,
    a_to_b_delay: Option<Pin<Box<tokio::time::Sleep>>>,
    b_to_a_delay: Option<Pin<Box<tokio::time::Sleep>>>,
    a_to_b_timeout_duration: Duration,
    b_to_a_timeout_duration: Duration,
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
            a_to_b_count,
            b_to_a_count,
            a_to_b_delay,
            b_to_a_delay,
            a_to_b_timeout_duration,
            b_to_a_timeout_duration,
        } = &mut *self;

        let mut a = Pin::new(a);
        let mut b = Pin::new(b);

        loop {
            match a_to_b {
                TransferState::Running(buf) => {
                    let res = buf.poll_copy(cx, a.as_mut(), b.as_mut());
                    match res {
                        Poll::Ready(Ok(count)) => {
                            *a_to_b = TransferState::ShuttingDown(count);
                            continue;
                        }
                        Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                        Poll::Pending => {
                            if let Some(delay) = a_to_b_delay {
                                match delay.as_mut().poll(cx) {
                                    Poll::Ready(()) => {
                                        *a_to_b =
                                            TransferState::ShuttingDown(buf.amount_transferred());
                                        continue;
                                    }
                                    Poll::Pending => (),
                                }
                            }
                        }
                    }
                }
                TransferState::ShuttingDown(count) => {
                    let res = b.as_mut().poll_shutdown(cx);
                    match res {
                        Poll::Ready(Ok(())) => {
                            *a_to_b_count += *count;
                            *a_to_b = TransferState::Done;
                            b_to_a_delay
                                .replace(Box::pin(tokio::time::sleep(*b_to_a_timeout_duration)));
                            continue;
                        }
                        Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                        Poll::Pending => (),
                    }
                }
                TransferState::Done => (),
            }

            match b_to_a {
                TransferState::Running(buf) => {
                    let res = buf.poll_copy(cx, b.as_mut(), a.as_mut());
                    match res {
                        Poll::Ready(Ok(count)) => {
                            *b_to_a = TransferState::ShuttingDown(count);
                            continue;
                        }
                        Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                        Poll::Pending => {
                            if let Some(delay) = b_to_a_delay {
                                match delay.as_mut().poll(cx) {
                                    Poll::Ready(()) => {
                                        *b_to_a =
                                            TransferState::ShuttingDown(buf.amount_transferred());
                                        continue;
                                    }
                                    Poll::Pending => (),
                                }
                            }
                        }
                    }
                }
                TransferState::ShuttingDown(count) => {
                    let res = a.as_mut().poll_shutdown(cx);
                    match res {
                        Poll::Ready(Ok(())) => {
                            *b_to_a_count += *count;
                            *b_to_a = TransferState::Done;
                            a_to_b_delay
                                .replace(Box::pin(tokio::time::sleep(*a_to_b_timeout_duration)));
                            continue;
                        }
                        Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                        Poll::Pending => (),
                    }
                }
                TransferState::Done => (),
            }

            match (&a_to_b, &b_to_a) {
                (TransferState::Done, TransferState::Done) => break,
                _ => return Poll::Pending,
            }
        }

        Poll::Ready(Ok((*a_to_b_count, *b_to_a_count)))
    }
}

pub async fn copy_buf_bidirectional_with_timeout<A, B>(
    a: &mut A,
    b: &mut B,
    min_size: usize,
    max_size: usize,
    a_to_b_timeout_duration: Duration,
    b_to_a_timeout_duration: Duration,
) -> Result<(u64, u64), std::io::Error>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    CopyBidirectional {
        a,
        b,
        a_to_b: TransferState::Running(CopyBuffer::new_adaptive(min_size, max_size)?),
        b_to_a: TransferState::Running(CopyBuffer::new_adaptive(min_size, max_size)?),
        a_to_b_count: 0,
        b_to_a_count: 0,
        a_to_b_delay: None,
        b_to_a_delay: None,
        a_to_b_timeout_duration,
        b_to_a_timeout_duration,
    }
    .await
}
