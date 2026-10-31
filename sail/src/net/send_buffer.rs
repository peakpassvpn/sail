//! The send buffer of a TCP connection an inbound accepted, grown out of
//! the process's transfer budget while it is what holds the client's
//! transfer back (sail#10).
//!
//! A fixed buffer is the window of a download to a LAN client: at 256 KiB
//! (Linux keeps twice what is set) a client 8 ms away takes about 500
//! Mbit/s a connection, whatever the server behind. One large enough for
//! that, kept by every connection, is what twenty clients that stopped
//! reading would hold. So a connection starts at `inbound.tcp_send_buffer`
//! and doubles, up to `inbound.tcp_send_buffer_max`, when a write finds the
//! buffer full with almost all of it sent and not yet acknowledged: the
//! window, not the network or the client, is the limit then. What is
//! queued unsent tells the two apart, as quinn's windows grow only while
//! they are read about as fast as data arrives. The growth is given back
//! when the connection goes a second without filling its buffer (its
//! transfer slowed or ended), when a write stays blocked a second (the
//! client stopped reading, or is slower than the buffer needs), and when
//! it closes.
//!
//! What the kernel keeps, twice the size set, is what the budget is
//! charged. Only Linux and Android grow it: elsewhere the size stays as
//! set.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

/// How long a buffer that grew may go without filling, or stay full, before
/// it is given back. A judgment: many round trips of a LAN, and soon enough
/// for twenty stalled clients' growth to go back to the others.
#[cfg(any(target_os = "linux", target_os = "android"))]
const GIVE_BACK_AFTER: Duration = Duration::from_secs(1);

/// An accepted connection, its send buffer grown while that is what holds
/// its client back.
pub struct Growing {
    inner: TcpStream,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    growth: Option<Growth>,
}

impl Growing {
    /// `stream`, whose send buffer was set to `base` bytes, growing up to
    /// `max`; no growth if `max` is not more than `base`, `base` is zero
    /// (the system's own tuning), or outside Linux and Android.
    pub fn new(stream: TcpStream, base: usize, max: usize) -> Self {
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let _ = (base, max);
        Self {
            inner: stream,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            growth: (base > 0 && max > base)
                .then(|| Growth::new(base, max, crate::runtime::transfer_budget::global())),
        }
    }

    pub fn get_ref(&self) -> &TcpStream {
        &self.inner
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
struct Growth {
    budget: &'static crate::runtime::transfer_budget::TransferBudget,
    base: usize,
    max: usize,
    /// The size set now, in bytes.
    size: usize,
    /// Whether the last write found the buffer full.
    full: bool,
    /// When a write last found it full.
    last_full: tokio::time::Instant,
    /// Armed while a grown buffer is full: when it fires, the growth goes.
    give_back: Option<Pin<Box<tokio::time::Sleep>>>,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl Growth {
    fn new(
        base: usize,
        max: usize,
        budget: &'static crate::runtime::transfer_budget::TransferBudget,
    ) -> Self {
        Self {
            budget,
            base,
            max,
            size: base,
            full: false,
            last_full: tokio::time::Instant::now(),
            give_back: None,
        }
    }

    /// What the budget holds for this buffer: what the kernel keeps past
    /// twice the base.
    fn charged(&self) -> u64 {
        2 * (self.size - self.base) as u64
    }

    /// After a write to `stream`, which found the buffer full if `full`.
    fn wrote(&mut self, stream: &TcpStream, cx: &mut Context<'_>, full: bool) {
        let now = tokio::time::Instant::now();
        if !full {
            if !self.full && self.size > self.base && now - self.last_full >= GIVE_BACK_AFTER {
                self.shrink(stream);
            }
            self.full = false;
            return;
        }
        if !self.full {
            self.full = true;
            self.last_full = now;
            if self.size < self.max && window_limited(stream, self.size) {
                self.grow(stream);
            }
            if self.size > self.base {
                let deadline = now + GIVE_BACK_AFTER;
                match &mut self.give_back {
                    Some(timer) => timer.as_mut().reset(deadline),
                    None => self.give_back = Some(Box::pin(tokio::time::sleep_until(deadline))),
                }
            }
        }
        if self.size > self.base {
            if let Some(timer) = &mut self.give_back {
                if std::future::Future::poll(timer.as_mut(), cx).is_ready() {
                    self.shrink(stream);
                }
            }
        }
    }

    fn grow(&mut self, stream: &TcpStream) {
        let size = (self.size * 2).min(self.max);
        let more = 2 * (size - self.size) as u64;
        if !self.budget.try_grow(more) {
            return;
        }
        // Setting it wakes the blocked write.
        match super::dial::sockopt::send_buffer(socket2::SockRef::from(stream), size) {
            Ok(()) => self.size = size,
            Err(e) => {
                self.budget.release(more);
                tracing::debug!("send buffer not grown: {}", e);
            }
        }
    }

    fn shrink(&mut self, stream: &TcpStream) {
        // What is queued past the new size drains; nothing more is taken
        // until it has.
        if let Err(e) = super::dial::sockopt::send_buffer(socket2::SockRef::from(stream), self.base)
        {
            tracing::debug!("send buffer not given back: {}", e);
        }
        self.budget.release(self.charged());
        self.size = self.base;
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl Drop for Growth {
    fn drop(&mut self) {
        self.budget.release(self.charged());
    }
}

/// Whether a full send buffer of `size` bytes is what limits `stream`:
/// almost all of what the kernel keeps (twice `size`) is sent and waits to
/// be acknowledged, less than a quarter queued unsent. Otherwise the
/// network, or a client that reads slower, holds the data back, and a
/// larger buffer would only queue more.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn window_limited(stream: &TcpStream, size: usize) -> bool {
    match unsent(stream) {
        Some(unsent) => unsent < size / 2,
        None => false,
    }
}

/// The start of Linux's `struct tcp_info`, to `tcpi_notsent_bytes` (Linux
/// 4.6): libc's Android one ends before it.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[repr(C)]
#[derive(Default)]
struct TcpInfo {
    bytes: [u8; 8],
    words: [u32; 24],
    rates: [u64; 4],
    segs: [u32; 2],
    notsent_bytes: u32,
}

/// The bytes `stream` has queued and not yet sent; none on a kernel too old
/// to say.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn unsent(stream: &TcpStream) -> Option<usize> {
    use std::os::unix::io::AsRawFd;
    let mut info = TcpInfo::default();
    let mut len = std::mem::size_of::<TcpInfo>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            &mut info as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    let end = std::mem::offset_of!(TcpInfo, notsent_bytes) + std::mem::size_of::<u32>();
    (ret == 0 && len as usize >= end).then_some(info.notsent_bytes as usize)
}

impl AsyncRead for Growing {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Growing {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        let written = Pin::new(&mut me.inner).poll_write(cx, buf);
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if let Some(growth) = &mut me.growth {
            growth.wrote(&me.inner, cx, written.is_pending());
        }
        written
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        let written = Pin::new(&mut me.inner).poll_write_vectored(cx, bufs);
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if let Some(growth) = &mut me.growth {
            growth.wrote(&me.inner, cx, written.is_pending());
        }
        written
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

#[cfg(all(test, any(target_os = "linux", target_os = "android")))]
mod tests {
    use super::*;
    use crate::runtime::transfer_budget::TransferBudget;
    use tokio::io::AsyncWriteExt;

    const BASE: usize = 64 << 10;

    /// An accepted connection whose buffer grows out of a budget of its
    /// own of `limit` bytes, and its client.
    async fn pair(base: usize, max: usize, limit: u64) -> (Growing, TcpStream) {
        let listener = crate::net::TcpListener::bind_now(&"127.0.0.1:0".parse().unwrap())
            .unwrap()
            .send_buffer(base);
        let addr = listener.io().local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (accepted, _) = listener.accept().await.unwrap();
        let mut accepted = Growing::new(accepted, base, max);
        let budget: &'static TransferBudget = Box::leak(Box::new(TransferBudget::limited(limit)));
        if let Some(growth) = &mut accepted.growth {
            growth.budget = budget;
        }
        (accepted, client)
    }

    fn kernel_size(stream: &Growing) -> usize {
        socket2::SockRef::from(stream.get_ref())
            .send_buffer_size()
            .unwrap()
    }

    /// Each growth doubles the buffer up to the most and charges the
    /// budget what the kernel keeps for it; closing gives it all back.
    #[tokio::test]
    async fn growth_doubles_to_the_most_and_is_charged() {
        let (mut accepted, _client) = pair(BASE, 3 * BASE, u64::MAX).await;
        let growth = accepted.growth.as_mut().unwrap();
        growth.grow(&accepted.inner);
        assert_eq!(growth.size, 2 * BASE);
        growth.grow(&accepted.inner);
        assert_eq!(growth.size, 3 * BASE);
        let budget = growth.budget;
        assert_eq!(budget.held(), 4 * BASE as u64);
        assert!(kernel_size(&accepted) >= 6 * BASE);
        drop(accepted);
        assert_eq!(budget.held(), 0);
    }

    /// A growth the budget has no room for leaves the buffer as it is.
    #[tokio::test]
    async fn a_growth_the_budget_refuses_keeps_the_size() {
        let (mut accepted, _client) = pair(BASE, 4 * BASE, BASE as u64).await;
        let growth = accepted.growth.as_mut().unwrap();
        growth.grow(&accepted.inner);
        assert_eq!((growth.size, growth.budget.held()), (BASE, 0));
        assert!(kernel_size(&accepted) < 4 * BASE);
    }

    /// A client that stopped reading: its writes stay blocked, with what
    /// is queued unsent, so the buffer does not grow; and one that grew
    /// goes back to the base a second later.
    #[tokio::test]
    async fn a_stalled_client_s_growth_goes_back() {
        let (mut accepted, _client) = pair(BASE, 4 * BASE, u64::MAX).await;
        let growth = accepted.growth.as_mut().unwrap();
        growth.grow(&accepted.inner);
        assert_eq!(growth.size, 2 * BASE);
        let budget = growth.budget;
        let chunk = vec![0; BASE];
        let blocked = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                accepted.write_all(&chunk).await.unwrap();
            }
        })
        .await;
        assert!(blocked.is_err());
        assert_eq!(accepted.growth.as_ref().unwrap().size, BASE);
        assert_eq!(budget.held(), 0);
        assert!(kernel_size(&accepted) < 4 * BASE);
    }

    /// Without a larger most, or with the system's tuning, nothing grows.
    #[tokio::test]
    async fn no_growth_without_room_to_grow() {
        assert!(pair(BASE, BASE, u64::MAX).await.0.growth.is_none());
        assert!(pair(0, BASE, u64::MAX).await.0.growth.is_none());
    }
}
