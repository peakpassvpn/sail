//! Keeps a socket serving through the errors its accept or receive calls
//! run into on the way.
//!
//! A listener that stops at the first failed accept stops for good: one
//! moment out of descriptors, and every later connection is refused until a
//! restart. So an accept or receive loop hands each error to an
//! [`AcceptBackoff`], which waits as long as the error calls for and says
//! whether the socket is still worth serving:
//!
//! ```ignore
//! let mut backoff = AcceptBackoff::new(format!("listen tcp {}", addr));
//! loop {
//!     let (stream, _) = match listener.accept().await {
//!         Ok(accepted) => {
//!             backoff.succeeded();
//!             accepted
//!         }
//!         Err(e) => {
//!             backoff.failed(e).await?;
//!             continue;
//!         }
//!     };
//!     // ...
//! }
//! ```
//!
//! The waits are Go's `net/http` `Server.Serve`: 5 ms after the first
//! failure, doubling to at most a second, back to 5 ms after a success.

use std::borrow::Cow;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::Instant;
use tracing::{debug, error, warn};

/// The first wait after a failure the system may recover from. Go's
/// `net/http` `Server.Serve`.
const FIRST_DELAY: Duration = Duration::from_millis(5);

/// The longest wait, which the doubling stops at. Go's `net/http`
/// `Server.Serve`.
const MAX_DELAY: Duration = Duration::from_secs(1);

/// How many failures of one connection alone (a peer that reset before it
/// was accepted, say) are retried at once in a row before they are waited
/// out like any other: a socket that fails that way on every call is not
/// spun on. A judgment call: far above what a burst of aborted handshakes
/// produces, far below a spin anyone would notice.
const TRANSIENT_RUN: u32 = 64;

/// How often a failing socket may log, at most. Repeats in between are
/// counted, and the count goes with the next line.
const LOG_INTERVAL: Duration = Duration::from_secs(1);

/// What an error from `accept` or `recv` says about the socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    /// The socket itself is gone or was never one: serving ends.
    Dead,
    /// The system is out of something, descriptors or buffers, that frees
    /// up as other connections close: waited out, longer each time.
    Exhausted,
    /// One connection, or one datagram, failed, not the socket: the next
    /// call is tried at once.
    Transient,
    /// Anything else: waited out as if the system were exhausted, since
    /// serving on is what a listener is for.
    Other,
}

/// Sorts `e` by what it says about the socket that returned it.
pub fn classify(e: &io::Error) -> Failure {
    if e.kind() == io::ErrorKind::UnexpectedEof {
        // Only a stream or a device ends; a socket is not coming back.
        return Failure::Dead;
    }
    match e.raw_os_error() {
        Some(code) => classify_os(code, e.kind()),
        None => match e.kind() {
            io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock => Failure::Transient,
            _ => Failure::Other,
        },
    }
}

#[cfg(unix)]
fn classify_os(code: i32, _kind: io::ErrorKind) -> Failure {
    // The dead: the descriptor is closed, is no socket, or is not
    // listening any more. And for a device, the device is gone.
    let dead: &[i32] = &[
        libc::EBADF,
        libc::EINVAL,
        libc::ENOTSOCK,
        libc::EFAULT,
        libc::ENXIO,
        libc::ENODEV,
        #[cfg(any(target_os = "linux", target_os = "android"))]
        libc::EBADFD,
    ];
    let exhausted: &[i32] = &[libc::EMFILE, libc::ENFILE, libc::ENOBUFS, libc::ENOMEM];
    // Of one connection or one datagram. accept(2) on Linux: errors
    // already pending on the new socket are returned by accept itself,
    // and "should be treated like EAGAIN by retrying": ENETDOWN, EPROTO,
    // ENOPROTOOPT, EHOSTDOWN, ENONET, EHOSTUNREACH, EOPNOTSUPP,
    // ENETUNREACH. EPERM is a firewall's refusal of the one connection.
    // ECONNREFUSED and the unreachables are also an unconnected UDP
    // socket's report of an ICMP error for some datagram sent earlier.
    let transient: &[i32] = &[
        libc::ECONNABORTED,
        libc::ECONNRESET,
        libc::ECONNREFUSED,
        libc::EPROTO,
        libc::EPERM,
        libc::EINTR,
        libc::EAGAIN,
        libc::EWOULDBLOCK,
        libc::ETIMEDOUT,
        libc::ENETDOWN,
        libc::ENETUNREACH,
        libc::EHOSTDOWN,
        libc::EHOSTUNREACH,
        libc::ENOPROTOOPT,
        libc::EOPNOTSUPP,
        libc::EMSGSIZE,
        #[cfg(any(target_os = "linux", target_os = "android"))]
        libc::ENONET,
    ];
    if dead.contains(&code) {
        Failure::Dead
    } else if exhausted.contains(&code) {
        Failure::Exhausted
    } else if transient.contains(&code) {
        Failure::Transient
    } else {
        Failure::Other
    }
}

#[cfg(windows)]
fn classify_os(code: i32, _kind: io::ErrorKind) -> Failure {
    use windows_sys::Win32::Networking::WinSock::*;
    let dead = [
        WSAEBADF,
        WSAEINVAL,
        WSAENOTSOCK,
        WSAEFAULT,
        WSANOTINITIALISED,
    ];
    let exhausted = [WSAEMFILE, WSAENOBUFS, WSA_NOT_ENOUGH_MEMORY];
    // WSAECONNRESET is also how Windows reports an ICMP port unreachable
    // on an unconnected UDP socket, for some datagram sent earlier.
    let transient = [
        WSAECONNABORTED,
        WSAECONNRESET,
        WSAECONNREFUSED,
        WSAEINTR,
        WSAEWOULDBLOCK,
        WSAETIMEDOUT,
        WSAENETDOWN,
        WSAENETUNREACH,
        WSAENETRESET,
        WSAEHOSTDOWN,
        WSAEHOSTUNREACH,
        WSAEMSGSIZE,
    ];
    if dead.contains(&code) {
        Failure::Dead
    } else if exhausted.contains(&code) {
        Failure::Exhausted
    } else if transient.contains(&code) {
        Failure::Transient
    } else {
        Failure::Other
    }
}

#[cfg(not(any(unix, windows)))]
fn classify_os(_code: i32, kind: io::ErrorKind) -> Failure {
    match kind {
        io::ErrorKind::ConnectionAborted
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionRefused
        | io::ErrorKind::Interrupted
        | io::ErrorKind::WouldBlock => Failure::Transient,
        _ => Failure::Other,
    }
}

/// The failures of one socket's accept or receive calls: how long to wait
/// after each, and a log of them at most once a second.
#[derive(Debug)]
pub struct AcceptBackoff {
    what: Cow<'static, str>,
    /// The last wait, none since the last success.
    delay: Option<Duration>,
    /// Transient failures since the last success.
    transient: u32,
    logged: Option<Instant>,
    suppressed: u64,
}

impl AcceptBackoff {
    /// For the socket `what` names in its logs, "[tag] listen tcp
    /// 127.0.0.1:1080" say.
    pub fn new(what: impl Into<Cow<'static, str>>) -> Self {
        Self {
            what: what.into(),
            delay: None,
            transient: 0,
            logged: None,
            suppressed: 0,
        }
    }

    /// A call succeeded: the next failure waits the shortest again.
    pub fn succeeded(&mut self) {
        self.delay = None;
        self.transient = 0;
    }

    /// A call failed with `e`. Waits as long as the error calls for and
    /// returns, for the caller to try again, or returns `e` itself if the
    /// socket is dead and serving should end.
    pub async fn failed(&mut self, e: io::Error) -> io::Result<()> {
        let failure = classify(&e);
        if failure == Failure::Dead {
            error!("{}: {}; it stops", self.what, e);
            return Err(e);
        }
        if failure == Failure::Transient && self.transient < TRANSIENT_RUN {
            self.transient += 1;
            if let Some(suppressed) = self.may_log() {
                debug!("{}: {}{}", self.what, e, Repeats(suppressed));
            }
            tokio::task::yield_now().await;
            return Ok(());
        }
        let delay = self.next_delay();
        if let Some(suppressed) = self.may_log() {
            warn!(
                "{}: {}; retrying in {:?}{}",
                self.what,
                e,
                delay,
                Repeats(suppressed)
            );
        }
        tokio::time::sleep(delay).await;
        Ok(())
    }

    fn next_delay(&mut self) -> Duration {
        let delay = match self.delay {
            None => FIRST_DELAY,
            Some(last) => (last * 2).min(MAX_DELAY),
        };
        self.delay = Some(delay);
        delay
    }

    /// The repeats suppressed since the last line, if a line may be
    /// logged now; counts this one as suppressed otherwise.
    fn may_log(&mut self) -> Option<u64> {
        let now = Instant::now();
        match self.logged {
            Some(at) if now.duration_since(at) < LOG_INTERVAL => {
                self.suppressed += 1;
                None
            }
            _ => {
                self.logged = Some(now);
                Some(std::mem::take(&mut self.suppressed))
            }
        }
    }
}

/// A datagram from `socket`, waiting out with `backoff` whatever fails for
/// one datagram alone (an ICMP error reported for an earlier send, say)
/// or for want of buffers. Fails only if the socket is dead.
pub async fn recv_from(
    socket: &UdpSocket,
    buf: &mut [u8],
    backoff: &mut AcceptBackoff,
) -> io::Result<(usize, SocketAddr)> {
    loop {
        match socket.recv_from(buf).await {
            Ok(received) => {
                backoff.succeeded();
                return Ok(received);
            }
            Err(e) => backoff.failed(e).await?,
        }
    }
}

/// ", and N more" for repeats a log line stands for, nothing for none.
struct Repeats(u64);

impl std::fmt::Display for Repeats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            0 => Ok(()),
            n => write!(f, " ({} more like it in the last second)", n),
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use super::*;

    /// A listener whose accepts return what `script` says, in turn, and
    /// then wait for ever.
    struct FakeListener {
        script: std::sync::Mutex<VecDeque<io::Result<u32>>>,
        calls: AtomicUsize,
    }

    impl FakeListener {
        fn new(script: Vec<io::Result<u32>>) -> Self {
            Self {
                script: std::sync::Mutex::new(script.into()),
                calls: AtomicUsize::new(0),
            }
        }

        async fn accept(&self) -> io::Result<u32> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let next = self.script.lock().unwrap().pop_front();
            match next {
                Some(result) => result,
                None => std::future::pending().await,
            }
        }
    }

    /// The loop every listener runs, over the fake one: each accepted
    /// connection is handed to `handled`.
    async fn serve(listener: Arc<FakeListener>, handled: Arc<AtomicUsize>) -> io::Result<()> {
        let mut backoff = AcceptBackoff::new("listen fake");
        loop {
            match listener.accept().await {
                Ok(_) => {
                    backoff.succeeded();
                    handled.fetch_add(1, Ordering::SeqCst);
                }
                Err(e) => backoff.failed(e).await?,
            }
        }
    }

    fn os(code: i32) -> io::Error {
        io::Error::from_raw_os_error(code)
    }

    #[tokio::test(start_paused = true)]
    async fn out_of_descriptors_is_waited_out_and_serving_goes_on() {
        let listener = Arc::new(FakeListener::new(vec![
            Err(os(libc::EMFILE)),
            Err(os(libc::EMFILE)),
            Err(os(libc::ENFILE)),
            Ok(1),
            Err(os(libc::ECONNABORTED)),
            Ok(2),
        ]));
        let handled = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn(serve(listener.clone(), handled.clone()));
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert_eq!(handled.load(Ordering::SeqCst), 2);
        // Past the script, and waiting for the next connection: the loop
        // is still running.
        assert_eq!(listener.calls.load(Ordering::SeqCst), 7);
        assert!(!task.is_finished());
        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn waits_double_to_a_second_and_start_over_after_a_success() {
        let mut backoff = AcceptBackoff::new("listen fake");
        let mut waits = Vec::new();
        for _ in 0..10 {
            let before = Instant::now();
            backoff.failed(os(libc::EMFILE)).await.unwrap();
            waits.push(before.elapsed().as_millis());
        }
        assert_eq!(waits, [5, 10, 20, 40, 80, 160, 320, 640, 1000, 1000]);
        backoff.succeeded();
        let before = Instant::now();
        backoff.failed(os(libc::ENOBUFS)).await.unwrap();
        assert_eq!(before.elapsed().as_millis(), 5);
    }

    #[tokio::test(start_paused = true)]
    async fn a_dead_socket_ends_serving() {
        for code in [libc::EBADF, libc::EINVAL, libc::ENOTSOCK] {
            let listener = Arc::new(FakeListener::new(vec![
                Err(os(libc::EMFILE)),
                Ok(1),
                Err(os(code)),
                Ok(2),
            ]));
            let handled = Arc::new(AtomicUsize::new(0));
            let result = serve(listener, handled.clone()).await;
            assert_eq!(result.unwrap_err().raw_os_error(), Some(code));
            assert_eq!(handled.load(Ordering::SeqCst), 1);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn transient_failures_are_retried_at_once_but_not_spun_on() {
        let mut backoff = AcceptBackoff::new("listen fake");
        let before = Instant::now();
        for _ in 0..TRANSIENT_RUN {
            backoff.failed(os(libc::ECONNABORTED)).await.unwrap();
        }
        assert_eq!(before.elapsed(), Duration::ZERO);
        // One more in a row, and they are waited out.
        backoff.failed(os(libc::ECONNABORTED)).await.unwrap();
        assert_eq!(before.elapsed(), FIRST_DELAY);
    }

    #[test]
    fn classifies() {
        assert_eq!(classify(&os(libc::EMFILE)), Failure::Exhausted);
        assert_eq!(classify(&os(libc::ENOMEM)), Failure::Exhausted);
        assert_eq!(classify(&os(libc::ECONNREFUSED)), Failure::Transient);
        assert_eq!(classify(&os(libc::EPROTO)), Failure::Transient);
        assert_eq!(classify(&os(libc::EBADF)), Failure::Dead);
        assert_eq!(
            classify(&io::Error::from(io::ErrorKind::UnexpectedEof)),
            Failure::Dead
        );
        assert_eq!(classify(&io::Error::other("detour")), Failure::Other);
    }

    #[test]
    fn repeats_read_as_a_count() {
        assert_eq!(Repeats(0).to_string(), "");
        assert_eq!(
            Repeats(3).to_string(),
            " (3 more like it in the last second)"
        );
    }
}
