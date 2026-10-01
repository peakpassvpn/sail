//! Keeps a QUIC endpoint receiving through the errors a moment of memory
//! pressure brings.
//!
//! quinn's endpoint driver skips `ConnectionReset` from its socket and ends
//! on any other receive error, and every connection on the endpoint dies
//! with it: one ENOBUFS on a busy server, and all its clients reconnect.
//! [`RecvBackoff`] sits under quinn and waits such errors out instead.

use std::fmt;
use std::future::Future;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use tokio::time::{Instant, Sleep};
use tracing::warn;

/// The first wait after a transient receive error. A judgment call: long
/// enough not to spin, short enough that no peer notices.
const FIRST_DELAY: Duration = Duration::from_millis(1);

/// The longest wait, which the doubling stops at. A judgment call: well
/// inside QUIC's idle timeouts, so connections outlive a long squeeze.
const MAX_DELAY: Duration = Duration::from_secs(1);

/// How often a failing socket may log, at most.
const LOG_INTERVAL: Duration = Duration::from_secs(1);

/// Whether `e` from a receive is the system's, for a while, and not the
/// socket's: worth waiting out.
///
/// quic-go's Temporary set (EINTR, EMFILE, ENFILE, ECONNRESET,
/// ECONNABORTED, EAGAIN, ETIMEDOUT; transport.go `listen`), plus ENOMEM
/// and ENOBUFS. quic-go closes the transport on those last two; sail
/// deliberately keeps going, for memory comes back as connections close.
/// ECONNRESET quinn skips itself, and EAGAIN never gets here: the socket
/// turns it into `Pending`.
fn transient(e: &io::Error) -> bool {
    match e.raw_os_error() {
        Some(code) => transient_os(code),
        None => false,
    }
}

#[cfg(unix)]
fn transient_os(code: i32) -> bool {
    [
        libc::ENOMEM,
        libc::ENOBUFS,
        libc::EINTR,
        libc::EMFILE,
        libc::ENFILE,
        libc::ECONNABORTED,
        libc::ETIMEDOUT,
    ]
    .contains(&code)
}

/// Windows has no ENFILE.
#[cfg(windows)]
fn transient_os(code: i32) -> bool {
    use windows_sys::Win32::Networking::WinSock::*;
    [
        WSA_NOT_ENOUGH_MEMORY,
        WSAENOBUFS,
        WSAEINTR,
        WSAEMFILE,
        WSAECONNABORTED,
        WSAETIMEDOUT,
    ]
    .contains(&code)
}

#[cfg(not(any(unix, windows)))]
fn transient_os(_code: i32) -> bool {
    false
}

#[derive(Default)]
struct State {
    /// The wait under way, if any.
    sleep: Option<Pin<Box<Sleep>>>,
    /// The last wait, none since the last datagram.
    delay: Option<Duration>,
    logged: Option<Instant>,
}

/// A socket of quinn's that waits out transient receive errors, longer
/// each time in a row, instead of handing them to quinn.
pub struct RecvBackoff {
    inner: Arc<dyn AsyncUdpSocket>,
    state: Mutex<State>,
}

impl RecvBackoff {
    pub fn new(inner: Arc<dyn AsyncUdpSocket>) -> Self {
        Self {
            inner,
            state: Mutex::new(State::default()),
        }
    }
}

impl fmt::Debug for RecvBackoff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecvBackoff")
            .field("inner", &self.inner)
            .finish()
    }
}

impl AsyncUdpSocket for RecvBackoff {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        self.inner.try_send(transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if let Some(sleep) = state.sleep.as_mut() {
                if sleep.as_mut().poll(cx).is_pending() {
                    return Poll::Pending;
                }
                state.sleep = None;
            }
            match self.inner.poll_recv(cx, bufs, meta) {
                Poll::Ready(Ok(n)) => {
                    state.delay = None;
                    return Poll::Ready(Ok(n));
                }
                Poll::Ready(Err(e)) if transient(&e) => {
                    let delay = match state.delay {
                        None => FIRST_DELAY,
                        Some(last) => (last * 2).min(MAX_DELAY),
                    };
                    state.delay = Some(delay);
                    let now = Instant::now();
                    if state
                        .logged
                        .is_none_or(|at| now.duration_since(at) >= LOG_INTERVAL)
                    {
                        state.logged = Some(now);
                        warn!("[quic] receive failed, retrying: {}", e);
                    }
                    state.sleep = Some(Box::pin(tokio::time::sleep(delay)));
                }
                other => return other,
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::transport::quic::{
        client_crypto, endpoint_on, server_config, server_crypto, wrap_socket,
    };

    #[cfg(unix)]
    const ENOMEM: i32 = libc::ENOMEM;
    #[cfg(windows)]
    const ENOMEM: i32 = windows_sys::Win32::Networking::WinSock::WSA_NOT_ENOUGH_MEMORY;
    #[cfg(unix)]
    const EBADF: i32 = libc::EBADF;
    #[cfg(windows)]
    const EBADF: i32 = windows_sys::Win32::Networking::WinSock::WSAEBADF;

    #[derive(Debug)]
    struct Writable;

    impl UdpPoller for Writable {
        fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// Receives what it is given, an error code or a datagram, in turn.
    #[derive(Debug)]
    struct Scripted(Mutex<VecDeque<Result<Vec<u8>, i32>>>);

    impl AsyncUdpSocket for Scripted {
        fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
            Box::pin(Writable)
        }

        fn try_send(&self, _transmit: &Transmit) -> io::Result<()> {
            Ok(())
        }

        fn poll_recv(
            &self,
            _cx: &mut Context,
            bufs: &mut [IoSliceMut<'_>],
            meta: &mut [RecvMeta],
        ) -> Poll<io::Result<usize>> {
            match self.0.lock().unwrap().pop_front() {
                Some(Ok(packet)) => {
                    bufs[0][..packet.len()].copy_from_slice(&packet);
                    meta[0].len = packet.len();
                    meta[0].stride = packet.len();
                    Poll::Ready(Ok(1))
                }
                Some(Err(code)) => Poll::Ready(Err(io::Error::from_raw_os_error(code))),
                None => Poll::Pending,
            }
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok((Ipv4Addr::LOCALHOST, 0).into())
        }
    }

    /// What one receive on `socket` yields: the datagram, or the error.
    async fn recv(socket: &RecvBackoff) -> io::Result<Vec<u8>> {
        let mut buf = [0u8; 64];
        let mut meta = [RecvMeta::default()];
        std::future::poll_fn(|cx| {
            let mut bufs = [IoSliceMut::new(&mut buf)];
            socket.poll_recv(cx, &mut bufs, &mut meta)
        })
        .await?;
        Ok(buf[..meta[0].len].to_vec())
    }

    fn scripted(script: Vec<Result<Vec<u8>, i32>>) -> RecvBackoff {
        RecvBackoff::new(Arc::new(Scripted(Mutex::new(script.into()))))
    }

    #[tokio::test]
    async fn transient_errors_are_waited_out() {
        let socket = scripted(vec![
            Err(ENOMEM),
            Err(ENOMEM),
            Err(ENOMEM),
            Ok(b"hello".to_vec()),
        ]);
        let got = tokio::time::timeout(Duration::from_secs(5), recv(&socket))
            .await
            .expect("the datagram comes");
        assert_eq!(got.unwrap(), b"hello");
        assert_eq!(socket.state.lock().unwrap().delay, None);
    }

    #[tokio::test]
    async fn other_errors_pass_through() {
        let socket = scripted(vec![Err(EBADF), Ok(b"late".to_vec())]);
        let e = recv(&socket).await.unwrap_err();
        assert_eq!(e.raw_os_error(), Some(EBADF));
    }

    /// quinn's own socket, failing its next `failures` receives with
    /// ENOMEM once told to.
    #[derive(Debug)]
    struct Faulty {
        inner: Arc<dyn AsyncUdpSocket>,
        failures: AtomicUsize,
    }

    impl AsyncUdpSocket for Faulty {
        fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
            self.inner.clone().create_io_poller()
        }

        fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
            self.inner.try_send(transmit)
        }

        fn poll_recv(
            &self,
            cx: &mut Context,
            bufs: &mut [IoSliceMut<'_>],
            meta: &mut [RecvMeta],
        ) -> Poll<io::Result<usize>> {
            let fail = self
                .failures
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1))
                .is_ok();
            if fail {
                return Poll::Ready(Err(io::Error::from_raw_os_error(ENOMEM)));
            }
            self.inner.poll_recv(cx, bufs, meta)
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            self.inner.local_addr()
        }

        fn max_transmit_segments(&self) -> usize {
            self.inner.max_transmit_segments()
        }

        fn max_receive_segments(&self) -> usize {
            self.inner.max_receive_segments()
        }

        fn may_fragment(&self) -> bool {
            self.inner.may_fragment()
        }
    }

    /// One round trip on a new stream of `conn`, to a server echoing it.
    async fn echo(conn: &quinn::Connection, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let (mut send, mut recv) = conn.open_bi().await?;
        send.write_all(data).await?;
        send.finish()?;
        Ok(recv.read_to_end(1024).await?)
    }

    #[tokio::test]
    async fn a_server_endpoint_outlives_enomem() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let pem = cert.cert.pem();
        let crypto = server_crypto(&pem, &cert.key_pair.serialize_pem(), &[]).unwrap();
        let faulty = Arc::new(Faulty {
            inner: wrap_socket(std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap())
                .unwrap(),
            failures: AtomicUsize::new(0),
        });
        let server = endpoint_on(faulty.clone(), Some(server_config(crypto).unwrap())).unwrap();
        let server_addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let conn = server.accept().await.unwrap().await.unwrap();
            while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                tokio::spawn(async move {
                    let data = recv.read_to_end(1024).await.unwrap();
                    send.write_all(&data).await.unwrap();
                    send.finish().unwrap();
                });
            }
        });

        let client = endpoint_on(
            wrap_socket(std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap()).unwrap(),
            None,
        )
        .unwrap();
        let roots = crate::transport::tls::tests::test_roots();
        let crypto = client_crypto(Some(&pem), false, &[], &roots).unwrap();
        let conn = client
            .connect_with(
                quinn::ClientConfig::new(Arc::new(crypto)),
                server_addr,
                "localhost",
            )
            .unwrap()
            .await
            .unwrap();
        assert_eq!(echo(&conn, b"before").await.unwrap(), b"before");

        faulty.failures.store(6, Ordering::Relaxed);
        let after = tokio::time::timeout(Duration::from_secs(5), echo(&conn, b"after"))
            .await
            .expect("the echo comes back");
        assert_eq!(after.unwrap(), b"after");
        assert_eq!(faulty.failures.load(Ordering::Relaxed), 0);
    }
}
