//! Keeping a socket out of the host's VPN, before it binds or connects:
//! the host's `Platform::protect_socket`, or a Unix socket the socket's
//! descriptor is handed to, sing-box's `protect_path`.

use std::io;
use std::os::unix::io::{AsRawFd, RawFd};

use tokio::io::{AsyncReadExt, Interest};
use tokio::net::UnixStream;
use tracing::trace;

use super::SocketProtect;

/// Protects the socket `fd` as the host says, `host`, then through the
/// dial's own `protect_path`, `path`: both where both are given, as
/// sing-box appends both (common/dialer/default.go:122-147).
pub(super) async fn protect(
    fd: RawFd,
    host: Option<&SocketProtect>,
    path: Option<&str>,
) -> io::Result<()> {
    match host {
        None => {}
        Some(SocketProtect::Platform(platform)) => {
            let start = std::time::Instant::now();
            platform.protect_socket(fd).map_err(|e| {
                io::Error::other(format!("failed to protect outbound socket {}: {}", fd, e))
            })?;
            trace!(
                "protected socket {} in {} µs",
                fd,
                start.elapsed().as_micros()
            );
        }
        Some(SocketProtect::Unix(path)) => through_path(fd, path).await?,
    }
    if let Some(path) = path {
        through_path(fd, path).await?;
    }
    Ok(())
}

/// Hands `fd` to the Unix socket at `path` to be protected, as sing does
/// (sing common/control/protect_unix.go:11-35): a connection of its own
/// for each socket; one byte, 1, carrying the descriptor as `SCM_RIGHTS`;
/// then one byte back, whatever its value, once it is protected. A
/// connection closed before it answers has refused. No time limit of its
/// own, as in sing.
async fn through_path(fd: RawFd, path: &str) -> io::Result<()> {
    let failed = |e: io::Error| {
        io::Error::new(
            e.kind(),
            format!(
                "failed to protect outbound socket {} through {}: {}",
                fd, path, e
            ),
        )
    };
    let mut stream = UnixStream::connect(path).await.map_err(failed)?;
    #[cfg(target_vendor = "apple")]
    socket2::SockRef::from(&stream)
        .set_nosigpipe(true)
        .map_err(failed)?;
    let raw = stream.as_raw_fd();
    stream
        .async_io(Interest::WRITABLE, || send_fd(raw, fd))
        .await
        .map_err(failed)?;
    let mut answer = [0u8; 1];
    match stream.read(&mut answer).await.map_err(failed)? {
        0 => Err(failed(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "closed without answering",
        ))),
        _ => Ok(()),
    }
}

/// What a send to a peer gone must not raise: `SIGPIPE`, where a flag
/// says so (Apple's sockets say it by `SO_NOSIGPIPE`).
#[cfg(any(target_os = "linux", target_os = "android"))]
const NO_SIGNAL: libc::c_int = libc::MSG_NOSIGNAL;
#[cfg(not(any(target_os = "linux", target_os = "android")))]
const NO_SIGNAL: libc::c_int = 0;

/// Room for the header of a control message and one descriptor, aligned
/// as the header is.
type Control = [u64; 4];

/// Sends the byte 1 over the stream `socket`, with `fd` as `SCM_RIGHTS`.
fn send_fd(socket: RawFd, fd: RawFd) -> io::Result<()> {
    let mut byte = [1u8];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: byte.len(),
    };
    let mut control: Control = [0; 4];
    // SAFETY: arithmetic on a length only.
    let space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as libc::c_uint) };
    assert!(space as usize <= std::mem::size_of::<Control>());
    // SAFETY: an all-zero msghdr is an empty message.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = space as _;
    // SAFETY: the control buffer, which `msg` points at, has room for the
    // header and the descriptor, as checked above; the data may be
    // unaligned.
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as libc::c_uint) as _;
        std::ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<RawFd>(), fd);
    }
    // SAFETY: `msg` and what it points at outlive the call.
    match unsafe { libc::sendmsg(socket, &msg, NO_SIGNAL) } {
        n if n < 0 => Err(io::Error::last_os_error()),
        0 => Err(io::Error::new(io::ErrorKind::WriteZero, "nothing sent")),
        _ => Ok(()),
    }
}

/// The other end, for tests: a protect server as sing-box's hosts run one.
#[cfg(test)]
pub(crate) mod server {
    use std::io::{self, Write};
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::os::unix::io::AsRawFd;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};

    /// What the server does with a descriptor it takes.
    #[derive(Debug, Clone, Copy)]
    pub(crate) enum Answer {
        /// Answers this byte.
        Byte(u8),
        /// Closes the connection unanswered.
        Close,
    }

    /// A Unix socket that takes one descriptor on each connection, as many
    /// connections as it has answers, keeping what it takes.
    pub(crate) struct Server {
        pub(crate) path: String,
        serving: JoinHandle<Vec<Option<OwnedFd>>>,
    }

    impl Server {
        pub(crate) fn start(answers: Vec<Answer>) -> Server {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let path: PathBuf = std::env::temp_dir().join(format!(
                "sail-protect-{}-{}.sock",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = std::fs::remove_file(&path);
            let listener = UnixListener::bind(&path).unwrap();
            // Waits for no connection for ever, so that a test of a socket
            // that never comes fails rather than hangs.
            listener.set_nonblocking(true).unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            let serving = std::thread::spawn(move || {
                let mut taken = Vec::new();
                for answer in answers {
                    let mut conn = loop {
                        match listener.accept() {
                            Ok((conn, _)) => break conn,
                            Err(e)
                                if e.kind() == io::ErrorKind::WouldBlock
                                    && Instant::now() < deadline =>
                            {
                                std::thread::sleep(Duration::from_millis(5));
                            }
                            Err(_) => return taken,
                        }
                    };
                    conn.set_nonblocking(false).unwrap();
                    taken.push(receive(&conn).unwrap());
                    if let Answer::Byte(byte) = answer {
                        conn.write_all(&[byte]).unwrap();
                    }
                }
                taken
            });
            Server {
                path: path.to_str().unwrap().to_owned(),
                serving,
            }
        }

        /// The descriptors taken, once every connection was served, or as
        /// many as came in time.
        pub(crate) fn taken(self) -> Vec<Option<OwnedFd>> {
            let taken = self.serving.join().unwrap();
            let _ = std::fs::remove_file(&self.path);
            taken
        }
    }

    /// One byte, and the descriptor it carries if it carries one.
    fn receive(conn: &UnixStream) -> io::Result<Option<OwnedFd>> {
        let mut byte = [0u8; 1];
        let mut iov = libc::iovec {
            iov_base: byte.as_mut_ptr().cast(),
            iov_len: 1,
        };
        let mut control: super::Control = [0; 4];
        // SAFETY: an all-zero msghdr is an empty message.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = std::mem::size_of::<super::Control>() as _;
        // SAFETY: `msg` points at buffers that outlive the call.
        if unsafe { libc::recvmsg(conn.as_raw_fd(), &mut msg, 0) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: recvmsg filled the control buffer `msg` points at.
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            if cmsg.is_null()
                || (*cmsg).cmsg_level != libc::SOL_SOCKET
                || (*cmsg).cmsg_type != libc::SCM_RIGHTS
            {
                return Ok(None);
            }
            let fd = std::ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast::<libc::c_int>());
            assert_eq!(byte, [1], "sing sends 1 with the descriptor");
            Ok(Some(OwnedFd::from_raw_fd(fd)))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::os::fd::OwnedFd;

    use super::server::{Answer, Server};
    use super::*;
    use crate::net::dial::{DialDefaults, DialEnv, DialFields, Dialer};

    /// The local address of the socket a descriptor taken is, which
    /// `getsockname` gives only for a socket.
    fn local(fd: &Option<OwnedFd>) -> SocketAddr {
        let fd = fd.as_ref().expect("a descriptor, by SCM_RIGHTS");
        socket2::SockRef::from(fd)
            .local_addr()
            .unwrap()
            .as_socket()
            .unwrap()
    }

    /// A dialer whose host protects its sockets through `path`.
    fn host_protects(path: &str) -> Dialer {
        DialDefaults {
            env: DialEnv {
                protect: Some(SocketProtect::Unix(path.to_owned())),
                ..Default::default()
            },
            ..Default::default()
        }
        .dialer(&DialFields::default(), None)
        .unwrap()
    }

    /// A dialer of `protect_path`, `path`.
    fn protect_path(path: &str) -> Dialer {
        let fields = serde_json::from_value(serde_json::json!({ "protect_path": path })).unwrap();
        DialDefaults::default().dialer(&fields, None).unwrap()
    }

    #[tokio::test]
    async fn each_socket_is_handed_over_by_scm_rights_and_then_dialled() {
        // Any byte answers: sing reads one, and looks at its count only.
        let server = Server::start(vec![Answer::Byte(1), Answer::Byte(0)]);
        let dialer = host_protects(&server.path);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (dialled, accepted) = tokio::join!(dialer.tcp_to(addr), listener.accept());
        let (dialled, _accepted) = (dialled.unwrap(), accepted.unwrap());
        let udp = dialer
            .udp_socket(&"127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let taken = server.taken();
        assert_eq!(taken.len(), 2, "sockets handed over");
        // The very sockets: the server's descriptors are bound as they are.
        assert_eq!(local(&taken[0]), dialled.local_addr().unwrap());
        assert_eq!(local(&taken[1]), udp.local_addr().unwrap());
    }

    #[tokio::test]
    async fn a_socket_not_protected_is_not_dialled() {
        // Closed unanswered.
        let server = Server::start(vec![Answer::Close, Answer::Close]);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let err = host_protects(&server.path).tcp_to(addr).await.unwrap_err();
        assert!(
            err.to_string().contains("closed without answering"),
            "{}",
            err
        );
        assert!(err.to_string().contains(&server.path), "{}", err);
        let err = protect_path(&server.path)
            .udp_socket(&"127.0.0.1:0".parse().unwrap())
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("closed without answering"),
            "{}",
            err
        );
        let taken = server.taken();
        assert_eq!(taken.len(), 2, "sockets handed over");
        assert!(taken.iter().all(Option::is_some));
        // Nothing listening.
        let gone = std::env::temp_dir().join("sail-protect-nothing-here.sock");
        let err = protect_path(gone.to_str().unwrap())
            .tcp_to(addr)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("failed to protect"), "{}", err);
        // Nothing dialled the listener all the while.
        let accepted =
            tokio::time::timeout(std::time::Duration::from_millis(50), listener.accept()).await;
        assert!(accepted.is_err());
    }

    #[tokio::test]
    async fn protect_path_goes_with_the_host_s_protection() {
        let host = Server::start(vec![Answer::Byte(1)]);
        let own = Server::start(vec![Answer::Byte(1)]);
        let fields =
            serde_json::from_value(serde_json::json!({ "protect_path": own.path })).unwrap();
        let dialer = DialDefaults {
            env: DialEnv {
                protect: Some(SocketProtect::Unix(host.path.clone())),
                ..Default::default()
            },
            ..Default::default()
        }
        .dialer(&fields, None)
        .unwrap();
        let udp = dialer
            .udp_socket(&"127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let local_addr = udp.local_addr().unwrap();
        for server in [host, own] {
            let taken = server.taken();
            assert_eq!(taken.len(), 1, "sockets handed over");
            assert_eq!(local(&taken[0]), local_addr);
        }
    }
}
