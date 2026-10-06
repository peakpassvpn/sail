//! The socket options of sing-box's dial fields that differ by platform:
//! don't-fragment on UDP, address reuse, `IP_BIND_ADDRESS_NO_PORT` and
//! TCP Fast Open.

use std::io;
use std::net::SocketAddr;

use socket2::SockRef;
use tokio::net::{TcpSocket, TcpStream};

/// Whether `bind_address_no_port` can be used on this platform.
pub const SUPPORTS_BIND_ADDRESS_NO_PORT: bool =
    cfg!(any(target_os = "linux", target_os = "android"));

/// Whether `tcp_fast_open` can be used on this platform, and why not.
pub fn supports_tcp_fast_open() -> Result<(), &'static str> {
    if cfg!(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios"
    )) {
        Ok(())
    } else if cfg!(windows) {
        // tfo-go, sing-box's, returns a connection of its own that
        // connects at the first write; sail's TCP dial returns the stream.
        Err(
            "not supported on Windows, which sends Fast Open data only with the connect \
             (ConnectEx), and sail connects before the first write",
        )
    } else {
        Err("not supported on this platform")
    }
}

/// Sets an integer socket option.
#[cfg(unix)]
fn set_int(
    socket: &SockRef<'_>,
    level: libc::c_int,
    name: libc::c_int,
    value: libc::c_int,
) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let ret = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            name,
            &value as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Reads an integer socket option.
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
pub(crate) fn get_int(
    socket: &SockRef<'_>,
    level: libc::c_int,
    name: libc::c_int,
) -> io::Result<libc::c_int> {
    use std::os::unix::io::AsRawFd;
    let mut value: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            level,
            name,
            &mut value as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if ret == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(value)
}

/// `IP_BIND_ADDRESS_NO_PORT` on a TCP socket about to be bound to an
/// address: the port is picked at connect, with the destination known,
/// so that many connections from one address do not run out of ports. A
/// kernel that does not know it binds as before, as in sing-box.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn bind_address_no_port(socket: SockRef<'_>) -> io::Result<()> {
    match set_int(&socket, libc::IPPROTO_IP, libc::IP_BIND_ADDRESS_NO_PORT, 1) {
        Err(e) if matches!(e.raw_os_error(), Some(libc::ENOPROTOOPT | libc::EINVAL)) => Ok(()),
        r => r,
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn bind_address_no_port(_socket: SockRef<'_>) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "bind_address_no_port is only supported on Linux",
    ))
}

/// `SO_REUSEADDR`, and `SO_REUSEPORT` on Unix, on a UDP socket not bound
/// yet.
pub fn reuse_addr(socket: SockRef<'_>) -> io::Result<()> {
    socket.set_reuse_address(true)?;
    #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
    socket.set_reuse_port(true)?;
    Ok(())
}

/// Sets "don't fragment" on a UDP socket of `ipv6` or not: datagrams too
/// large for the path are refused (`EMSGSIZE`) rather than fragmented. A
/// dual-stack socket gets it for IPv4 too, where the system lets it.
pub fn dont_fragment(socket: SockRef<'_>, ipv6: bool) -> io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        if ipv6 {
            set_int(
                &socket,
                libc::IPPROTO_IPV6,
                libc::IPV6_MTU_DISCOVER,
                libc::IPV6_PMTUDISC_DO,
            )?;
            // For the IPv4 it sends, dual-stack.
            let _ = set_int(
                &socket,
                libc::IPPROTO_IP,
                libc::IP_MTU_DISCOVER,
                libc::IP_PMTUDISC_DO,
            );
            Ok(())
        } else {
            set_int(
                &socket,
                libc::IPPROTO_IP,
                libc::IP_MTU_DISCOVER,
                libc::IP_PMTUDISC_DO,
            )
        }
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        // A system without the option sends as it would: as in sing-box.
        let ignore = |r: io::Result<()>| match r {
            Err(e) if matches!(e.raw_os_error(), Some(libc::ENOPROTOOPT | libc::EOPNOTSUPP)) => {
                Ok(())
            }
            r => r,
        };
        if ipv6 {
            ignore(set_int(&socket, libc::IPPROTO_IPV6, libc::IPV6_DONTFRAG, 1))?;
            let _ = set_int(&socket, libc::IPPROTO_IP, libc::IP_DONTFRAG, 1);
            Ok(())
        } else {
            ignore(set_int(&socket, libc::IPPROTO_IP, libc::IP_DONTFRAG, 1))
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        use windows_sys::Win32::Networking::WinSock;
        // IP_DONTFRAGMENT and IPV6_DONTFRAG, the options quinn-udp sets on
        // every socket it is given, so that it sets them again to what
        // they are. sing-box sets IP_MTU_DISCOVER to IP_PMTUDISC_DO
        // instead; on a socket with that, quinn-udp failed with WSAEINVAL
        // in the Windows test runs, so a QUIC outbound with
        // `udp_fragment: false` could not open its endpoint.
        let set = |level: i32, name: i32| {
            let value: u32 = 1;
            let ret = unsafe {
                WinSock::setsockopt(
                    socket.as_raw_socket() as WinSock::SOCKET,
                    level,
                    name,
                    &value as *const u32 as *const u8,
                    std::mem::size_of::<u32>() as i32,
                )
            };
            if ret != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        };
        if ipv6 {
            set(WinSock::IPPROTO_IPV6, WinSock::IPV6_DONTFRAG)?;
            // For the IPv4 it sends, dual-stack.
            let _ = set(WinSock::IPPROTO_IP, WinSock::IP_DONTFRAGMENT);
            Ok(())
        } else {
            set(WinSock::IPPROTO_IP, WinSock::IP_DONTFRAGMENT)
        }
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        windows
    )))]
    {
        let _ = (socket, ipv6);
        Ok(())
    }
}

/// Connects `socket` to `addr`, with TCP Fast Open if `fast_open`: then the
/// SYN waits for the first data written and carries it, and the connect
/// completes at once where the system has the server's cookie. Its errors
/// show at that first write, as in sing-box.
pub async fn connect(
    socket: TcpSocket,
    addr: SocketAddr,
    fast_open: bool,
) -> io::Result<TcpStream> {
    if !fast_open {
        return socket.connect(addr).await;
    }
    fast_open_connect(socket, addr).await
}

/// Linux: `TCP_FASTOPEN_CONNECT`, after which `connect` returns without
/// sending a SYN when there is a cookie, and the socket is writable.
#[cfg(any(target_os = "linux", target_os = "android"))]
async fn fast_open_connect(socket: TcpSocket, addr: SocketAddr) -> io::Result<TcpStream> {
    set_int(
        &SockRef::from(&socket),
        libc::IPPROTO_TCP,
        libc::TCP_FASTOPEN_CONNECT,
        1,
    )
    .map_err(|e| io::Error::new(e.kind(), format!("TCP_FASTOPEN_CONNECT: {}", e)))?;
    socket.connect(addr).await
}

/// Darwin: `connectx` with `CONNECT_RESUME_ON_READ_WRITE`, which leaves the
/// SYN to the first write and sends that write's data with it; the kernel's
/// back-off from Fast Open after failures is turned off, as tfo-go does.
#[cfg(any(target_os = "macos", target_os = "ios"))]
async fn fast_open_connect(socket: TcpSocket, addr: SocketAddr) -> io::Result<TcpStream> {
    use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd};
    // Darwin's `TCP_FASTOPEN_FORCE_ENABLE`.
    const TCP_FASTOPEN_FORCE_ENABLE: libc::c_int = 0x218;
    match set_int(
        &SockRef::from(&socket),
        libc::IPPROTO_TCP,
        TCP_FASTOPEN_FORCE_ENABLE,
        1,
    ) {
        // An older system backs off as it does.
        Err(e) if e.raw_os_error() == Some(libc::ENOPROTOOPT) => {}
        r => {
            r.map_err(|e| io::Error::new(e.kind(), format!("TCP_FASTOPEN_FORCE_ENABLE: {}", e)))?
        }
    }
    connectx_resume(socket.as_raw_fd(), addr)?;
    let stream = unsafe { std::net::TcpStream::from_raw_fd(socket.into_raw_fd()) };
    let stream = TcpStream::from_std(stream)?;
    // Writable once the connect is under way, or at once where it waits
    // for the first write, as tokio's connect.
    stream.writable().await?;
    if let Some(e) = stream.take_error()? {
        return Err(e);
    }
    Ok(stream)
}

/// `connectx` to `addr`, the SYN left to the first write.
#[cfg(any(target_os = "macos", target_os = "ios"))]
fn connectx_resume(fd: std::os::unix::io::RawFd, addr: SocketAddr) -> io::Result<()> {
    let to = socket2::SockAddr::from(addr);
    let endpoints = libc::sa_endpoints_t {
        sae_srcif: 0,
        sae_srcaddr: std::ptr::null(),
        sae_srcaddrlen: 0,
        sae_dstaddr: to.as_ptr() as *const libc::sockaddr,
        sae_dstaddrlen: to.len(),
    };
    let ret = unsafe {
        libc::connectx(
            fd,
            &endpoints,
            libc::SAE_ASSOCID_ANY,
            libc::CONNECT_RESUME_ON_READ_WRITE | libc::CONNECT_DATA_IDEMPOTENT,
            std::ptr::null(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if ret == -1 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(io::Error::new(e.kind(), format!("connectx: {}", e)));
        }
    }
    Ok(())
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios"
)))]
async fn fast_open_connect(_socket: TcpSocket, _addr: SocketAddr) -> io::Result<TcpStream> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "tcp_fast_open is not supported on this platform",
    ))
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::*;
    use crate::net::dial::{DialDefaults, DialFields, Dialer};

    fn dialer(json: serde_json::Value) -> Dialer {
        let fields: DialFields = serde_json::from_value(json).unwrap();
        DialDefaults::default().dialer(&fields, None).unwrap()
    }

    /// Whether "don't fragment" is set on `socket`, of IPv4.
    fn dont_fragment_set(socket: &tokio::net::UdpSocket) -> bool {
        let socket = SockRef::from(socket);
        #[cfg(target_os = "linux")]
        return get_int(&socket, libc::IPPROTO_IP, libc::IP_MTU_DISCOVER).unwrap()
            == libc::IP_PMTUDISC_DO;
        #[cfg(target_os = "macos")]
        return get_int(&socket, libc::IPPROTO_IP, libc::IP_DONTFRAG).unwrap() != 0;
    }

    #[tokio::test]
    async fn udp_is_not_fragmented_unless_the_place_or_protocol_says() {
        let v4 = "127.0.0.1:0".parse().unwrap();
        let udp = |json| async move { dialer(json).udp_socket(&v4).await.unwrap() };
        assert!(dont_fragment_set(&udp(serde_json::json!({})).await));
        assert!(!dont_fragment_set(
            &udp(serde_json::json!({ "udp_fragment": true })).await
        ));
        // Direct, hysteria2 and tuic allow it by default; set, the field
        // goes first.
        let with_default = |json| {
            let fields = DialFields {
                udp_fragment_default: true,
                ..serde_json::from_value(json).unwrap()
            };
            DialDefaults::default().dialer(&fields, None).unwrap()
        };
        let socket = with_default(serde_json::json!({}))
            .udp_socket(&v4)
            .await
            .unwrap();
        assert!(!dont_fragment_set(&socket));
        let socket = with_default(serde_json::json!({ "udp_fragment": false }))
            .udp_socket(&v4)
            .await
            .unwrap();
        assert!(dont_fragment_set(&socket));
    }

    #[tokio::test]
    async fn a_dual_stack_udp_socket_is_not_fragmented_either() {
        let socket = dialer(serde_json::json!({}))
            .udp_socket(&"[::]:0".parse().unwrap())
            .await
            .unwrap();
        let socket = SockRef::from(&socket);
        #[cfg(target_os = "linux")]
        assert_eq!(
            get_int(&socket, libc::IPPROTO_IPV6, libc::IPV6_MTU_DISCOVER).unwrap(),
            libc::IPV6_PMTUDISC_DO
        );
        #[cfg(target_os = "macos")]
        assert_ne!(
            get_int(&socket, libc::IPPROTO_IPV6, libc::IPV6_DONTFRAG).unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn reuse_addr_sets_both_options_on_udp() {
        let v4 = "127.0.0.1:0".parse().unwrap();
        let reused = |socket: &tokio::net::UdpSocket| {
            let socket = SockRef::from(socket);
            (
                socket.reuse_address().unwrap(),
                get_int(&socket, libc::SOL_SOCKET, libc::SO_REUSEPORT).unwrap() != 0,
            )
        };
        let socket = dialer(serde_json::json!({ "reuse_addr": true }))
            .udp_socket(&v4)
            .await
            .unwrap();
        assert_eq!(reused(&socket), (true, true));
        let socket = dialer(serde_json::json!({})).udp_socket(&v4).await.unwrap();
        assert_eq!(reused(&socket), (false, false));
    }

    /// A Fast Open connection carries what is written first to the server,
    /// and is marked for Fast Open where the system shows it.
    #[tokio::test]
    async fn a_fast_open_connection_carries_its_first_write() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let dialer = dialer(serde_json::json!({ "tcp_fast_open": true }));
        let mut dialled = dialer.tcp_to(addr).await.unwrap();
        {
            let socket = SockRef::from(&dialled);
            #[cfg(target_os = "linux")]
            assert_eq!(
                get_int(&socket, libc::IPPROTO_TCP, libc::TCP_FASTOPEN_CONNECT).unwrap(),
                1
            );
            #[cfg(target_os = "macos")]
            assert_ne!(get_int(&socket, libc::IPPROTO_TCP, 0x218).unwrap(), 0);
        }
        dialled.write_all(b"hello").await.unwrap();
        let (mut accepted, _) = listener.accept().await.unwrap();
        let mut got = [0; 5];
        accepted.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"hello");
        accepted.write_all(b"back").await.unwrap();
        let mut got = [0; 4];
        dialled.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"back");
        // Keepalive applies to it as to any.
        assert!(SockRef::from(&dialled).keepalive().unwrap());
    }

    /// Where nothing listens, a Fast Open connection fails, if not at
    /// connect then at its first read or write.
    #[tokio::test]
    async fn a_fast_open_connection_to_nothing_fails() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let unused = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = unused.local_addr().unwrap();
        drop(unused);
        let dialer = dialer(serde_json::json!({ "tcp_fast_open": true }));
        let Ok(mut dialled) = dialer.tcp_to(addr).await else {
            return;
        };
        let written = dialled.write_all(b"hello").await;
        let mut buf = [0; 1];
        let read = dialled.read(&mut buf).await;
        assert!(written.is_err() || !matches!(read, Ok(1)), "{:?}", read);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bind_address_no_port_is_set_before_binding_tcp() {
        let spec = crate::net::dial::DialSpec {
            inet4_bind_address: Some(std::net::Ipv4Addr::LOCALHOST),
            bind_address_no_port: true,
            ..Default::default()
        };
        let target = "192.0.2.1:443".parse().unwrap();
        let tcp = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
        crate::net::dial::bind(&tcp, &target, &spec, None).unwrap();
        let tcp = SockRef::from(&tcp);
        match get_int(&tcp, libc::IPPROTO_IP, libc::IP_BIND_ADDRESS_NO_PORT) {
            // A kernel, or an emulator, that does not know it: the bind
            // goes on without it.
            Err(e) if e.raw_os_error() == Some(libc::ENOPROTOOPT) => {
                // To stderr itself, which the test harness does not capture,
                // so that a skip shows in the log.
                use std::io::Write;
                let _ = writeln!(
                    std::io::stderr(),
                    "bind_address_no_port_is_set_before_binding_tcp: skipped, \
                     IP_BIND_ADDRESS_NO_PORT is unknown here (ENOPROTOOPT)"
                );
                return;
            }
            r => assert_eq!(r.unwrap(), 1),
        }
        // UDP has no use for it.
        let udp = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None).unwrap();
        crate::net::dial::bind(&udp, &target, &spec, None).unwrap();
        let udp = SockRef::from(&udp);
        assert_eq!(
            get_int(&udp, libc::IPPROTO_IP, libc::IP_BIND_ADDRESS_NO_PORT).unwrap(),
            0
        );
    }
}
