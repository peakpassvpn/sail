//! How an outbound's sockets are opened: the interface or address they are
//! bound to, their routing mark, and how long a connect may take.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tracing::debug;

mod detour;
mod dialer;
pub mod fields;
mod spec;

pub use detour::Outbounds;
pub use dialer::{DialDefaults, DialEnv, Dialer, InboundDialer, InstanceDial, SharedDialDefaults};
pub use fields::DialFields;
pub use spec::{DialSpec, ResolveSpec, RouteDefaults};

#[cfg(all(test, unix))]
pub(crate) use dialer::recording;

/// The default time a TCP connect to one address may take: sing-box's
/// and Mihomo's.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

pub use super::TcpKeepAlive;

/// The keepalive sing-box's fields ask for: `disable_tcp_keep_alive`,
/// `tcp_keep_alive` and `tcp_keep_alive_interval`, the defaults where they
/// are unset.
pub fn tcp_keep_alive(
    disable: bool,
    idle: Option<Duration>,
    interval: Option<Duration>,
) -> Option<TcpKeepAlive> {
    // Zero is unset, as in sing-box.
    let set = |d: Option<Duration>| d.filter(|d| !d.is_zero());
    (!disable).then(|| TcpKeepAlive {
        idle: set(idle).unwrap_or(TcpKeepAlive::DEFAULT.idle),
        interval: set(interval).unwrap_or(TcpKeepAlive::DEFAULT.interval),
    })
}

/// How the host keeps outbound sockets out of its VPN (Android).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocketProtect {
    /// An endpoint that takes each socket's file descriptor as an int32
    /// and answers 0 once it is protected: a Unix domain socket, by path.
    Unix(String),
    /// The same, over TCP.
    Tcp(SocketAddr),
    /// The host's `Platform::protect_socket`.
    Platform(crate::runtime::PlatformRef),
}

/// Applies `spec` to `socket`, which is about to talk to `target`, with
/// `auto` finding the interface where the spec leaves that to
/// `auto_detect_interface`; returns whether that bound it to a local
/// address.
///
/// A socket to a loopback address is bound to loopback and nothing else:
/// binding it to an interface would make the destination unreachable.
pub(crate) fn bind(
    socket: &socket2::Socket,
    target: &SocketAddr,
    spec: &DialSpec,
    auto: Option<&super::interface::AutoInterface>,
) -> io::Result<bool> {
    if target.ip().is_loopback() {
        let loopback: SocketAddr = match target {
            SocketAddr::V4(_) => (Ipv4Addr::LOCALHOST, 0).into(),
            SocketAddr::V6(_) => (Ipv6Addr::LOCALHOST, 0).into(),
        };
        socket.bind(&loopback.into())?;
        debug!("socket bind loopback {}", loopback);
        return Ok(true);
    }
    let auto = auto.filter(|_| spec.auto_detect_interface);
    if !spec.binds() && auto.is_none() {
        return Ok(false);
    }
    let detected = match (&spec.bind_interface, auto) {
        (None, Some(auto)) => Some(auto.for_target(target.ip()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NetworkUnreachable,
                "auto_detect_interface: no interface to send through",
            )
        })?),
        _ => None,
    };
    if let Some(iface) = spec.bind_interface.as_ref().or(detected.as_ref()) {
        bind_interface(socket, target, iface)
            .map_err(|e| io::Error::new(e.kind(), format!("bind to interface {}: {}", iface, e)))?;
        debug!("socket bind {}", iface);
    }
    let address = spec.bind_address(target.ip());
    if let Some(address) = address {
        socket.bind(&SocketAddr::new(address, 0).into())?;
        debug!("socket bind {}", address);
    }
    if let Some(mark) = spec.routing_mark {
        set_mark(socket, mark)?;
    }
    Ok(address.is_some())
}

#[cfg(target_os = "macos")]
fn bind_interface(socket: &socket2::Socket, target: &SocketAddr, iface: &str) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let name = std::ffi::CString::new(iface.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid interface name"))?;
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        return Err(io::Error::last_os_error());
    }
    let (level, option) = match target {
        SocketAddr::V4(_) => (libc::IPPROTO_IP, libc::IP_BOUND_IF),
        SocketAddr::V6(_) => (libc::IPPROTO_IPV6, libc::IPV6_BOUND_IF),
    };
    let ret = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            option,
            &index as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
        )
    };
    if ret == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn bind_interface(socket: &socket2::Socket, _target: &SocketAddr, iface: &str) -> io::Result<()> {
    socket.bind_device(Some(iface.as_bytes()))
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "android")))]
fn bind_interface(_socket: &socket2::Socket, _target: &SocketAddr, _iface: &str) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "bind_interface is not supported on this platform",
    ))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn set_mark(socket: &socket2::Socket, mark: u32) -> io::Result<()> {
    socket.set_mark(mark)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn set_mark(_socket: &socket2::Socket, _mark: u32) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "routing_mark is only supported on Linux",
    ))
}

/// Whether `routing_mark` can be used on this platform, for checking a
/// configuration before anything is dialled.
pub fn supports_routing_mark() -> bool {
    cfg!(any(target_os = "linux", target_os = "android"))
}

/// Whether the host has an interface named `name`, where that can be
/// asked. It is not asked on Android, where interfaces come and go with the
/// network.
pub fn interface_exists(name: &str) -> Option<bool> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        let name = std::ffi::CString::new(name).ok()?;
        Some(unsafe { libc::if_nametoindex(name.as_ptr()) } != 0)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = name;
        None
    }
}

/// Whether `bind_interface` can be used on this platform.
pub fn supports_bind_interface() -> bool {
    cfg!(any(
        target_os = "macos",
        target_os = "linux",
        target_os = "android"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bound_to(iface: &str) -> DialSpec {
        DialSpec {
            bind_interface: Some(iface.into()),
            ..Default::default()
        }
    }

    #[test]
    fn a_loopback_target_is_bound_to_loopback_only() {
        let socket =
            socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None).unwrap();
        let spec = bound_to("no-such-interface");
        bind(&socket, &"127.0.0.1:53".parse().unwrap(), &spec, None).unwrap();
        let local = socket.local_addr().unwrap().as_socket().unwrap();
        assert!(local.ip().is_loopback());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn binding_to_an_interface_applies_to_the_socket() {
        let socket =
            socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None).unwrap();
        let bound = bind(
            &socket,
            &"1.1.1.1:53".parse().unwrap(),
            &bound_to("lo0"),
            None,
        )
        .unwrap();
        // Bound to an interface, not to an address.
        assert!(!bound);
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn a_missing_interface_is_known_as_missing() {
        let loopback = if cfg!(target_os = "macos") {
            "lo0"
        } else {
            "lo"
        };
        assert_eq!(interface_exists(loopback), Some(true));
        assert_eq!(interface_exists("no-such-if0"), Some(false));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn binding_to_a_missing_interface_fails() {
        let socket =
            socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None).unwrap();
        let spec = bound_to("no-such-interface");
        assert!(bind(&socket, &"1.1.1.1:53".parse().unwrap(), &spec, None).is_err());
    }

    /// The interface auto_detect_interface finds is applied only where the
    /// spec leaves the interface to it.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_detected_interface_applies_where_the_spec_says() {
        let auto =
            crate::net::interface::AutoInterface::new(Vec::new(), || Ok("no-such-if0".into()));
        let socket =
            || socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None).unwrap();
        let target = "1.1.1.1:53".parse().unwrap();
        let following = DialSpec {
            auto_detect_interface: true,
            ..Default::default()
        };
        // Bound to the missing interface it detected, which fails.
        assert!(bind(&socket(), &target, &following, Some(&auto)).is_err());
        // Not following, or bound itself, it does not look.
        assert!(!bind(&socket(), &target, &DialSpec::default(), Some(&auto)).unwrap());
        let own = DialSpec {
            auto_detect_interface: true,
            ..bound_to("lo0")
        };
        bind(&socket(), &target, &own, Some(&auto)).unwrap();
    }
}
