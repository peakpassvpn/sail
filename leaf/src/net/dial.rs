//! How an outbound's sockets are opened: the interface or address they are
//! bound to, their routing mark, and how long a connect may take.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tracing::debug;

/// The default time a TCP connect may take.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(8);

/// Options for the sockets one outbound opens, already combined with the
/// instance's defaults (`route.default_interface`, `route.default_mark`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialOptions {
    /// The interface to send through, by name.
    pub bind_interface: Option<String>,
    /// The local address for IPv4 destinations.
    pub inet4_bind_address: Option<Ipv4Addr>,
    /// The local address for IPv6 destinations.
    pub inet6_bind_address: Option<Ipv6Addr>,
    /// `SO_MARK`, Linux only.
    pub routing_mark: Option<u32>,
    pub connect_timeout: Duration,
}

impl Default for DialOptions {
    fn default() -> Self {
        Self {
            bind_interface: None,
            inet4_bind_address: None,
            inet6_bind_address: None,
            routing_mark: None,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
        }
    }
}

impl DialOptions {
    /// These options, with what they leave unset taken from `defaults`.
    pub fn or(&self, defaults: &DialOptions) -> DialOptions {
        let binds_itself = self.bind_interface.is_some()
            || self.inet4_bind_address.is_some()
            || self.inet6_bind_address.is_some();
        DialOptions {
            // An outbound bound to an address is not also bound to the
            // default interface, which could contradict it.
            bind_interface: self.bind_interface.clone().or_else(|| {
                if binds_itself {
                    None
                } else {
                    defaults.bind_interface.clone()
                }
            }),
            inet4_bind_address: self.inet4_bind_address.or(if binds_itself {
                None
            } else {
                defaults.inet4_bind_address
            }),
            inet6_bind_address: self.inet6_bind_address.or(if binds_itself {
                None
            } else {
                defaults.inet6_bind_address
            }),
            routing_mark: self.routing_mark.or(defaults.routing_mark),
            connect_timeout: self.connect_timeout,
        }
    }

    /// The instance's defaults, as `route` sets them. What
    /// `auto_detect_interface` finds is added at start, where the system is
    /// asked.
    pub fn defaults(route: &crate::config::Route) -> anyhow::Result<DialOptions> {
        let defaults = DialOptions {
            bind_interface: route.default_interface.clone(),
            routing_mark: route.default_mark,
            ..Default::default()
        };
        if defaults.routing_mark.is_some() && !supports_routing_mark() {
            anyhow::bail!("route.default_mark: only supported on Linux");
        }
        if defaults.bind_interface.is_some() && !supports_bind_interface() {
            anyhow::bail!("route.default_interface: not supported on this platform");
        }
        Ok(defaults)
    }

    /// Whether any option would be applied to a socket.
    fn binds(&self) -> bool {
        self.bind_interface.is_some()
            || self.inet4_bind_address.is_some()
            || self.inet6_bind_address.is_some()
            || self.routing_mark.is_some()
    }
}

/// Applies `dial` to `socket`, which is about to talk to `target`, and
/// returns whether that bound it to a local address.
///
/// A socket to a loopback address is bound to loopback and nothing else:
/// binding it to an interface would make the destination unreachable.
pub(crate) fn bind(
    socket: &socket2::Socket,
    target: &SocketAddr,
    dial: &DialOptions,
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
    if !dial.binds() {
        return Ok(false);
    }
    if let Some(iface) = &dial.bind_interface {
        bind_interface(socket, target, iface)
            .map_err(|e| io::Error::new(e.kind(), format!("bind to interface {}: {}", iface, e)))?;
        debug!("socket bind {}", iface);
    }
    let address = match target.ip() {
        IpAddr::V4(_) => dial.inet4_bind_address.map(IpAddr::V4),
        IpAddr::V6(_) => dial.inet6_bind_address.map(IpAddr::V6),
    };
    if let Some(address) = address {
        socket.bind(&SocketAddr::new(address, 0).into())?;
        debug!("socket bind {}", address);
    }
    if let Some(mark) = dial.routing_mark {
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

    #[test]
    fn an_outbound_bound_to_an_address_does_not_take_the_default_interface() {
        let defaults = DialOptions {
            bind_interface: Some("en0".into()),
            routing_mark: Some(1),
            ..Default::default()
        };
        let own = DialOptions {
            inet4_bind_address: Some(Ipv4Addr::new(10, 0, 0, 2)),
            ..Default::default()
        };
        let combined = own.or(&defaults);
        assert_eq!(combined.bind_interface, None);
        assert_eq!(
            combined.inet4_bind_address,
            Some(Ipv4Addr::new(10, 0, 0, 2))
        );
        // A mark is not an address and still applies.
        assert_eq!(combined.routing_mark, Some(1));
    }

    #[test]
    fn an_unbound_outbound_takes_the_defaults() {
        let defaults = DialOptions {
            bind_interface: Some("en0".into()),
            ..Default::default()
        };
        let combined = DialOptions::default().or(&defaults);
        assert_eq!(combined.bind_interface.as_deref(), Some("en0"));
    }

    #[test]
    fn a_loopback_target_is_bound_to_loopback_only() {
        let socket =
            socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None).unwrap();
        let dial = DialOptions {
            bind_interface: Some("no-such-interface".into()),
            ..Default::default()
        };
        bind(&socket, &"127.0.0.1:53".parse().unwrap(), &dial).unwrap();
        let local = socket.local_addr().unwrap().as_socket().unwrap();
        assert!(local.ip().is_loopback());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn binding_to_an_interface_applies_to_the_socket() {
        let socket =
            socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None).unwrap();
        let dial = DialOptions {
            bind_interface: Some("lo0".into()),
            ..Default::default()
        };
        let bound = bind(&socket, &"1.1.1.1:53".parse().unwrap(), &dial).unwrap();
        // Bound to an interface, not to an address.
        assert!(!bound);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn binding_to_a_missing_interface_fails() {
        let socket =
            socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None).unwrap();
        let dial = DialOptions {
            bind_interface: Some("no-such-interface".into()),
            ..Default::default()
        };
        assert!(bind(&socket, &"1.1.1.1:53".parse().unwrap(), &dial).is_err());
    }
}
