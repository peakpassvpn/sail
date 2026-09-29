//! `auto_detect_interface`: the interface sail's own traffic leaves
//! through, kept as the system changes it. A socket to an address on a
//! network one interface is directly on goes through that interface; any
//! other goes through the default one, as in sing-box.

use std::io;
use std::net::IpAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;

/// What the interfaces were at the last look.
#[derive(Debug, Default, PartialEq, Eq)]
struct State {
    /// The interface of the system's default route.
    default: Option<String>,
    /// The networks the interfaces are directly on: address, prefix
    /// length, interface.
    subnets: Vec<(IpAddr, u8, String)>,
}

/// Finds the default interface's name.
pub type Detect = fn() -> io::Result<String>;

pub struct AutoInterface {
    state: ArcSwap<State>,
    /// Interfaces never to send through: the TUN's own.
    skip: Vec<String>,
    detect: Detect,
}

impl std::fmt::Debug for AutoInterface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AutoInterface")
            .field("state", &self.state.load())
            .finish()
    }
}

/// Two are the same only when they are one.
impl PartialEq for AutoInterface {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(self, other)
    }
}

impl Eq for AutoInterface {}

impl AutoInterface {
    /// Looks at the interfaces now; `skip` names those never to send
    /// through.
    pub fn new(skip: Vec<String>, detect: Detect) -> Arc<AutoInterface> {
        let this = Arc::new(AutoInterface {
            state: ArcSwap::from_pointee(State::default()),
            skip,
            detect,
        });
        this.refresh();
        this
    }

    /// Looks again, and says whether anything changed.
    pub fn refresh(&self) -> bool {
        let default = match (self.detect)() {
            Ok(name) if !self.skip.contains(&name) => Some(name),
            Ok(name) => {
                tracing::warn!("the default route goes through {}, sail's own", name);
                None
            }
            Err(e) => {
                tracing::warn!("no default interface: {}", e);
                None
            }
        };
        let subnets = subnets()
            .unwrap_or_default()
            .into_iter()
            .filter(|(_, _, name)| !self.skip.contains(name))
            .collect();
        let state = State { default, subnets };
        if **self.state.load() == state {
            return false;
        }
        tracing::info!(
            "outbound traffic goes through {}",
            state.default.as_deref().unwrap_or("no interface")
        );
        self.state.store(Arc::new(state));
        true
    }

    /// The interface to send to `target` through.
    pub fn for_target(&self, target: IpAddr) -> Option<String> {
        let state = self.state.load();
        state
            .subnets
            .iter()
            .filter(|(network, len, _)| contains(*network, *len, target))
            .max_by_key(|(_, len, _)| *len)
            .map(|(_, _, name)| name.clone())
            .or_else(|| state.default.clone())
    }

    /// The default interface now.
    pub fn current(&self) -> Option<String> {
        self.state.load().default.clone()
    }
}

fn contains(network: IpAddr, len: u8, address: IpAddr) -> bool {
    match (network, address.to_canonical()) {
        (IpAddr::V4(n), IpAddr::V4(a)) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0);
            u32::from(n) & mask == u32::from(a) & mask
        }
        (IpAddr::V6(n), IpAddr::V6(a)) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(len)).unwrap_or(0);
            u128::from(n) & mask == u128::from(a) & mask
        }
        _ => false,
    }
}

/// The networks the interfaces that are up are directly on, loopback
/// aside.
#[cfg(unix)]
fn subnets() -> io::Result<Vec<(IpAddr, u8, String)>> {
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills `list`, freed below.
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut subnets = Vec::new();
    let mut entry = list;
    while !entry.is_null() {
        // SAFETY: a node of the list getifaddrs returned, not yet freed.
        let ifa = unsafe { &*entry };
        entry = ifa.ifa_next;
        let up = ifa.ifa_flags & libc::IFF_UP as u32 != 0;
        let loopback = ifa.ifa_flags & libc::IFF_LOOPBACK as u32 != 0;
        if !up || loopback || ifa.ifa_addr.is_null() || ifa.ifa_netmask.is_null() {
            continue;
        }
        // SAFETY: both are sockaddrs of the family the first says.
        let (address, mask) = unsafe {
            (
                socket_address(ifa.ifa_addr),
                socket_address(ifa.ifa_netmask),
            )
        };
        let (Some(address), Some(mask)) = (address, mask) else {
            continue;
        };
        let len = match mask {
            IpAddr::V4(m) => u32::from(m).count_ones(),
            IpAddr::V6(m) => u128::from(m).count_ones(),
        } as u8;
        // SAFETY: the name is a C string owned by the list.
        let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }
            .to_string_lossy()
            .into_owned();
        subnets.push((address, len, name));
    }
    // SAFETY: the list getifaddrs returned, freed once.
    unsafe { libc::freeifaddrs(list) };
    Ok(subnets)
}

#[cfg(not(unix))]
fn subnets() -> io::Result<Vec<(IpAddr, u8, String)>> {
    Ok(Vec::new())
}

/// The address of `sockaddr`, if it is IPv4 or IPv6.
///
/// # Safety
///
/// `sockaddr` points to a sockaddr of the family it says.
#[cfg(unix)]
unsafe fn socket_address(sockaddr: *const libc::sockaddr) -> Option<IpAddr> {
    match i32::from((*sockaddr).sa_family) {
        libc::AF_INET => {
            let sin = &*(sockaddr as *const libc::sockaddr_in);
            Some(IpAddr::from(
                u32::from_be(sin.sin_addr.s_addr).to_be_bytes(),
            ))
        }
        libc::AF_INET6 => {
            let sin6 = &*(sockaddr as *const libc::sockaddr_in6);
            Some(IpAddr::from(sin6.sin6_addr.s6_addr))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed() -> io::Result<String> {
        Ok("eth0".into())
    }

    #[test]
    fn a_network_an_interface_is_on_goes_through_it() {
        let auto = AutoInterface::new(vec!["tun0".into()], fixed);
        auto.state.store(Arc::new(State {
            default: Some("eth0".into()),
            subnets: vec![
                ("192.168.1.0".parse().unwrap(), 24, "wlan0".into()),
                ("192.168.0.0".parse().unwrap(), 16, "eth1".into()),
            ],
        }));
        assert_eq!(
            auto.for_target("192.168.1.7".parse().unwrap()).as_deref(),
            Some("wlan0")
        );
        assert_eq!(
            auto.for_target("192.168.9.7".parse().unwrap()).as_deref(),
            Some("eth1")
        );
        assert_eq!(
            auto.for_target("1.1.1.1".parse().unwrap()).as_deref(),
            Some("eth0")
        );
        assert_eq!(
            auto.for_target("::ffff:192.168.1.7".parse().unwrap())
                .as_deref(),
            Some("wlan0")
        );
    }

    #[test]
    fn the_tun_is_never_the_way_out() {
        fn tun() -> io::Result<String> {
            Ok("tun0".into())
        }
        let auto = AutoInterface::new(vec!["tun0".into()], tun);
        assert_eq!(auto.current(), None);
        assert!(auto
            .state
            .load()
            .subnets
            .iter()
            .all(|(_, _, name)| name != "tun0"));
    }

    #[cfg(unix)]
    #[test]
    fn the_host_s_networks_are_read() {
        // Whatever the host has, every entry is a real prefix.
        for (address, len, name) in subnets().unwrap() {
            assert!(!name.is_empty());
            assert!(u32::from(len) <= if address.is_ipv4() { 32 } else { 128 });
        }
    }
}
