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
    /// The same authority as network rules/events, including a push before
    /// this detector is first constructed or after an OS lookup began.
    network: Option<super::network::Network>,
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
        Self::create(skip, detect, None)
    }

    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows", test))]
    pub(crate) fn with_network(
        skip: Vec<String>,
        detect: Detect,
        network: super::network::Network,
    ) -> Arc<AutoInterface> {
        Self::create(skip, detect, Some(network))
    }

    fn create(
        skip: Vec<String>,
        detect: Detect,
        network: Option<super::network::Network>,
    ) -> Arc<Self> {
        let this = Arc::new(AutoInterface {
            state: ArcSwap::from_pointee(State::default()),
            skip,
            detect,
            network,
        });
        this.refresh();
        this
    }

    /// Looks again, and says whether anything changed.
    pub fn refresh(&self) -> bool {
        self.refresh_from(|| ((self.detect)(), subnets().unwrap_or_default()))
    }

    fn refresh_from(
        &self,
        detect: impl FnOnce() -> (io::Result<String>, Vec<(IpAddr, u8, String)>),
    ) -> bool {
        if self
            .network
            .as_ref()
            .is_some_and(|network| network.pushed())
        {
            return false;
        }
        let (default, subnets) = detect();
        let default = match default {
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
        let subnets = subnets
            .into_iter()
            .filter(|(_, _, name)| !self.skip.contains(name))
            .collect();
        let state = State { default, subnets };
        match &self.network {
            Some(network) => network
                .while_detecting(|| self.install(state))
                .unwrap_or(false),
            None => self.install(state),
        }
    }

    fn install(&self, state: State) -> bool {
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
        if let Some(state) = self
            .network
            .as_ref()
            .and_then(|network| network.host_state())
        {
            return state
                .addresses
                .iter()
                .filter_map(|inet| state.interface.as_ref().map(|name| (inet, name)))
                .chain(state.interfaces.iter().flat_map(|interface| {
                    interface
                        .addresses
                        .iter()
                        .map(move |inet| (inet, &interface.name))
                }))
                .filter(|(inet, name)| {
                    !self.skip.contains(name)
                        && contains(inet.address(), inet.network_length(), target)
                })
                .max_by_key(|(inet, _)| inet.network_length())
                .map(|(_, name)| name.clone())
                .or_else(|| {
                    state
                        .interface
                        .as_ref()
                        .filter(|name| !self.skip.contains(name))
                        .cloned()
                });
        }
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
        if let Some(state) = self
            .network
            .as_ref()
            .and_then(|network| network.host_state())
        {
            return state
                .interface
                .as_ref()
                .filter(|name| !self.skip.contains(name))
                .cloned();
        }
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

/// Whether `address` is on a network one of the interfaces `names` is
/// directly on.
pub(crate) fn on_interfaces(names: &[String], address: IpAddr) -> bool {
    !names.is_empty()
        && subnets().is_ok_and(|subnets| {
            subnets.iter().any(|(network, len, name)| {
                names.contains(name) && contains(*network, *len, address)
            })
        })
}

/// The networks the interfaces that are up are directly on, loopback
/// aside.
#[cfg(unix)]
pub(crate) fn subnets() -> io::Result<Vec<(IpAddr, u8, String)>> {
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
        // SAFETY: both are sockaddrs of the list, not yet freed.
        let Some((address, len)) = (unsafe { network(ifa.ifa_addr, ifa.ifa_netmask) }) else {
            continue;
        };
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

#[cfg(windows)]
fn subnets() -> io::Result<Vec<(IpAddr, u8, String)>> {
    crate::platform::windows::ip_helper::subnets()
}

#[cfg(not(any(unix, windows)))]
fn subnets() -> io::Result<Vec<(IpAddr, u8, String)>> {
    Ok(Vec::new())
}

/// An interface multicast can go out of: up, multicast-capable, not
/// loopback.
#[derive(Debug, Clone)]
pub(crate) struct MulticastInterface {
    pub name: String,
    pub index: u32,
    /// Its addresses, and the lengths of their networks' prefixes.
    pub addresses: Vec<(IpAddr, u8)>,
}

/// The interfaces multicast can go out of, with an address each.
#[cfg(unix)]
pub(crate) fn multicast_interfaces() -> io::Result<Vec<MulticastInterface>> {
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills `list`, freed below.
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut interfaces: Vec<MulticastInterface> = Vec::new();
    let mut entry = list;
    while !entry.is_null() {
        // SAFETY: a node of the list getifaddrs returned, not yet freed.
        let ifa = unsafe { &*entry };
        entry = ifa.ifa_next;
        let flags = ifa.ifa_flags;
        let usable = flags & libc::IFF_UP as u32 != 0
            && flags & libc::IFF_MULTICAST as u32 != 0
            && flags & libc::IFF_LOOPBACK as u32 == 0;
        if !usable || ifa.ifa_addr.is_null() || ifa.ifa_netmask.is_null() {
            continue;
        }
        // SAFETY: both are sockaddrs of the list, not yet freed.
        let Some((address, len)) = (unsafe { network(ifa.ifa_addr, ifa.ifa_netmask) }) else {
            continue;
        };
        // SAFETY: the name is a C string owned by the list.
        let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) };
        match interfaces
            .iter_mut()
            .find(|i| i.name.as_bytes() == name.to_bytes())
        {
            Some(interface) => interface.addresses.push((address, len)),
            None => {
                // SAFETY: a C string, as above.
                let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
                if index == 0 {
                    continue;
                }
                interfaces.push(MulticastInterface {
                    name: name.to_string_lossy().into_owned(),
                    index,
                    addresses: vec![(address, len)],
                });
            }
        }
    }
    // SAFETY: the list getifaddrs returned, freed once.
    unsafe { libc::freeifaddrs(list) };
    Ok(interfaces)
}

/// The interfaces multicast can go out of, with an address each, named as
/// the system shows them (the friendly name).
#[cfg(windows)]
pub(crate) fn multicast_interfaces() -> io::Result<Vec<MulticastInterface>> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
        GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH, IP_ADAPTER_NO_MULTICAST,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows_sys::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6,
    };

    /// IF_TYPE_SOFTWARE_LOOPBACK.
    const LOOPBACK: u32 = 24;
    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    let mut size: u32 = 16 * 1024;
    let mut buf: Vec<u64> = Vec::new();
    for attempt in 0..3 {
        buf = vec![0u64; (size as usize).div_ceil(8)];
        // SAFETY: the buffer is as long as `size` says, and aligned for the
        // structures written into it.
        let code = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                flags,
                std::ptr::null(),
                buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                &mut size,
            )
        };
        match code {
            0 => break,
            // ERROR_BUFFER_OVERFLOW: `size` is now what it needs.
            111 if attempt < 2 => continue,
            code => return Err(io::Error::from_raw_os_error(code as i32)),
        }
    }
    let mut interfaces = Vec::new();
    let mut adapter = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    // SAFETY: a list GetAdaptersAddresses wrote into `buf`, which outlives
    // the walk; each pointer is null or to a node within it, and the name
    // a NUL-terminated wide string.
    unsafe {
        while !adapter.is_null() {
            let a = &*adapter;
            adapter = a.Next;
            if a.OperStatus != IfOperStatusUp
                || a.IfType == LOOPBACK
                || a.Anonymous2.Flags & IP_ADAPTER_NO_MULTICAST != 0
            {
                continue;
            }
            let mut addresses = Vec::new();
            let mut unicast = a.FirstUnicastAddress;
            while !unicast.is_null() {
                let u = &*unicast;
                unicast = u.Next;
                let sockaddr = u.Address.lpSockaddr;
                if sockaddr.is_null() {
                    continue;
                }
                let ip = match (*sockaddr).sa_family {
                    AF_INET => IpAddr::from(
                        (*(sockaddr as *const SOCKADDR_IN))
                            .sin_addr
                            .S_un
                            .S_addr
                            .to_ne_bytes(),
                    ),
                    AF_INET6 => IpAddr::from((*(sockaddr as *const SOCKADDR_IN6)).sin6_addr.u.Byte),
                    _ => continue,
                };
                addresses.push((ip, u.OnLinkPrefixLength));
            }
            // The index IPv6 multicast is sent by; IPv4 goes by address.
            let index = if a.Ipv6IfIndex != 0 {
                a.Ipv6IfIndex
            } else {
                a.Anonymous1.Anonymous.IfIndex
            };
            if addresses.is_empty() || index == 0 || a.FriendlyName.is_null() {
                continue;
            }
            let len = (0..).take_while(|&i| *a.FriendlyName.add(i) != 0).count();
            let name = String::from_utf16_lossy(std::slice::from_raw_parts(a.FriendlyName, len));
            interfaces.push(MulticastInterface {
                name,
                index,
                addresses,
            });
        }
    }
    Ok(interfaces)
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn multicast_interfaces() -> io::Result<Vec<MulticastInterface>> {
    Ok(Vec::new())
}

/// An interface's address and the length of its network's prefix, from
/// the sockaddrs of its address and netmask.
///
/// # Safety
///
/// Both point to sockaddrs getifaddrs returned, not yet freed.
#[cfg(unix)]
unsafe fn network(
    address: *const libc::sockaddr,
    netmask: *const libc::sockaddr,
) -> Option<(IpAddr, u8)> {
    let address = socket_address(address)?;
    Some((address, prefix_len(netmask, address)))
}

/// The address of `sockaddr`, if it is IPv4 or IPv6 and all there.
///
/// # Safety
///
/// `sockaddr` points to a sockaddr getifaddrs returned, not yet freed.
#[cfg(unix)]
unsafe fn socket_address(sockaddr: *const libc::sockaddr) -> Option<IpAddr> {
    let family_end =
        std::mem::offset_of!(libc::sockaddr, sa_family) + std::mem::size_of::<libc::sa_family_t>();
    if sockaddr_len(sockaddr, family_end) < family_end {
        return None;
    }
    let family = std::ptr::addr_of!((*sockaddr).sa_family).read_unaligned();
    match i32::from(family) {
        libc::AF_INET => {
            let (sin, len) = read_sockaddr::<libc::sockaddr_in>(sockaddr);
            let end = std::mem::offset_of!(libc::sockaddr_in, sin_addr)
                + std::mem::size_of::<libc::in_addr>();
            (len >= end).then(|| IpAddr::from(u32::from_be(sin.sin_addr.s_addr).to_be_bytes()))
        }
        libc::AF_INET6 => {
            let (sin6, len) = read_sockaddr::<libc::sockaddr_in6>(sockaddr);
            let end = std::mem::offset_of!(libc::sockaddr_in6, sin6_addr)
                + std::mem::size_of::<libc::in6_addr>();
            (len >= end).then(|| IpAddr::from(sin6.sin6_addr.s6_addr))
        }
        _ => None,
    }
}

/// The length of the prefix netmask `sockaddr` gives a network of
/// `address`. The BSDs cut a netmask's trailing zero bytes off, down to
/// its family at times, so it is read as `address`'s family, and what is
/// missing is zero.
///
/// # Safety
///
/// `sockaddr` points to a sockaddr getifaddrs returned, not yet freed.
#[cfg(unix)]
unsafe fn prefix_len(sockaddr: *const libc::sockaddr, address: IpAddr) -> u8 {
    let ones = match address {
        IpAddr::V4(_) => {
            let (sin, _) = read_sockaddr::<libc::sockaddr_in>(sockaddr);
            sin.sin_addr.s_addr.count_ones()
        }
        IpAddr::V6(_) => {
            let (sin6, _) = read_sockaddr::<libc::sockaddr_in6>(sockaddr);
            u128::from_ne_bytes(sin6.sin6_addr.s6_addr).count_ones()
        }
    };
    ones as u8
}

/// A copy of what there is of `sockaddr` as a `T`, the rest zero, and how
/// many bytes there were. No reference over the whole `T` is made, as the
/// sockaddr may be shorter.
///
/// # Safety
///
/// `sockaddr` points to a sockaddr getifaddrs returned, not yet freed;
/// `T` is a plain sockaddr struct, for which all zeros is a value.
#[cfg(unix)]
unsafe fn read_sockaddr<T>(sockaddr: *const libc::sockaddr) -> (T, usize) {
    let len = sockaddr_len(sockaddr, std::mem::size_of::<T>());
    let mut out = std::mem::MaybeUninit::<T>::zeroed();
    std::ptr::copy_nonoverlapping(sockaddr.cast::<u8>(), out.as_mut_ptr().cast::<u8>(), len);
    (out.assume_init(), len)
}

/// How many bytes of `sockaddr` there are, at most `full`: its own
/// `sa_len` where it has one.
///
/// # Safety
///
/// `sockaddr` points to a sockaddr getifaddrs returned, not yet freed.
#[cfg(any(
    target_vendor = "apple",
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "openbsd",
    target_os = "netbsd"
))]
unsafe fn sockaddr_len(sockaddr: *const libc::sockaddr, full: usize) -> usize {
    usize::from(std::ptr::addr_of!((*sockaddr).sa_len).read()).min(full)
}

/// How many bytes of `sockaddr` there are, at most `full`: there is no
/// `sa_len` here, and a sockaddr is the whole struct of its family.
///
/// # Safety
///
/// `sockaddr` points to a sockaddr getifaddrs returned, not yet freed.
#[cfg(all(
    unix,
    not(any(
        target_vendor = "apple",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "openbsd",
        target_os = "netbsd"
    ))
))]
unsafe fn sockaddr_len(_sockaddr: *const libc::sockaddr, full: usize) -> usize {
    full
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed() -> io::Result<String> {
        Ok("eth0".into())
    }

    fn host(name: &str) -> super::super::network::NetworkState {
        super::super::network::NetworkState {
            interface: Some(name.into()),
            ..Default::default()
        }
    }

    #[test]
    fn host_push_before_or_after_construction_overrides_os_routes_and_subnets() {
        for before in [true, false] {
            let network = super::super::network::Network::default();
            if before {
                network.push(host("en0"));
            }
            let auto = AutoInterface::with_network(vec![], fixed, network.clone());
            // A capture interface may be unknown to the static skip list.
            auto.state.store(Arc::new(State {
                default: Some("utun233".into()),
                subnets: vec![("192.0.2.0".parse().unwrap(), 24, "utun233".into())],
            }));
            if !before {
                network.push(host("en0"));
            }
            assert_eq!(auto.current().as_deref(), Some("en0"));
            for target in [
                "192.0.2.1",
                "203.0.113.1",
                "::ffff:192.0.2.1",
                "2001:db8::1",
            ] {
                assert_eq!(
                    auto.for_target(target.parse().unwrap()).as_deref(),
                    Some("en0")
                );
            }
            assert!(!auto.refresh_from(|| panic!("OS detection after host push")));
            network.push(host("en1"));
            assert_eq!(auto.current().as_deref(), Some("en1"));
            network.push(Default::default());
            assert_eq!(auto.current(), None);
            assert_eq!(auto.for_target("192.0.2.1".parse().unwrap()), None);
        }
    }

    #[test]
    fn automatic_detection_and_its_reset_notice_work_until_the_host_takes_over() {
        use super::super::network::{ChangeReason, Network};
        let network = Network::default();
        network.settle_first(Some(host("eth0")));
        let auto = AutoInterface::with_network(vec![], fixed, network.clone());
        assert!(auto.refresh_from(|| (Ok("eth1".into()), vec![])));
        assert_eq!(auto.current().as_deref(), Some("eth1"));
        assert_eq!(network.announce(ChangeReason::DefaultInterface), Some(2));
        assert!(network.detected(host("eth1"), ChangeReason::State));
        assert_eq!(network.snapshot_with_generation().generation, 3);
        assert_eq!(network.snapshot().interface.as_deref(), Some("eth1"));
    }

    #[test]
    fn only_host_listed_subnets_can_override_its_default() {
        let network = super::super::network::Network::default();
        let mut state = host("en0");
        state.addresses = vec!["192.0.0.1/16".parse().unwrap()];
        state.interfaces = vec![super::super::network::NetworkInterface {
            name: "en1".into(),
            index: None,
            kind: super::super::network::NetworkType::Ethernet,
            addresses: vec![
                "192.0.2.1/24".parse().unwrap(),
                "2001:db8:1::1/64".parse().unwrap(),
            ],
            expensive: false,
            constrained: false,
        }];
        let mut default = state.interfaces[0].clone();
        default.name = "en0".into();
        default.addresses = state.addresses.clone();
        state.interfaces.push(default);
        network.push(state.normalized().unwrap());
        let auto = AutoInterface::with_network(vec![], fixed, network);
        auto.state.store(Arc::new(State {
            default: Some("utun233".into()),
            subnets: vec![("192.0.2.1".parse().unwrap(), 32, "utun233".into())],
        }));
        for target in ["192.0.2.1", "::ffff:192.0.2.1", "2001:db8:1::2"] {
            assert_eq!(
                auto.for_target(target.parse().unwrap()).as_deref(),
                Some("en1")
            );
        }
        assert_eq!(
            auto.for_target("192.0.3.1".parse().unwrap()).as_deref(),
            Some("en0")
        );
        assert_eq!(
            auto.for_target("203.0.113.1".parse().unwrap()).as_deref(),
            Some("en0")
        );
    }

    #[test]
    fn host_authority_still_excludes_exact_known_own_interfaces() {
        use super::super::network::{Network, NetworkInterface, NetworkType};
        let network = Network::default();
        let mut state = host("tun0");
        state.addresses = vec!["192.0.2.1/24".parse().unwrap()];
        network.push(state);
        let auto = AutoInterface::with_network(vec!["tun0".into()], fixed, network.clone());
        assert_eq!(auto.current(), None);
        assert_eq!(auto.for_target("192.0.2.1".parse().unwrap()), None);
        assert_eq!(auto.for_target("203.0.113.1".parse().unwrap()), None);
        let interface = |name: &str, address: &str| NetworkInterface {
            name: name.into(),
            index: None,
            kind: NetworkType::Other,
            addresses: vec![address.parse().unwrap()],
            expensive: false,
            constrained: false,
        };
        let mut state = host("en0");
        state.addresses = vec!["192.0.0.1/16".parse().unwrap()];
        state.interfaces = vec![
            interface("en0", "192.0.0.1/16"),
            interface("tun0", "192.0.2.1/32"),
            interface("utun99", "203.0.113.1/24"),
        ];
        network.push(state.normalized().unwrap());
        assert_eq!(auto.current().as_deref(), Some("en0"));
        assert_eq!(
            auto.for_target("192.0.2.1".parse().unwrap()).as_deref(),
            Some("en0")
        );
        // Another explicitly supplied VPN interface remains valid; skip is
        // exact ownership, not a blanket utun/tun prefix restriction.
        assert_eq!(
            auto.for_target("203.0.113.2".parse().unwrap()).as_deref(),
            Some("utun99")
        );
    }

    #[test]
    fn an_os_lookup_already_in_flight_cannot_publish_after_host_push() {
        let network = super::super::network::Network::default();
        let auto = AutoInterface::with_network(vec![], fixed, network.clone());
        let (started_tx, started) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel();
        let detector = auto.clone();
        let task = std::thread::spawn(move || {
            detector.refresh_from(|| {
                started_tx.send(()).unwrap();
                released.recv().unwrap();
                (
                    Ok("utun233".into()),
                    vec![("192.0.2.0".parse().unwrap(), 24, "utun233".into())],
                )
            })
        });
        started.recv().unwrap();
        network.push(host("en0"));
        release.send(()).unwrap();
        assert!(!task.join().unwrap());
        assert_eq!(auto.state.load().default.as_deref(), Some("eth0"));
        assert_eq!(auto.current().as_deref(), Some("en0"));
        assert_eq!(
            auto.for_target("192.0.2.1".parse().unwrap()).as_deref(),
            Some("en0")
        );
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

    /// Whether sockaddrs carry their own length here.
    #[cfg(unix)]
    const SA_LEN: bool = cfg!(any(
        target_vendor = "apple",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "openbsd",
        target_os = "netbsd"
    ));

    /// The bytes of `value`.
    #[cfg(unix)]
    fn bytes_of<T>(value: &T) -> Vec<u8> {
        // SAFETY: a plain sockaddr struct, read as its own bytes.
        unsafe {
            std::slice::from_raw_parts((value as *const T).cast::<u8>(), std::mem::size_of::<T>())
        }
        .to_vec()
    }

    /// The first `len` bytes of a sockaddr, saying so in `sa_len` where
    /// there is one, as a buffer of just that many bytes.
    #[cfg(unix)]
    fn cut(mut bytes: Vec<u8>, len: usize) -> Vec<u8> {
        bytes.truncate(len);
        if SA_LEN && !bytes.is_empty() {
            bytes[0] = len as u8;
        }
        bytes
    }

    #[cfg(unix)]
    fn sockaddr_v4(family: i32, address: [u8; 4]) -> Vec<u8> {
        // SAFETY: all zeros is a sockaddr_in.
        let mut sin: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        sin.sin_family = family as libc::sa_family_t;
        sin.sin_addr.s_addr = u32::from_ne_bytes(address);
        let full = std::mem::size_of::<libc::sockaddr_in>();
        cut(bytes_of(&sin), full)
    }

    #[cfg(unix)]
    fn sockaddr_v6(family: i32, address: std::net::Ipv6Addr) -> Vec<u8> {
        // SAFETY: all zeros is a sockaddr_in6.
        let mut sin6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        sin6.sin6_family = family as libc::sa_family_t;
        sin6.sin6_addr.s6_addr = address.octets();
        let full = std::mem::size_of::<libc::sockaddr_in6>();
        cut(bytes_of(&sin6), full)
    }

    #[cfg(unix)]
    fn parse(address: &[u8], netmask: &[u8]) -> Option<(IpAddr, u8)> {
        // SAFETY: both are sockaddrs, of the lengths they say.
        unsafe { network(address.as_ptr().cast(), netmask.as_ptr().cast()) }
    }

    #[cfg(unix)]
    #[test]
    fn a_whole_netmask_gives_its_prefix() {
        let address = sockaddr_v4(libc::AF_INET, [192, 0, 2, 7]);
        let netmask = sockaddr_v4(libc::AF_INET, [255, 255, 255, 0]);
        assert_eq!(
            parse(&address, &netmask),
            Some(("192.0.2.7".parse().unwrap(), 24))
        );
        let address = sockaddr_v6(libc::AF_INET6, "2001:db8::1".parse().unwrap());
        let netmask = sockaddr_v6(libc::AF_INET6, "ffff:ffff:ffff:ffff::".parse().unwrap());
        assert_eq!(
            parse(&address, &netmask),
            Some(("2001:db8::1".parse().unwrap(), 64))
        );
    }

    #[cfg(unix)]
    #[test]
    fn an_address_of_another_family_is_no_network() {
        let address = sockaddr_v4(libc::AF_UNIX, [192, 0, 2, 7]);
        let netmask = sockaddr_v4(libc::AF_INET, [255, 255, 255, 0]);
        assert_eq!(parse(&address, &netmask), None);
    }

    /// A BSD netmask stops after its last byte that is not zero, and may
    /// say no family.
    #[cfg(any(
        target_vendor = "apple",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    #[test]
    fn a_short_netmask_is_read_by_its_own_length() {
        let address = sockaddr_v4(libc::AF_INET, [192, 0, 2, 7]);
        let start = std::mem::offset_of!(libc::sockaddr_in, sin_addr);
        for family in [libc::AF_INET, libc::AF_UNSPEC] {
            let netmask = cut(sockaddr_v4(family, [255, 255, 255, 0]), start + 3);
            assert_eq!(
                parse(&address, &netmask),
                Some(("192.0.2.7".parse().unwrap(), 24))
            );
        }
        let netmask = cut(sockaddr_v4(libc::AF_INET, [255, 0, 0, 0]), start + 1);
        assert_eq!(parse(&address, &netmask).map(|(_, len)| len), Some(8));
        // Nothing but its length: a prefix of none.
        let netmask = cut(sockaddr_v4(libc::AF_UNSPEC, [0; 4]), 1);
        assert_eq!(parse(&address, &netmask).map(|(_, len)| len), Some(0));

        let address = sockaddr_v6(libc::AF_INET6, "2001:db8::1".parse().unwrap());
        let start = std::mem::offset_of!(libc::sockaddr_in6, sin6_addr);
        for family in [libc::AF_INET6, libc::AF_UNSPEC] {
            let netmask = cut(
                sockaddr_v6(family, "ffff:ffff:ffff:ffff::".parse().unwrap()),
                start + 8,
            );
            assert_eq!(
                parse(&address, &netmask),
                Some(("2001:db8::1".parse().unwrap(), 64))
            );
        }
        let netmask = cut(
            sockaddr_v6(libc::AF_INET6, "ffff:ffff:ffff::".parse().unwrap()),
            start + 6,
        );
        assert_eq!(parse(&address, &netmask).map(|(_, len)| len), Some(48));
    }

    /// An address cut short is no address.
    #[cfg(any(
        target_vendor = "apple",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    #[test]
    fn a_short_address_is_no_network() {
        let netmask = sockaddr_v4(libc::AF_INET, [255, 255, 255, 0]);
        let start = std::mem::offset_of!(libc::sockaddr_in, sin_addr);
        let address = cut(sockaddr_v4(libc::AF_INET, [192, 0, 2, 7]), start + 3);
        assert_eq!(parse(&address, &netmask), None);
        let address = cut(sockaddr_v4(libc::AF_INET, [192, 0, 2, 7]), 1);
        assert_eq!(parse(&address, &netmask), None);

        let netmask = sockaddr_v6(libc::AF_INET6, "ffff:ffff:ffff:ffff::".parse().unwrap());
        let start = std::mem::offset_of!(libc::sockaddr_in6, sin6_addr);
        let address = cut(
            sockaddr_v6(libc::AF_INET6, "2001:db8::1".parse().unwrap()),
            start + 15,
        );
        assert_eq!(parse(&address, &netmask), None);
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
