//! The network the host is on, as the system tells it without asking the
//! user: the default route's interface and gateway, the kind of that
//! interface, and on Linux and Windows the Wi-Fi network's name. For
//! sail-cli and hosts that push no state (`net::network`).
//!
//! What each system gives:
//!
//! - Linux: the main table's default route (rtnetlink), the kind from
//!   `/sys/class/net`, the SSID and BSSID from nl80211.
//! - macOS: the IPv4 default route (the routing socket), the kind from the
//!   interface's functional type. No SSID: CoreWLAN asks for the user's
//!   location.
//! - Windows: the adapter with a gateway and the lowest metric (IP
//!   Helper), its kind from its interface type, the SSID and BSSID from
//!   the WLAN service.
//! - Elsewhere, nothing: the host pushes it.
//!
//! No system here says whether the network is metered, so a cellular one
//! is taken as expensive, as sing-box does when the platform does not
//! say; none is constrained.
//!
//! Every interface a connection may go out of is listed too, for
//! `network_strategy`: up, loopback aside, with an address beyond its link
//! (one with link-local addresses alone, such as macOS's AWDL `llw0`,
//! reaches no further), typed as the default is. sing-box lists them only in its graphical clients, so its
//! `network_strategy` works there alone; sail lists them on these three
//! systems as well (dial-design §4.6). What is virtual (a VPN's tunnel, a
//! bridge, a container's) is `other`, which a strategy takes only when a
//! configuration names it.

#[cfg(any(target_os = "linux", test))]
mod nl80211;
#[cfg(any(target_os = "linux", test))]
mod sysfs;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;
#[cfg(any(target_os = "windows", test))]
mod wlan;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::net::network::NetworkInterface;
use crate::net::network::{NetworkState, NetworkType};

/// The network the host is on now. It blocks on the system, a few
/// milliseconds; what cannot be read is left unknown.
pub fn detect() -> NetworkState {
    #[cfg(target_os = "linux")]
    let state = linux::detect();
    #[cfg(target_os = "macos")]
    let state = macos::detect();
    #[cfg(target_os = "windows")]
    let state = windows::detect();
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    let state = NetworkState::default();
    finish(state)
}

/// What follows from the rest: a cellular network is expensive, and so is
/// a cellular interface.
fn finish(mut state: NetworkState) -> NetworkState {
    state.expensive = state.kind == Some(NetworkType::Cellular);
    for interface in &mut state.interfaces {
        interface.expensive = interface.kind == NetworkType::Cellular;
    }
    state
}

/// `aa:bb:cc:dd:ee:ff`, as `NetworkState` keeps a BSSID.
#[cfg(any(target_os = "linux", target_os = "windows", test))]
fn bssid(mac: &[u8]) -> Option<String> {
    if mac.len() != 6 || mac.iter().all(|&b| b == 0) {
        return None;
    }
    Some(
        mac.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

/// An SSID as text; a hidden network's, empty, is unknown.
#[cfg(any(target_os = "linux", target_os = "windows", test))]
fn ssid(bytes: &[u8]) -> Option<String> {
    (!bytes.is_empty()).then(|| String::from_utf8_lossy(bytes).into_owned())
}

/// The interfaces that are up, loopback aside, with their addresses; each
/// of the kind `kind` says of it.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn interfaces(kind: impl Fn(&str) -> NetworkType) -> Vec<NetworkInterface> {
    let mut interfaces: Vec<NetworkInterface> = Vec::new();
    for (address, len, name) in crate::net::interface::subnets().unwrap_or_default() {
        let Ok(inet) = cidr::IpInet::new(address, len) else {
            continue;
        };
        if let Some(interface) = interfaces.iter_mut().find(|i| i.name == name) {
            interface.addresses.push(inet);
            continue;
        }
        let Ok(c_name) = std::ffi::CString::new(name.as_str()) else {
            continue;
        };
        // SAFETY: a C string.
        let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
        if index == 0 {
            continue;
        }
        interfaces.push(NetworkInterface {
            kind: kind(&name),
            name,
            index: Some(index),
            addresses: vec![inet],
            expensive: false,
            constrained: false,
        });
    }
    interfaces.retain(|i| i.addresses.iter().any(|a| !link_local(a.address())));
    interfaces
}

/// An address that reaches no further than its link.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows", test))]
fn link_local(address: std::net::IpAddr) -> bool {
    match address {
        std::net::IpAddr::V4(a) => a.is_link_local(),
        std::net::IpAddr::V6(a) => a.segments()[0] & 0xffc0 == 0xfe80,
    }
}

/// The addresses of interface `name`, with their prefixes.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn addresses_of(name: &str) -> Vec<cidr::IpInet> {
    crate::net::interface::subnets()
        .unwrap_or_default()
        .into_iter()
        .filter(|(_, _, n)| n == name)
        .filter_map(|(address, len, _)| cidr::IpInet::new(address, len).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_host_s_network_is_read() {
        let state = detect();
        // Whatever the host is on, what was read holds together.
        if state.kind == Some(NetworkType::Cellular) {
            assert!(state.expensive);
        }
        if state.ssid.is_some() {
            assert_eq!(state.kind, Some(NetworkType::Wifi));
        }
        assert_eq!(state.clone().normalized().unwrap(), state);
    }

    /// Every interface is up with an address, loopback aside, once, with
    /// its own index; the default is among them, of the same kind.
    #[test]
    fn this_host_s_interfaces_are_listed() {
        let state = detect();
        let mut indexes = std::collections::HashSet::new();
        for interface in &state.interfaces {
            assert!(!interface.addresses.is_empty(), "{:?}", interface);
            assert!(
                interface
                    .addresses
                    .iter()
                    .all(|a| !a.address().is_loopback()),
                "{:?}",
                interface
            );
            assert!(
                interface.addresses.iter().any(|a| !link_local(a.address())),
                "{:?}",
                interface
            );
            let index = interface.index.expect("an index");
            assert!(indexes.insert(index), "index {} twice", index);
            assert_eq!(
                interface.expensive,
                interface.kind == NetworkType::Cellular,
                "{:?}",
                interface
            );
        }
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        if let Some(default) = &state.interface {
            let listed = state
                .interfaces
                .iter()
                .find(|i| &i.name == default)
                .expect("the default is listed");
            assert_eq!(Some(listed.kind), state.kind);
            assert_eq!(listed.index, state.index);
        }
        eprintln!(
            "interfaces: {:?}",
            state
                .interfaces
                .iter()
                .map(|i| (&i.name, i.kind))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn macs_and_ssids_are_written_as_the_state_keeps_them() {
        assert_eq!(
            bssid(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x0f]).as_deref(),
            Some("aa:bb:cc:dd:ee:0f")
        );
        assert_eq!(bssid(&[0; 6]), None);
        assert_eq!(bssid(&[1, 2, 3]), None);
        assert_eq!(ssid(b"Home").as_deref(), Some("Home"));
        assert_eq!(ssid(b""), None);
    }

    #[test]
    fn link_local_addresses_are_told() {
        for a in ["169.254.3.4", "fe80::1", "febf::1"] {
            assert!(link_local(a.parse().unwrap()), "{}", a);
        }
        for a in [
            "192.168.1.2",
            "10.0.0.1",
            "fec0::1",
            "2001:db8::1",
            "fd00::1",
        ] {
            assert!(!link_local(a.parse().unwrap()), "{}", a);
        }
    }

    #[test]
    fn a_cellular_network_is_expensive() {
        let state = finish(NetworkState {
            kind: Some(NetworkType::Cellular),
            ..Default::default()
        });
        assert!(state.expensive && !state.constrained);
        assert!(!finish(NetworkState::default()).expensive);
    }
}
