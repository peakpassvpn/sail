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

/// What follows from the rest: a cellular network is expensive.
fn finish(mut state: NetworkState) -> NetworkState {
    state.expensive = state.kind == Some(NetworkType::Cellular);
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
    fn a_cellular_network_is_expensive() {
        let state = finish(NetworkState {
            kind: Some(NetworkType::Cellular),
            ..Default::default()
        });
        assert!(state.expensive && !state.constrained);
        assert!(!finish(NetworkState::default()).expensive);
    }
}
