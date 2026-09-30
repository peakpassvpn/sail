//! Linux: the main table's default route, IPv4's first as
//! `detect_default_interface` takes it; the interface's kind and MTU from
//! sysfs; a Wi-Fi network's SSID and BSSID from nl80211.

use std::path::Path;

use crate::net::network::{NetworkState, NetworkType};
use crate::platform::rtnetlink::{Family, Netlink};

pub(super) fn detect() -> NetworkState {
    let mut state = NetworkState::default();
    let netlink = match Netlink::open() {
        Ok(netlink) => netlink,
        Err(e) => {
            tracing::debug!("network: no rtnetlink: {}", e);
            return state;
        }
    };
    let v4 = netlink.default_routes(Family::V4).unwrap_or_default();
    let v6 = netlink.default_routes(Family::V6).unwrap_or_default();
    let Some(index) = v4.first().or(v6.first()).map(|r| r.oif) else {
        return state;
    };
    let Ok(name) = netlink.link_name(index) else {
        return state;
    };
    // The next hop out of that interface, IPv4's first.
    state.gateway = v4
        .iter()
        .chain(&v6)
        .filter(|r| r.oif == index)
        .find_map(|r| r.gateway);
    let root = Path::new("/");
    let kind = super::sysfs::kind(root, &name);
    if kind == NetworkType::Wifi {
        match super::nl80211::wifi(index) {
            Ok((ssid, bssid)) => {
                state.ssid = ssid;
                state.bssid = bssid;
            }
            Err(e) => tracing::debug!("network: no Wi-Fi network of {}: {}", name, e),
        }
    }
    state.kind = Some(kind);
    state.index = Some(index);
    state.mtu = super::sysfs::mtu(root, &name);
    state.addresses = super::addresses_of(&name);
    state.interface = Some(name);
    state
}
