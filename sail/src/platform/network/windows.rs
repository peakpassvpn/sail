//! Windows: the adapter up, not virtual, with a gateway and the lowest
//! metric, IPv4's first, from IP Helper (`GetAdaptersAddresses`), its kind from its
//! interface type; a Wi-Fi network's SSID and BSSID from the WLAN service
//! (`WlanQueryInterface`). Windows 11 24H2 answers the WLAN service only
//! to apps the user lets see their location: the SSID is then unknown.
//! Every adapter that is up, loopback aside, with an address beyond its
//! link, typed the same way.

use std::net::IpAddr;

use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS, HANDLE};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST,
    GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, IF_TYPE_ETHERNET_CSMACD, IF_TYPE_IEEE80211,
    IF_TYPE_PROP_VIRTUAL, IF_TYPE_SOFTWARE_LOOPBACK, IF_TYPE_WWANPP, IF_TYPE_WWANPP2,
    IP_ADAPTER_ADDRESSES_LH,
};
use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows_sys::Win32::NetworkManagement::WiFi::{
    wlan_interface_state_connected, wlan_intf_opcode_current_connection, WlanCloseHandle,
    WlanFreeMemory, WlanOpenHandle, WlanQueryInterface, WLAN_CONNECTION_ATTRIBUTES,
};
use windows_sys::Win32::Networking::WinSock::{AF_UNSPEC, SOCKET_ADDRESS};

use crate::net::network::{NetworkInterface, NetworkState, NetworkType};

/// What of an adapter is read.
struct Adapter {
    name: String,
    guid: String,
    index: u32,
    mtu: u32,
    if_type: u32,
    metric: (u32, u32),
    addresses: Vec<cidr::IpInet>,
    gateways: Vec<IpAddr>,
}

pub(super) fn detect() -> NetworkState {
    let mut state = NetworkState::default();
    let adapters = match adapters() {
        Ok(adapters) => adapters,
        Err(e) => {
            tracing::debug!("network: no adapters: {}", e);
            return state;
        }
    };
    state.interfaces = adapters
        .iter()
        .filter(|a| a.if_type != IF_TYPE_SOFTWARE_LOOPBACK)
        .filter(|a| a.addresses.iter().any(|i| !super::link_local(i.address())))
        .map(|a| NetworkInterface {
            name: a.name.clone(),
            index: Some(a.index),
            kind: kind(a.if_type),
            addresses: a.addresses.clone(),
            expensive: false,
            constrained: false,
        })
        .collect();
    let Some(adapter) = default(adapters) else {
        return state;
    };
    let kind = kind(adapter.if_type);
    if kind == NetworkType::Wifi {
        if let Some((ssid, bssid)) = wifi(&adapter.guid) {
            state.ssid = ssid;
            state.bssid = bssid;
        }
    }
    state.kind = Some(kind);
    state.gateway = adapter
        .gateways
        .iter()
        .find(|g| g.is_ipv4())
        .or(adapter.gateways.first())
        .copied();
    state.index = Some(adapter.index);
    state.mtu = Some(adapter.mtu);
    state.addresses = adapter.addresses;
    state.interface = Some(adapter.name);
    state
}

/// The adapter the default route goes through: up, with a gateway, of the
/// lowest metric -- an IPv4 gateway's first. Not a virtual one (a TUN,
/// wintun's or another VPN's), as `ip_helper::default_interface` and
/// sing-tun pick it: auto_route's 0/0 through wintun at metric 0 would
/// win otherwise, its on-link route listed as a gateway of 0.0.0.0, and
/// the TUN coming up would read as the network moving. An unspecified
/// gateway is none.
fn default(mut adapters: Vec<Adapter>) -> Option<Adapter> {
    for a in &mut adapters {
        a.gateways.retain(|g| !g.is_unspecified());
    }
    adapters
        .into_iter()
        .filter(|a| {
            a.if_type != IF_TYPE_SOFTWARE_LOOPBACK
                && a.if_type != IF_TYPE_PROP_VIRTUAL
                && !a.gateways.is_empty()
        })
        .min_by_key(|a| {
            let v4 = a.gateways.iter().any(|g| g.is_ipv4());
            (!v4, if v4 { a.metric.0 } else { a.metric.1 })
        })
}

/// The kind of an adapter of interface type `ty`.
fn kind(ty: u32) -> NetworkType {
    match ty {
        IF_TYPE_IEEE80211 => NetworkType::Wifi,
        IF_TYPE_WWANPP | IF_TYPE_WWANPP2 => NetworkType::Cellular,
        IF_TYPE_ETHERNET_CSMACD => NetworkType::Ethernet,
        _ => NetworkType::Other,
    }
}

/// The adapters that are up.
fn adapters() -> std::io::Result<Vec<Adapter>> {
    let flags = GAA_FLAG_INCLUDE_GATEWAYS
        | GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_DNS_SERVER;
    // 15 KB, as Microsoft advises; grown to what it asks for, a few times.
    let mut size: u32 = 15 * 1024;
    let mut buffer: Vec<u64>;
    let mut attempts = 0;
    loop {
        buffer = vec![0u64; (size as usize).div_ceil(8)];
        // SAFETY: `buffer` is writable for `size` bytes and 8-aligned.
        let ret = unsafe {
            GetAdaptersAddresses(
                u32::from(AF_UNSPEC),
                flags,
                std::ptr::null(),
                buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                &mut size,
            )
        };
        attempts += 1;
        match ret {
            ERROR_SUCCESS => break,
            ERROR_BUFFER_OVERFLOW if attempts < 4 => continue,
            e => return Err(std::io::Error::from_raw_os_error(e as i32)),
        }
    }
    let mut adapters = Vec::new();
    let mut next = buffer.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    while !next.is_null() {
        // SAFETY: a node of the list GetAdaptersAddresses wrote into
        // `buffer`, which lives until the end of this function.
        let a = unsafe { &*next };
        next = a.Next;
        if a.OperStatus != IfOperStatusUp {
            continue;
        }
        let mut addresses = Vec::new();
        let mut unicast = a.FirstUnicastAddress;
        while !unicast.is_null() {
            // SAFETY: a node of the adapter's list, in `buffer`.
            let u = unsafe { &*unicast };
            unicast = u.Next;
            if let Some(address) = socket_address(&u.Address) {
                if let Ok(inet) = cidr::IpInet::new(address, u.OnLinkPrefixLength) {
                    addresses.push(inet);
                }
            }
        }
        let mut gateways = Vec::new();
        let mut gateway = a.FirstGatewayAddress;
        while !gateway.is_null() {
            // SAFETY: as above.
            let g = unsafe { &*gateway };
            gateway = g.Next;
            gateways.extend(socket_address(&g.Address));
        }
        adapters.push(Adapter {
            // SAFETY: both are strings of the adapter, in `buffer`.
            name: unsafe { wide(a.FriendlyName) },
            guid: unsafe { std::ffi::CStr::from_ptr(a.AdapterName as *const std::ffi::c_char) }
                .to_string_lossy()
                .into_owned(),
            // SAFETY: the union's fields are both plain integers.
            index: unsafe { a.Anonymous1.Anonymous.IfIndex },
            mtu: a.Mtu,
            if_type: a.IfType,
            metric: (a.Ipv4Metric, a.Ipv6Metric),
            addresses,
            gateways,
        });
    }
    Ok(adapters)
}

/// The IP address of a `SOCKET_ADDRESS`.
fn socket_address(address: &SOCKET_ADDRESS) -> Option<IpAddr> {
    if address.lpSockaddr.is_null() || address.iSockaddrLength <= 0 {
        return None;
    }
    // SAFETY: the sockaddr is `iSockaddrLength` bytes long.
    let bytes = unsafe {
        std::slice::from_raw_parts(
            address.lpSockaddr as *const u8,
            address.iSockaddrLength as usize,
        )
    };
    super::wlan::sockaddr(bytes)
}

/// A NUL-terminated UTF-16 string.
///
/// # Safety
///
/// `s` is null or such a string.
unsafe fn wide(s: *const u16) -> String {
    if s.is_null() {
        return String::new();
    }
    let mut len = 0;
    while *s.add(len) != 0 {
        len += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(s, len))
}

/// The SSID and BSSID of the network the Wi-Fi adapter named `guid` is
/// connected to; none when it is not, or the WLAN service does not answer.
fn wifi(guid: &str) -> Option<(Option<String>, Option<String>)> {
    let (data1, data2, data3, data4) = super::wlan::parse_guid(guid)?;
    let guid = GUID {
        data1,
        data2,
        data3,
        data4,
    };
    let mut version = 0;
    let mut handle: HANDLE = std::ptr::null_mut();
    // SAFETY: plain WlanOpenHandle; the handle is closed below.
    let ret = unsafe { WlanOpenHandle(2, std::ptr::null(), &mut version, &mut handle) };
    if ret != ERROR_SUCCESS {
        tracing::debug!("network: no WLAN service: error {}", ret);
        return None;
    }
    let mut size = 0;
    let mut data: *mut std::ffi::c_void = std::ptr::null_mut();
    // SAFETY: the WLAN service allocates `data`, freed below.
    let ret = unsafe {
        WlanQueryInterface(
            handle,
            &guid,
            wlan_intf_opcode_current_connection,
            std::ptr::null(),
            &mut size,
            &mut data,
            std::ptr::null_mut(),
        )
    };
    let mut found = None;
    if ret == ERROR_SUCCESS
        && !data.is_null()
        && size as usize >= std::mem::size_of::<WLAN_CONNECTION_ATTRIBUTES>()
    {
        // SAFETY: the service answered this opcode with this struct.
        let connection = unsafe { &*(data as *const WLAN_CONNECTION_ATTRIBUTES) };
        if connection.isState == wlan_interface_state_connected {
            let association = &connection.wlanAssociationAttributes;
            found = Some((
                super::wlan::ssid(
                    association.dot11Ssid.uSSIDLength,
                    &association.dot11Ssid.ucSSID,
                ),
                super::bssid(&association.dot11Bssid),
            ));
        }
    } else if ret != ERROR_SUCCESS {
        tracing::debug!("network: the WLAN service did not answer: error {}", ret);
    }
    // SAFETY: what the service allocated and opened, once each.
    unsafe {
        if !data.is_null() {
            WlanFreeMemory(data);
        }
        WlanCloseHandle(handle, std::ptr::null());
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adapter(name: &str, if_type: u32, metric: (u32, u32), gateways: &[&str]) -> Adapter {
        Adapter {
            name: name.into(),
            guid: String::new(),
            index: 1,
            mtu: 1500,
            if_type,
            metric,
            addresses: Vec::new(),
            gateways: gateways.iter().map(|g| g.parse().unwrap()).collect(),
        }
    }

    #[test]
    fn the_default_adapter_has_a_gateway_and_the_lowest_metric() {
        let adapters = vec![
            adapter(
                "Ethernet",
                IF_TYPE_ETHERNET_CSMACD,
                (25, 25),
                &["192.168.1.1"],
            ),
            adapter("Wi-Fi", IF_TYPE_IEEE80211, (35, 35), &["10.0.0.1"]),
            adapter("wintun", 53, (5, 5), &[]),
            adapter("v6 only", IF_TYPE_ETHERNET_CSMACD, (1, 1), &["fe80::1"]),
        ];
        assert_eq!(default(adapters).unwrap().name, "Ethernet");

        // auto_route's 0/0 through wintun, at metric 0, on-link: not the
        // default, nor is another VPN's adapter, nor an on-link gateway.
        let adapters = vec![
            adapter("Wi-Fi", IF_TYPE_IEEE80211, (35, 35), &["10.0.0.1"]),
            adapter("wintun", IF_TYPE_PROP_VIRTUAL, (0, 0), &["0.0.0.0", "::"]),
            adapter("vpn", IF_TYPE_PROP_VIRTUAL, (1, 1), &["10.8.0.1"]),
            adapter("on-link", IF_TYPE_ETHERNET_CSMACD, (2, 2), &["0.0.0.0"]),
        ];
        assert_eq!(default(adapters).unwrap().name, "Wi-Fi");
        assert_eq!(kind(IF_TYPE_IEEE80211), NetworkType::Wifi);
        assert_eq!(kind(IF_TYPE_WWANPP2), NetworkType::Cellular);
        assert_eq!(kind(53), NetworkType::Other);
    }
}
