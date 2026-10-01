//! The IP Helper calls route management makes, as sing-tun makes them
//! through winipcfg: interfaces by LUID, their addresses, parameters and
//! DNS, routes, and the notices of changes to routes and interfaces.
//!
//! Without the TUN only the interfaces and the notices are asked for.
#![cfg_attr(not(feature = "inbound-tun"), allow(dead_code))]

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{
    ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS, HANDLE, NO_ERROR,
};
use windows_sys::Win32::NetworkManagement::IpHelper::*;
use windows_sys::Win32::NetworkManagement::Ndis::{IfOperStatusUp, NET_LUID_LH};
use windows_sys::Win32::Networking::WinSock::{
    IpDadStatePreferred, RouterDiscoveryDisabled, ADDRESS_FAMILY, AF_INET, AF_INET6, AF_UNSPEC,
    MIB_IPPROTO_NETMGMT, SOCKADDR_INET,
};

/// A Win32 error code as an io::Error; success as Ok.
fn check(code: u32) -> io::Result<()> {
    if code == NO_ERROR {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code as i32))
    }
}

fn family(v6: bool) -> ADDRESS_FAMILY {
    if v6 {
        AF_INET6
    } else {
        AF_INET
    }
}

pub(crate) fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn from_wide(s: &[u16]) -> String {
    let end = s.iter().position(|&c| c == 0).unwrap_or(s.len());
    String::from_utf16_lossy(&s[..end])
}

pub(crate) fn sockaddr(address: IpAddr) -> SOCKADDR_INET {
    let mut out = SOCKADDR_INET::default();
    match address {
        IpAddr::V4(v4) => {
            out.Ipv4.sin_family = AF_INET;
            out.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(v4.octets());
        }
        IpAddr::V6(v6) => {
            out.Ipv6.sin6_family = AF_INET6;
            out.Ipv6.sin6_addr.u.Byte = v6.octets();
        }
    }
    out
}

fn address(sockaddr: &SOCKADDR_INET) -> Option<IpAddr> {
    // SAFETY: the family says which member is set.
    unsafe {
        match sockaddr.si_family {
            AF_INET => Some(IpAddr::V4(Ipv4Addr::from(
                sockaddr.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes(),
            ))),
            AF_INET6 => Some(IpAddr::V6(Ipv6Addr::from(sockaddr.Ipv6.sin6_addr.u.Byte))),
            _ => None,
        }
    }
}

/// An interface, by its locally unique identifier.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(crate) struct Luid(pub u64);

impl Luid {
    fn raw(self) -> NET_LUID_LH {
        NET_LUID_LH { Value: self.0 }
    }

    fn of(raw: &NET_LUID_LH) -> Luid {
        // SAFETY: every bit pattern is a u64.
        Luid(unsafe { raw.Value })
    }

    /// The interface of the name (alias) Windows shows.
    pub(crate) fn by_alias(alias: &str) -> io::Result<Luid> {
        let mut luid = NET_LUID_LH::default();
        let alias = wide(alias);
        // SAFETY: a NUL-terminated wide string and a place for the result.
        check(unsafe { ConvertInterfaceAliasToLuid(alias.as_ptr(), &mut luid) })?;
        Ok(Luid::of(&luid))
    }

    /// The name (alias) Windows shows.
    pub(crate) fn alias(self) -> io::Result<String> {
        let mut alias = [0u16; 257];
        // SAFETY: the buffer is as long as said.
        check(unsafe {
            ConvertInterfaceLuidToAlias(&self.raw(), alias.as_mut_ptr(), alias.len())
        })?;
        Ok(from_wide(&alias))
    }

    pub(crate) fn index(self) -> io::Result<u32> {
        let mut index = 0;
        // SAFETY: a place for the result.
        check(unsafe { ConvertInterfaceLuidToIndex(&self.raw(), &mut index) })?;
        Ok(index)
    }

    fn guid(self) -> io::Result<GUID> {
        let mut guid: GUID = unsafe { std::mem::zeroed() };
        // SAFETY: a place for the result.
        check(unsafe { ConvertInterfaceLuidToGuid(&self.raw(), &mut guid) })?;
        Ok(guid)
    }

    fn row(self) -> io::Result<MIB_IF_ROW2> {
        let mut row = MIB_IF_ROW2 {
            InterfaceLuid: self.raw(),
            ..Default::default()
        };
        // SAFETY: the row says which interface.
        check(unsafe { GetIfEntry2(&mut row) })?;
        Ok(row)
    }

    fn ip_interface(self, v6: bool) -> io::Result<MIB_IPINTERFACE_ROW> {
        let mut row = MIB_IPINTERFACE_ROW::default();
        // SAFETY: initialized, then the family and interface said.
        unsafe { InitializeIpInterfaceEntry(&mut row) };
        row.Family = family(v6);
        row.InterfaceLuid = self.raw();
        // SAFETY: as above.
        check(unsafe { GetIpInterfaceEntry(&mut row) })?;
        Ok(row)
    }

    /// Replaces its addresses of the family of `addresses`' with them.
    pub(crate) fn set_addresses(self, v6: bool, addresses: &[(IpAddr, u8)]) -> io::Result<()> {
        for row in unicast_addresses(family(v6))? {
            if Luid::of(&row.InterfaceLuid) == self {
                // SAFETY: a row the system gave.
                let _ = unsafe { DeleteUnicastIpAddressEntry(&row) };
            }
        }
        for &(address, len) in addresses {
            let mut row = MIB_UNICASTIPADDRESS_ROW::default();
            // SAFETY: initialized, then filled.
            unsafe { InitializeUnicastIpAddressEntry(&mut row) };
            row.InterfaceLuid = self.raw();
            row.Address = sockaddr(address);
            row.OnLinkPrefixLength = len;
            row.DadState = IpDadStatePreferred;
            // SAFETY: as above.
            match unsafe { CreateUnicastIpAddressEntry(&row) } {
                ERROR_OBJECT_ALREADY_EXISTS => {}
                code => check(code)?,
            }
        }
        Ok(())
    }

    /// sing-tun's parameters for the TUN (tun_windows.go:123-161): no
    /// router discovery or DAD, the MTU, and, when it routes, metric 0.
    pub(crate) fn configure(self, v6: bool, mtu: u32, route: bool) -> io::Result<()> {
        let mut row = self.ip_interface(v6)?;
        if !v6 {
            row.ForwardingEnabled = true;
        }
        row.RouterDiscoveryBehavior = RouterDiscoveryDisabled;
        row.DadTransmits = 0;
        row.ManagedAddressConfigurationSupported = false;
        row.OtherStatefulConfigurationSupported = false;
        row.NlMtu = mtu;
        if route {
            row.UseAutomaticMetric = false;
            row.Metric = 0;
        }
        // IPv4 takes no site prefix length (winipcfg's Set does the same).
        if !v6 {
            row.SitePrefixLength = 0;
        }
        // SAFETY: a row the system gave, changed.
        check(unsafe { SetIpInterfaceEntry(&mut row) })
    }

    /// The DNS servers of one family, and whether its name is registered.
    /// None registers nothing, as `DisableDNSRegistration` does.
    pub(crate) fn set_dns(self, v6: bool, servers: &[IpAddr]) -> io::Result<()> {
        let list: Vec<String> = servers.iter().map(IpAddr::to_string).collect();
        let mut list = wide(&list.join(","));
        let mut flags = DNS_SETTING_NAMESERVER
            | DNS_SETTING_REGISTRATION_ENABLED
            | DNS_SETTING_REGISTER_ADAPTER_NAME;
        if v6 {
            flags |= DNS_SETTING_IPV6;
        }
        let settings = DNS_INTERFACE_SETTINGS {
            Version: DNS_INTERFACE_SETTINGS_VERSION1,
            Flags: u64::from(flags),
            NameServer: list.as_mut_ptr(),
            RegistrationEnabled: 0,
            RegisterAdapterName: 0,
            ..unsafe { std::mem::zeroed() }
        };
        // SAFETY: the settings and the list they point to outlive the call.
        check(unsafe { SetInterfaceDnsSettings(self.guid()?, &settings) })
    }
}

fn unicast_addresses(family: ADDRESS_FAMILY) -> io::Result<Vec<MIB_UNICASTIPADDRESS_ROW>> {
    let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
    // SAFETY: the table is freed below.
    check(unsafe { GetUnicastIpAddressTable(family, &mut table) })?;
    // SAFETY: NumEntries rows follow, as the system wrote them.
    let rows = unsafe {
        std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize).to_vec()
    };
    // SAFETY: the table GetUnicastIpAddressTable allocated, freed once.
    unsafe { FreeMibTable(table as *const _) };
    Ok(rows)
}

fn forward_rows(family: ADDRESS_FAMILY) -> io::Result<Vec<MIB_IPFORWARD_ROW2>> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    // SAFETY: the table is freed below.
    check(unsafe { GetIpForwardTable2(family, &mut table) })?;
    // SAFETY: NumEntries rows follow, as the system wrote them.
    let rows = unsafe {
        std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize).to_vec()
    };
    // SAFETY: the table GetIpForwardTable2 allocated, freed once.
    unsafe { FreeMibTable(table as *const _) };
    Ok(rows)
}

/// A route through an interface.
fn forward_row(luid: Luid, (address, len): (IpAddr, u8), next_hop: IpAddr) -> MIB_IPFORWARD_ROW2 {
    let mut row = MIB_IPFORWARD_ROW2::default();
    // SAFETY: initialized, then filled.
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceLuid = luid.raw();
    row.DestinationPrefix = IP_ADDRESS_PREFIX {
        Prefix: sockaddr(address),
        PrefixLength: len,
    };
    row.NextHop = sockaddr(next_hop);
    row.Metric = 0;
    row.Protocol = MIB_IPPROTO_NETMGMT;
    row
}

/// Adds a route to `prefix` through `luid`, `next_hop` its gateway, with
/// metric 0; one there already is taken as added.
pub(crate) fn add_route(luid: Luid, prefix: (IpAddr, u8), next_hop: IpAddr) -> io::Result<()> {
    // SAFETY: a filled row.
    match unsafe { CreateIpForwardEntry2(&forward_row(luid, prefix, next_hop)) } {
        ERROR_OBJECT_ALREADY_EXISTS => Ok(()),
        code => check(code),
    }
}

/// Removes it; one gone already is taken as removed.
pub(crate) fn delete_route(luid: Luid, prefix: (IpAddr, u8), next_hop: IpAddr) -> io::Result<()> {
    // SAFETY: a filled row.
    match unsafe { DeleteIpForwardEntry2(&forward_row(luid, prefix, next_hop)) } {
        ERROR_NOT_FOUND => Ok(()),
        code => check(code),
    }
}

/// Whether the interface is up and neither loopback nor, when
/// `physical`, virtual (a TUN, wintun's or another VPN's).
fn usable(row: &MIB_IF_ROW2, physical: bool) -> bool {
    row.OperStatus == IfOperStatusUp
        && row.Type != IF_TYPE_SOFTWARE_LOOPBACK
        && !(physical && row.Type == IF_TYPE_PROP_VIRTUAL)
}

/// The interface of the IPv4 default route with the lowest route and
/// interface metric, among those up, connected and not virtual, as
/// sing-tun picks it (monitor_windows.go:60-115).
pub(crate) fn default_interface() -> io::Result<Luid> {
    let mut best: Option<(u64, Luid)> = None;
    for route in forward_rows(AF_INET)? {
        if route.DestinationPrefix.PrefixLength != 0 {
            continue;
        }
        let luid = Luid::of(&route.InterfaceLuid);
        let Ok(row) = luid.row() else {
            continue;
        };
        if !usable(&row, true) {
            continue;
        }
        let Ok(ip) = luid.ip_interface(false) else {
            continue;
        };
        if !ip.Connected {
            continue;
        }
        let metric = u64::from(route.Metric) + u64::from(ip.Metric);
        if best.is_none_or(|(m, _)| metric < m) {
            best = Some((metric, luid));
        }
    }
    best.map(|(_, luid)| luid).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "no IPv4 default route through an interface that is up and connected",
        )
    })
}

/// The networks the interfaces that are up are directly on, loopback
/// aside: address, prefix length, interface name.
pub(crate) fn subnets() -> io::Result<Vec<(IpAddr, u8, String)>> {
    let mut interfaces: HashMap<Luid, Option<String>> = HashMap::new();
    let mut subnets = Vec::new();
    for row in unicast_addresses(AF_UNSPEC)? {
        let luid = Luid::of(&row.InterfaceLuid);
        let name = interfaces.entry(luid).or_insert_with(|| {
            luid.row()
                .ok()
                .filter(|row| usable(row, false))
                .and_then(|_| luid.alias().ok())
        });
        if let (Some(name), Some(address)) = (name.clone(), address(&row.Address)) {
            subnets.push((address, row.OnLinkPrefixLength, name));
        }
    }
    Ok(subnets)
}

/// Whether the system has an interface of this name (alias).
pub(crate) fn interface_exists(alias: &str) -> bool {
    Luid::by_alias(alias).is_ok()
}

/// Empties the system's DNS cache, as sing-tun does after routing: its
/// answers were for the network before. `DnsFlushResolverCache` is not
/// in the SDK's headers; it is looked up.
pub(crate) fn flush_dns_cache() {
    use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
    let dnsapi = wide("dnsapi.dll");
    // SAFETY: a NUL-terminated name; the function, if there, takes nothing.
    unsafe {
        let module = LoadLibraryW(dnsapi.as_ptr());
        if module.is_null() {
            return;
        }
        if let Some(flush) = GetProcAddress(module, c"DnsFlushResolverCache".as_ptr().cast()) {
            let flush: unsafe extern "system" fn() -> i32 = std::mem::transmute(flush);
            flush();
        }
    }
}

/// Notices of changes to routes and interfaces, while it lives.
pub(crate) struct ChangeNotices {
    handles: Vec<HANDLE>,
    /// Given to the callbacks; freed once they are cancelled.
    notify: *const tokio::sync::Notify,
}

// SAFETY: the handles are only cancelled, once, and the Notify is Sync.
unsafe impl Send for ChangeNotices {}
unsafe impl Sync for ChangeNotices {}

unsafe extern "system" fn on_route(
    context: *const core::ffi::c_void,
    _row: *const MIB_IPFORWARD_ROW2,
    _kind: MIB_NOTIFICATION_TYPE,
) {
    // SAFETY: the Notify ChangeNotices keeps until the callbacks stop.
    (*(context as *const tokio::sync::Notify)).notify_one();
}

unsafe extern "system" fn on_interface(
    context: *const core::ffi::c_void,
    _row: *const MIB_IPINTERFACE_ROW,
    _kind: MIB_NOTIFICATION_TYPE,
) {
    // SAFETY: as in on_route.
    (*(context as *const tokio::sync::Notify)).notify_one();
}

unsafe extern "system" fn on_address(
    context: *const core::ffi::c_void,
    _row: *const MIB_UNICASTIPADDRESS_ROW,
    _kind: MIB_NOTIFICATION_TYPE,
) {
    // SAFETY: as in on_route.
    (*(context as *const tokio::sync::Notify)).notify_one();
}

impl ChangeNotices {
    /// Notices on `notify` of any change to a route or an interface, of
    /// either family, as sing-tun takes them (monitor_windows.go:29-46),
    /// and to an address: an adapter that is not the default one gets or
    /// loses one without a route or interface notice, and the interfaces
    /// listed for a connection's choice of network change with it.
    pub(crate) fn start(notify: Arc<tokio::sync::Notify>) -> io::Result<ChangeNotices> {
        let mut this = ChangeNotices {
            handles: Vec::new(),
            notify: Arc::into_raw(notify),
        };
        let context = this.notify as *const core::ffi::c_void;
        let mut handle: HANDLE = std::ptr::null_mut();
        // SAFETY: the callback and its context live until cancelled.
        check(unsafe {
            NotifyRouteChange2(AF_UNSPEC, Some(on_route), context, false, &mut handle)
        })?;
        this.handles.push(handle);
        let mut handle: HANDLE = std::ptr::null_mut();
        // SAFETY: as above.
        check(unsafe {
            NotifyIpInterfaceChange(AF_UNSPEC, Some(on_interface), context, false, &mut handle)
        })?;
        this.handles.push(handle);
        let mut handle: HANDLE = std::ptr::null_mut();
        // SAFETY: as above.
        check(unsafe {
            NotifyUnicastIpAddressChange(AF_UNSPEC, Some(on_address), context, false, &mut handle)
        })?;
        this.handles.push(handle);
        Ok(this)
    }
}

impl Drop for ChangeNotices {
    fn drop(&mut self) {
        for &handle in &self.handles {
            // SAFETY: a handle a Notify call gave; cancelling waits for
            // callbacks running to return.
            unsafe { CancelMibChangeNotify2(handle) };
        }
        // SAFETY: the Arc into_raw made, released once no callback runs.
        unsafe { drop(Arc::from_raw(self.notify)) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_go_to_sockaddrs_and_back() {
        for address in ["172.18.0.1", "fdfe:dcba:9876::1"] {
            let address: IpAddr = address.parse().unwrap();
            assert_eq!(super::address(&sockaddr(address)), Some(address));
        }
    }

    /// Only reads the system: its default interface, if it has one, is
    /// up and named, and every network is a real prefix.
    #[test]
    fn the_host_s_interfaces_are_read() {
        if let Ok(luid) = default_interface() {
            let alias = luid.alias().unwrap();
            assert!(!alias.is_empty());
            assert_eq!(Luid::by_alias(&alias).unwrap(), luid);
            assert!(luid.index().unwrap() > 0);
            assert!(interface_exists(&alias));
        }
        assert!(!interface_exists("sail-no-such-interface"));
        for (address, len, name) in subnets().unwrap() {
            assert!(!name.is_empty());
            assert!(u32::from(len) <= if address.is_ipv4() { 32 } else { 128 });
        }
    }
}
