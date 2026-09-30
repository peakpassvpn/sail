//! Windows: route management through IP Helper and the firewall (WFP),
//! and the TUN through wintun, as sing-tun does it; never netsh or
//! route.exe.

pub(crate) mod ip_helper;
#[cfg(feature = "inbound-tun")]
pub(crate) mod wfp;
#[cfg(feature = "inbound-tun")]
pub(crate) mod wintun;

/// The name of the interface the IPv4 default route with the lowest
/// metric goes through, among those up, connected and not virtual.
pub fn detect_default_interface() -> std::io::Result<String> {
    ip_helper::default_interface()?.alias()
}
