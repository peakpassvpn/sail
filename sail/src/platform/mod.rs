//! Operating-system integration: routes, interfaces and forwarding that the
//! host needs set up around the core.

// Linux only; its encoder builds everywhere under test so it is tested on
// any host.
#[cfg(any(target_os = "linux", test))]
pub mod nft;

// auto_redirect's routing, Linux only; its commands are tested on macOS too.
#[cfg(all(
    feature = "inbound-tun",
    any(target_os = "linux", all(test, target_os = "macos"))
))]
pub(crate) mod policy_route;

#[cfg(all(
    target_os = "linux",
    any(feature = "inbound-redirect", feature = "inbound-tun")
))]
pub(crate) mod original_dst;

#[cfg(all(
    feature = "inbound-tun",
    any(target_os = "linux", target_os = "macos", test)
))]
pub(crate) mod ip_ranges;

// auto_route's rules without auto_redirect; built everywhere under test.
#[cfg(all(
    feature = "inbound-tun",
    any(target_os = "linux", target_os = "macos", test)
))]
pub(crate) mod auto_route;

#[cfg(target_os = "linux")]
pub(crate) mod addr_monitor;

#[cfg(all(target_os = "linux", feature = "inbound-tun"))]
pub(crate) mod openwrt;
#[cfg(target_os = "macos")]
pub(crate) mod route_socket;
#[cfg(all(target_os = "macos", feature = "inbound-tun"))]
pub(crate) mod utun;

// Linux only, like nft, whose netlink framing it uses.
#[cfg(any(target_os = "linux", test))]
pub mod nfqueue;

// Routes, rules, links and addresses over netlink, Linux only; its encoder
// builds everywhere under test, like nft's, whose framing it uses.
#[cfg(any(target_os = "linux", test))]
pub mod rtnetlink;

// The nftables ruleset of the TUN's auto_redirect; built everywhere under
// test, like nft.
#[cfg(any(target_os = "linux", test))]
pub mod auto_redirect;

#[cfg(target_os = "windows")]
pub(crate) mod windows;

// The network the host is on, as the system tells it.
pub mod network;

#[cfg(any(
    all(target_os = "linux", feature = "inbound-tun"),
    not(any(target_os = "linux", target_os = "macos"))
))]
use anyhow::{anyhow, Result};

/// Runs a command that reads the system, and returns what it printed.
#[cfg(all(target_os = "linux", feature = "inbound-tun"))]
fn output(cmd: &mut std::process::Command) -> Result<String> {
    let out = cmd
        .output()
        .map_err(|e| anyhow!("cannot run {:?}: {}", cmd.get_program(), e))?;
    if !out.status.success() {
        return Err(anyhow!(
            "{:?} failed: {}: {}",
            cmd,
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// The name of the interface the system's default route goes through,
/// for `auto_detect_interface`.
/// On macOS, the IPv4 default route's in the routing table: asking where
/// 1.1.1.1 goes would answer the TUN once it routes.
#[cfg(target_os = "macos")]
pub fn detect_default_interface() -> std::io::Result<String> {
    route_socket::default_interface()
}

/// On Linux, the main table's default route with the lowest metric, IPv4's
/// first: asking where 1.1.1.1 goes would answer the TUN once it routes.
#[cfg(target_os = "linux")]
pub fn detect_default_interface() -> std::io::Result<String> {
    let netlink = rtnetlink::Netlink::open()?;
    for family in [rtnetlink::Family::V4, rtnetlink::Family::V6] {
        if let Some(route) = netlink.default_routes(family)?.first() {
            return netlink.link_name(route.oif);
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "no default route in the main table",
    ))
}

/// The addresses of the system's default interface, IPv4's and IPv6's,
/// which send through it: for `route.auto_detect_interface`, where it is
/// not followed as it changes (`net::interface`).
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn default_interface() -> Result<(Option<std::net::Ipv4Addr>, Option<std::net::Ipv6Addr>)> {
    #[cfg(target_os = "windows")]
    {
        let (mut inet4, mut inet6) = (None, None);
        for ip in windows::get_default_interface_ips()
            .split(',')
            .filter(|s| !s.is_empty())
        {
            match ip.parse::<std::net::IpAddr>() {
                Ok(std::net::IpAddr::V4(v4)) => inet4 = Some(v4),
                Ok(std::net::IpAddr::V6(v6)) => inet6 = Some(v6),
                Err(_) => {}
            }
        }
        if inet4.is_none() && inet6.is_none() {
            return Err(anyhow!(
                "route.auto_detect_interface: no default interface found"
            ));
        }
        Ok((inet4, inet6))
    }
    #[cfg(not(target_os = "windows"))]
    Err(anyhow!(
        "route.auto_detect_interface: not supported on this platform"
    ))
}
