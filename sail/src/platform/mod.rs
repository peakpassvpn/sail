//! Operating-system integration: routes, interfaces and forwarding that the
//! host needs set up around the core.

#[cfg(target_os = "macos")]
pub mod cmd_macos;
#[cfg(target_os = "macos")]
pub use cmd_macos as cmd;

#[cfg(target_os = "linux")]
pub mod cmd_linux;
#[cfg(target_os = "linux")]
pub use cmd_linux as cmd;

#[cfg(all(feature = "inbound-tun", any(target_os = "macos", target_os = "linux")))]
pub(crate) mod tun_setup;

#[cfg(target_os = "windows")]
pub(crate) mod windows;

use anyhow::{anyhow, Result};

use crate::net::DialOptions;

/// Dial options that send through the system's default interface, for
/// `route.auto_detect_interface`: its name where sockets can be bound to an
/// interface, its addresses otherwise.
pub fn default_interface() -> Result<DialOptions> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        let name = cmd::get_default_interface()
            .map_err(|e| anyhow!("route.auto_detect_interface: {}", e))?;
        Ok(DialOptions {
            bind_interface: Some(name),
            ..Default::default()
        })
    }
    #[cfg(target_os = "windows")]
    {
        let mut dial = DialOptions::default();
        for ip in windows::get_default_interface_ips()
            .split(',')
            .filter(|s| !s.is_empty())
        {
            match ip.parse::<std::net::IpAddr>() {
                Ok(std::net::IpAddr::V4(v4)) => dial.inet4_bind_address = Some(v4),
                Ok(std::net::IpAddr::V6(v6)) => dial.inet6_bind_address = Some(v6),
                Err(_) => {}
            }
        }
        if dial.inet4_bind_address.is_none() && dial.inet6_bind_address.is_none() {
            return Err(anyhow!(
                "route.auto_detect_interface: no default interface found"
            ));
        }
        Ok(dial)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    Err(anyhow!(
        "route.auto_detect_interface: not supported on this platform"
    ))
}
