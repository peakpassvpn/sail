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

/// Runs a command that changes the system. Failing to run it at all is an
/// error; a failure it reports is logged, as the change may well be there
/// already -- a route left by an earlier run, say.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn run(cmd: &mut std::process::Command) -> Result<()> {
    let status = cmd
        .status()
        .map_err(|e| anyhow!("cannot run {:?}: {}", cmd.get_program(), e))?;
    if !status.success() {
        tracing::warn!("{:?} failed: {}", cmd, status);
    }
    Ok(())
}

/// Runs a command that reads the system, and returns what it printed.
#[cfg(any(target_os = "macos", target_os = "linux"))]
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

/// A sysctl flag as `sysctl -n` prints it: whether it is not 0.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn sysctl_flag(name: &str) -> Result<bool> {
    let out = output(std::process::Command::new("sysctl").arg("-n").arg(name))?;
    let value = out
        .trim()
        .parse::<i64>()
        .map_err(|_| anyhow!("sysctl {}: unexpected value \"{}\"", name, out.trim()))?;
    Ok(value != 0)
}

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
