//! The TUN on Windows: a wintun adapter, set up through IP Helper as
//! sing-tun sets it up (tun_windows.go:39-163), never through netsh.

use std::io;
use std::net::IpAddr;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use wintun_bindings::{Adapter, Session, Wintun, MAX_RING_CAPACITY};

use super::ip_helper::Luid;

/// What the device is made of: its session, which holds the adapter.
pub(crate) struct Device {
    pub session: Arc<Session>,
}

/// The adapter's GUID, the same for the same name, as sing-tun makes it
/// (from "wintun" and the name): a run that died leaves an adapter the
/// next one takes up.
fn guid(name: &str) -> u128 {
    // FNV-1a, twice over, for 128 bits.
    let fnv = |seed: u64| {
        "wintun".bytes().chain(name.bytes()).fold(seed, |h, b| {
            (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3)
        })
    };
    (u128::from(fnv(0xcbf2_9ce4_8422_2325)) << 64) | u128::from(fnv(0x6c62_272e_07bb_0142))
}

/// wintun.dll beside the executable, else wherever Windows finds it.
fn load() -> Result<Wintun> {
    let beside = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join("wintun.dll")))
        .filter(|dll| dll.exists());
    // SAFETY: wintun.dll, as its bindings expect it.
    let loaded = match beside {
        Some(dll) => unsafe { wintun_bindings::load_from_path(dll) },
        None => unsafe { wintun_bindings::load() },
    };
    loaded.map_err(|e| anyhow!("wintun.dll: {} (it goes beside sail.exe)", e))
}

/// Opens the adapter `name`, left by a run that died or made anew, with
/// the addresses of each family, and its parameters: no router discovery
/// or DAD, the MTU, and metric 0 when it routes. No DNS is registered for
/// it, and none is set until routing sets it.
pub(crate) fn open(
    name: &str,
    addresses: &[(IpAddr, u8)],
    mtu: u16,
    auto_route: bool,
) -> Result<Device> {
    let wintun = load()?;
    let adapter = match Adapter::create(&wintun, name, "sail", Some(guid(name))) {
        Ok(adapter) => adapter,
        Err(created) => Adapter::open(&wintun, name)
            .map_err(|_| anyhow!("wintun adapter {}: {}", name, created))?,
    };
    // SAFETY: every bit pattern is a u64.
    let luid = Luid(unsafe { adapter.get_luid().Value });
    for v6 in [false, true] {
        let mine: Vec<(IpAddr, u8)> = addresses
            .iter()
            .filter(|(address, _)| address.is_ipv6() == v6)
            .copied()
            .collect();
        if mine.is_empty() {
            continue;
        }
        let family = if v6 { "IPv6" } else { "IPv4" };
        luid.set_addresses(v6, &mine)
            .map_err(|e| anyhow!("{}: {} address: {}", name, family, e))?;
        luid.configure(v6, u32::from(mtu), auto_route)
            .map_err(|e| anyhow!("{}: {} parameters: {}", name, family, e))?;
        luid.set_dns(v6, &[])
            .map_err(|e| anyhow!("{}: {} DNS: {}", name, family, e))?;
    }
    let session = adapter
        .start_session(MAX_RING_CAPACITY)
        .map_err(|e| anyhow!("wintun adapter {}: session: {}", name, e))?;
    Ok(Device { session })
}

/// Whether a send failed only because the ring was full: the packet is
/// dropped, as a full queue drops it.
pub(crate) fn ring_full(e: &io::Error) -> bool {
    // ERROR_BUFFER_OVERFLOW
    e.raw_os_error() == Some(111)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_guid_is_the_name_s() {
        assert_eq!(guid("sail-tun"), guid("sail-tun"));
        assert_ne!(guid("sail-tun"), guid("sail-tun2"));
    }
}
