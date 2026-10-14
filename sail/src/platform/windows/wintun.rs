//! The TUN on Windows: a wintun adapter, set up through IP Helper as
//! sing-tun sets it up (tun_windows.go:39-163), never through netsh, and
//! when WireGuard for Windows sets its own up: on the TCP/IP interface the
//! system has made for it, and again on one it makes anew.

use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use wintun_bindings::{Adapter, Session, Wintun, MAX_RING_CAPACITY};

use super::ip_helper::{InterfaceAdds, Luid};

/// What the device is made of: its session, which holds the adapter, and
/// the notices of the interfaces the system adds for it.
pub(crate) struct Device {
    pub session: Arc<Session>,
    _adds: InterfaceAdds,
}

/// How long the system may take to make the adapter's TCP/IP interface,
/// as WireGuard for Windows waits (tunnel/interfacewatcher.go: a minute).
const INTERFACE_WAIT: Duration = Duration::from_secs(60);

/// The adapter's GUID, the same for the same name: a run that died leaves
/// an adapter the next one takes up. From "wintun" and the name, as
/// sing-tun's, but hashed otherwise (sing-tun takes md5), so an adapter
/// sing-box left under the same name is not taken up.
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
///
/// The session first, which brings the adapter up, as sing-tun does; then
/// each family once the system has made its TCP/IP interface, as WireGuard
/// for Windows does: settings made on an interface the system then makes
/// anew are gone, and the system gives it a link-local address of its own
/// (169.254.0.0/16) in place of the TUN's. One it makes anew while the
/// adapter lives gets its addresses and parameters again.
pub(crate) fn open(
    name: &str,
    addresses: &[(IpAddr, u8)],
    mtu: u16,
    auto_route: bool,
) -> Result<Device> {
    let wintun = load()?;
    // Before the adapter: none of its interfaces is missed.
    let (adds, added) =
        InterfaceAdds::start().map_err(|e| anyhow!("{}: interface notices: {}", name, e))?;
    let adapter = match Adapter::create(&wintun, name, "sail", Some(guid(name))) {
        Ok(adapter) => adapter,
        Err(created) => Adapter::open(&wintun, name)
            .map_err(|_| anyhow!("wintun adapter {}: {}", name, created))?,
    };
    // SAFETY: every bit pattern is a u64.
    let luid = Luid(unsafe { adapter.get_luid().Value });
    let session = adapter
        .start_session(MAX_RING_CAPACITY)
        .map_err(|e| anyhow!("wintun adapter {}: session: {}", name, e))?;
    let families: Vec<(bool, Vec<(IpAddr, u8)>)> = [false, true]
        .into_iter()
        .map(|v6| {
            let mine = addresses
                .iter()
                .filter(|(address, _)| address.is_ipv6() == v6)
                .copied()
                .collect::<Vec<_>>();
            (v6, mine)
        })
        .filter(|(_, mine)| !mine.is_empty())
        .collect();
    let deadline = Instant::now() + INTERFACE_WAIT;
    // The families settled, and the adapter's interfaces told of as added
    // after: made anew while another family was waited for.
    let mut settled: Vec<bool> = Vec::new();
    let mut again: Vec<bool> = Vec::new();
    for (v6, mine) in &families {
        let family = if *v6 { "IPv6" } else { "IPv4" };
        // Its interface, there already or told of as it is added.
        while !luid.has_ip_interface(*v6) {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(anyhow!(
                    "{}: the {} interface did not appear within {}s",
                    name,
                    family,
                    INTERFACE_WAIT.as_secs()
                ));
            }
            match added.recv_timeout(left.min(Duration::from_millis(500))) {
                Ok((of, of_v6)) if of == luid && settled.contains(&of_v6) => again.push(of_v6),
                Ok(_) | Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(anyhow!("{}: interface notices ended", name))
                }
            }
        }
        settle(luid, *v6, mine, mtu, auto_route)
            .map_err(|e| anyhow!("{}: {} {}", name, family, e))?;
        luid.set_dns(*v6, &[])
            .map_err(|e| anyhow!("{}: {} DNS: {}", name, family, e))?;
        settled.push(*v6);
    }
    for v6 in again {
        if let Some((_, mine)) = families.iter().find(|(f, _)| *f == v6) {
            settle(luid, v6, mine, mtu, auto_route).map_err(|e| anyhow!("{}: {}", name, e))?;
        }
    }
    // An interface made anew: its addresses and parameters again. DNS is
    // the adapter's, kept by the system; routes are auto_route's, whose
    // own check tells of those gone.
    let name = name.to_owned();
    std::thread::Builder::new()
        .name(format!("{} interfaces", name))
        .spawn(move || {
            for (of, v6) in added {
                if of != luid {
                    continue;
                }
                let Some((_, mine)) = families.iter().find(|(f, _)| *f == v6) else {
                    continue;
                };
                // A notice of the interface it was set up on, told late,
                // finds the addresses there: nothing to do. One made anew
                // has lost them.
                let kept = luid.addresses().unwrap_or_default();
                if mine.iter().all(|(address, _)| kept.contains(address)) {
                    continue;
                }
                match settle(luid, v6, mine, mtu, auto_route) {
                    Ok(()) => tracing::info!(
                        "{}: the system made its {} interface anew, without the TUN's addresses; set again",
                        name,
                        if v6 { "IPv6" } else { "IPv4" }
                    ),
                    Err(e) => tracing::warn!("{}: setting a new interface: {}", name, e),
                }
            }
        })
        .map_err(|e| anyhow!("interface notices thread: {}", e))?;
    Ok(Device {
        session,
        _adds: adds,
    })
}

/// A family's addresses and parameters on the adapter's interface.
fn settle(luid: Luid, v6: bool, mine: &[(IpAddr, u8)], mtu: u16, auto_route: bool) -> Result<()> {
    luid.set_addresses(v6, mine)
        .map_err(|e| anyhow!("address: {}", e))?;
    luid.configure(v6, u32::from(mtu), auto_route)
        .map_err(|e| anyhow!("parameters: {}", e))
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
