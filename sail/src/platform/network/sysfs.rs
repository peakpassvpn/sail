//! What `/sys/class/net/<interface>` tells of an interface: its kind and
//! MTU. The root is a parameter, so a made-up tree tests it anywhere.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::path::{Path, PathBuf};

use crate::net::network::NetworkType;

fn dir(root: &Path, name: &str) -> PathBuf {
    root.join("sys/class/net").join(name)
}

/// The kind of interface `name`: Wi-Fi when it has a wireless extension or
/// phy (or says `DEVTYPE=wlan`), cellular when it says `DEVTYPE=wwan` or
/// is named as modems' are (`wwan*`, `rmnet*`), Ethernet when it is a
/// device at all, and other when it is virtual (a bridge, a tunnel, a
/// VPN's).
pub(super) fn kind(root: &Path, name: &str) -> NetworkType {
    let dir = dir(root, name);
    let uevent = std::fs::read_to_string(dir.join("uevent")).unwrap_or_default();
    let devtype = uevent
        .lines()
        .find_map(|l| l.trim().strip_prefix("DEVTYPE="));
    if dir.join("wireless").exists() || dir.join("phy80211").exists() || devtype == Some("wlan") {
        NetworkType::Wifi
    } else if devtype == Some("wwan") || name.starts_with("wwan") || name.starts_with("rmnet") {
        NetworkType::Cellular
    } else if dir.join("device").exists() {
        NetworkType::Ethernet
    } else {
        NetworkType::Other
    }
}

/// The MTU of interface `name`.
pub(super) fn mtu(root: &Path, name: &str) -> Option<u32> {
    std::fs::read_to_string(dir(root, name).join("mtu"))
        .ok()?
        .trim()
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tree as the kernel lays it out: `device` a link to the bus's
    /// device, `wireless` and `phy80211` of Wi-Fi drivers, `uevent` a few
    /// lines.
    fn tree(interfaces: &[(&str, &[&str], &str)]) -> PathBuf {
        let root = std::env::temp_dir().join(format!("sail-sysfs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for (name, entries, uevent) in interfaces {
            let dir = dir(&root, name);
            std::fs::create_dir_all(&dir).unwrap();
            for entry in *entries {
                std::fs::create_dir_all(dir.join(entry)).unwrap();
            }
            std::fs::write(dir.join("uevent"), uevent).unwrap();
            std::fs::write(dir.join("mtu"), "1500\n").unwrap();
        }
        root
    }

    #[test]
    fn interfaces_are_told_apart_by_what_sysfs_has() {
        let root = tree(&[
            (
                "wlp2s0",
                &["device", "wireless", "phy80211"],
                "DEVTYPE=wlan\nINTERFACE=wlp2s0\nIFINDEX=3\n",
            ),
            ("wlan1", &["device", "phy80211"], "INTERFACE=wlan1\n"),
            ("wwan0", &["device"], "DEVTYPE=wwan\nINTERFACE=wwan0\n"),
            ("rmnet_data0", &[], "INTERFACE=rmnet_data0\n"),
            ("enp3s0", &["device"], "INTERFACE=enp3s0\nIFINDEX=2\n"),
            ("br0", &["bridge"], "DEVTYPE=bridge\nINTERFACE=br0\n"),
            ("wg0", &[], "DEVTYPE=wireguard\nINTERFACE=wg0\n"),
        ]);
        let kind = |name| kind(&root, name);
        assert_eq!(kind("wlp2s0"), NetworkType::Wifi);
        assert_eq!(kind("wlan1"), NetworkType::Wifi);
        assert_eq!(kind("wwan0"), NetworkType::Cellular);
        assert_eq!(kind("rmnet_data0"), NetworkType::Cellular);
        assert_eq!(kind("enp3s0"), NetworkType::Ethernet);
        assert_eq!(kind("br0"), NetworkType::Other);
        assert_eq!(kind("wg0"), NetworkType::Other);
        // One the tree has not: nothing says what it is.
        assert_eq!(kind("eth9"), NetworkType::Other);
        assert_eq!(mtu(&root, "enp3s0"), Some(1500));
        assert_eq!(mtu(&root, "eth9"), None);
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// The real tree reads the same: the loopback is no device.
    #[cfg(target_os = "linux")]
    #[test]
    fn this_host_s_interfaces_are_read() {
        let root = Path::new("/");
        assert_eq!(kind(root, "lo"), NetworkType::Other);
        assert!(mtu(root, "lo").is_some());
    }
}
