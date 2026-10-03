//! macOS: the DNS servers of one interface, from the dynamic store: those
//! of the services on it, set by hand (`Setup:/Network/Service/<id>/DNS`)
//! or else told by the network (`State:/Network/Service/<id>/DNS`), which
//! `scutil --dns` shows as that interface's scoped resolver. Not the
//! global one (`State:/Network/Global/DNS`, /etc/resolv.conf): that is the
//! primary service's, which another VPN, or a host pointing the system at
//! sail's own TUN, may be. A split-DNS resolver (one with
//! `SupplementalMatchDomains`) is left out: its servers answer only its
//! domains.
//!
//! Public CoreFoundation and SystemConfiguration calls, declared here
//! rather than through a crate.

use std::ffi::{c_char, c_void, CStr};
use std::net::IpAddr;

type CFTypeRef = *const c_void;
type CFIndex = isize;
type CFTypeID = usize;

const UTF8: u32 = 0x0800_0100; // kCFStringEncodingUTF8

#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    fn CFStringCreateWithBytes(
        alloc: CFTypeRef,
        bytes: *const u8,
        len: CFIndex,
        encoding: u32,
        external: u8,
    ) -> CFTypeRef;
    fn CFStringGetCString(s: CFTypeRef, buf: *mut c_char, size: CFIndex, encoding: u32) -> u8;
    fn CFStringGetLength(s: CFTypeRef) -> CFIndex;
    fn CFStringGetMaximumSizeForEncoding(len: CFIndex, encoding: u32) -> CFIndex;
    fn CFStringGetTypeID() -> CFTypeID;
    fn CFArrayGetTypeID() -> CFTypeID;
    fn CFDictionaryGetTypeID() -> CFTypeID;
    fn CFGetTypeID(cf: CFTypeRef) -> CFTypeID;
    fn CFArrayGetCount(a: CFTypeRef) -> CFIndex;
    fn CFArrayGetValueAtIndex(a: CFTypeRef, i: CFIndex) -> CFTypeRef;
    fn CFDictionaryGetValue(d: CFTypeRef, key: CFTypeRef) -> CFTypeRef;
    fn CFRelease(cf: CFTypeRef);
}

#[link(name = "SystemConfiguration", kind = "framework")]
extern "C" {
    fn SCDynamicStoreCreate(
        alloc: CFTypeRef,
        name: CFTypeRef,
        callout: *const c_void,
        context: *mut c_void,
    ) -> CFTypeRef;
    fn SCDynamicStoreCopyKeyList(store: CFTypeRef, pattern: CFTypeRef) -> CFTypeRef;
    fn SCDynamicStoreCopyValue(store: CFTypeRef, key: CFTypeRef) -> CFTypeRef;
}

/// A CoreFoundation object this owns, released when dropped; null when a
/// call gave none.
struct Owned(CFTypeRef);

impl Drop for Owned {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: an object a Create or Copy call returned, released once.
            unsafe { CFRelease(self.0) }
        }
    }
}

fn string(s: &str) -> Owned {
    // SAFETY: the bytes are valid UTF-8 of the length given.
    Owned(unsafe {
        CFStringCreateWithBytes(std::ptr::null(), s.as_ptr(), s.len() as CFIndex, UTF8, 0)
    })
}

/// `cf` as a Rust string, when it is a string.
///
/// # Safety
/// `cf` is null or a live CoreFoundation object.
unsafe fn to_string(cf: CFTypeRef) -> Option<String> {
    if cf.is_null() || CFGetTypeID(cf) != CFStringGetTypeID() {
        return None;
    }
    let size = CFStringGetMaximumSizeForEncoding(CFStringGetLength(cf), UTF8) + 1;
    let mut buf = vec![0 as c_char; size as usize];
    if CFStringGetCString(cf, buf.as_mut_ptr(), size, UTF8) == 0 {
        return None;
    }
    Some(CStr::from_ptr(buf.as_ptr()).to_string_lossy().into_owned())
}

/// The value at `key` of `dict`, when `dict` is a dictionary; borrowed.
///
/// # Safety
/// `dict` is null or a live CoreFoundation object.
unsafe fn get(dict: CFTypeRef, key: &str) -> CFTypeRef {
    if dict.is_null() || CFGetTypeID(dict) != CFDictionaryGetTypeID() {
        return std::ptr::null();
    }
    let key = string(key);
    CFDictionaryGetValue(dict, key.0)
}

/// The strings of `array`, when it is an array.
///
/// # Safety
/// `array` is null or a live CoreFoundation object.
unsafe fn strings(array: CFTypeRef) -> Vec<String> {
    if array.is_null() || CFGetTypeID(array) != CFArrayGetTypeID() {
        return Vec::new();
    }
    (0..CFArrayGetCount(array))
        .filter_map(|i| to_string(CFArrayGetValueAtIndex(array, i)))
        .collect()
}

/// What the dynamic store has of one network service.
#[derive(Clone, Debug, Default)]
pub(super) struct Service {
    /// The interface it is on.
    pub interface: Option<String>,
    /// Its DNS servers as set by hand (`Setup:`), which win, as they do
    /// for macOS's own resolver.
    pub manual: Vec<String>,
    /// As the network told them (`State:`: DHCP, router advertisements).
    pub learned: Vec<String>,
    /// Its resolver answers only some domains (split DNS, a VPN's
    /// `SupplementalMatchDomains`): not a general one, and left out.
    pub supplemental: bool,
}

/// The servers of the services on `interface`: those set by hand where a
/// service has any, else those the network told; none of a split-DNS
/// resolver.
pub(super) fn select(services: &[Service], interface: &str) -> Vec<super::Listed> {
    let mut servers = Vec::new();
    for service in services {
        if service.supplemental || service.interface.as_deref() != Some(interface) {
            continue;
        }
        let addresses = if service.manual.is_empty() {
            &service.learned
        } else {
            &service.manual
        };
        // A link-local server carries its scope: fe80::1%en0.
        for listed in addresses.iter().filter_map(|a| super::Listed::parse(a)) {
            if !servers.contains(&listed) {
                servers.push(listed);
            }
        }
    }
    servers
}

/// The DNS servers of the services on `interface`, as the dynamic store
/// has them; none when no service there has any.
pub(super) fn servers_of(interface: &str) -> anyhow::Result<Vec<super::Listed>> {
    Ok(select(&services()?, interface))
}

/// The network services the dynamic store knows, with DNS servers set by
/// hand or told.
fn services() -> anyhow::Result<Vec<Service>> {
    // SAFETY: every object is checked for its type before it is read, and
    // those created or copied are owned and released once.
    let services = unsafe {
        let store = Owned(SCDynamicStoreCreate(
            std::ptr::null(),
            string("sail").0,
            std::ptr::null(),
            std::ptr::null_mut(),
        ));
        if store.0.is_null() {
            return Err(anyhow::anyhow!("the dynamic store cannot be opened"));
        }
        let copy = |key: &str| Owned(SCDynamicStoreCopyValue(store.0, string(key).0));
        let list = |pattern: &str| {
            let keys = Owned(SCDynamicStoreCopyKeyList(store.0, string(pattern).0));
            strings(keys.0)
        };
        // Every service with DNS servers, told or set by hand.
        let mut ids: Vec<String> = Vec::new();
        for prefix in ["State", "Setup"] {
            for key in list(&format!("{prefix}:/Network/Service/[^/]+/DNS")) {
                let id = key
                    .trim_start_matches(&format!("{prefix}:/Network/Service/"))
                    .trim_end_matches("/DNS")
                    .to_owned();
                if !ids.contains(&id) {
                    ids.push(id);
                }
            }
        }
        ids.iter()
            .map(|id| {
                let state = format!("State:/Network/Service/{id}");
                let dns = copy(&format!("{state}/DNS"));
                let setup = copy(&format!("Setup:/Network/Service/{id}/DNS"));
                // A scoped resolver names its interface; otherwise the
                // service's addresses do, or its configuration.
                let interface = to_string(get(dns.0, "InterfaceName"))
                    .or_else(|| {
                        ["IPv4", "IPv6"].iter().find_map(|family| {
                            to_string(get(copy(&format!("{state}/{family}")).0, "InterfaceName"))
                        })
                    })
                    .or_else(|| {
                        let setup = copy(&format!("Setup:/Network/Service/{id}/Interface"));
                        to_string(get(setup.0, "DeviceName"))
                    });
                Service {
                    interface,
                    manual: strings(get(setup.0, "ServerAddresses")),
                    learned: strings(get(dns.0, "ServerAddresses")),
                    supplemental: !strings(get(dns.0, "SupplementalMatchDomains")).is_empty(),
                }
            })
            .collect::<Vec<_>>()
    };
    Ok(services)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What `scutil` shows for each service's DNS on this Mac is what
    /// `servers_of` reads for that service's interface.
    #[test]
    fn the_servers_of_an_interface_are_scutil_s() {
        let scutil = |commands: &str| {
            use std::io::Write;
            let mut child = std::process::Command::new("scutil")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(commands.as_bytes())
                .unwrap();
            String::from_utf8(child.wait_with_output().unwrap().stdout).unwrap()
        };
        let listed = scutil("list State:/Network/Service/[^/]+/DNS\nquit\n");
        let mut checked = 0;
        for key in listed.lines().filter_map(|l| l.split(" = ").nth(1)) {
            let service = key.trim_end_matches("/DNS");
            let shown = scutil(&format!("show {key}\nshow {service}/IPv4\nquit\n"));
            let Some(interface) = shown
                .lines()
                .find_map(|l| l.trim().strip_prefix("InterfaceName : "))
            else {
                continue;
            };
            let read = servers_of(interface).unwrap();
            // Every address the service lists, before its IPv4 part.
            let dns_part = shown.split("<dictionary>").nth(1).unwrap_or("");
            for line in dns_part.lines() {
                let Some((_, value)) = line.trim().split_once(" : ") else {
                    continue;
                };
                if let Ok(ip) = value.split('%').next().unwrap().parse::<IpAddr>() {
                    if line.trim().starts_with(char::is_numeric) {
                        assert!(
                            read.iter().any(|l| l.ip == ip),
                            "{interface}: {ip} not in {read:?}"
                        );
                    }
                }
            }
            checked += 1;
        }
        // A Mac with no network has nothing to compare.
        eprintln!("services compared: {checked}");
        assert!(servers_of("no-such-interface0").unwrap().is_empty());
    }

    fn service(interface: &str, manual: &[&str], learned: &[&str]) -> Service {
        Service {
            interface: Some(interface.into()),
            manual: manual.iter().map(|s| s.to_string()).collect(),
            learned: learned.iter().map(|s| s.to_string()).collect(),
            supplemental: false,
        }
    }

    fn ips(listed: &[super::super::Listed]) -> Vec<String> {
        listed.iter().map(|l| l.ip.to_string()).collect()
    }

    /// Another VPN's tunnel is the primary service: the dialer's interface
    /// still has its own servers, not the tunnel's.
    #[test]
    fn the_dialer_s_interface_has_its_own_servers_whatever_is_primary() {
        let services = [
            service("utun4", &[], &["198.51.100.2"]),
            service("en0", &[], &["192.0.2.1", "2001:db8::1"]),
            service("en1", &[], &["192.0.2.9"]),
        ];
        assert_eq!(ips(&select(&services, "en0")), ["192.0.2.1", "2001:db8::1"]);
        assert!(select(&services, "en7").is_empty());
    }

    /// Servers set by hand win over those the network told, and are taken
    /// where the network told none (a static address).
    #[test]
    fn servers_set_by_hand_win() {
        let dhcp_and_manual = [service("en0", &["192.0.2.53"], &["192.0.2.1"])];
        assert_eq!(ips(&select(&dhcp_and_manual, "en0")), ["192.0.2.53"]);
        let static_only = [service("en0", &["192.0.2.53", "192.0.2.54"], &[])];
        assert_eq!(
            ips(&select(&static_only, "en0")),
            ["192.0.2.53", "192.0.2.54"]
        );
    }

    /// A split-DNS resolver on the same interface is not a general one;
    /// a link-local server keeps its zone; one listed twice counts once.
    #[test]
    fn split_dns_is_left_out_and_link_local_keeps_its_zone() {
        let mut split = service("en0", &[], &["192.0.2.99"]);
        split.supplemental = true;
        let services = [
            split,
            service("en0", &[], &["fe80::1%en0", "192.0.2.1", "192.0.2.1"]),
        ];
        let selected = select(&services, "en0");
        assert_eq!(ips(&selected), ["fe80::1", "192.0.2.1"]);
        assert_eq!(
            selected[0].zone,
            Some(super::super::Zone::Name("en0".into()))
        );
    }
}
