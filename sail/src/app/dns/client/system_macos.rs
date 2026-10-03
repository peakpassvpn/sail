//! macOS: the DNS servers of one interface, from the dynamic store
//! (`State:/Network/Service/<id>/DNS`), which `scutil --dns` shows as that
//! interface's scoped resolver. Not the global one (`State:/Network/Global/DNS`,
//! /etc/resolv.conf): that is the primary service's, which another VPN, or a
//! host pointing the system at sail's own TUN, may be.
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

/// The DNS servers of the services on `interface`, as the dynamic store
/// has them; none when no service there has any.
pub(super) fn servers_of(interface: &str) -> Vec<IpAddr> {
    // SAFETY: every object is checked for its type before it is read, and
    // those created or copied are owned and released once.
    unsafe {
        let store = Owned(SCDynamicStoreCreate(
            std::ptr::null(),
            string("sail").0,
            std::ptr::null(),
            std::ptr::null_mut(),
        ));
        if store.0.is_null() {
            return Vec::new();
        }
        let pattern = string("State:/Network/Service/[^/]+/DNS");
        let keys = Owned(SCDynamicStoreCopyKeyList(store.0, pattern.0));
        let copy = |key: &str| Owned(SCDynamicStoreCopyValue(store.0, string(key).0));
        let mut servers = Vec::new();
        for key in strings(keys.0) {
            let dns = copy(&key);
            // A scoped resolver names its interface; otherwise the service's
            // addresses do.
            let service = key.trim_end_matches("/DNS");
            let name = to_string(get(dns.0, "InterfaceName")).or_else(|| {
                ["IPv4", "IPv6"].iter().find_map(|family| {
                    to_string(get(copy(&format!("{service}/{family}")).0, "InterfaceName"))
                })
            });
            if name.as_deref() != Some(interface) {
                continue;
            }
            for address in strings(get(dns.0, "ServerAddresses")) {
                // A link-local server carries its scope: fe80::1%en0.
                if let Ok(ip) = address.split('%').next().unwrap_or("").parse::<IpAddr>() {
                    if !servers.contains(&ip) {
                        servers.push(ip);
                    }
                }
            }
        }
        servers
    }
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
            let read = servers_of(interface);
            // Every address the service lists, before its IPv4 part.
            let dns_part = shown.split("<dictionary>").nth(1).unwrap_or("");
            for line in dns_part.lines() {
                let Some((_, value)) = line.trim().split_once(" : ") else {
                    continue;
                };
                if let Ok(ip) = value.split('%').next().unwrap().parse::<IpAddr>() {
                    if line.trim().starts_with(char::is_numeric) {
                        assert!(read.contains(&ip), "{interface}: {ip} not in {read:?}");
                    }
                }
            }
            checked += 1;
        }
        // A Mac with no network has nothing to compare.
        eprintln!("services compared: {checked}");
        assert!(servers_of("no-such-interface0").is_empty());
    }
}
