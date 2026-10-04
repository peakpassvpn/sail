//! macOS: the system DNS while sail's TUN runs, as one dynamic-store key
//! of a network service that does not exist:
//!
//! ```text
//! State:/Network/Service/<id from the TUN's name>/DNS = {
//!   ServerAddresses: [the TUN's peer], SupplementalMatchDomains: [""],
//!   SearchOrder: 100000 }
//! ```
//!
//! An empty match domain makes it a supplemental resolver with no domain,
//! which macOS ranks first, as the default resolver (configd's
//! dns-configuration.c; CI's macos_dns_probe.sh saw it as `resolver #1`,
//! ahead of DHCP's). It is added as temporary: configd removes it when the
//! session that added it closes, a process killed with it (measured in
//! CI), so a kill -9 leaves nothing. No real service's DNS is touched.
//!
//! Public CoreFoundation and SystemConfiguration calls, declared here
//! rather than through a crate.

use std::ffi::{c_char, c_void, CStr};
use std::io;
use std::net::IpAddr;

type CFTypeRef = *const c_void;
type CFIndex = isize;

const UTF8: u32 = 0x0800_0100; // kCFStringEncodingUTF8
const SINT32: CFIndex = 3; // kCFNumberSInt32Type

/// Below the default resolver order (200000, dnsinfo.h), as Tailscale's.
const SEARCH_ORDER: i32 = 100_000;

/// CoreFoundation's callback tables, only ever passed by address.
#[repr(C)]
struct CallBacks {
    _opaque: [u8; 0],
}

#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    static kCFTypeArrayCallBacks: CallBacks;
    static kCFTypeDictionaryKeyCallBacks: CallBacks;
    static kCFTypeDictionaryValueCallBacks: CallBacks;
    fn CFStringCreateWithBytes(
        alloc: CFTypeRef,
        bytes: *const u8,
        len: CFIndex,
        encoding: u32,
        external: u8,
    ) -> CFTypeRef;
    fn CFArrayCreate(
        alloc: CFTypeRef,
        values: *const CFTypeRef,
        count: CFIndex,
        callbacks: *const CallBacks,
    ) -> CFTypeRef;
    fn CFDictionaryCreate(
        alloc: CFTypeRef,
        keys: *const CFTypeRef,
        values: *const CFTypeRef,
        count: CFIndex,
        key_callbacks: *const CallBacks,
        value_callbacks: *const CallBacks,
    ) -> CFTypeRef;
    fn CFNumberCreate(alloc: CFTypeRef, kind: CFIndex, value: *const c_void) -> CFTypeRef;
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
    fn SCDynamicStoreAddTemporaryValue(store: CFTypeRef, key: CFTypeRef, value: CFTypeRef) -> u8;
    fn SCDynamicStoreRemoveValue(store: CFTypeRef, key: CFTypeRef) -> u8;
    fn SCDynamicStoreCopyValue(store: CFTypeRef, key: CFTypeRef) -> CFTypeRef;
    fn SCError() -> i32;
    fn SCErrorString(status: i32) -> *const c_char;
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

/// The last SystemConfiguration error, in words.
fn sc_error(what: &str) -> io::Error {
    // SAFETY: plain calls; SCErrorString's string is static.
    let (code, words) = unsafe {
        let code = SCError();
        let words = SCErrorString(code);
        let words = if words.is_null() {
            String::new()
        } else {
            CStr::from_ptr(words).to_string_lossy().into_owned()
        };
        (code, words)
    };
    io::Error::other(format!("{}: {} ({})", what, words, code))
}

/// The key of the TUN `tun`'s DNS. The id is the same for the same name,
/// so that a start finds what an earlier one left; not a real service's.
pub(crate) fn key(tun: &str) -> String {
    // FNV-1a, 64 bits: enough to keep two TUNs' keys apart.
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in tun.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    format!(
        "State:/Network/Service/5A11D0E5-{:04X}-4{:03X}-8{:03X}-{:012X}/DNS",
        (h >> 48) & 0xffff,
        (h >> 36) & 0xfff,
        (h >> 24) & 0xfff,
        h & 0xffff_ffff_ffff
    )
}

/// The value: `servers` as the resolver with no domain.
fn value(servers: &[IpAddr]) -> io::Result<Owned> {
    let addresses: Vec<Owned> = servers.iter().map(|s| string(&s.to_string())).collect();
    let empty = string("");
    let order = SEARCH_ORDER;
    // SAFETY: arrays of live objects of the counts given; the callbacks are
    // CoreFoundation's own, which retain what the containers hold.
    unsafe {
        let refs: Vec<CFTypeRef> = addresses.iter().map(|a| a.0).collect();
        let server_array = Owned(CFArrayCreate(
            std::ptr::null(),
            refs.as_ptr(),
            refs.len() as CFIndex,
            std::ptr::addr_of!(kCFTypeArrayCallBacks),
        ));
        let domains = Owned(CFArrayCreate(
            std::ptr::null(),
            &empty.0,
            1,
            std::ptr::addr_of!(kCFTypeArrayCallBacks),
        ));
        let number = Owned(CFNumberCreate(
            std::ptr::null(),
            SINT32,
            &order as *const i32 as *const c_void,
        ));
        let keys = [
            string("ServerAddresses"),
            string("SupplementalMatchDomains"),
            string("SearchOrder"),
        ];
        let key_refs: Vec<CFTypeRef> = keys.iter().map(|k| k.0).collect();
        let values = [server_array.0, domains.0, number.0];
        if key_refs.iter().chain(&values).any(|r| r.is_null()) {
            return Err(io::Error::other("building the DNS entry"));
        }
        let dict = Owned(CFDictionaryCreate(
            std::ptr::null(),
            key_refs.as_ptr(),
            values.as_ptr(),
            3,
            std::ptr::addr_of!(kCFTypeDictionaryKeyCallBacks),
            std::ptr::addr_of!(kCFTypeDictionaryValueCallBacks),
        ));
        if dict.0.is_null() {
            return Err(io::Error::other("building the DNS entry"));
        }
        Ok(dict)
    }
}

/// The TUN's DNS, set; the session that holds it, open until dropped.
pub(crate) struct TunDns {
    store: Owned,
    key: Owned,
    value: Owned,
    name: String,
}

// SAFETY: the objects are only used through `&self` behind the owner's
// lock, one call at a time, and CoreFoundation objects may move between
// threads.
unsafe impl Send for TunDns {}

impl TunDns {
    /// Sets `servers` as the system's default resolver while the TUN `tun`
    /// runs. A key of that name already there (left by a writer that did
    /// not add it as temporary) is replaced.
    pub(crate) fn set(tun: &str, servers: &[IpAddr]) -> io::Result<TunDns> {
        let name = key(tun);
        let label = string("sail");
        // SAFETY: a session of our own, no callout.
        let store = Owned(unsafe {
            SCDynamicStoreCreate(
                std::ptr::null(),
                label.0,
                std::ptr::null(),
                std::ptr::null_mut(),
            )
        });
        if store.0.is_null() {
            return Err(sc_error("opening the dynamic store"));
        }
        let dns = TunDns {
            key: string(&name),
            value: value(servers)?,
            store,
            name,
        };
        // SAFETY: live objects.
        unsafe { SCDynamicStoreRemoveValue(dns.store.0, dns.key.0) };
        dns.add()?;
        Ok(dns)
    }

    fn add(&self) -> io::Result<()> {
        // SAFETY: live objects.
        if unsafe { SCDynamicStoreAddTemporaryValue(self.store.0, self.key.0, self.value.0) } == 0 {
            return Err(sc_error(&format!("adding {}", self.name)));
        }
        Ok(())
    }

    fn there(&self) -> bool {
        // SAFETY: live objects; the copy is released.
        let copy = Owned(unsafe { SCDynamicStoreCopyValue(self.store.0, self.key.0) });
        !copy.0.is_null()
    }

    /// Adds it again when it is gone (configd restarted, or something
    /// removed it); whether it did.
    pub(crate) fn restore(&self) -> io::Result<bool> {
        if self.there() {
            return Ok(false);
        }
        self.add().map(|()| true)
    }

    /// Removes it; gone already is as wanted.
    pub(crate) fn remove(&self) -> io::Result<()> {
        // SAFETY: live objects.
        if unsafe { SCDynamicStoreRemoveValue(self.store.0, self.key.0) } == 0 && self.there() {
            return Err(sc_error(&format!("removing {}", self.name)));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_tun_s_key_is_its_own_and_the_same_each_start() {
        let a = super::key("utun4");
        assert_eq!(a, super::key("utun4"));
        assert_ne!(a, super::key("utun5"));
        // State:/Network/Service/<a UUID's shape>/DNS
        let id = a
            .strip_prefix("State:/Network/Service/")
            .and_then(|s| s.strip_suffix("/DNS"))
            .unwrap();
        let groups: Vec<usize> = id.split('-').map(str::len).collect();
        assert_eq!(groups, [8, 4, 4, 4, 12]);
        assert!(id.chars().all(|c| c == '-' || c.is_ascii_hexdigit()));
    }

    #[test]
    fn the_entry_builds() {
        let servers = ["172.19.0.2".parse().unwrap(), "fdfe::2".parse().unwrap()];
        assert!(!super::value(&servers).unwrap().0.is_null());
    }
}
