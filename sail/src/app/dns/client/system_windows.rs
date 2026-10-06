//! Windows: the split resolvers of the Name Resolution Policy Table
//! (NRPT), as `Get-DnsClientNrptPolicy` shows them. Its rules are keys
//! under `DnsPolicyConfig`: those of group policy, which replace the
//! local ones when there are any, or else the local ones, which
//! `Add-DnsClientNrptRule` writes. A rule's `Name` lists its namespaces
//! (".corp.example" for the names under a domain, "host.corp.example"
//! for one name) and its `GenericDNSServers` the servers asked for them.
//! A rule with no generic servers (DirectAccess, DNSSEC only) makes no
//! split resolver, nor does a namespace for every name (".") or for an
//! address range. NRPT names no interface: its servers are asked on the
//! one the system routes them through.

/// A rule's split resolver: its namespaces as domains, and the servers
/// of `servers` (separated by semicolons, commas or spaces).
pub(super) fn rule(names: &[String], servers: &str) -> Option<super::Split> {
    let domains: Vec<String> = names
        .iter()
        .filter(|n| !n.contains('/') && !n.contains(':'))
        .filter_map(|n| super::domain(n))
        .collect();
    let servers: Vec<super::Listed> = servers
        .split([';', ',', ' '])
        .filter_map(|s| super::Listed::parse(s.trim()))
        .collect();
    (!domains.is_empty() && !servers.is_empty()).then_some(super::Split {
        domains,
        servers,
        interface: None,
    })
}

/// The NRPT's split resolvers: group policy's rules where there are any,
/// else the local ones.
#[cfg(windows)]
pub(super) fn nrpt() -> Vec<super::Split> {
    const POLICY: &str = r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig";
    const LOCAL: &str = r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig";
    let policy = registry::rules(POLICY);
    let rules = if policy.is_empty() {
        registry::rules(LOCAL)
    } else {
        policy
    };
    rules
        .iter()
        .filter_map(|(names, servers)| rule(names, servers))
        .collect()
}

#[cfg(windows)]
mod registry {
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE,
        KEY_READ, REG_MULTI_SZ, REG_SZ,
    };

    use crate::platform::windows::ip_helper::wide;

    /// A key this opened, closed when dropped.
    struct Key(HKEY);

    impl Drop for Key {
        fn drop(&mut self) {
            // SAFETY: a key RegOpenKeyExW opened, closed once.
            unsafe { RegCloseKey(self.0) };
        }
    }

    fn open(parent: HKEY, path: &str) -> Option<Key> {
        let path = wide(path);
        let mut key: HKEY = std::ptr::null_mut();
        // SAFETY: a NUL-terminated wide path and a place for the key.
        let code = unsafe { RegOpenKeyExW(parent, path.as_ptr(), 0, KEY_READ, &mut key) };
        (code == 0).then_some(Key(key))
    }

    /// The names of `key`'s subkeys.
    fn subkeys(key: &Key) -> Vec<String> {
        let mut names = Vec::new();
        for index in 0.. {
            let mut name = [0u16; 256];
            let mut len = name.len() as u32;
            // SAFETY: the buffer is as long as `len` says; the rest unasked.
            let code = unsafe {
                RegEnumKeyExW(
                    key.0,
                    index,
                    name.as_mut_ptr(),
                    &mut len,
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            if code != 0 {
                break;
            }
            names.push(String::from_utf16_lossy(&name[..len as usize]));
        }
        names
    }

    /// The strings of `key`'s value `name`: one for REG_SZ, each of a
    /// REG_MULTI_SZ; none for any other type, or none such value.
    fn strings(key: &Key, name: &str) -> Vec<String> {
        let name = wide(name);
        let mut kind = 0u32;
        let mut size = 0u32;
        // SAFETY: asks only the type and the size.
        let code = unsafe {
            RegQueryValueExW(
                key.0,
                name.as_ptr(),
                std::ptr::null(),
                &mut kind,
                std::ptr::null_mut(),
                &mut size,
            )
        };
        if code != 0 || (kind != REG_SZ && kind != REG_MULTI_SZ) || size == 0 {
            return Vec::new();
        }
        let mut data = vec![0u16; (size as usize).div_ceil(2)];
        // SAFETY: the buffer holds `size` bytes, as the call before said.
        let code = unsafe {
            RegQueryValueExW(
                key.0,
                name.as_ptr(),
                std::ptr::null(),
                &mut kind,
                data.as_mut_ptr().cast(),
                &mut size,
            )
        };
        if code != 0 {
            return Vec::new();
        }
        data.truncate(size as usize / 2);
        data.split(|&c| c == 0)
            .filter(|s| !s.is_empty())
            .map(String::from_utf16_lossy)
            .collect()
    }

    /// The rules under `path`: each one's namespaces, and its generic
    /// servers as one string.
    pub(super) fn rules(path: &str) -> Vec<(Vec<String>, String)> {
        let Some(table) = open(HKEY_LOCAL_MACHINE, path) else {
            return Vec::new();
        };
        subkeys(&table)
            .iter()
            .filter_map(|name| {
                let rule = open(table.0, name)?;
                let servers = strings(&rule, "GenericDNSServers").join(";");
                Some((strings(&rule, "Name"), servers))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(all: &[&str]) -> Vec<String> {
        all.iter().map(|s| s.to_string()).collect()
    }

    /// A rule's namespaces are its domains and its generic servers its
    /// servers; a rule for every name, for an address range, or with no
    /// generic servers is none.
    #[test]
    fn nrpt_rules_are_read_as_windows_keeps_them() {
        let corp = rule(
            &names(&[".Corp.Example", "vpn.example"]),
            "10.0.0.53;10.0.0.54",
        )
        .unwrap();
        assert_eq!(corp.domains, ["corp.example", "vpn.example"]);
        let servers: Vec<String> = corp.servers.iter().map(|l| l.ip.to_string()).collect();
        assert_eq!(servers, ["10.0.0.53", "10.0.0.54"]);
        assert_eq!(corp.interface, None);
        assert!(rule(&names(&["."]), "10.0.0.53").is_none());
        assert!(rule(&names(&["10.0.0.0/8"]), "10.0.0.53").is_none());
        assert!(rule(&names(&[".corp.example"]), "").is_none());
        let spaced = rule(&names(&[".corp.example"]), "10.0.0.53, fd00::53").unwrap();
        assert_eq!(spaced.servers.len(), 2);
    }
}
