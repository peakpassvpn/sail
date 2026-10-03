//! DHCP lease files: which address a device was leased, its MAC address and
//! the host name it gave, as sing-box 1.14 reads them
//! (route/neighbor_resolver_lease.go, _parse.go and _hostname.go).
//!
//! The format of a file is told by its name, as sing-box tells it:
//! `dhcpd_leases` (macOS bootpd), `kea-leases4.csv`, `kea-leases6.csv`,
//! `dhcpd.leases` (ISC dhcpd), and anything else dnsmasq or odhcpd.
//! Only the ending counts, so an odhcpd file named `odhcpd.leases` is read
//! as ISC dhcpd, as in sing-box.
//!
//! sing-box keeps MAC addresses as `net.HardwareAddr`, which Go's
//! `net.ParseMAC` also fills with 8- and 20-byte addresses (EUI-64,
//! InfiniBand). sail keeps 6-byte Ethernet MACs only: a longer one is taken
//! as unparsable, which skips the entry where sing-box would skip a bad MAC.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) type Mac = [u8; 6];

/// What lease files say.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct Leases {
    pub ip_to_mac: HashMap<IpAddr, Mac>,
    pub ip_to_hostname: HashMap<IpAddr, String>,
    pub mac_to_hostname: HashMap<Mac, String>,
}

impl Leases {
    /// Records a lease: the MAC if known, and the host name if not empty,
    /// against the address and (when the MAC is known) the MAC.
    fn record(&mut self, address: IpAddr, mac: Option<Mac>, hostname: &str) {
        if let Some(mac) = mac {
            self.ip_to_mac.insert(address, mac);
        }
        if !hostname.is_empty() {
            self.ip_to_hostname.insert(address, hostname.to_owned());
            if let Some(mac) = mac {
                self.mac_to_hostname.insert(mac, hostname.to_owned());
            }
        }
    }
}

/// sing-box's defaultLeaseFiles on Linux (Go's `linux` tag covers Android).
#[cfg(any(target_os = "linux", target_os = "android"))]
const DEFAULT_LEASE_FILES: &[&str] = &[
    "/tmp/dhcp.leases",
    "/var/lib/dhcp/dhcpd.leases",
    "/var/lib/dhcpd/dhcpd.leases",
    "/var/lib/kea/kea-leases4.csv",
    "/var/lib/kea/kea-leases6.csv",
];

/// sing-box's defaultLeaseFiles on macOS.
#[cfg(target_os = "macos")]
const DEFAULT_LEASE_FILES: &[&str] = &["/var/db/dhcpd_leases", "/tmp/dhcp.leases"];

/// sing-box has no neighbor resolver elsewhere, so no lease files.
#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
const DEFAULT_LEASE_FILES: &[&str] = &[];

/// The lease files sing-box looks for on this platform when none are
/// configured: those that exist with a non-zero size (following symlinks,
/// as Go's os.Stat does), in sing-box's order. sing-box's newNeighborResolver.
pub(crate) fn default_lease_files() -> Vec<PathBuf> {
    DEFAULT_LEASE_FILES
        .iter()
        .map(PathBuf::from)
        .filter(|path| std::fs::metadata(path).is_ok_and(|info| info.len() > 0))
        .collect()
}

/// Reads each file in order, detecting its format as sing-box does. Files
/// that cannot be read are skipped, as sing-box skips them. sing-box's
/// ReloadLeaseFiles.
///
/// All files fill the same tables, so a later file (or a later line) wins
/// for the same address or MAC, and an ISC dhcpd lease that is not active
/// removes the address even when an earlier file gave it.
pub(crate) fn read_lease_files(paths: &[PathBuf]) -> Leases {
    let now = unix_now();
    let mut leases = Leases::default();
    for path in paths {
        read_lease_file(path, now, &mut leases);
    }
    leases
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

fn read_lease_file(path: &Path, now: i64, leases: &mut Leases) {
    let Ok(content) = std::fs::read(path) else {
        return;
    };
    // Go compares the path as a string; the names looked for are ASCII.
    parse_lease_file(&path.to_string_lossy(), &content, now, leases);
}

/// sing-box's parseLeaseFile: the format by the name's ending.
pub(crate) fn parse_lease_file(name: &str, content: &[u8], now: i64, leases: &mut Leases) {
    let lines = lines(content);
    if name.ends_with("dhcpd_leases") {
        parse_bootpd_leases(&lines, now, leases);
    } else if name.ends_with("kea-leases4.csv") {
        parse_kea_csv4(&lines, leases);
    } else if name.ends_with("kea-leases6.csv") {
        parse_kea_csv6(&lines, leases);
    } else if name.ends_with("dhcpd.leases") {
        parse_isc_dhcpd(&lines, leases);
    } else {
        parse_dnsmasq_odhcpd(&lines, now, leases);
    }
}

/// The lines of a file as Go's bufio.Scanner gives them: split at `\n`,
/// with a trailing `\r` dropped. Bytes that are not UTF-8 are replaced.
///
/// Unlike the Scanner, a line longer than 64 KiB does not end the file.
fn lines(content: &[u8]) -> Vec<String> {
    let mut lines: Vec<String> = content
        .split(|&byte| byte == b'\n')
        .map(|line| String::from_utf8_lossy(line.strip_suffix(b"\r").unwrap_or(line)).into_owned())
        .collect();
    // A final newline does not start another line.
    if content.ends_with(b"\n") || content.is_empty() {
        lines.pop();
    }
    lines
}

/// sing-box's parseDnsmasqOdhcpd. dnsmasq writes
/// `<expiry> <mac> <ipv4> <hostname> <client-id>` and, for IPv6,
/// `<expiry> <iaid> <ipv6> <hostname> <duid>`, with a `duid <server-duid>`
/// line; odhcpd writes its leases as `# `-prefixed lines.
fn parse_dnsmasq_odhcpd(lines: &[String], now: i64, leases: &mut Leases) {
    for line in lines {
        if line.starts_with("duid ") {
            continue;
        }
        if let Some(rest) = line.strip_prefix("# ") {
            parse_odhcpd_line(rest, now, leases);
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }
        let Ok(expiry) = fields[0].parse::<i64>() else {
            continue;
        };
        // An expiry of 0 is dnsmasq's infinite lease.
        if expiry != 0 && expiry < now {
            continue;
        }
        // `*` is dnsmasq's placeholder for a client that gave no name.
        let hostname = if fields[3] == "*" { "" } else { fields[3] };
        // A MAC written with colons is IPv4; anything else is an IAID. So a
        // dash-separated MAC takes the IPv6 path, as in sing-box.
        if fields[1].contains(':') {
            let Some(mac) = parse_mac(fields[1]) else {
                continue;
            };
            let Some(address) = parse_ip(fields[2]) else {
                continue;
            };
            leases.record(address, Some(mac), hostname);
        } else {
            let mac = fields
                .get(4)
                .and_then(|duid| decode_hex(&duid.replace(':', "")))
                .and_then(|duid| mac_from_duid(&duid));
            let Some(address) = parse_ip(fields[2]) else {
                continue;
            };
            leases.record(address, mac, hostname);
        }
    }
}

/// sing-box's parseOdhcpdLine, on a line without its `# `:
/// `<iface> <duid|mac> <iaid|"ipv4"> <hostname> <valid-until> <id> <len>
/// <address>/<len> ...`.
fn parse_odhcpd_line(line: &str, now: i64, leases: &mut Leases) {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 5 {
        return;
    }
    let Ok(valid_until) = fields[4].parse::<i64>() else {
        return;
    };
    // Unlike dnsmasq's expiry, 0 here skips the lease; a negative time
    // (odhcpd's infinite) keeps it.
    if valid_until == 0 || (valid_until > 0 && valid_until < now) {
        return;
    }
    // `-` is no name; `broken\x20...` (a literal backslash) is odhcpd's
    // mark for a name it could not use.
    let hostname = fields[3];
    let hostname = if hostname == "-" || hostname.starts_with(r"broken\x20") {
        ""
    } else {
        hostname
    };
    if fields.len() >= 8 && fields[2] == "ipv4" {
        let Some(mac) = parse_mac(fields[1]) else {
            return;
        };
        let Some(address) = parse_ip(strip_prefix_length(fields[7])) else {
            return;
        };
        leases.record(address, Some(mac), hostname);
        return;
    }
    let mac = decode_hex(fields[1]).and_then(|duid| mac_from_duid(&duid));
    for field in fields.iter().skip(7) {
        let Some(address) = parse_ip(strip_prefix_length(field)) else {
            continue;
        };
        leases.record(address, mac, hostname);
    }
}

fn strip_prefix_length(field: &str) -> &str {
    field.split_once('/').map_or(field, |(address, _)| address)
}

/// sing-box's parseISCDhcpd: `lease <ip> { ... }` blocks, of which only
/// those with `binding state active;` and a `hardware ethernet` count. A
/// block that does not count removes its address from the address tables
/// (not from the MAC-to-name table), so the last block for an address wins.
/// Lease end times are not looked at.
fn parse_isc_dhcpd(lines: &[String], leases: &mut Leases) {
    let mut current_ip: Option<IpAddr> = None;
    let mut current_mac: Option<Mac> = None;
    let mut current_hostname = String::new();
    let mut current_active = false;
    let mut in_lease = false;
    for line in lines {
        let line = line.trim();
        if line.starts_with("lease ") && line.ends_with('{') {
            let ip = line.strip_prefix("lease ").unwrap_or(line);
            let ip = ip.strip_suffix(" {").unwrap_or(ip);
            // A header whose address does not parse starts nothing and
            // leaves the block state as it was, as in sing-box.
            if let Some(address) = parse_ip(ip) {
                current_ip = Some(address);
                in_lease = true;
                current_mac = None;
                current_hostname.clear();
                current_active = false;
            }
            continue;
        }
        if line == "}" && in_lease {
            if let Some(ip) = current_ip {
                if current_active && current_mac.is_some() {
                    leases.record(ip, current_mac, &current_hostname);
                } else {
                    leases.ip_to_mac.remove(&ip);
                    leases.ip_to_hostname.remove(&ip);
                }
            }
            in_lease = false;
            continue;
        }
        if !in_lease {
            continue;
        }
        if let Some(rest) = line.strip_prefix("hardware ethernet ") {
            let mac = rest.strip_suffix(';').unwrap_or(rest);
            if let Some(mac) = parse_mac(mac) {
                current_mac = Some(mac);
            }
        } else if let Some(rest) = line.strip_prefix("client-hostname ") {
            let hostname = rest.strip_suffix(';').unwrap_or(rest).trim_matches('"');
            if !hostname.is_empty() {
                current_hostname = hostname.to_owned();
            }
        } else if let Some(rest) = line.strip_prefix("binding state ") {
            // `next binding state` and `rewind binding state` do not match.
            let state = rest.strip_suffix(';').unwrap_or(rest);
            current_active = state == "active";
        }
    }
}

/// sing-box's parseKeaCSV4. Columns: address, hwaddr, client_id,
/// valid_lifetime, expire, subnet_id, fqdn_fwd, fqdn_rev, hostname, state,
/// ... The first line is the header. Only state 0 (default, i.e. assigned)
/// counts; the expire column is not looked at. Fields are split at plain
/// commas: Kea's `&#x2c` escape is left as it is.
fn parse_kea_csv4(lines: &[String], leases: &mut Leases) {
    for line in lines.iter().skip(1) {
        let fields: Vec<&str> = line.split(',').collect();
        if fields.len() < 10 || fields[9] != "0" {
            continue;
        }
        let Some(address) = parse_ip(fields[0]) else {
            continue;
        };
        let Some(mac) = parse_mac(fields[1]) else {
            continue;
        };
        leases.record(address, Some(mac), fields[8]);
    }
}

/// sing-box's parseKeaCSV6. Columns: address, duid, valid_lifetime, expire,
/// subnet_id, pref_lifetime, lease_type, iaid, prefix_len, fqdn_fwd,
/// fqdn_rev, hostname, hwaddr, state, ... The first line is the header.
/// Only state 0 counts. The MAC is the hwaddr column, or else the one in
/// the DUID.
fn parse_kea_csv6(lines: &[String], leases: &mut Leases) {
    for line in lines.iter().skip(1) {
        let fields: Vec<&str> = line.split(',').collect();
        if fields.len() < 14 || fields[13] != "0" {
            continue;
        }
        let Some(address) = parse_ip(fields[0]) else {
            continue;
        };
        let mac = if fields[12].is_empty() {
            None
        } else {
            parse_mac(fields[12])
        };
        let mac = mac.or_else(|| {
            decode_hex(&fields[1].replace(':', "")).and_then(|duid| mac_from_duid(&duid))
        });
        leases.record(address, mac, fields[11]);
    }
}

/// sing-box's parseBootpdLeases: macOS bootpd's `{ key=value ... }` blocks
/// with `name`, `ip_address`, `hw_address=1,<mac>` (type 1, Ethernet) and
/// `lease=0x<hex unix time>`. A block counts when it has both an address
/// and a MAC and its lease is 0 or not yet past.
///
/// The MAC is parsed as Go's net.ParseMAC parses it, as sing-box does: a
/// lease whose MAC has an octet written without its leading zero, as
/// bootpd may write it, is left out, as there.
fn parse_bootpd_leases(lines: &[String], now: i64, leases: &mut Leases) {
    let mut current_name = String::new();
    let mut current_ip: Option<IpAddr> = None;
    let mut current_mac: Option<Mac> = None;
    let mut current_lease: i64 = 0;
    let mut in_block = false;
    for line in lines {
        let line = line.trim();
        if line == "{" {
            in_block = true;
            current_name.clear();
            current_ip = None;
            current_mac = None;
            current_lease = 0;
            continue;
        }
        if line == "}" && in_block {
            if let (Some(ip), Some(mac)) = (current_ip, current_mac) {
                if current_lease == 0 || current_lease >= now {
                    leases.record(ip, Some(mac), &current_name);
                }
            }
            in_block = false;
            continue;
        }
        if !in_block {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key {
            "name" => current_name = value.to_owned(),
            "ip_address" => {
                if let Some(address) = parse_ip(value) {
                    current_ip = Some(address);
                }
            }
            "hw_address" => {
                if let Some(mac) = value.strip_prefix("1,").and_then(parse_mac) {
                    current_mac = Some(mac);
                }
            }
            "lease" => {
                let hex = value.strip_prefix("0x").unwrap_or(value);
                if let Ok(lease) = i64::from_str_radix(hex, 16) {
                    current_lease = lease;
                }
            }
            _ => {}
        }
    }
}

/// An address as `netip.AddrFromSlice(net.ParseIP(s)).Unmap()` gives it:
/// IPv4 or IPv6 without a zone, with an IPv4-mapped IPv6 address as IPv4.
fn parse_ip(s: &str) -> Option<IpAddr> {
    s.parse::<IpAddr>()
        .ok()
        .map(|address| address.to_canonical())
}

/// Go's net.ParseMAC for 6-byte addresses: `00:00:5e:00:53:01`,
/// `00-00-5e-00-53-01` or `0000.5e00.5301`, two hex digits to an octet
/// (four to a group), one separator throughout. 8- and 20-byte forms, which
/// Go accepts, are refused (see the module comment).
fn parse_mac(s: &str) -> Option<Mac> {
    let bytes = s.as_bytes();
    let mut mac = [0u8; 6];
    match bytes.len() {
        17 if bytes[2] == b':' || bytes[2] == b'-' => {
            let separator = bytes[2];
            for (i, octet) in mac.iter_mut().enumerate() {
                let at = i * 3;
                if i < 5 && bytes[at + 2] != separator {
                    return None;
                }
                *octet = hex_pair(bytes[at], bytes[at + 1])?;
            }
        }
        14 if bytes[4] == b'.' => {
            for (i, octet) in mac.iter_mut().enumerate() {
                let group = i / 2 * 5;
                if i % 2 == 0 && i < 4 && bytes[group + 4] != b'.' {
                    return None;
                }
                let at = group + i % 2 * 2;
                *octet = hex_pair(bytes[at], bytes[at + 1])?;
            }
        }
        _ => return None,
    }
    Some(mac)
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn hex_pair(high: u8, low: u8) -> Option<u8> {
    Some((hex_digit(high)? << 4) | hex_digit(low)?)
}

/// Go's hex.DecodeString: an even number of hex digits, either case.
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let (pairs, rest) = s.as_bytes().as_chunks::<2>();
    if !rest.is_empty() {
        return None;
    }
    pairs
        .iter()
        .map(|&[high, low]| hex_pair(high, low))
        .collect()
}

/// The MAC address in a SLAAC EUI-64 interface identifier: the IPv6
/// address has `ff:fe` in bytes 11 and 12, and the universal/local bit is
/// flipped back. sing-box's extractMACFromEUI64.
///
/// Go's `Is6` is true for IPv4-mapped IPv6 addresses too, so one of those
/// whose IPv4 part starts with 254 yields a MAC, as in sing-box.
pub(crate) fn mac_from_eui64(address: &IpAddr) -> Option<Mac> {
    let IpAddr::V6(address) = address else {
        return None;
    };
    let b = address.octets();
    if b[11] != 0xff || b[12] != 0xfe {
        return None;
    }
    Some([b[8] ^ 0x02, b[9], b[10], b[13], b[14], b[15]])
}

/// The MAC address in a DHCPv6 DUID of type 1 (link-layer plus time, MAC
/// at bytes 8..14) or 3 (link-layer, MAC at bytes 4..10), with hardware
/// type 1 (Ethernet). sing-box's extractMACFromDUID.
pub(crate) fn mac_from_duid(duid: &[u8]) -> Option<Mac> {
    if duid.len() < 4 {
        return None;
    }
    let duid_type = u16::from_be_bytes([duid[0], duid[1]]);
    let hardware_type = u16::from_be_bytes([duid[2], duid[3]]);
    if hardware_type != 1 {
        return None;
    }
    let mac = match duid_type {
        1 => duid.get(8..14)?,
        3 => duid.get(4..10)?,
        _ => return None,
    };
    mac.try_into().ok()
}

/// The addresses of `hostname`, given the tables: those whose own name
/// matches, then those whose MAC (in the neighbor table, then the leases)
/// has a matching name. Names match ignoring case; one trailing dot on
/// `hostname` is dropped, but names in the tables are compared as they
/// are. Link-local IPv6 addresses are left out, as an AAAA record cannot
/// carry their zone. The order within each part is the tables' iteration
/// order, which is unspecified, as Go's map order is. sing-box's
/// lookupAddressesByHostname.
pub(crate) fn addresses_by_hostname(
    hostname: &str,
    ip_to_hostname: &HashMap<IpAddr, String>,
    mac_to_hostname: &HashMap<Mac, String>,
    neighbor_ip_to_mac: &HashMap<IpAddr, Mac>,
    lease_ip_to_mac: &HashMap<IpAddr, Mac>,
) -> Vec<IpAddr> {
    let hostname = fqdn_to_domain(hostname);
    if hostname.is_empty() {
        return Vec::new();
    }
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    let mut add = |address: IpAddr| {
        if !is_scoped_ipv6_address(&address) && seen.insert(address) {
            result.push(address);
        }
    };
    for (address, entry_hostname) in ip_to_hostname {
        if equal_fold(entry_hostname, hostname) {
            add(*address);
        }
    }
    for (mac, entry_hostname) in mac_to_hostname {
        if !equal_fold(entry_hostname, hostname) {
            continue;
        }
        for table in [neighbor_ip_to_mac, lease_ip_to_mac] {
            for (address, entry_mac) in table {
                if entry_mac == mac {
                    add(*address);
                }
            }
        }
    }
    result
}

/// sing-box's dns.FqdnToDomain: drops a trailing dot unless it is escaped
/// by an odd number of backslashes (miekg/dns IsFqdn).
fn fqdn_to_domain(name: &str) -> &str {
    let Some(stripped) = name.strip_suffix('.') else {
        return name;
    };
    let backslashes = stripped.bytes().rev().take_while(|&b| b == b'\\').count();
    if backslashes % 2 == 0 {
        stripped
    } else {
        name
    }
}

/// Go's strings.EqualFold, closely: equal under per-character lowercase.
fn equal_fold(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
        || a.chars()
            .flat_map(char::to_lowercase)
            .eq(b.chars().flat_map(char::to_lowercase))
}

/// sing-box's isScopedIPv6Address. sail's addresses carry no zone, so only
/// the link-local test is left; as Go's IsLinkLocalUnicast unmaps first, an
/// IPv4-mapped 169.254.0.0/16 address counts too.
fn is_scoped_ipv6_address(address: &IpAddr) -> bool {
    let IpAddr::V6(v6) = address else {
        return false;
    };
    match v6.to_ipv4_mapped() {
        Some(v4) => v4.is_link_local(),
        None => v6.segments()[0] & 0xffc0 == 0xfe80,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::atomic::{AtomicUsize, Ordering};

    const NOW: i64 = 1_700_000_000;
    const MAC_A: Mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    const MAC_B: Mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

    /// A file in a fresh temp directory, removed when dropped.
    struct TempFile {
        dir: PathBuf,
        path: PathBuf,
    }

    impl TempFile {
        fn new(name: &str, content: &str) -> Self {
            static COUNTER: AtomicUsize = AtomicUsize::new(0);
            let dir = std::env::temp_dir().join(format!(
                "sail-lease-test-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&dir).expect("create temp dir");
            let path = dir.join(name);
            std::fs::write(&path, content).expect("write lease file");
            Self { dir, path }
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn read_at(files: &[&TempFile], now: i64) -> Leases {
        let mut leases = Leases::default();
        for file in files {
            read_lease_file(&file.path, now, &mut leases);
        }
        leases
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("test address")
    }

    fn sorted(mut addresses: Vec<IpAddr>) -> Vec<IpAddr> {
        addresses.sort();
        addresses
    }

    #[test]
    fn dnsmasq_ipv4_and_ipv6() {
        let file = TempFile::new(
            "dhcp.leases",
            "1700000100 00:11:22:33:44:55 192.168.1.10 laptop 01:00:11:22:33:44:55\n\
             0 aa:bb:cc:dd:ee:ff 192.168.1.11 * *\n\
             1600000000 00:11:22:33:44:66 192.168.1.12 expired *\n\
             duid 00:01:00:01:2a:2b:2c:2d:de:ad:be:ef:00:01\n\
             1700000200 12345678 fd00::10 phone 00:03:00:01:00:11:22:33:44:55\n\
             1700000200 12345679 fd00::11 tablet 00:02:00:00:ab:11:01:02\n\
             1700000200 notamac 999.1.1.1 bad *\n\
             short line\n",
        );
        let leases = read_at(&[&file], NOW);
        assert_eq!(leases.ip_to_mac.get(&ip("192.168.1.10")), Some(&MAC_A));
        assert_eq!(leases.ip_to_hostname[&ip("192.168.1.10")], "laptop");
        // An expiry of 0 is infinite; `*` is no name, but the MAC stays.
        assert_eq!(leases.ip_to_mac.get(&ip("192.168.1.11")), Some(&MAC_B));
        assert!(!leases.ip_to_hostname.contains_key(&ip("192.168.1.11")));
        assert!(!leases.mac_to_hostname.contains_key(&MAC_B));
        // Expired.
        assert!(!leases.ip_to_mac.contains_key(&ip("192.168.1.12")));
        // IPv6 with a type-3 DUID: the MAC comes from it.
        assert_eq!(leases.ip_to_mac.get(&ip("fd00::10")), Some(&MAC_A));
        assert_eq!(leases.ip_to_hostname[&ip("fd00::10")], "phone");
        // The later line wins for the same MAC.
        assert_eq!(leases.mac_to_hostname[&MAC_A], "phone");
        // A type-2 DUID has no MAC; the name is still kept.
        assert!(!leases.ip_to_mac.contains_key(&ip("fd00::11")));
        assert_eq!(leases.ip_to_hostname[&ip("fd00::11")], "tablet");
        assert_eq!(leases.ip_to_mac.len(), 3);
        assert_eq!(leases.ip_to_hostname.len(), 3);
    }

    #[test]
    fn dnsmasq_dash_mac_takes_the_ipv6_path() {
        // No colon in the MAC column: sing-box treats it as an IAID, so the
        // address gets its name but no MAC.
        let file = TempFile::new("dhcp.leases", "0 00-11-22-33-44-55 192.168.1.20 host *\n");
        let leases = read_at(&[&file], NOW);
        assert!(leases.ip_to_mac.is_empty());
        assert_eq!(leases.ip_to_hostname[&ip("192.168.1.20")], "host");
    }

    #[test]
    fn odhcpd_lines() {
        // OpenWrt's default odhcpd lease file is /tmp/hosts/odhcpd.
        let file = TempFile::new(
            "odhcpd",
            "# br-lan 000300010011223344aa 12345 phone 1700000500 100 128 fd00::20/128 fd00::21/128\n\
             # br-lan 00:11:22:33:44:55 ipv4 laptop 1700000500 5 32 192.168.1.30/24\n\
             # br-lan aa:bb:cc:dd:ee:ff ipv4 - -1 5 32 192.168.1.31/24\n\
             # br-lan 00:11:22:33:44:66 ipv4 zero 0 5 32 192.168.1.32/24\n\
             # br-lan 00:11:22:33:44:77 ipv4 old 1600000000 5 32 192.168.1.33/24\n\
             # br-lan 00:11:22:33:44:88 ipv4 broken\\x20name 1700000500 5 32 192.168.1.34/24\n\
             # br-lan 0002abcd 1 nomac 1700000500 1 128 fd00::22/128\n",
        );
        let leases = read_at(&[&file], NOW);
        let duid_mac: Mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0xaa];
        // Every address of an IPv6 lease, prefix lengths dropped.
        assert_eq!(leases.ip_to_mac.get(&ip("fd00::20")), Some(&duid_mac));
        assert_eq!(leases.ip_to_mac.get(&ip("fd00::21")), Some(&duid_mac));
        assert_eq!(leases.ip_to_hostname[&ip("fd00::21")], "phone");
        assert_eq!(leases.mac_to_hostname[&duid_mac], "phone");
        assert_eq!(leases.ip_to_mac.get(&ip("192.168.1.30")), Some(&MAC_A));
        assert_eq!(leases.ip_to_hostname[&ip("192.168.1.30")], "laptop");
        // A negative time keeps the lease; `-` is no name.
        assert_eq!(leases.ip_to_mac.get(&ip("192.168.1.31")), Some(&MAC_B));
        assert!(!leases.ip_to_hostname.contains_key(&ip("192.168.1.31")));
        // 0 and past times skip it.
        assert!(!leases.ip_to_mac.contains_key(&ip("192.168.1.32")));
        assert!(!leases.ip_to_mac.contains_key(&ip("192.168.1.33")));
        // A broken name is no name.
        assert!(leases.ip_to_mac.contains_key(&ip("192.168.1.34")));
        assert!(!leases.ip_to_hostname.contains_key(&ip("192.168.1.34")));
        // A DUID without a MAC: the name alone.
        assert!(!leases.ip_to_mac.contains_key(&ip("fd00::22")));
        assert_eq!(leases.ip_to_hostname[&ip("fd00::22")], "nomac");
    }

    #[test]
    fn isc_dhcpd_blocks() {
        let file = TempFile::new(
            "dhcpd.leases",
            "# The format of this file is documented in the dhcpd.leases(5) manual page.\n\
             lease 10.0.0.5 {\n\
             \x20 starts 4 2023/11/14 22:13:20;\n\
             \x20 binding state active;\n\
             \x20 next binding state free;\n\
             \x20 rewind binding state free;\n\
             \x20 hardware ethernet 00:11:22:33:44:55;\n\
             \x20 client-hostname \"desktop\";\n\
             }\n\
             lease 10.0.0.6 {\n\
             \x20 binding state active;\n\
             \x20 hardware ethernet aa:bb:cc:dd:ee:ff;\n\
             }\n\
             lease 10.0.0.6 {\n\
             \x20 binding state free;\n\
             \x20 hardware ethernet aa:bb:cc:dd:ee:ff;\n\
             }\n\
             lease 10.0.0.7 {\n\
             \x20 binding state active;\n\
             \x20 client-hostname \"nomac\";\n\
             }\n",
        );
        let leases = read_at(&[&file], NOW);
        assert_eq!(leases.ip_to_mac.get(&ip("10.0.0.5")), Some(&MAC_A));
        assert_eq!(leases.ip_to_hostname[&ip("10.0.0.5")], "desktop");
        assert_eq!(leases.mac_to_hostname[&MAC_A], "desktop");
        // `next binding state free` did not undo `binding state active`, but
        // a later free block for the address removes it.
        assert!(!leases.ip_to_mac.contains_key(&ip("10.0.0.6")));
        // Active without a MAC does not count.
        assert!(!leases.ip_to_mac.contains_key(&ip("10.0.0.7")));
        assert!(!leases.ip_to_hostname.contains_key(&ip("10.0.0.7")));
    }

    #[test]
    fn isc_inactive_lease_removes_an_earlier_files_entry() {
        let dnsmasq = TempFile::new("dhcp.leases", "0 00:11:22:33:44:55 10.0.0.9 early *\n");
        let isc = TempFile::new(
            "dhcpd.leases",
            "lease 10.0.0.9 {\n  binding state expired;\n  hardware ethernet 00:11:22:33:44:55;\n}\n",
        );
        let leases = read_at(&[&dnsmasq, &isc], NOW);
        assert!(!leases.ip_to_mac.contains_key(&ip("10.0.0.9")));
        assert!(!leases.ip_to_hostname.contains_key(&ip("10.0.0.9")));
        // The MAC-to-name table is left as it was.
        assert_eq!(leases.mac_to_hostname[&MAC_A], "early");
    }

    #[test]
    fn kea_csv4() {
        let file = TempFile::new(
            "kea-leases4.csv",
            "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id\n\
             192.0.2.1,00:11:22:33:44:55,01:00:11:22:33:44:55,4000,1700004000,1,0,0,printer,0,,0\n\
             192.0.2.2,aa:bb:cc:dd:ee:ff,,4000,1700004000,1,0,0,declined,1,,0\n\
             192.0.2.3,aa:bb:cc:dd:ee:ff,,4000,1500000000,1,0,0,,0,,0\n\
             192.0.2.4,,,4000,1700004000,1,0,0,nomac,0,,0\n\
             192.0.2.5,00:11:22:33:44:55,short\n",
        );
        let leases = read_at(&[&file], NOW);
        assert_eq!(leases.ip_to_mac.get(&ip("192.0.2.1")), Some(&MAC_A));
        assert_eq!(leases.ip_to_hostname[&ip("192.0.2.1")], "printer");
        assert_eq!(leases.mac_to_hostname[&MAC_A], "printer");
        // State 1 (declined) is skipped.
        assert!(!leases.ip_to_hostname.contains_key(&ip("192.0.2.2")));
        // The expire column is not looked at; an empty name is no name.
        assert_eq!(leases.ip_to_mac.get(&ip("192.0.2.3")), Some(&MAC_B));
        assert!(!leases.mac_to_hostname.contains_key(&MAC_B));
        // No MAC: the whole row is skipped, name included.
        assert!(!leases.ip_to_hostname.contains_key(&ip("192.0.2.4")));
        assert!(!leases.ip_to_mac.contains_key(&ip("192.0.2.5")));
        assert_eq!(leases.ip_to_mac.len(), 2);
    }

    #[test]
    fn kea_csv4_header_is_skipped_even_if_it_is_data() {
        let file = TempFile::new(
            "kea-leases4.csv",
            "192.0.2.1,00:11:22:33:44:55,,4000,1700004000,1,0,0,first,0\n",
        );
        assert_eq!(read_at(&[&file], NOW), Leases::default());
    }

    #[test]
    fn kea_csv6() {
        let file = TempFile::new(
            "kea-leases6.csv",
            "address,duid,valid_lifetime,expire,subnet_id,pref_lifetime,lease_type,iaid,prefix_len,fqdn_fwd,fqdn_rev,hostname,hwaddr,state,user_context,hwtype,hwaddr_source,pool_id\n\
             2001:db8::1,00:01:00:01:2a:2b:2c:2d:de:ad:be:ef:00:01,4000,1700004000,1,3000,0,1,128,0,0,nas,aa:bb:cc:dd:ee:ff,0,,1,0,0\n\
             2001:db8::2,00:03:00:01:00:11:22:33:44:55,4000,1700004000,1,3000,0,1,128,0,0,tv,,0,,1,0,0\n\
             2001:db8::3,00:03:00:01:00:11:22:33:44:55,4000,1700004000,1,3000,0,1,128,0,0,gone,,2,,1,0,0\n\
             2001:db8::4,00:02:00:00:ab:11:01:02,4000,1700004000,1,3000,0,1,128,0,0,iot,bogus,0,,1,0,0\n",
        );
        let leases = read_at(&[&file], NOW);
        // The hwaddr column wins over the DUID.
        assert_eq!(leases.ip_to_mac.get(&ip("2001:db8::1")), Some(&MAC_B));
        assert_eq!(leases.mac_to_hostname[&MAC_B], "nas");
        // No hwaddr: the DUID's MAC.
        assert_eq!(leases.ip_to_mac.get(&ip("2001:db8::2")), Some(&MAC_A));
        assert_eq!(leases.mac_to_hostname[&MAC_A], "tv");
        // State 2 is skipped.
        assert!(!leases.ip_to_hostname.contains_key(&ip("2001:db8::3")));
        // A bad hwaddr falls back to the DUID, which has none: the name alone.
        assert!(!leases.ip_to_mac.contains_key(&ip("2001:db8::4")));
        assert_eq!(leases.ip_to_hostname[&ip("2001:db8::4")], "iot");
    }

    #[test]
    fn bootpd_blocks() {
        let file = TempFile::new(
            "dhcpd_leases",
            "{\n\
             \tname=macbook\n\
             \tip_address=192.168.64.2\n\
             \thw_address=1,00:11:22:03:44:55\n\
             \tidentifier=1,00:11:22:03:44:55\n\
             \tlease=0x6553f200\n\
             }\n\
             {\n\
             \tname=old\n\
             \tip_address=192.168.64.3\n\
             \thw_address=1,aa:bb:cc:dd:ee:ff\n\
             \tlease=0x5f000000\n\
             }\n\
             {\n\
             \tname=forever\n\
             \tip_address=192.168.64.4\n\
             \thw_address=1,aa:bb:cc:dd:ee:ff\n\
             }\n\
             {\n\
             \tname=notether\n\
             \tip_address=192.168.64.5\n\
             \thw_address=ff,00:11:22:33:44:55\n\
             }\n\
             {\n\
             \tname=unpadded\n\
             \tip_address=192.168.64.6\n\
             \thw_address=1,0:11:22:3:44:55\n\
             }\n",
        );
        let leases = read_at(&[&file], NOW);
        // 0x6553f200 = 1700000256, not yet past.
        let mac: Mac = [0x00, 0x11, 0x22, 0x03, 0x44, 0x55];
        assert_eq!(leases.ip_to_mac.get(&ip("192.168.64.2")), Some(&mac));
        assert_eq!(leases.ip_to_hostname[&ip("192.168.64.2")], "macbook");
        assert_eq!(leases.mac_to_hostname[&mac], "macbook");
        // Past lease.
        assert!(!leases.ip_to_mac.contains_key(&ip("192.168.64.3")));
        // No lease line: 0, kept.
        assert_eq!(leases.ip_to_mac.get(&ip("192.168.64.4")), Some(&MAC_B));
        // Not hardware type 1.
        assert!(!leases.ip_to_mac.contains_key(&ip("192.168.64.5")));
        assert!(!leases.ip_to_hostname.contains_key(&ip("192.168.64.5")));
        // Octets without their leading zeros: net.ParseMAC refuses the MAC,
        // so the lease is left out, as in sing-box.
        assert!(!leases.ip_to_mac.contains_key(&ip("192.168.64.6")));
    }

    #[test]
    fn format_is_chosen_by_file_name() {
        let kea = "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state\n\
                   192.0.2.1,00:11:22:33:44:55,,4000,1700004000,1,0,0,printer,0\n";
        // Kea text under a name that is not Kea's is read as dnsmasq, which
        // finds nothing in it.
        let other = TempFile::new("leases.csv", kea);
        assert_eq!(read_at(&[&other], NOW), Leases::default());
        let named = TempFile::new("kea-leases4.csv", kea);
        assert_eq!(
            read_at(&[&named], NOW).ip_to_hostname[&ip("192.0.2.1")],
            "printer"
        );
        // Only the ending counts: an odhcpd file named `odhcpd.leases` ends
        // with `dhcpd.leases` and is read as ISC dhcpd, finding nothing.
        let odhcpd = "# br-lan 00:11:22:33:44:55 ipv4 laptop -1 5 32 192.168.1.30/24\n";
        assert_eq!(
            read_at(&[&TempFile::new("odhcpd.leases", odhcpd)], NOW),
            Leases::default()
        );
        assert_eq!(
            read_at(&[&TempFile::new("odhcpd", odhcpd)], NOW).ip_to_mac[&ip("192.168.1.30")],
            MAC_A
        );
    }

    #[test]
    fn later_file_wins_and_missing_files_are_skipped() {
        let first = TempFile::new("a.leases", "0 00:11:22:33:44:55 10.1.0.1 first *\n");
        let second = TempFile::new("b.leases", "0 aa:bb:cc:dd:ee:ff 10.1.0.1 second *\n");
        let missing = first.dir.join("does-not-exist");
        let leases = read_lease_files(&[first.path.clone(), missing, second.path.clone()]);
        assert_eq!(leases.ip_to_mac.get(&ip("10.1.0.1")), Some(&MAC_B));
        assert_eq!(leases.ip_to_hostname[&ip("10.1.0.1")], "second");
        // The first file's MAC keeps its name.
        assert_eq!(leases.mac_to_hostname[&MAC_A], "first");
    }

    #[test]
    fn read_lease_files_uses_the_clock() {
        // Far past and far future, so the test does not depend on when it runs.
        let file = TempFile::new(
            "dhcp.leases",
            "1000 00:11:22:33:44:55 10.2.0.1 past *\n\
             99999999999 aa:bb:cc:dd:ee:ff 10.2.0.2 future *\n",
        );
        let leases = read_lease_files(std::slice::from_ref(&file.path));
        assert!(!leases.ip_to_mac.contains_key(&ip("10.2.0.1")));
        assert_eq!(leases.ip_to_mac.get(&ip("10.2.0.2")), Some(&MAC_B));
    }

    #[test]
    fn crlf_lines_and_mapped_addresses() {
        let file = TempFile::new(
            "dhcp.leases",
            "0 00:11:22:33:44:55 ::ffff:10.3.0.1 host\r\n",
        );
        let leases = read_at(&[&file], NOW);
        // The IPv4-mapped address is kept as IPv4, and `\r` is not in the name.
        assert_eq!(
            leases.ip_to_hostname[&IpAddr::V4(Ipv4Addr::new(10, 3, 0, 1))],
            "host"
        );
    }

    #[test]
    fn default_lease_files_exist_and_are_not_empty() {
        for path in default_lease_files() {
            assert!(DEFAULT_LEASE_FILES
                .iter()
                .any(|known| Path::new(known) == path));
            assert!(std::fs::metadata(&path).expect("listed file exists").len() > 0);
        }
    }

    #[test]
    fn mac_parsing() {
        assert_eq!(parse_mac("00:11:22:33:44:55"), Some(MAC_A));
        assert_eq!(parse_mac("AA-BB-CC-DD-EE-FF"), Some(MAC_B));
        assert_eq!(parse_mac("0011.2233.4455"), Some(MAC_A));
        assert_eq!(parse_mac("00:11-22:33:44:55"), None);
        assert_eq!(parse_mac("00:11:22:33:44:5g"), None);
        assert_eq!(parse_mac("0:11:22:33:44:55"), None);
        assert_eq!(parse_mac("0011.2233-4455"), None);
        // 8-byte EUI-64, which Go accepts, is refused.
        assert_eq!(parse_mac("00:11:22:33:44:55:66:77"), None);
        assert_eq!(parse_mac(""), None);
    }

    #[test]
    fn eui64() {
        let slaac = ip("fe80::211:22ff:fe33:4455");
        assert_eq!(mac_from_eui64(&slaac), Some(MAC_A));
        // The universal/local bit is flipped back.
        let local = ip("2001:db8::a8bb:ccff:fedd:eeff");
        assert_eq!(mac_from_eui64(&local), Some(MAC_B));
        assert_eq!(mac_from_eui64(&ip("2001:db8::1")), None);
        assert_eq!(mac_from_eui64(&ip("2001:db8::211:22ff:ff33:4455")), None);
        assert_eq!(mac_from_eui64(&ip("192.168.1.1")), None);
    }

    #[test]
    fn duid() {
        let llt = [
            0, 1, 0, 1, 0x2a, 0x2b, 0x2c, 0x2d, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        ];
        assert_eq!(mac_from_duid(&llt), Some(MAC_A));
        let ll = [0, 3, 0, 1, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        assert_eq!(mac_from_duid(&ll), Some(MAC_B));
        // Too short for its type.
        assert_eq!(mac_from_duid(&llt[..13]), None);
        assert_eq!(mac_from_duid(&ll[..9]), None);
        // Not Ethernet.
        assert_eq!(
            mac_from_duid(&[0, 3, 0, 6, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            None
        );
        // Enterprise and UUID DUIDs carry no MAC.
        assert_eq!(
            mac_from_duid(&[0, 2, 0, 1, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            None
        );
        assert_eq!(
            mac_from_duid(&[0, 4, 0, 1, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            None
        );
        assert_eq!(mac_from_duid(&[0, 3, 0]), None);
    }

    #[test]
    fn hex_decoding() {
        assert_eq!(decode_hex("00aAfF"), Some(vec![0x00, 0xaa, 0xff]));
        assert_eq!(decode_hex("abc"), None);
        assert_eq!(decode_hex("zz"), None);
        assert_eq!(decode_hex(""), Some(vec![]));
    }

    #[test]
    fn hostname_lookup() {
        let v6_global = ip("2001:db8::5");
        let v6_link = ip("fe80::5");
        let mut ip_to_hostname = HashMap::new();
        ip_to_hostname.insert(ip("10.0.0.1"), "Laptop".to_owned());
        ip_to_hostname.insert(v6_link, "laptop".to_owned());
        ip_to_hostname.insert(ip("10.0.0.9"), "other".to_owned());
        ip_to_hostname.insert(ip("10.0.0.8"), "laptop.lan.".to_owned());
        let mut mac_to_hostname = HashMap::new();
        mac_to_hostname.insert(MAC_A, "LAPTOP".to_owned());
        mac_to_hostname.insert(MAC_B, "other".to_owned());
        let mut neighbors = HashMap::new();
        neighbors.insert(v6_global, MAC_A);
        neighbors.insert(ip("10.0.0.1"), MAC_A);
        neighbors.insert(ip("10.0.0.9"), MAC_B);
        let mut lease_macs = HashMap::new();
        lease_macs.insert(ip("10.0.0.2"), MAC_A);
        lease_macs.insert(ip("fe80::6"), MAC_A);

        let lookup = |name: &str| {
            addresses_by_hostname(
                name,
                &ip_to_hostname,
                &mac_to_hostname,
                &neighbors,
                &lease_macs,
            )
        };
        // Case is ignored; link-local IPv6 is left out; 10.0.0.1 is found by
        // name and by MAC but listed once; the trailing dot is dropped.
        let found = lookup("laptop.");
        assert_eq!(found.len(), 3);
        assert_eq!(
            sorted(found),
            sorted(vec![ip("10.0.0.1"), ip("10.0.0.2"), v6_global])
        );
        assert!(lookup("").is_empty());
        assert!(lookup(".").is_empty());
        assert!(lookup("nobody").is_empty());
        // Names in the tables keep their trailing dot, and only one dot is
        // dropped from the query.
        assert!(lookup("laptop.lan").is_empty());
        assert_eq!(lookup("laptop.lan.."), vec![ip("10.0.0.8")]);
        assert_eq!(lookup("OTHER"), vec![ip("10.0.0.9")]);
    }

    #[test]
    fn fqdn_and_scope_helpers() {
        assert_eq!(fqdn_to_domain("a.b."), "a.b");
        assert_eq!(fqdn_to_domain("a.b"), "a.b");
        assert_eq!(fqdn_to_domain(r"a\."), r"a\.");
        assert_eq!(fqdn_to_domain(r"a\\."), r"a\\");
        assert!(equal_fold("Straße", "STRAßE"));
        assert!(equal_fold("ÉCOLE", "école"));
        assert!(!equal_fold("host", "hosts"));
        assert!(is_scoped_ipv6_address(&ip("fe80::1")));
        assert!(is_scoped_ipv6_address(&ip("febf::1")));
        assert!(!is_scoped_ipv6_address(&ip("fec0::1")));
        assert!(is_scoped_ipv6_address(&IpAddr::V6(
            Ipv4Addr::new(169, 254, 1, 1).to_ipv6_mapped()
        )));
        assert!(!is_scoped_ipv6_address(&ip("169.254.1.1")));
        assert!(!is_scoped_ipv6_address(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }
}
