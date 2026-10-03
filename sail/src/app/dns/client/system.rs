//! The system's DNS servers, for a `local` server with dial fields, or
//! one whose instance's default dialer binds its sockets: sail asks them
//! itself, through its dialer, as sing-box's local server does off
//! Apple's systems (dns/transport/local: `dnsReadConfig`, then
//! `exchangeOne` through its dialer). Otherwise a local server is the
//! system's resolver, which knows them itself.
//!
//! - Unix: `nameserver` lines of /etc/resolv.conf; where they are only
//!   systemd-resolved's stub (127.0.0.53, 127.0.0.54), the servers it
//!   forwards to, in /run/systemd/resolve/resolv.conf: a detour could not
//!   reach the stub, which listens on the host.
//! - macOS, where the dialer sends through an interface: that interface's
//!   servers, as the dynamic store has them (system_macos.rs), not the
//!   primary service's, which another VPN may be.
//! - Windows: the DNS servers of the adapter the dialer sends through, or,
//!   where it sends by the default route, of the adapters that are up and
//!   have a gateway, as IP Helper tells them.
//!
//! Read again at most every 5 s, as Go's resolver reads resolv.conf, every
//! second while none is found, and after the network changed. Servers on sail's own TUNs' networks are
//! left out: auto_route gives a TUN a DNS server of its own (resolved's,
//! the adapter's), which a query sent past the TUN cannot reach. So are
//! the site-local servers Windows lists for an adapter without any
//! (fec0:0:0:ffff::1-3).

use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};

/// How long what was read is taken: Go's (net/dnsclient_unix.go).
const REREAD: Duration = Duration::from_secs(5);
/// How long a read that found no server is taken: the servers may come a
/// moment later (DHCP), with nothing changing that would say so.
const REREAD_EMPTY: Duration = Duration::from_secs(1);

/// The servers asked at most, as sing-box takes them from resolv.conf
/// (`len(conf.servers) < 3`).
const MAX_SERVERS: usize = 3;

/// The least time a server is given: with a shorter query, fewer servers
/// are asked rather than the query taking longer.
const MIN_SHARE: Duration = Duration::from_secs(1);

/// How many of `n` servers a query of `budget` asks, in order, each with
/// an even share of the time left: at most three, each with a second at
/// least, and one in any case. sing-box gives each server resolv.conf's
/// `timeout` (5 s) instead, so that with a 10 s query a third is never
/// asked.
pub(super) fn servers_asked(budget: Duration, n: usize) -> usize {
    let fit = (budget.as_millis() / MIN_SHARE.as_millis()) as usize;
    n.min(MAX_SERVERS).min(fit.max(1))
}

#[cfg(target_os = "macos")]
#[path = "system_macos.rs"]
mod macos;

/// The interface whose servers are asked: the one the instance's dialer
/// sends through, as it is when a query is asked.
#[derive(Clone, Default)]
pub(super) enum Interface {
    /// The default route, whichever interface it takes.
    #[default]
    Any,
    /// `route.default_interface`.
    Fixed(String),
    /// What `auto_detect_interface` follows.
    Auto(std::sync::Arc<crate::net::interface::AutoInterface>),
}

impl Interface {
    /// The interface's name now; none for the default route, or when
    /// there is no interface to send through.
    pub(super) fn now(&self) -> Option<String> {
        match self {
            Interface::Any => None,
            Interface::Fixed(name) => Some(name.clone()),
            Interface::Auto(auto) => auto.current(),
        }
    }
}

/// The servers, as last read, and the interface they are of.
#[derive(Default)]
pub(super) struct SystemServers {
    read: Mutex<Option<Read>>,
}

struct Read {
    at: Instant,
    interface: Option<String>,
    servers: Vec<SocketAddr>,
}

impl Read {
    /// Whether it is taken as it is for `interface`: of that interface,
    /// and read within 5 s, or within a second if it found no server.
    fn fresh(&self, interface: Option<&str>) -> bool {
        let keep = if self.servers.is_empty() {
            REREAD_EMPTY
        } else {
            REREAD
        };
        self.at.elapsed() < keep && self.interface.as_deref() == interface
    }
}

impl SystemServers {
    /// Takes `servers` as the system's, for good.
    #[cfg(test)]
    pub(super) fn set(&self, servers: Vec<SocketAddr>) {
        *self.read.lock().unwrap_or_else(|e| e.into_inner()) = Some(Read {
            at: Instant::now() + Duration::from_secs(86400),
            interface: None,
            servers,
        });
    }

    /// Forgets what was read: the network changed, and the next query
    /// reads the servers again.
    pub(super) fn forget(&self) {
        *self.read.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    /// The system's DNS servers now, those of `interface` where the
    /// system tells them by interface, but those on the networks of the
    /// interfaces `own` (sail's TUNs); an error at once when no other is
    /// left, with no fallback to the system's resolver or to a server on
    /// this host.
    pub(super) fn get(&self, own: &[String], interface: Option<&str>) -> Result<Vec<SocketAddr>> {
        let servers = {
            let mut read = self.read.lock().unwrap_or_else(|e| e.into_inner());
            match read.as_ref() {
                Some(r) if r.fresh(interface) => r.servers.clone(),
                _ => {
                    let servers: Vec<SocketAddr> = servers(interface)
                        .into_iter()
                        .filter_map(|listed| listed.address(interface))
                        .collect();
                    *read = Some(Read {
                        at: Instant::now(),
                        interface: interface.map(str::to_owned),
                        servers: servers.clone(),
                    });
                    servers
                }
            }
        };
        let servers: Vec<SocketAddr> = servers
            .into_iter()
            .filter(|s| !crate::net::interface::on_interfaces(own, s.ip()))
            .collect();
        if servers.is_empty() {
            return Err(match interface {
                Some(interface) => anyhow!("the system has no DNS server to ask on {}", interface),
                None => anyhow!("the system has no DNS server to ask"),
            });
        }
        Ok(servers)
    }
}

/// A server as the system lists it, with the interface a link-local one
/// is reached on when the system says (`fe80::1%en0`, a scope ID).
#[derive(Clone, Debug, PartialEq)]
pub(super) struct Listed {
    pub ip: IpAddr,
    pub zone: Option<Zone>,
}

#[derive(Clone, Debug, PartialEq)]
pub(super) enum Zone {
    Name(String),
    Index(u32),
}

impl Listed {
    /// `fe80::1%en0`, `fe80::1%4`, `192.0.2.1`.
    pub(super) fn parse(text: &str) -> Option<Listed> {
        let (ip, zone) = match text.split_once('%') {
            Some((ip, zone)) => (ip, Some(zone)),
            None => (text, None),
        };
        Some(Listed {
            ip: ip.parse().ok()?,
            zone: zone.filter(|z| !z.is_empty()).map(|z| match z.parse() {
                Ok(index) => Zone::Index(index),
                Err(_) => Zone::Name(z.to_owned()),
            }),
        })
    }

    /// Where it is asked, port 53: a link-local server on its zone's
    /// interface, or on `interface` (the dialer's) when the system names
    /// none, and left out when neither is known, as sing-box keeps one
    /// with its zone. Not the site-local servers Windows lists for an
    /// adapter without any (fec0::/10).
    fn address(&self, interface: Option<&str>) -> Option<SocketAddr> {
        let v6 = match self.ip {
            IpAddr::V4(_) => return Some(SocketAddr::new(self.ip, 53)),
            IpAddr::V6(v6) => v6,
        };
        let scope = match v6.segments()[0] & 0xffc0 {
            0xfec0 => return None,
            0xfe80 => {
                let scope = match &self.zone {
                    Some(Zone::Index(index)) => *index,
                    Some(Zone::Name(name)) => index_of(name)?,
                    None => index_of(interface?)?,
                };
                if scope == 0 {
                    return None;
                }
                scope
            }
            _ => 0,
        };
        Some(SocketAddr::V6(std::net::SocketAddrV6::new(
            v6, 53, 0, scope,
        )))
    }
}

/// The index of the interface `name`.
#[cfg(unix)]
fn index_of(name: &str) -> Option<u32> {
    let name = std::ffi::CString::new(name).ok()?;
    // SAFETY: a NUL-terminated string, read only.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    (index != 0).then_some(index)
}

/// Windows gives each link-local server its scope ID itself.
#[cfg(not(unix))]
fn index_of(_: &str) -> Option<u32> {
    None
}

/// The `nameserver` addresses of a resolv.conf.
#[cfg_attr(not(unix), allow(dead_code))]
fn nameservers(text: &str) -> Vec<Listed> {
    text.lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            (words.next() == Some("nameserver"))
                .then(|| Listed::parse(words.next()?))
                .flatten()
        })
        .collect()
}

/// Whether `listed` are only systemd-resolved's stub.
#[cfg_attr(not(unix), allow(dead_code))]
fn only_resolved_stub(listed: &[Listed]) -> bool {
    let stub = |l: &Listed| {
        ["127.0.0.53", "127.0.0.54"]
            .iter()
            .any(|s| s.parse::<IpAddr>().ok() == Some(l.ip))
    };
    !listed.is_empty() && listed.iter().all(stub)
}

/// The servers of `interface`, where the system tells them by interface.
#[cfg(target_os = "macos")]
fn servers(interface: Option<&str>) -> Vec<Listed> {
    match interface {
        Some(interface) => macos::servers_of(interface),
        None => resolv_conf(),
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
fn servers(_: Option<&str>) -> Vec<Listed> {
    resolv_conf()
}

#[cfg(unix)]
fn resolv_conf() -> Vec<Listed> {
    let read = |path: &str| std::fs::read_to_string(path).map(|t| nameservers(&t));
    match read("/etc/resolv.conf") {
        Ok(ips) if only_resolved_stub(&ips) => {
            read("/run/systemd/resolve/resolv.conf").unwrap_or(ips)
        }
        Ok(ips) => ips,
        Err(_) => Vec::new(),
    }
}

#[cfg(windows)]
fn servers(interface: Option<&str>) -> Vec<Listed> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST,
        GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows_sys::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6,
    };

    let flags = GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;
    let mut size: u32 = 16 * 1024;
    let mut buf: Vec<u64> = Vec::new();
    for _ in 0..3 {
        buf = vec![0u64; (size as usize).div_ceil(8)];
        // SAFETY: the buffer is as long as `size` says, and aligned for the
        // structures written into it.
        let code = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                flags,
                std::ptr::null(),
                buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                &mut size,
            )
        };
        match code {
            0 => break,
            // ERROR_BUFFER_OVERFLOW: `size` is now what it needs.
            111 => continue,
            _ => return Vec::new(),
        }
    }
    let mut ips = Vec::new();
    let mut adapter = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    // SAFETY: a list GetAdaptersAddresses wrote into `buf`, which outlives
    // the walk; each pointer is null or to a node within it.
    unsafe {
        while !adapter.is_null() {
            let a = &*adapter;
            adapter = a.Next;
            if a.OperStatus != IfOperStatusUp {
                continue;
            }
            match interface {
                // The adapter the dialer sends through, by the name it
                // goes by (its alias).
                Some(interface) => {
                    if a.FriendlyName.is_null() {
                        continue;
                    }
                    let len = (0..).take_while(|&i| *a.FriendlyName.add(i) != 0).count();
                    let name =
                        String::from_utf16_lossy(std::slice::from_raw_parts(a.FriendlyName, len));
                    if name != interface {
                        continue;
                    }
                }
                None if a.FirstGatewayAddress.is_null() => continue,
                None => {}
            }
            let mut dns = a.FirstDnsServerAddress;
            while !dns.is_null() {
                let sockaddr = (*dns).Address.lpSockaddr;
                dns = (*dns).Next;
                if sockaddr.is_null() {
                    continue;
                }
                match (*sockaddr).sa_family {
                    AF_INET => {
                        let v4 = &*(sockaddr as *const SOCKADDR_IN);
                        ips.push(Listed {
                            ip: IpAddr::from(v4.sin_addr.S_un.S_addr.to_ne_bytes()),
                            zone: None,
                        });
                    }
                    AF_INET6 => {
                        let v6 = &*(sockaddr as *const SOCKADDR_IN6);
                        let scope = v6.Anonymous.sin6_scope_id;
                        ips.push(Listed {
                            ip: IpAddr::from(v6.sin6_addr.u.Byte),
                            zone: (scope != 0).then_some(Zone::Index(scope)),
                        });
                    }
                    _ => {}
                }
            }
        }
    }
    ips.dedup();
    ips
}

#[cfg(not(any(unix, windows)))]
fn servers(_: Option<&str>) -> Vec<IpAddr> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nameservers_are_read_as_resolv_conf_has_them() {
        let text = "# generated\nsearch lan\nnameserver 192.168.1.1\nnameserver fe80::1%en0\n\
                    nameserver  2001:db8::53 \noptions ndots:1\nnameserver bad\n";
        let listed = |ip: &str, zone: Option<Zone>| Listed {
            ip: ip.parse().unwrap(),
            zone,
        };
        assert_eq!(
            nameservers(text),
            [
                listed("192.168.1.1", None),
                listed("fe80::1", Some(Zone::Name("en0".into()))),
                listed("2001:db8::53", None),
            ]
        );
        assert_eq!(
            Listed::parse("fe80::1%4"),
            Some(listed("fe80::1", Some(Zone::Index(4))))
        );
        assert!(only_resolved_stub(&nameservers("nameserver 127.0.0.53\n")));
        assert!(!only_resolved_stub(&nameservers(
            "nameserver 127.0.0.53\nnameserver 1.1.1.1\n"
        )));
        assert!(!only_resolved_stub(&[]));
    }

    /// Whatever the host has, what is read is servers on port 53, none
    /// site-local, and a link-local one with the interface it is on.
    #[test]
    fn the_host_s_servers_are_read() {
        if let Ok(servers) = SystemServers::default().get(&[], None) {
            for server in servers {
                assert_eq!(server.port(), 53);
                if let SocketAddr::V6(v6) = server {
                    let prefix = v6.ip().segments()[0] & 0xffc0;
                    assert_ne!(prefix, 0xfec0);
                    assert!(prefix != 0xfe80 || v6.scope_id() != 0, "{}", v6);
                }
            }
        }
    }

    /// A link-local server is asked on its zone's interface, or the
    /// dialer's when the system names none, and left out when neither is
    /// known; a site-local one is left out.
    #[cfg(unix)]
    #[test]
    fn a_link_local_server_is_asked_on_its_interface() {
        let loopback = if cfg!(target_os = "macos") {
            "lo0"
        } else {
            "lo"
        };
        let index = index_of(loopback).unwrap();
        let scope = |listed: Listed, interface: Option<&str>| match listed.address(interface) {
            Some(SocketAddr::V6(v6)) => Some(v6.scope_id()),
            other => panic!("{:?}", other),
        };
        let parse = |s: &str| Listed::parse(s).unwrap();
        assert_eq!(
            scope(parse(&format!("fe80::1%{loopback}")), None),
            Some(index)
        );
        assert_eq!(scope(parse("fe80::1%7"), None), Some(7));
        assert_eq!(scope(parse("fe80::1"), Some(loopback)), Some(index));
        assert_eq!(parse("fe80::1").address(None), None);
        assert_eq!(parse("fe80::1%no-such-interface0").address(None), None);
        assert_eq!(parse("fec0:0:0:ffff::1").address(None), None);
        assert_eq!(scope(parse("2001:db8::53"), None), Some(0));
        assert_eq!(
            parse("192.0.2.1").address(Some(loopback)),
            Some("192.0.2.1:53".parse().unwrap())
        );
    }

    /// A server on the network of one of sail's own interfaces is left
    /// out, and with none left the answer is an error at once.
    #[cfg(unix)]
    #[test]
    fn servers_on_sail_s_own_interfaces_are_left_out() {
        let Some((network, _, name)) = crate::net::interface::subnets()
            .unwrap()
            .into_iter()
            .find(|(network, ..)| network.is_ipv4())
        else {
            return;
        };
        let on = SocketAddr::new(network, 53);
        let other: SocketAddr = "192.0.2.1:53".parse().unwrap();
        let servers = SystemServers::default();
        servers.set(vec![on, other]);
        assert_eq!(servers.get(&[], None).unwrap(), [on, other]);
        assert_eq!(
            servers.get(std::slice::from_ref(&name), None).unwrap(),
            [other]
        );
        servers.set(vec![on]);
        assert!(servers.get(&[name], None).is_err());
    }

    /// After the network changed, the servers are read again.
    #[test]
    fn a_change_of_network_reads_them_again() {
        let set: SocketAddr = "192.0.2.1:53".parse().unwrap();
        let servers = SystemServers::default();
        servers.set(vec![set]);
        assert_eq!(servers.get(&[], None).unwrap(), [set]);
        servers.forget();
        assert!(!servers.get(&[], None).unwrap_or_default().contains(&set));
    }

    /// A read that found no server is read again after a second, one that
    /// found some after 5 s, and one of another interface at once.
    #[test]
    fn what_was_read_is_taken_for_a_while() {
        let read = |age: u64, servers: Vec<SocketAddr>| Read {
            at: Instant::now() - Duration::from_millis(age),
            interface: Some("en0".into()),
            servers,
        };
        let some = vec!["192.0.2.1:53".parse().unwrap()];
        assert!(read(1500, some.clone()).fresh(Some("en0")));
        assert!(!read(6000, some.clone()).fresh(Some("en0")));
        assert!(!read(0, some).fresh(Some("en1")));
        assert!(read(500, vec![]).fresh(Some("en0")));
        assert!(!read(1500, vec![]).fresh(Some("en0")));
    }
}
