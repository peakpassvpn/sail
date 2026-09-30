//! The system's DNS servers, for a `local` server with dial fields: sail
//! asks them itself, through its dialer, as sing-box's local server does
//! off Apple's systems (dns/transport/local: `dnsReadConfig`, then
//! `exchangeOne` through its dialer). Without dial fields a local server
//! is the system's resolver, which knows them itself.
//!
//! - Unix: `nameserver` lines of /etc/resolv.conf; where they are only
//!   systemd-resolved's stub (127.0.0.53, 127.0.0.54), the servers it
//!   forwards to, in /run/systemd/resolve/resolv.conf: a detour could not
//!   reach the stub, which listens on the host.
//! - Windows: the DNS servers of the adapters that are up and have a
//!   gateway, as IP Helper tells them.
//!
//! Read again at most every 5 s, as Go's resolver reads resolv.conf.

use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};

/// How long what was read is taken: Go's (net/dnsclient_unix.go).
const REREAD: Duration = Duration::from_secs(5);

/// The servers, as last read.
#[derive(Default)]
pub(super) struct SystemServers {
    read: Mutex<Option<(Instant, Vec<SocketAddr>)>>,
}

impl SystemServers {
    /// Takes `servers` as the system's, for good.
    #[cfg(test)]
    pub(super) fn set(&self, servers: Vec<SocketAddr>) {
        *self.read.lock().unwrap_or_else(|e| e.into_inner()) =
            Some((Instant::now() + Duration::from_secs(86400), servers));
    }

    /// The system's DNS servers now; an error when it has none.
    pub(super) fn get(&self) -> Result<Vec<SocketAddr>> {
        let mut read = self.read.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((at, servers)) = read.as_ref() {
            if at.elapsed() < REREAD {
                return Ok(servers.clone());
            }
        }
        let servers: Vec<SocketAddr> = servers()
            .into_iter()
            // A link-local IPv6 server needs a scope the files do not tell.
            .filter(|ip| !matches!(ip, IpAddr::V6(v6) if (v6.segments()[0] & 0xffc0) == 0xfe80))
            .map(|ip| SocketAddr::new(ip, 53))
            .collect();
        *read = Some((Instant::now(), servers.clone()));
        if servers.is_empty() {
            return Err(anyhow!("the system has no DNS server to ask"));
        }
        Ok(servers)
    }
}

/// The `nameserver` addresses of a resolv.conf.
#[cfg_attr(not(unix), allow(dead_code))]
fn nameservers(text: &str) -> Vec<IpAddr> {
    text.lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            (words.next() == Some("nameserver"))
                .then(|| words.next()?.split('%').next()?.parse().ok())
                .flatten()
        })
        .collect()
}

/// Whether `ips` are only systemd-resolved's stub.
#[cfg_attr(not(unix), allow(dead_code))]
fn only_resolved_stub(ips: &[IpAddr]) -> bool {
    let stub = |ip: &IpAddr| {
        ["127.0.0.53", "127.0.0.54"]
            .iter()
            .any(|s| s.parse::<IpAddr>().ok() == Some(*ip))
    };
    !ips.is_empty() && ips.iter().all(stub)
}

#[cfg(unix)]
fn servers() -> Vec<IpAddr> {
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
fn servers() -> Vec<IpAddr> {
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
            if a.OperStatus != IfOperStatusUp || a.FirstGatewayAddress.is_null() {
                continue;
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
                        ips.push(IpAddr::from(v4.sin_addr.S_un.S_addr.to_ne_bytes()));
                    }
                    AF_INET6 => {
                        let v6 = &*(sockaddr as *const SOCKADDR_IN6);
                        ips.push(IpAddr::from(v6.sin6_addr.u.Byte));
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
fn servers() -> Vec<IpAddr> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nameservers_are_read_as_resolv_conf_has_them() {
        let text = "# generated\nsearch lan\nnameserver 192.168.1.1\nnameserver fe80::1%en0\n\
                    nameserver  2001:db8::53 \noptions ndots:1\nnameserver bad\n";
        assert_eq!(
            nameservers(text),
            [
                "192.168.1.1".parse::<IpAddr>().unwrap(),
                "fe80::1".parse().unwrap(),
                "2001:db8::53".parse().unwrap()
            ]
        );
        assert!(only_resolved_stub(&nameservers("nameserver 127.0.0.53\n")));
        assert!(!only_resolved_stub(&nameservers(
            "nameserver 127.0.0.53\nnameserver 1.1.1.1\n"
        )));
        assert!(!only_resolved_stub(&[]));
    }

    /// Whatever the host has, what is read is servers on port 53, none
    /// link-local.
    #[test]
    fn the_host_s_servers_are_read() {
        if let Ok(servers) = SystemServers::default().get() {
            for server in servers {
                assert_eq!(server.port(), 53);
                assert!(
                    !matches!(server.ip(), IpAddr::V6(v6) if (v6.segments()[0] & 0xffc0) == 0xfe80)
                );
            }
        }
    }
}
