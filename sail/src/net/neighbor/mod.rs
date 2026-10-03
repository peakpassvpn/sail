//! The devices on the LAN, by address: their MAC addresses from the
//! system's neighbor table and DHCP leases, and their host names from the
//! leases, as sing-box's neighbor resolver has them (route/neighbor_*.go).
//! For `source_mac_address` and `source_hostname` rules, and a local DNS
//! server's `neighbor_domain`.

pub(crate) mod lease;
pub(crate) mod table;

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use tracing::{debug, warn};

use lease::Leases;
pub(crate) use lease::Mac;

/// How often the lease files are looked at for a change: judgment, as
/// sing-box watches them (fswatch) and a device's name may take this long
/// to be known; looking costs a stat of each file.
const LEASE_POLL: Duration = Duration::from_secs(5);

/// A LAN device, as the resolver knows it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Neighbor {
    pub mac: Option<Mac>,
    pub hostname: Option<String>,
}

impl Neighbor {
    /// The MAC address as sing-box writes it (Go's net.HardwareAddr):
    /// lower case, colon-separated.
    pub fn mac_string(&self) -> Option<String> {
        self.mac.map(|m| format_mac(&m))
    }
}

/// `mac` in lower case, colon-separated.
pub(crate) fn format_mac(mac: &Mac) -> String {
    mac.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":")
}

#[derive(Default)]
struct Tables {
    neighbor_ip_to_mac: HashMap<IpAddr, Mac>,
    leases: Leases,
}

/// sing-box's neighborResolver: the neighbor table as the system reports
/// it, followed as it changes, and the lease files, read again as they
/// change.
pub struct NeighborResolver {
    tables: RwLock<Tables>,
    tasks: Vec<tokio::task::AbortHandle>,
}

impl NeighborResolver {
    /// Reads the neighbor table and `lease_files` (the platform's usual
    /// ones when none are given), and follows both. Needs a tokio runtime.
    pub fn start(lease_files: &[PathBuf]) -> Arc<NeighborResolver> {
        let lease_files = if lease_files.is_empty() {
            lease::default_lease_files()
        } else {
            lease_files.to_vec()
        };
        // Followed before it is read, so that no change between is lost,
        // as sing-box loses it.
        let events = table::watch_neighbors();
        let mut tables = Tables {
            leases: lease::read_lease_files(&lease_files),
            ..Default::default()
        };
        match table::read_neighbors() {
            Ok(entries) => tables.neighbor_ip_to_mac.extend(entries),
            Err(e) => warn!("neighbor: cannot read the neighbor table: {}", e),
        }
        debug!(
            "neighbor: {} neighbors, {} leases from {:?}",
            tables.neighbor_ip_to_mac.len(),
            tables.leases.ip_to_mac.len(),
            lease_files
        );
        Arc::new_cyclic(|me: &std::sync::Weak<NeighborResolver>| {
            let mut tasks = Vec::new();
            match events {
                Ok(mut events) => {
                    let me = me.clone();
                    tasks.push(
                        crate::runtime::scope::spawn_essential("neighbor events", async move {
                            while let Some(event) = events.recv().await {
                                let Some(me) = me.upgrade() else { return };
                                me.apply(event);
                            }
                        })
                        .abort_handle(),
                    );
                }
                Err(e) => warn!("neighbor: cannot follow the neighbor table: {}", e),
            }
            if !lease_files.is_empty() {
                let me = me.clone();
                tasks.push(
                    crate::runtime::scope::spawn_essential("neighbor lease watch", async move {
                        let mut seen = stamps(&lease_files);
                        loop {
                            tokio::time::sleep(LEASE_POLL).await;
                            let now = stamps(&lease_files);
                            if now == seen {
                                continue;
                            }
                            seen = now;
                            let leases = lease::read_lease_files(&lease_files);
                            let Some(me) = me.upgrade() else { return };
                            me.tables.write().unwrap_or_else(|e| e.into_inner()).leases = leases;
                            debug!("neighbor: lease files read again");
                        }
                    })
                    .abort_handle(),
                );
            }
            NeighborResolver {
                tables: RwLock::new(tables),
                tasks,
            }
        })
    }

    fn apply(&self, event: table::NeighborEvent) {
        let mut tables = self.tables.write().unwrap_or_else(|e| e.into_inner());
        match event {
            table::NeighborEvent::Add(ip, mac) => {
                tables.neighbor_ip_to_mac.insert(ip, mac);
            }
            table::NeighborEvent::Delete(ip) => {
                tables.neighbor_ip_to_mac.remove(&ip);
            }
        }
    }

    /// sing-box's LookupMAC: the neighbor table's, the leases', or the one
    /// an EUI-64 IPv6 address holds.
    pub fn lookup_mac(&self, ip: IpAddr) -> Option<Mac> {
        let ip = ip.to_canonical();
        let tables = self.tables.read().unwrap_or_else(|e| e.into_inner());
        mac_of(&tables, &ip)
    }

    /// sing-box's LookupHostname: the lease's name for the address, or for
    /// its MAC address.
    pub fn lookup_hostname(&self, ip: IpAddr) -> Option<String> {
        let ip = ip.to_canonical();
        let tables = self.tables.read().unwrap_or_else(|e| e.into_inner());
        if let Some(name) = tables.leases.ip_to_hostname.get(&ip) {
            return Some(name.clone());
        }
        let mac = mac_of(&tables, &ip)?;
        tables.leases.mac_to_hostname.get(&mac).cloned()
    }

    /// sing-box's LookupAddresses: the addresses of the device `hostname`.
    pub fn lookup_addresses(&self, hostname: &str) -> Vec<IpAddr> {
        let tables = self.tables.read().unwrap_or_else(|e| e.into_inner());
        lease::addresses_by_hostname(
            hostname,
            &tables.leases.ip_to_hostname,
            &tables.leases.mac_to_hostname,
            &tables.neighbor_ip_to_mac,
            &tables.leases.ip_to_mac,
        )
    }

    /// The device at `ip`, when anything is known of it.
    pub fn neighbor(&self, ip: IpAddr) -> Option<Neighbor> {
        let mac = self.lookup_mac(ip);
        // An empty name is none, as sing-box's source_hostname takes it.
        let hostname = self.lookup_hostname(ip).filter(|h| !h.is_empty());
        (mac.is_some() || hostname.is_some()).then_some(Neighbor { mac, hostname })
    }

    #[cfg(test)]
    pub(crate) fn with(neighbors: HashMap<IpAddr, Mac>, leases: Leases) -> NeighborResolver {
        NeighborResolver {
            tables: RwLock::new(Tables {
                neighbor_ip_to_mac: neighbors,
                leases,
            }),
            tasks: Vec::new(),
        }
    }
}

impl Drop for NeighborResolver {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// The instance's resolver: started the first time a configuration needs
/// it, and kept across reloads, as the lease files it reads are the ones
/// it started with.
#[derive(Clone, Default)]
pub struct Neighbors(Arc<std::sync::OnceLock<Arc<NeighborResolver>>>);

impl std::fmt::Debug for Neighbors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.0.get().is_some() {
            "Neighbors(started)"
        } else {
            "Neighbors"
        })
    }
}

impl Neighbors {
    /// The resolver, once started.
    pub fn get(&self) -> Option<&Arc<NeighborResolver>> {
        self.0.get()
    }

    /// Runs `resolver`, in place of the system's tables.
    #[cfg(test)]
    pub(crate) fn set(&self, resolver: NeighborResolver) {
        let _ = self.0.set(Arc::new(resolver));
    }

    /// Starts the resolver if `config` needs it and it is not running.
    /// Needs a tokio runtime.
    pub fn start_if_needed(&self, config: &crate::config::Config) {
        if !needed(config) || self.0.get().is_some() {
            return;
        }
        let files: Vec<PathBuf> = config
            .route
            .dhcp_lease_files
            .iter()
            .map(PathBuf::from)
            .collect();
        self.0.get_or_init(|| NeighborResolver::start(&files));
    }

    /// The device at `source`, when the resolver runs and knows of it; as
    /// sing-box, logged at info when found.
    pub fn lookup(&self, source: std::net::SocketAddr) -> Option<Arc<Neighbor>> {
        let neighbor = self.0.get()?.neighbor(source.ip())?;
        // A device is a source: with sources redacted, not logged at all.
        let shown = !crate::app::logger::redacts(crate::config::model::LogRedact::Source);
        match (neighbor.mac_string(), &neighbor.hostname) {
            _ if !shown => {}
            (Some(mac), Some(name)) => {
                tracing::info!("found neighbor: {}, hostname: {}", mac, name)
            }
            (None, Some(name)) => tracing::info!("found neighbor hostname: {}", name),
            (Some(mac), None) => tracing::info!("found neighbor: {}", mac),
            (None, None) => {}
        }
        Some(Arc::new(neighbor))
    }
}

/// sing-box's needFindNeighbor: a routing or DNS rule on the source's MAC
/// address or host name, a local DNS server with `neighbor_domain`, or
/// `route.find_neighbor`.
pub fn needed(config: &crate::config::Config) -> bool {
    fn route(rule: &crate::config::model::Rule) -> bool {
        !rule.source_mac_address.is_empty()
            || !rule.source_hostname.is_empty()
            || rule.rules.iter().any(route)
    }
    fn dns(rule: &crate::config::model::DnsRule) -> bool {
        !rule.source_mac_address.is_empty()
            || !rule.source_hostname.is_empty()
            || rule.rules.iter().any(dns)
    }
    config.route.find_neighbor
        || config.route.rules.iter().any(route)
        || config.dns.rules.iter().any(dns)
        || config.dns.servers.iter().any(|s| {
            s.kind == "local"
                && s.options
                    .get("neighbor_domain")
                    .is_some_and(|v| !v.is_null() && v != &serde_json::json!([]))
        })
}

/// The MAC address of `ip`, in sing-box's order: neighbor table, leases,
/// EUI-64.
fn mac_of(tables: &Tables, ip: &IpAddr) -> Option<Mac> {
    tables
        .neighbor_ip_to_mac
        .get(ip)
        .or_else(|| tables.leases.ip_to_mac.get(ip))
        .copied()
        .or_else(|| lease::mac_from_eui64(ip))
}

/// When each file last changed, and how long it is: what tells a lease
/// file was written.
fn stamps(files: &[PathBuf]) -> Vec<Option<(SystemTime, u64)>> {
    files
        .iter()
        .map(|f| {
            let meta = std::fs::metadata(f).ok()?;
            Some((meta.modified().ok()?, meta.len()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: Mac = [0x02, 0, 0, 0, 0, 0x0a];
    const B: Mac = [0x02, 0, 0, 0, 0, 0x0b];

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// The neighbor table goes before the leases, a lease's name for the
    /// address before its MAC address's, and IPv4-mapped addresses are the
    /// IPv4 ones.
    #[test]
    fn lookups_follow_sing_box_s_order() {
        let mut leases = Leases::default();
        leases.ip_to_mac.insert(ip("192.168.1.10"), B);
        leases.ip_to_mac.insert(ip("192.168.1.20"), B);
        leases.mac_to_hostname.insert(A, "nas".into());
        leases
            .ip_to_hostname
            .insert(ip("192.168.1.20"), "printer".into());
        let resolver = NeighborResolver::with(HashMap::from([(ip("192.168.1.10"), A)]), leases);
        assert_eq!(resolver.lookup_mac(ip("192.168.1.10")), Some(A));
        assert_eq!(resolver.lookup_mac(ip("::ffff:192.168.1.10")), Some(A));
        assert_eq!(resolver.lookup_mac(ip("192.168.1.20")), Some(B));
        assert_eq!(
            resolver.lookup_hostname(ip("192.168.1.10")).as_deref(),
            Some("nas")
        );
        assert_eq!(
            resolver.lookup_hostname(ip("192.168.1.20")).as_deref(),
            Some("printer")
        );
        assert_eq!(resolver.neighbor(ip("192.168.1.99")), None);
        assert_eq!(
            resolver
                .neighbor(ip("192.168.1.10"))
                .and_then(|n| n.mac_string()),
            Some("02:00:00:00:00:0a".to_string())
        );
    }

    /// Changes to the table as the system reports them.
    /// sing-box's needFindNeighbor.
    #[test]
    fn it_runs_when_a_rule_or_server_needs_it() {
        let needed = |json: serde_json::Value| {
            super::needed(&crate::config::Config::from_json(&json.to_string()).unwrap())
        };
        assert!(!needed(serde_json::json!({})));
        assert!(needed(
            serde_json::json!({ "route": { "find_neighbor": true } })
        ));
        assert!(needed(serde_json::json!({ "route": { "rules": [{
            "type": "logical", "mode": "or",
            "rules": [{ "source_hostname": "nas" }, { "domain": "a.example" }],
            "outbound": "direct" }] },
            "outbounds": [{ "type": "direct", "tag": "direct" }] })));
        assert!(needed(serde_json::json!({ "dns": {
            "servers": [{ "type": "local", "tag": "l" }],
            "rules": [{ "source_mac_address": "02:00:00:00:00:0a", "server": "l" }] } })));
        assert!(needed(serde_json::json!({ "dns": {
            "servers": [{ "type": "local", "tag": "l", "neighbor_domain": [".lan"] }] } })));
        assert!(!needed(serde_json::json!({ "dns": {
            "servers": [{ "type": "local", "tag": "l", "neighbor_domain": [] }] } })));
    }

    #[test]
    fn the_table_follows_its_events() {
        let resolver = NeighborResolver::with(HashMap::new(), Leases::default());
        resolver.apply(table::NeighborEvent::Add(ip("10.0.0.2"), A));
        assert_eq!(resolver.lookup_mac(ip("10.0.0.2")), Some(A));
        resolver.apply(table::NeighborEvent::Delete(ip("10.0.0.2")));
        assert_eq!(resolver.lookup_mac(ip("10.0.0.2")), None);
    }
}
