//! What a group remembers of its sites, kept across restarts in the cache
//! file (roadmap 1.9), when the configuration has one.
//!
//! - Only the sites: each one's member and how the members tried did for
//!   it. The members' own scores fade within minutes (`score::HALF_LIFE`),
//!   and the probes measure them again in a round.
//! - The site keys are the domains and networks visited: they are stored
//!   as the first 16 bytes of SHA-256 over a salt and the key, the salt
//!   made once for the file, so the file is no browsing history. The
//!   network the sites were learnt on is stored the same way.
//! - Read once, when the group is built: a site past `site_ttl` by the
//!   wall clock goes, a failure past its time is forgotten, a member no
//!   longer configured is dropped. Sites learnt on another network go, as
//!   a change of network clears them; while the network is not known yet
//!   they wait, unused, for the first state.
//! - Written when they changed, at most every `cache_file::KEEP_INTERVAL`,
//!   and as the instance stops, sleeps or reloads (`cache_file::Keep`).

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use tokio::time::Instant;
use tracing::{debug, warn};

use super::site::{Site, StoredSite};
use crate::net::network::{NetworkState, NetworkType};
use crate::protocol::group::members::MemberKey;
use crate::runtime::cache_file::CacheFile;

/// The layout's version: a value of another is dropped, never an error.
const VERSION: u32 = 1;

#[derive(Debug, serde_derive::Serialize, serde_derive::Deserialize)]
struct Stored {
    v: u32,
    /// The hash of the network the sites were learnt on; none if it was
    /// not known.
    #[serde(default)]
    network: Option<String>,
    saved_ms: u64,
    #[serde(default)]
    sites: Vec<StoredSite>,
}

pub(super) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

fn hashed(salt: &[u8; 16], what: &str) -> String {
    let digest = Sha256::new()
        .chain_update(salt)
        .chain_update(what.as_bytes())
        .finalize();
    digest[..16].iter().map(|b| format!("{:02x}", b)).collect()
}

/// What identifies a network, as a change of it compares them: the
/// default interface, its gateway and type, its addresses' networks (/24,
/// /64), and the SSID on Wi-Fi; none while nothing is known.
fn identity(state: &NetworkState) -> Option<String> {
    if *state == NetworkState::default() {
        return None;
    }
    let mut networks: Vec<String> = state
        .addresses
        .iter()
        .map(|inet| match inet.address() {
            std::net::IpAddr::V4(v4) => {
                let [a, b, c, _] = v4.octets();
                format!("{}.{}.{}.0/24", a, b, c)
            }
            std::net::IpAddr::V6(v6) => {
                let s = v6.segments();
                format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
            }
        })
        .collect();
    networks.sort();
    networks.dedup();
    let ssid = (state.kind == Some(NetworkType::Wifi))
        .then_some(state.ssid.as_deref())
        .flatten();
    Some(format!(
        "{:?}|{:?}|{:?}|{:?}|{}",
        state.interface,
        state.gateway,
        state.kind,
        ssid,
        networks.join(",")
    ))
}

/// Sites read back and not yet used, by their hashed key.
struct Parked {
    sites: HashMap<String, Site>,
    /// The hash of the network they were learnt on.
    network: Option<String>,
    /// Whether the instance is on that network: they are used only then.
    confirmed: bool,
}

/// A group's sites as kept in the cache file.
pub(super) struct Memory {
    tag: String,
    salt: [u8; 16],
    capacity: usize,
    /// Taken after the group's `sites` (`with_site` holds those and calls
    /// `take`), never before them.
    parked: Mutex<Parked>,
    /// Whether the sites changed since the last write.
    dirty: AtomicBool,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Memory {
    /// What `cache` keeps of the group `tag`: its sites as of now, on
    /// `network`; `configured` are the configuration's members (a
    /// provider's are kept: the provider may not have given them yet).
    /// None, and the group starts empty, if the file cannot be used.
    pub(super) fn load(
        cache: &CacheFile,
        tag: &str,
        site_ttl: Duration,
        capacity: usize,
        configured: &HashSet<MemberKey>,
        network: &NetworkState,
    ) -> Option<Memory> {
        let salt = match cache.smart_salt() {
            Ok(salt) => salt,
            Err(e) => {
                warn!("[{}] smart: its sites are not kept: {:#}", tag, e);
                return None;
            }
        };
        let memory = Memory {
            tag: tag.to_string(),
            salt,
            capacity,
            parked: Mutex::new(Parked {
                sites: HashMap::new(),
                network: None,
                confirmed: true,
            }),
            dirty: AtomicBool::new(false),
        };
        let stored = match cache.load_smart(tag) {
            Ok(Some(bytes)) => match serde_json::from_slice::<Stored>(&bytes) {
                Ok(stored) if stored.v == VERSION => stored,
                Ok(stored) => {
                    debug!(
                        "[{}] smart: kept sites of version {} dropped",
                        tag, stored.v
                    );
                    return Some(memory);
                }
                Err(e) => {
                    debug!("[{}] smart: kept sites do not read, dropped: {}", tag, e);
                    return Some(memory);
                }
            },
            Ok(None) => return Some(memory),
            Err(e) => {
                debug!("[{}] smart: kept sites not read: {:#}", tag, e);
                return Some(memory);
            }
        };
        let here = identity(network).map(|id| hashed(&salt, &id));
        let confirmed = match (&here, &stored.network) {
            (Some(here), Some(then)) if here == then => true,
            // Learnt on another network, or on none known.
            (Some(_), _) => {
                debug!(
                    "[{}] smart: kept sites are of another network, dropped",
                    tag
                );
                return Some(memory);
            }
            // Not known yet: they wait for the first state.
            (None, _) => false,
        };
        let (now, now_ms) = (Instant::now(), now_ms());
        let kept = |key: &MemberKey| key.source.is_some() || configured.contains(key);
        let sites: HashMap<String, Site> = stored
            .sites
            .iter()
            .take(capacity)
            .filter_map(|s| {
                Site::restored(s, site_ttl, kept, now, now_ms).map(|site| (s.key.clone(), site))
            })
            .collect();
        debug!(
            "[{}] smart: {} kept sites read, {}",
            tag,
            sites.len(),
            if confirmed {
                "in use"
            } else {
                "waiting for the network"
            }
        );
        *lock(&memory.parked) = Parked {
            sites,
            network: stored.network,
            confirmed,
        };
        Some(memory)
    }

    /// The kept site of `key`, taken: once the network is confirmed.
    pub(super) fn take(&self, key: &str) -> Option<Site> {
        let mut parked = lock(&self.parked);
        if !parked.confirmed || parked.sites.is_empty() {
            return None;
        }
        parked.sites.remove(&hashed(&self.salt, key))
    }

    /// The sites changed.
    pub(super) fn touched(&self) {
        self.dirty.store(true, Ordering::Relaxed);
    }

    /// The network changed to `state`: kept sites waiting for it are used
    /// if it is theirs, and dropped if not; those in use go, as a change
    /// clears the group's sites.
    pub(super) fn network_changed(&self, state: &NetworkState) {
        let mut parked = lock(&self.parked);
        if parked.confirmed {
            parked.sites.clear();
        } else if let Some(here) = identity(state).map(|id| hashed(&self.salt, &id)) {
            if parked.network.as_deref() == Some(here.as_str()) {
                parked.confirmed = true;
            } else {
                parked.sites.clear();
                parked.confirmed = true;
            }
        }
        self.touched();
    }

    /// Writes `sites` (the group's, by their keys in clear) and those kept
    /// and not used yet, if they changed, as learnt on `network`.
    pub(super) fn store<'a>(
        &self,
        cache: &CacheFile,
        sites: impl Iterator<Item = (&'a String, &'a Site)>,
        network: &NetworkState,
    ) {
        if !self.dirty.swap(false, Ordering::Relaxed) {
            return;
        }
        let (now, now_ms) = (Instant::now(), now_ms());
        let parked = lock(&self.parked);
        let mut stored: Vec<StoredSite> = sites
            .take(self.capacity)
            .map(|(key, site)| site.stored(hashed(&self.salt, key), now, now_ms))
            .collect();
        let room = self.capacity.saturating_sub(stored.len());
        stored.extend(
            parked
                .sites
                .iter()
                .take(room)
                .map(|(key, site)| site.stored(key.clone(), now, now_ms)),
        );
        let network = match identity(network) {
            Some(id) => Some(hashed(&self.salt, &id)),
            None => parked.network.clone(),
        };
        drop(parked);
        let value = Stored {
            v: VERSION,
            network,
            saved_ms: now_ms,
            sites: stored,
        };
        let written = serde_json::to_vec(&value)
            .map_err(anyhow::Error::from)
            .and_then(|bytes| cache.store_smart(&self.tag, &bytes));
        if let Err(e) = written {
            // Tried again at the next write.
            self.touched();
            warn!("[{}] smart: sites not written: {:#}", self.tag, e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wifi(ssid: &str, address: &str) -> NetworkState {
        NetworkState {
            interface: Some("en0".into()),
            kind: Some(NetworkType::Wifi),
            ssid: Some(ssid.into()),
            addresses: vec![address.parse().unwrap()],
            ..Default::default()
        }
    }

    #[test]
    fn a_network_is_known_by_what_a_change_compares() {
        assert_eq!(identity(&NetworkState::default()), None);
        let home = identity(&wifi("home", "192.168.1.2/24"));
        // Another address on the same /24 is the same network.
        assert_eq!(home, identity(&wifi("home", "192.168.1.9/24")));
        assert_ne!(home, identity(&wifi("work", "192.168.1.2/24")));
        assert_ne!(home, identity(&wifi("home", "10.0.0.2/24")));
    }

    fn slot(
        name: &str,
    ) -> (
        crate::runtime::cache_file::CacheFileSlot,
        std::path::PathBuf,
    ) {
        use crate::runtime::cache_file::tests::{enabled, env};
        let dir = std::env::temp_dir().join(format!(
            "sail-smart-memory-{}-{}-{:?}",
            name,
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let slot = crate::runtime::cache_file::CacheFileSlot::default();
        slot.replace(Some(&enabled()), &env(&dir)).unwrap().keep();
        (slot, dir)
    }

    fn configured() -> HashSet<MemberKey> {
        ["a", "b"].iter().map(|t| MemberKey::outbound(t)).collect()
    }

    /// A site learnt, written, and read back by the next group on the same
    /// network: its member as it was; on another network, or past its
    /// TTL, none; while the network is not known, it waits for it. The
    /// file never holds the site's name.
    #[test]
    fn sites_come_back_on_the_same_network_only() {
        let (slot, dir) = slot("back");
        let cache = slot.get().unwrap();
        let home = wifi("home", "192.168.1.2/24");
        let ttl = Duration::from_secs(3600);
        let memory = Memory::load(&cache, "smart", ttl, 64, &configured(), &home).unwrap();
        let now = Instant::now();
        let mut site = Site::default();
        site.answered(&MemberKey::outbound("b"), 80.0, None, now);
        site.failed(&MemberKey::outbound("a"), now);
        let key = "example.com".to_string();
        memory.touched();
        memory.store(&cache, std::iter::once((&key, &site)), &home);
        let file = std::fs::read(cache.path()).unwrap();
        assert!(
            !file.windows(11).any(|w| w == b"example.com"),
            "a name in the file"
        );

        let again = Memory::load(&cache, "smart", ttl, 64, &configured(), &home).unwrap();
        let back = again.take("example.com").expect("the site, back");
        assert_eq!(back.pinned(), Some(&MemberKey::outbound("b")));
        assert!(again.take("example.com").is_none(), "taken once");

        let work = wifi("work", "10.0.0.2/24");
        let elsewhere = Memory::load(&cache, "smart", ttl, 64, &configured(), &work).unwrap();
        assert!(elsewhere.take("example.com").is_none(), "another network");

        let stale =
            Memory::load(&cache, "smart", Duration::ZERO, 64, &configured(), &home).unwrap();
        assert!(stale.take("example.com").is_none(), "past its TTL");

        let gone = ["a"].iter().map(|t| MemberKey::outbound(t)).collect();
        let fewer = Memory::load(&cache, "smart", ttl, 64, &gone, &home).unwrap();
        let back = fewer.take("example.com").expect("a member left");
        assert_eq!(back.pinned(), None, "its member is gone");

        let waiting = Memory::load(
            &cache,
            "smart",
            ttl,
            64,
            &configured(),
            &NetworkState::default(),
        )
        .unwrap();
        assert!(
            waiting.take("example.com").is_none(),
            "not until the network is known"
        );
        waiting.network_changed(&home);
        assert!(waiting.take("example.com").is_some(), "its network, known");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// What does not read, or is of another version, is dropped: the group
    /// starts empty, and no error.
    #[test]
    fn an_unknown_layout_is_dropped() {
        let (slot, dir) = slot("layout");
        let cache = slot.get().unwrap();
        let home = wifi("home", "192.168.1.2/24");
        let ttl = Duration::from_secs(3600);
        for value in [
            &b"not json"[..],
            br#"{"v": 99, "saved_ms": 0, "sites": []}"#,
        ] {
            cache.store_smart("smart", value).unwrap();
            let memory = Memory::load(&cache, "smart", ttl, 64, &configured(), &home);
            assert!(memory.is_some_and(|m| m.take("example.com").is_none()));
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn keys_are_hashed_with_the_salt() {
        let (a, b) = ([1u8; 16], [2u8; 16]);
        assert_eq!(hashed(&a, "example.com"), hashed(&a, "example.com"));
        assert_ne!(hashed(&a, "example.com"), hashed(&b, "example.com"));
        assert_eq!(hashed(&a, "example.com").len(), 32);
        assert!(!hashed(&a, "example.com").contains("example"));
    }
}
