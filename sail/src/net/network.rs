//! The network the host is on: its type, Wi-Fi name, gateway and carrier,
//! which rules (`wifi_ssid`, `network_type`, …) and `network` groups
//! match, and on whose change connections are reset. The host pushes it
//! (FFI, the runtime API); without a push, sail detects what the system
//! tells it. One state and one notice of change for all of sail.

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use serde_derive::{Deserialize, Serialize};
use tokio::sync::watch;

/// The kind of network, as sing-box names them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkType {
    Wifi,
    Cellular,
    Ethernet,
    Other,
}

/// What is known of the network. What is not known is `None`, and a
/// condition on it does not match.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkState {
    /// The interface of the default route.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    /// Its index and MTU, which sail finds itself: a host does not push
    /// them.
    #[serde(skip)]
    pub index: Option<u32>,
    #[serde(skip)]
    pub mtu: Option<u32>,
    /// Its addresses, with their prefixes (`192.168.1.2/24`): a new lease
    /// or IPv6 prefix on the same interface is a change of network too.
    #[serde(default, with = "inets", skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<cidr::IpInet>,
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<NetworkType>,
    /// The Wi-Fi network's name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssid: Option<String>,
    /// The Wi-Fi access point's address, `aa:bb:cc:dd:ee:ff`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bssid: Option<String>,
    /// The default gateway (the router).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<IpAddr>,
    /// The cellular carrier, its MCC and MNC as one string of digits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcc_mnc: Option<String>,
    /// Metered, as the system says (a cellular network or a hotspot).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub expensive: bool,
    /// In a low data mode, as the system says.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub constrained: bool,
}

impl NetworkState {
    /// Whether the connections made on `self` do not survive going to
    /// `other`: the default interface, its gateway, its kind or its
    /// addresses (IPv6 by /64, as sing-box compares them) differ. A new
    /// SSID or access point on the same interface and addresses (a roam)
    /// is not; nor is a first state known after none.
    pub fn moved_to(&self, other: &NetworkState) -> bool {
        if *self == NetworkState::default() {
            return false;
        }
        self.interface != other.interface
            || self.index != other.index
            || self.gateway != other.gateway
            || self.kind != other.kind
            || networks(&self.addresses) != networks(&other.addresses)
    }

    /// Reads a state as a host writes it (JSON), the BSSID normalized.
    pub fn from_json(json: &str) -> Result<NetworkState> {
        let de = &mut serde_json::Deserializer::from_str(json);
        let state: NetworkState = serde_path_to_error::deserialize(de)
            .map_err(|e| anyhow!("network state: {}: {}", e.path(), e.inner()))?;
        state.normalized()
    }

    /// The same state, its BSSID written `aa:bb:cc:dd:ee:ff`, empty
    /// strings taken as unknown, and a carrier code of digits only.
    pub fn normalized(mut self) -> Result<NetworkState> {
        let empty = |s: &mut Option<String>| {
            if s.as_deref().is_some_and(|s| s.trim().is_empty()) {
                *s = None;
            }
        };
        empty(&mut self.interface);
        empty(&mut self.ssid);
        empty(&mut self.bssid);
        empty(&mut self.mcc_mnc);
        if let Some(bssid) = &self.bssid {
            self.bssid =
                Some(normalize_bssid(bssid).ok_or_else(|| {
                    anyhow!("network state: bssid: {:?} is no MAC address", bssid)
                })?);
        }
        if let Some(code) = &self.mcc_mnc {
            if !(5..=6).contains(&code.len()) || !code.bytes().all(|b| b.is_ascii_digit()) {
                return Err(anyhow!(
                    "network state: mcc_mnc: {:?} is not an MCC and MNC, 5 or 6 digits",
                    code
                ));
            }
        }
        Ok(self)
    }
}

/// Addresses written `address/prefix`, or a bare address as a host one.
mod inets {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(inets: &[cidr::IpInet], s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq(inets.iter().map(ToString::to_string))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<cidr::IpInet>, D::Error> {
        Vec::<String>::deserialize(d)?
            .iter()
            .map(|s| {
                s.parse::<cidr::IpInet>()
                    .or_else(|_| s.parse::<std::net::IpAddr>().map(cidr::IpInet::new_host))
                    .map_err(|_| serde::de::Error::custom(format!("{:?} is no address", s)))
            })
            .collect()
    }
}

/// `bssid` as `aa:bb:cc:dd:ee:ff`: from that form in any case, with `-`
/// between the bytes, or as 12 hex digits, as sing-box takes it; else
/// none.
pub fn normalize_bssid(bssid: &str) -> Option<String> {
    let bssid = bssid.trim();
    let hex: String = match bssid.len() {
        12 => bssid.to_string(),
        17 => {
            let sep = bssid.as_bytes()[2];
            if sep != b':' && sep != b'-' {
                return None;
            }
            let parts: Vec<&str> = bssid.split(sep as char).collect();
            if parts.len() != 6 || parts.iter().any(|p| p.len() != 2) {
                return None;
            }
            parts.concat()
        }
        _ => return None,
    };
    if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let hex = hex.to_ascii_lowercase();
    Some(
        hex.as_bytes()
            .chunks(2)
            .map(|b| std::str::from_utf8(b).unwrap_or_default())
            .collect::<Vec<_>>()
            .join(":"),
    )
}

/// The addresses as far as a change of network goes: IPv4 whole, IPv6 by
/// its /64, sorted.
fn networks(addresses: &[cidr::IpInet]) -> Vec<IpAddr> {
    let mut networks: Vec<IpAddr> = addresses
        .iter()
        .map(|inet| match inet.address() {
            IpAddr::V6(v6) => IpAddr::V6((u128::from(v6) & !u128::from(u64::MAX)).into()),
            v4 => v4,
        })
        .collect();
    networks.sort();
    networks.dedup();
    networks
}

/// What made sail look at the network again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChangeReason {
    /// The interface of the default route changed.
    DefaultInterface,
    /// What sail detects of the network changed.
    State,
    /// The host told it.
    HostPush,
    /// The system woke from sleep.
    Wake,
}

impl std::fmt::Display for ChangeReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ChangeReason::DefaultInterface => "default-interface",
            ChangeReason::State => "state",
            ChangeReason::HostPush => "host",
            ChangeReason::Wake => "wake",
        })
    }
}

/// A change of network that the connections made on the one before do not
/// survive: what the instance then drops and makes anew.
#[derive(Clone, Debug)]
pub struct NetworkChange {
    /// Counts the changes since the instance started, from 1.
    pub generation: u64,
    pub reason: ChangeReason,
    pub old: Arc<NetworkState>,
    pub new: Arc<NetworkState>,
}

/// The instance's network, kept across reloads: its state now, and a
/// notice to whoever subscribed when it changes.
#[derive(Clone)]
pub struct Network {
    state: Arc<watch::Sender<Arc<NetworkState>>>,
    /// The last change the connections do not survive.
    changes: Arc<watch::Sender<Option<Arc<NetworkChange>>>>,
    generation: Arc<AtomicU64>,
    /// Whether the host pushes the state, which detection then leaves.
    pushed: Arc<AtomicBool>,
}

impl Default for Network {
    fn default() -> Self {
        Network {
            state: Arc::new(watch::Sender::new(Arc::default())),
            changes: Arc::new(watch::Sender::new(None)),
            generation: Arc::default(),
            pushed: Arc::default(),
        }
    }
}

impl std::fmt::Debug for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Network")
            .field("pushed", &self.pushed.load(Ordering::Relaxed))
            .finish()
    }
}

impl Network {
    /// The state now.
    pub fn snapshot(&self) -> Arc<NetworkState> {
        self.state.borrow().clone()
    }

    /// Tells of each change of state from now on: rules that match the
    /// network take every one.
    pub fn subscribe(&self) -> watch::Receiver<Arc<NetworkState>> {
        self.state.subscribe()
    }

    /// Tells of each change that connections do not survive, from now on:
    /// the instance drops what was of the network before.
    pub fn changes(&self) -> watch::Receiver<Option<Arc<NetworkChange>>> {
        self.changes.subscribe()
    }

    /// Tells of a change whatever the state says: the host says the network
    /// changed, or the system woke.
    pub fn announce(&self, reason: ChangeReason) {
        let now = self.snapshot();
        self.publish(reason, now.clone(), now);
    }

    fn publish(&self, reason: ChangeReason, old: Arc<NetworkState>, new: Arc<NetworkState>) {
        let generation = self.generation.fetch_add(1, Ordering::Relaxed) + 1;
        self.changes.send_replace(Some(Arc::new(NetworkChange {
            generation,
            reason,
            old,
            new,
        })));
    }

    /// Whether the host pushes the state.
    pub fn pushed(&self) -> bool {
        self.pushed.load(Ordering::Relaxed)
    }

    /// The state as the host tells it; what sail detects is left from then
    /// on.
    pub fn push(&self, state: NetworkState) {
        self.pushed.store(true, Ordering::Relaxed);
        self.set(state, ChangeReason::HostPush);
    }

    /// The state as sail detected it, unless the host pushes it, for
    /// `reason`; whether a change connections do not survive was told.
    pub(crate) fn detected(&self, state: NetworkState, reason: ChangeReason) -> bool {
        !self.pushed() && self.set(state, reason)
    }

    /// Changes the state, telling subscribers only of a change, and of a
    /// move when the connections do not survive it; whether that was told.
    fn set(&self, state: NetworkState, reason: ChangeReason) -> bool {
        let old = self.snapshot();
        let changed = self.state.send_if_modified(|now| {
            if **now == state {
                return false;
            }
            *now = Arc::new(state);
            true
        });
        let moved = changed && old.moved_to(&self.snapshot());
        if moved {
            self.publish(reason, old, self.snapshot());
        }
        if changed {
            let now = self.snapshot();
            tracing::info!(
                "network: {} on {} via {}",
                now.kind
                    .map(|k| format!("{:?}", k).to_ascii_lowercase())
                    .unwrap_or_else(|| "unknown".into()),
                now.interface.as_deref().unwrap_or("?"),
                now.gateway
                    .map(|g| g.to_string())
                    .unwrap_or_else(|| "?".into()),
            );
            // A network's name says where the user is: not in the log's
            // default level.
            tracing::debug!("network: ssid {:?}, bssid {:?}", now.ssid, now.bssid);
        }
        moved
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_host_s_state_is_read_and_normalized() {
        let state = NetworkState::from_json(
            r#"{ "interface": "en0", "type": "wifi", "ssid": "Home", "bssid": "AA-BB-CC-DD-EE-0F",
                 "gateway": "192.168.1.1", "addresses": ["192.168.1.2/24", "fd00::2"],
                 "expensive": true }"#,
        )
        .unwrap();
        assert_eq!(state.kind, Some(NetworkType::Wifi));
        assert_eq!(state.bssid.as_deref(), Some("aa:bb:cc:dd:ee:0f"));
        assert_eq!(state.gateway, Some("192.168.1.1".parse().unwrap()));
        assert!(state.expensive && !state.constrained);
        assert_eq!(state.addresses[1].to_string(), "fd00::2");
        let back = serde_json::to_value(&state).unwrap();
        assert_eq!(
            back["addresses"],
            serde_json::json!(["192.168.1.2/24", "fd00::2"])
        );

        let state =
            NetworkState::from_json(r#"{ "type": "cellular", "mcc_mnc": "310260", "ssid": "" }"#)
                .unwrap();
        assert_eq!(state.ssid, None);

        for (json, message) in [
            (r#"{ "type": "wired" }"#, "type"),
            (r#"{ "bssid": "aa:bb" }"#, "bssid"),
            (r#"{ "mcc_mnc": "31026x" }"#, "mcc_mnc"),
            (r#"{ "ssi": "x" }"#, "ssi"),
            (r#"{ "addresses": ["x"] }"#, "addresses"),
            (r#"{ "mtu": 1500 }"#, "mtu"),
        ] {
            let err = NetworkState::from_json(json).unwrap_err().to_string();
            assert!(err.contains(message), "{}", err);
        }
    }

    #[test]
    fn bssids_are_one_form() {
        for bssid in [
            "aa:bb:cc:dd:ee:ff",
            "AA:BB:CC:DD:EE:FF",
            "aa-bb-cc-dd-ee-ff",
            "aabbccddeeff",
        ] {
            assert_eq!(normalize_bssid(bssid).as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        }
        for bad in [
            "",
            "aa:bb:cc:dd:ee",
            "aa:bb:cc:dd:ee:gg",
            "aa:bbc:cd:dee:ff:0",
        ] {
            assert_eq!(normalize_bssid(bad), None, "{}", bad);
        }
    }

    #[tokio::test]
    async fn subscribers_hear_of_changes_only() {
        let network = Network::default();
        let mut changes = network.subscribe();
        let wifi = NetworkState {
            kind: Some(NetworkType::Wifi),
            ..Default::default()
        };
        network.detected(wifi.clone(), ChangeReason::State);
        assert!(changes.has_changed().unwrap());
        changes.borrow_and_update();
        network.detected(wifi.clone(), ChangeReason::State);
        assert!(!changes.has_changed().unwrap());

        // Once the host pushes, detection is left.
        let cellular = NetworkState {
            kind: Some(NetworkType::Cellular),
            ..Default::default()
        };
        network.push(cellular.clone());
        network.detected(wifi, ChangeReason::State);
        assert_eq!(*network.snapshot(), cellular);
    }

    fn on(interface: &str, addresses: &[&str]) -> NetworkState {
        NetworkState {
            interface: Some(interface.into()),
            kind: Some(NetworkType::Wifi),
            gateway: Some("192.168.1.1".parse().unwrap()),
            addresses: addresses.iter().map(|a| a.parse().unwrap()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn what_connections_do_not_survive_is_a_move() {
        let home = on("en0", &["192.168.1.2/24", "2001:db8:1:2::5/64"]);
        // Another interface, a new lease, another /64, another router.
        assert!(home.moved_to(&on("en1", &["192.168.1.2/24", "2001:db8:1:2::5/64"])));
        assert!(home.moved_to(&on("en0", &["192.168.1.3/24", "2001:db8:1:2::5/64"])));
        assert!(home.moved_to(&on("en0", &["192.168.1.2/24", "2001:db8:1:3::5/64"])));
        let mut router = home.clone();
        router.gateway = Some("192.168.1.254".parse().unwrap());
        assert!(home.moved_to(&router));
        // A new address in the same /64 (privacy addresses), or a roam to
        // another access point of the same network, is not.
        assert!(!home.moved_to(&on("en0", &["192.168.1.2/24", "2001:db8:1:2::77/64"])));
        let mut roamed = home.clone();
        roamed.ssid = Some("Home".into());
        roamed.bssid = Some("aa:bb:cc:dd:ee:ff".into());
        assert!(!home.moved_to(&roamed));
        // Nor is the first state known.
        assert!(!NetworkState::default().moved_to(&home));
    }

    #[test]
    fn a_move_is_told_with_its_reason_and_generation() {
        let network = Network::default();
        let mut changes = network.changes();
        assert!(!network.detected(on("en0", &["192.168.1.2/24"]), ChangeReason::State));
        assert!(!changes.has_changed().unwrap());
        // A roam: the state changes, the connections survive.
        let mut roamed = on("en0", &["192.168.1.2/24"]);
        roamed.ssid = Some("Home".into());
        assert!(!network.detected(roamed, ChangeReason::State));
        assert!(!changes.has_changed().unwrap());

        assert!(network.detected(on("en1", &["10.0.0.2/24"]), ChangeReason::DefaultInterface));
        let change = changes.borrow_and_update().clone().unwrap();
        assert_eq!(change.generation, 1);
        assert_eq!(change.reason, ChangeReason::DefaultInterface);
        assert_eq!(change.old.interface.as_deref(), Some("en0"));
        assert_eq!(change.new.interface.as_deref(), Some("en1"));

        // The host, or waking, tells one whatever the state.
        network.announce(ChangeReason::Wake);
        let change = changes.borrow_and_update().clone().unwrap();
        assert_eq!((change.generation, change.reason), (2, ChangeReason::Wake));
        assert_eq!(change.old, change.new);
    }
}
