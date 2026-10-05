//! The network the host is on: its type, Wi-Fi name, gateway and carrier,
//! which rules (`wifi_ssid`, `network_type`, …) and `network` groups
//! match, and on whose change connections are reset. The host pushes it
//! (FFI, the runtime API); without a push, sail detects what the system
//! tells it. One state and one notice of change for all of sail.

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use serde_derive::{Deserialize, Serialize};
use tokio::sync::{broadcast, watch};

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
    /// Behind a captive portal, as the host says: every connection goes
    /// straight out, whatever the rules say, until it clears, for the user
    /// to log in. sail does not look for one itself.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub captive: bool,
    /// Every interface sail may dial out of, the default's among them
    /// (named by `interface`), for a connection's choice of network. The
    /// fields above describe the default network and are what rules and a
    /// change of network go by; these are for that choice alone.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interfaces: Vec<NetworkInterface>,
}

/// One of the host's interfaces, as sing-box's network manager lists them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkInterface {
    pub name: String,
    /// Its index, which sail finds itself: a host does not push it.
    #[serde(skip)]
    pub index: Option<u32>,
    #[serde(rename = "type")]
    pub kind: NetworkType,
    /// Its addresses, with their prefixes.
    #[serde(default, with = "inets", skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<cidr::IpInet>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub expensive: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub constrained: bool,
}

impl NetworkState {
    /// Whether the connections made on `self` do not survive going to
    /// `other`: the default interface, its gateway, its kind or its
    /// addresses (IPv6 by /64, as sing-box compares them) differ. A new
    /// SSID or access point on the same interface and addresses (a roam)
    /// is not. Losing the default interface, and getting one back, are.
    pub fn moved_to(&self, other: &NetworkState) -> bool {
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
    /// strings taken as unknown, and a carrier code of digits only; its
    /// interfaces each named once, the default among them.
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
        let mut names = std::collections::HashSet::new();
        for (i, interface) in self.interfaces.iter().enumerate() {
            if interface.name.trim().is_empty() {
                return Err(anyhow!("network state: interfaces[{}].name: empty", i));
            }
            if !names.insert(interface.name.as_str()) {
                return Err(anyhow!(
                    "network state: interfaces[{}].name: {:?} is listed twice",
                    i,
                    interface.name
                ));
            }
        }
        if let Some(default) = &self.interface {
            if !self.interfaces.is_empty() && !names.contains(default.as_str()) {
                return Err(anyhow!(
                    "network state: interface: {:?} is not in interfaces",
                    default
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

/// The state now, and the generation of the last change it came after, 0
/// before any: taken together, so that one does not run ahead of the other.
#[derive(Clone, Debug, Default)]
pub struct Current {
    pub state: Arc<NetworkState>,
    pub generation: u64,
}

/// How many changes a subscriber of `change_events` may fall behind by
/// before it is told it lagged: changes come seconds apart at most, a
/// burst (down, then up) a handful.
pub(crate) const EVENTS: usize = 64;

/// The instance's network, kept across reloads: its state now, and a
/// notice to whoever subscribed when it changes.
#[derive(Clone)]
pub struct Network {
    state: Arc<watch::Sender<Current>>,
    /// The last change the connections do not survive.
    changes: Arc<watch::Sender<Option<Arc<NetworkChange>>>>,
    /// Every such change, in order.
    events: Arc<broadcast::Sender<Arc<NetworkChange>>>,
    /// Held while a change is made and told, and while a subscriber takes
    /// the state and its events together.
    telling: Arc<Mutex<()>>,
    /// Whether a state was ever set: the first is no change of network.
    known: Arc<AtomicBool>,
    /// Whether the host pushes the state, which detection then leaves.
    pushed: Arc<AtomicBool>,
    /// The interfaces sail makes itself (its TUNs'), never listed as ones
    /// to go out of.
    own: Arc<std::sync::RwLock<Vec<String>>>,
}

impl Default for Network {
    fn default() -> Self {
        Network {
            state: Arc::new(watch::Sender::new(Current::default())),
            changes: Arc::new(watch::Sender::new(None)),
            events: Arc::new(broadcast::Sender::new(EVENTS)),
            telling: Arc::default(),
            known: Arc::default(),
            pushed: Arc::default(),
            own: Arc::default(),
        }
    }
}

impl Network {
    /// A network that tells its changes on `events`, a channel that may
    /// outlive it (an embedding instance's, through its runs).
    pub(crate) fn telling_to(events: broadcast::Sender<Arc<NetworkChange>>) -> Self {
        Network {
            events: Arc::new(events),
            ..Default::default()
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
        self.state.borrow().state.clone()
    }

    /// The state now with the generation of the last change it came after.
    pub fn snapshot_with_generation(&self) -> Current {
        self.state.borrow().clone()
    }

    /// Tells of each change of state from now on: rules that match the
    /// network take every one.
    pub fn subscribe(&self) -> watch::Receiver<Current> {
        self.state.subscribe()
    }

    /// Tells of each change that connections do not survive, from now on:
    /// the instance drops what was of the network before. The last one
    /// only: a reader that is slow sees the latest.
    pub fn changes(&self) -> watch::Receiver<Option<Arc<NetworkChange>>> {
        self.changes.subscribe()
    }

    /// Every change that connections do not survive, in order, from now
    /// on; a subscriber more than 64 behind is told it lagged.
    pub fn change_events(&self) -> broadcast::Receiver<Arc<NetworkChange>> {
        self.events.subscribe()
    }

    /// The state now, and every change after it, taken together: the
    /// events are those whose generation is past the state's, none
    /// missed and none the state already holds.
    pub fn state_and_events(&self) -> (Current, broadcast::Receiver<Arc<NetworkChange>>) {
        let _telling = self.telling.lock().unwrap_or_else(|e| e.into_inner());
        (self.state.borrow().clone(), self.events.subscribe())
    }

    /// Tells of a change whatever the state says: the host says the network
    /// changed, or the system woke.
    pub fn announce(&self, reason: ChangeReason) {
        let _telling = self.telling.lock().unwrap_or_else(|e| e.into_inner());
        let mut change = None;
        self.state.send_modify(|current| {
            current.generation += 1;
            change = Some(NetworkChange {
                generation: current.generation,
                reason,
                old: current.state.clone(),
                new: current.state.clone(),
            });
        });
        self.tell(change.expect("set in send_modify"));
    }

    /// Tells the subscribers of `change`, whose state is stored already;
    /// with `telling` held.
    fn tell(&self, change: NetworkChange) {
        let change = Arc::new(change);
        self.changes.send_replace(Some(change.clone()));
        // None subscribed is no error.
        let _ = self.events.send(change);
    }

    /// Whether there is no network: a state was known, and now nothing is,
    /// no default interface, address or type. Checks and updates on a
    /// timer wait while it is, rather than find everything failing; the
    /// change that ends it tells them to look again.
    pub fn is_down(&self) -> bool {
        self.known.load(Ordering::Relaxed) && *self.snapshot() == NetworkState::default()
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

    /// Settles the state sail starts on, before the instance runs: `state`
    /// as detected, or no network (None, the empty state, offline). It is
    /// known from then, at generation 1, and no change is told: a host
    /// subscribes, then reads it; what detection finds later is told as
    /// any change. Nothing when a state is known already, or the host
    /// pushes the state (it is the host's to tell).
    pub fn settle_first(&self, state: Option<NetworkState>) {
        if self.pushed() {
            return;
        }
        let mut state = state.unwrap_or_default();
        self.leave_own_out(&mut state);
        let _telling = self.telling.lock().unwrap_or_else(|e| e.into_inner());
        if self.known.swap(true, Ordering::Relaxed) {
            return;
        }
        let state = Arc::new(state);
        self.state.send_modify(|current| {
            current.state = state;
            current.generation = 1;
        });
    }

    /// The state as sail detected it, unless the host pushes it, for
    /// `reason`; whether a change connections do not survive was told.
    pub(crate) fn detected(&self, state: NetworkState, reason: ChangeReason) -> bool {
        !self.pushed() && self.set(state, reason)
    }

    /// Names the interfaces sail makes itself, its TUNs', which a state
    /// set from now on does not list as ones a connection may go out of,
    /// as sing-box leaves its own out of the interfaces it picks from
    /// (MyInterfaces). The default interface stays listed whatever it is.
    pub(crate) fn set_own_interfaces(&self, names: Vec<String>) {
        if let Ok(mut own) = self.own.write() {
            *own = names;
        }
    }

    /// Leaves sail's own interfaces out of `state`'s, but the default one.
    fn leave_own_out(&self, state: &mut NetworkState) {
        if let Ok(own) = self.own.read() {
            let default = state.interface.clone();
            state
                .interfaces
                .retain(|i| default.as_ref() == Some(&i.name) || !own.contains(&i.name));
        }
    }

    /// Changes the state, telling subscribers only of a change, and of a
    /// move when the connections do not survive it; whether that was told.
    fn set(&self, mut state: NetworkState, reason: ChangeReason) -> bool {
        self.leave_own_out(&mut state);
        let _telling = self.telling.lock().unwrap_or_else(|e| e.into_inner());
        let old = self.snapshot();
        // The first state known, at the start, moves nothing.
        let known = self.known.swap(true, Ordering::Relaxed);
        let changed = *old != state;
        let moved = changed && known && old.moved_to(&state);
        let mut change = None;
        if changed {
            // The state and the generation of its move, in one send.
            let state = Arc::new(state);
            self.state.send_modify(|current| {
                current.state = state.clone();
                if moved {
                    current.generation += 1;
                    change = Some(NetworkChange {
                        generation: current.generation,
                        reason,
                        old: old.clone(),
                        new: state,
                    });
                }
            });
        }
        let captive = self.snapshot().captive;
        if changed && captive != old.captive {
            if captive {
                tracing::info!(
                    "network: behind a captive portal; every connection goes direct, whatever \
                     the rules say, until it clears"
                );
            } else {
                tracing::info!("network: the captive portal cleared; the rules apply again");
            }
        }
        if let Some(change) = change {
            self.tell(change);
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

    /// The host lists its interfaces, each named once and the default
    /// among them; a change to them alone is no move.
    #[test]
    fn a_host_lists_its_interfaces() {
        let state = NetworkState::from_json(
            r#"{ "interface": "wlan0", "type": "wifi",
                 "interfaces": [
                   { "name": "wlan0", "type": "wifi", "addresses": ["192.168.1.5/24"] },
                   { "name": "rmnet0", "type": "cellular", "expensive": true,
                     "addresses": ["10.1.2.3"] } ] }"#,
        )
        .unwrap();
        assert_eq!(state.interfaces.len(), 2);
        assert_eq!(state.interfaces[1].kind, NetworkType::Cellular);
        assert!(state.interfaces[1].expensive && !state.interfaces[1].constrained);
        assert_eq!(state.interfaces[1].addresses[0].to_string(), "10.1.2.3");
        let back = serde_json::to_value(&state).unwrap();
        assert_eq!(
            back["interfaces"][0],
            serde_json::json!({ "name": "wlan0", "type": "wifi", "addresses": ["192.168.1.5/24"] })
        );

        let mut fewer = state.clone();
        fewer.interfaces.pop();
        assert_ne!(state, fewer);
        assert!(!state.moved_to(&fewer));

        // Without a default named, any list goes.
        NetworkState::from_json(r#"{ "interfaces": [{ "name": "en0", "type": "ethernet" }] }"#)
            .unwrap();
        for (json, message) in [
            (
                r#"{ "interfaces": [{ "name": "en0" }] }"#,
                "interfaces[0]: missing field `type`",
            ),
            (
                r#"{ "interfaces": [{ "name": " ", "type": "wifi" }] }"#,
                "interfaces[0].name: empty",
            ),
            (
                r#"{ "interfaces": [{ "name": "en0", "type": "wifi" },
                                     { "name": "en0", "type": "ethernet" }] }"#,
                "interfaces[1].name: \"en0\" is listed twice",
            ),
            (
                r#"{ "interface": "en1", "interfaces": [{ "name": "en0", "type": "wifi" }] }"#,
                "interface: \"en1\" is not in interfaces",
            ),
            (
                r#"{ "interfaces": [{ "name": "en0", "type": "wifi", "index": 3 }] }"#,
                "index",
            ),
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

    fn interface(name: &str, kind: NetworkType) -> NetworkInterface {
        NetworkInterface {
            name: name.into(),
            index: None,
            kind,
            addresses: Vec::new(),
            expensive: false,
            constrained: false,
        }
    }

    #[test]
    fn sail_s_own_tun_is_not_listed_to_go_out_of() {
        let network = Network::default();
        network.set_own_interfaces(vec!["utun233".into()]);
        let mut state = on("en0", &["192.168.1.2/24"]);
        state.interfaces = vec![
            interface("en0", NetworkType::Wifi),
            interface("utun233", NetworkType::Other),
            interface("utun4", NetworkType::Other),
        ];
        network.detected(state.clone(), ChangeReason::State);
        let names = |network: &Network| {
            network
                .snapshot()
                .interfaces
                .iter()
                .map(|i| i.name.clone())
                .collect::<Vec<_>>()
        };
        // Another VPN's stays, typed other.
        assert_eq!(names(&network), ["en0", "utun4"]);

        // Should the default be sail's own, it is still the default.
        state.interface = Some("utun233".into());
        network.detected(state, ChangeReason::State);
        assert_eq!(names(&network), ["en0", "utun233", "utun4"]);
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
        // Losing the default interface is, and getting it back.
        assert!(home.moved_to(&NetworkState::default()));
        assert!(NetworkState::default().moved_to(&home));
    }

    #[test]
    fn a_move_is_told_with_its_reason_and_generation() {
        let network = Network::default();
        let mut changes = network.changes();
        // The first state known, at the start, is no change.
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

        // Losing the network, and getting it back.
        assert!(network.detected(NetworkState::default(), ChangeReason::State));
        assert!(network.is_down());
        assert!(network.detected(on("en1", &["10.0.0.2/24"]), ChangeReason::State));
        assert!(!network.is_down());
        let change = changes.borrow_and_update().clone().unwrap();
        assert_eq!(change.generation, 3);
        assert_eq!(change.old.interface, None);

        // The host, or waking, tells one whatever the state.
        network.announce(ChangeReason::Wake);
        let change = changes.borrow_and_update().clone().unwrap();
        assert_eq!((change.generation, change.reason), (4, ChangeReason::Wake));
        assert_eq!(change.old, change.new);
    }

    /// Two changes in quick succession, the network lost and back: a
    /// subscriber of the events, slow to read, gets both, in order, with
    /// consecutive generations, where the watch keeps only the last.
    #[test]
    fn every_change_is_an_event_in_order() {
        let network = Network::default();
        network.detected(on("en0", &["192.168.1.2/24"]), ChangeReason::State);
        let mut events = network.change_events();
        let changes = network.changes();
        assert!(network.detected(NetworkState::default(), ChangeReason::State));
        assert!(network.detected(on("en0", &["192.168.1.2/24"]), ChangeReason::State));

        let lost = events.try_recv().unwrap();
        let back = events.try_recv().unwrap();
        assert_eq!((lost.generation, back.generation), (1, 2));
        assert_eq!(lost.new.interface, None);
        assert_eq!(back.new.interface.as_deref(), Some("en0"));
        assert!(events.try_recv().is_err());
        assert_eq!(changes.borrow().as_ref().unwrap().generation, 2);
        // The state carries the generation of the change it came after.
        let current = network.snapshot_with_generation();
        assert_eq!(current.generation, 2);
        assert_eq!(current.state, back.new);
    }

    /// The state and the events after it, taken together: none of the
    /// events is one the state holds, and none after it is missed.
    #[test]
    fn the_state_and_its_events_are_taken_together() {
        let network = Network::default();
        network.detected(on("en0", &["192.168.1.2/24"]), ChangeReason::State);
        network.detected(on("en1", &["10.0.0.2/24"]), ChangeReason::State);
        let (current, mut events) = network.state_and_events();
        assert_eq!(current.generation, 1);
        assert_eq!(current.state.interface.as_deref(), Some("en1"));
        assert!(
            events.try_recv().is_err(),
            "the state's own change is not an event"
        );
        network.announce(ChangeReason::Wake);
        assert_eq!(events.try_recv().unwrap().generation, 2);

        // A subscriber falling more than the bound behind is told so.
        let mut slow = network.change_events();
        for _ in 0..EVENTS + 1 {
            network.announce(ChangeReason::Wake);
        }
        assert!(matches!(
            slow.try_recv(),
            Err(broadcast::error::TryRecvError::Lagged(1))
        ));
    }

    /// The state sail starts on is known at once, at generation 1, with no
    /// change told; what detection finds later is told from there.
    #[test]
    fn the_first_state_is_settled_before_the_instance_runs() {
        let network = Network::default();
        let mut events = network.change_events();
        network.settle_first(Some(on("en0", &["192.168.1.2/24"])));
        let current = network.snapshot_with_generation();
        assert_eq!(
            (current.generation, current.state.interface.as_deref()),
            (1, Some("en0"))
        );
        assert!(events.try_recv().is_err(), "settling tells no change");
        // Settled once: a second is nothing, and the same state detected
        // is no change.
        network.settle_first(Some(on("en1", &["10.0.0.2/24"])));
        assert_eq!(network.snapshot().interface.as_deref(), Some("en0"));
        assert!(!network.detected(on("en0", &["192.168.1.2/24"]), ChangeReason::State));
        assert!(network.detected(on("en1", &["10.0.0.2/24"]), ChangeReason::DefaultInterface));
        assert_eq!(events.try_recv().unwrap().generation, 2);
    }

    /// Settled with no network, sail starts offline, and the first link
    /// is a change from it.
    #[test]
    fn settled_offline_the_first_link_is_a_change() {
        let network = Network::default();
        network.settle_first(None);
        assert!(network.is_down());
        assert_eq!(network.snapshot_with_generation().generation, 1);
        let mut events = network.change_events();
        assert!(network.detected(on("en0", &["192.168.1.2/24"]), ChangeReason::State));
        let change = events.try_recv().unwrap();
        assert_eq!(
            (change.generation, change.old.interface.as_deref()),
            (2, None)
        );
    }

    /// Once a state is known, or the host pushes, settling is nothing.
    #[test]
    fn settling_leaves_a_known_or_pushed_state() {
        let network = Network::default();
        network.detected(on("en0", &["192.168.1.2/24"]), ChangeReason::State);
        network.settle_first(None);
        assert_eq!(network.snapshot().interface.as_deref(), Some("en0"));
        assert_eq!(network.snapshot_with_generation().generation, 0);

        let pushed = Network::default();
        pushed.push(on("wlan0", &["10.1.0.2/24"]));
        pushed.settle_first(Some(on("en0", &["192.168.1.2/24"])));
        assert_eq!(pushed.snapshot().interface.as_deref(), Some("wlan0"));
    }
}
