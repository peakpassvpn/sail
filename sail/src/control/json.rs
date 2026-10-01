//! The JSON hosts are answered with, the C ABI and the management API
//! alike: sail's own shape, the control types serialized in snake_case
//! with typed fields (the Clash API renders Mihomo's from the same types).
//! It is a public contract, so the snapshot test below fails on any change
//! to it: change the snapshot and `VERSION` on purpose, and with them the
//! version of each API that answers with it.

/// The version of the shape, raised with any change to it.
pub const VERSION: u32 = 3;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;

fn millis_since_epoch(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

fn millis(delay: Duration) -> u64 {
    delay.as_millis().max(1) as u64
}

#[derive(Serialize)]
pub struct Capabilities {
    pub api_version: u32,
    /// `VERSION`: the shape of this JSON.
    pub json_version: u32,
    pub version: &'static str,
    pub features: Vec<&'static str>,
}

/// What an instance can do, as it runs.
#[derive(Serialize)]
pub struct InstanceCapabilities {
    pub has_tun: bool,
    pub opens_tun: bool,
    pub protects_sockets: bool,
    /// Whether the rules or groups pick by the network the host is on, so
    /// the host should tell it (`sail_set_network_state`).
    pub needs_network: bool,
    /// Whether it has modes to switch among.
    pub has_modes: bool,
}

/// An instance's state.
#[derive(Serialize, Clone, PartialEq, Eq, Debug)]
pub struct State {
    /// `idle`, `starting`, `running`, `stopping`, `stopped` or `failed`.
    pub state: String,
    /// Why it failed, for `failed`.
    pub error: Option<String>,
    /// When it last started running, in milliseconds since the epoch.
    pub started_at_ms: Option<u64>,
}

#[derive(Serialize)]
pub struct Traffic {
    pub up_total: u64,
    pub down_total: u64,
    pub connections: usize,
    /// The process's resident memory, in bytes; 0 where unknown.
    pub memory: u64,
}

impl Traffic {
    pub fn of(traffic: &crate::control::Traffic) -> Self {
        Self {
            up_total: traffic.up_total,
            down_total: traffic.down_total,
            connections: traffic.connections,
            memory: crate::control::resident_memory(),
        }
    }
}

/// A `status` event: the traffic, and its rate since the last.
#[derive(Serialize)]
pub struct Status {
    /// Bytes a second.
    pub up: u64,
    pub down: u64,
    pub up_total: u64,
    pub down_total: u64,
    pub connections: usize,
    pub memory: u64,
}

#[derive(Serialize, Clone)]
pub struct Connection {
    pub id: u64,
    pub network: String,
    pub inbound_type: String,
    pub inbound_tag: String,
    pub source: String,
    pub destination: String,
    pub host: Option<String>,
    pub process: Option<String>,
    pub user: Option<String>,
    /// Who opened it, as the host tells it (Android).
    pub uid: Option<u32>,
    pub packages: Vec<String>,
    pub upload: u64,
    pub download: u64,
    /// Unix seconds.
    pub start: u32,
    pub chains: Vec<String>,
    pub rule: Option<String>,
}

impl Connection {
    pub fn of(c: &crate::control::ConnectionInfo) -> Self {
        Self {
            id: c.id,
            network: c.network.to_string(),
            inbound_type: c.inbound_type.clone(),
            inbound_tag: c.inbound_tag.clone(),
            source: c.source.to_string(),
            destination: c.destination.to_string(),
            host: c.host.clone(),
            process: c.process.clone(),
            user: c.user.clone(),
            uid: c.uid,
            packages: c.packages.clone(),
            upload: c.upload,
            download: c.download,
            start: c.start,
            chains: c.chains.clone(),
            rule: c.rule.clone(),
        }
    }
}

#[derive(Serialize)]
pub struct Connections {
    pub connections: Vec<Connection>,
}

#[derive(Serialize, PartialEq)]
pub struct Delay {
    pub time_ms: u64,
    /// None for a test that failed.
    pub delay_ms: Option<u64>,
}

#[derive(Serialize, PartialEq)]
pub struct Group {
    pub selected: String,
    pub members: Vec<String>,
    pub selectable: bool,
}

#[derive(Serialize, PartialEq)]
pub struct Outbound {
    pub tag: String,
    pub kind: String,
    pub protocol: Option<String>,
    pub provider: Option<String>,
    pub udp: bool,
    pub history: Vec<Delay>,
    pub group: Option<Group>,
}

impl Outbound {
    pub fn of(o: &crate::control::OutboundInfo) -> Self {
        Self {
            tag: o.tag.clone(),
            kind: o.kind.to_string(),
            protocol: o.protocol.clone(),
            provider: o.provider.clone(),
            udp: o.udp,
            history: o
                .history
                .iter()
                .map(|d| Delay {
                    time_ms: millis_since_epoch(d.time),
                    delay_ms: d.delay.map(millis),
                })
                .collect(),
            group: o.group.as_ref().map(|g| Group {
                selected: g.selected.clone(),
                members: g.members.clone(),
                selectable: g.selectable,
            }),
        }
    }
}

#[derive(Serialize, PartialEq)]
pub struct Outbounds {
    pub outbounds: Vec<Outbound>,
}

#[derive(Serialize, PartialEq)]
pub struct Failure {
    pub at_ms: u64,
    pub error: String,
}

impl Failure {
    fn of(f: &crate::control::Failure) -> Self {
        Self {
            at_ms: millis_since_epoch(f.at),
            error: f.error.clone(),
        }
    }
}

#[derive(Serialize, PartialEq)]
pub struct Subscription {
    pub upload: u64,
    pub download: u64,
    pub total: u64,
    pub expire_ms: Option<u64>,
}

fn source(kind: crate::control::SourceKind) -> String {
    use crate::control::SourceKind;
    match kind {
        SourceKind::Remote => "remote",
        SourceKind::Local => "local",
        SourceKind::Inline => "inline",
    }
    .to_string()
}

/// An outbound provider.
#[derive(Serialize, PartialEq)]
pub struct Provider {
    pub tag: String,
    /// `remote`, `local` or `inline`.
    pub source: String,
    pub members: u64,
    pub updated_ms: Option<u64>,
    pub next_update_ms: Option<u64>,
    pub failure: Option<Failure>,
    pub subscription: Option<Subscription>,
}

impl Provider {
    pub fn of(p: &crate::control::ProviderInfo) -> Self {
        Self {
            tag: p.tag.clone(),
            source: source(p.source),
            members: p.members as u64,
            updated_ms: p.updated.map(millis_since_epoch),
            next_update_ms: p.next_update.map(millis_since_epoch),
            failure: p.failure.as_ref().map(Failure::of),
            subscription: p.subscription.map(|s| Subscription {
                upload: s.upload,
                download: s.download,
                total: s.total,
                expire_ms: s.expire.map(millis_since_epoch),
            }),
        }
    }
}

#[derive(Serialize, PartialEq)]
pub struct Providers {
    pub providers: Vec<Provider>,
}

/// A rule-set.
#[derive(Serialize, PartialEq)]
pub struct RuleSet {
    pub tag: String,
    /// `remote`, `local` or `inline`.
    pub source: String,
    pub format: Option<String>,
    pub behavior: Option<String>,
    pub rules: u64,
    pub updated_ms: Option<u64>,
    pub next_update_ms: Option<u64>,
    pub failure: Option<Failure>,
}

impl RuleSet {
    pub fn of(r: &crate::control::RuleSetInfo) -> Self {
        Self {
            tag: r.tag.clone(),
            source: source(r.source),
            format: r.format.clone(),
            behavior: r.behavior.clone(),
            rules: r.rules as u64,
            updated_ms: r.updated.map(millis_since_epoch),
            next_update_ms: r.next_update.map(millis_since_epoch),
            failure: r.failure.as_ref().map(Failure::of),
        }
    }
}

#[derive(Serialize, PartialEq)]
pub struct RuleSets {
    pub rule_sets: Vec<RuleSet>,
}

#[derive(Serialize)]
pub struct Mode {
    pub mode: String,
    pub modes: Vec<String>,
}

#[derive(Serialize)]
pub struct LogLine {
    /// `error`, `warn`, `info`, `debug` or `trace`.
    pub level: String,
    pub message: String,
    pub time_ms: u64,
}

impl LogLine {
    pub fn of(line: &crate::app::logger::LogLine) -> Self {
        Self {
            level: match line.level {
                tracing::Level::ERROR => "error",
                tracing::Level::WARN => "warn",
                tracing::Level::INFO => "info",
                tracing::Level::DEBUG => "debug",
                tracing::Level::TRACE => "trace",
            }
            .to_string(),
            message: line.message.clone(),
            time_ms: millis_since_epoch(line.time),
        }
    }
}

/// A `network` event: a change of network the connections made on the one
/// before do not survive.
#[derive(Serialize)]
pub struct NetworkEvent {
    /// Counts the changes since the instance started, from 1.
    pub generation: u64,
    /// `default-interface`, `state`, `host` or `wake`.
    pub reason: String,
    /// The network before and now, as `sail_set_network_state` takes it.
    pub old: crate::net::network::NetworkState,
    pub new: crate::net::network::NetworkState,
}

impl NetworkEvent {
    pub fn of(change: &crate::net::network::NetworkChange) -> Self {
        Self {
            generation: change.generation,
            reason: change.reason.to_string(),
            old: (*change.old).clone(),
            new: (*change.new).clone(),
        }
    }
}

/// A `log` event.
#[derive(Serialize)]
pub struct Log {
    /// The lines before were cleared: the host drops the lines it has.
    pub reset: bool,
    pub lines: Vec<LogLine>,
    /// Lines left out since the last event, as the host was too slow to
    /// take them.
    pub dropped: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// The contract, as it is: a change to the control types or to these
    /// that changes the JSON fails here.
    #[test]
    fn the_json_of_the_c_abi_is_as_published() {
        let at = UNIX_EPOCH + Duration::from_millis(1_759_300_000_123);
        let snapshot = serde_json::json!({
            "state": State { state: "failed".into(), error: Some("x".into()), started_at_ms: None },
            "traffic": Traffic { up_total: 1, down_total: 2, connections: 3, memory: 4 },
            "status": Status { up: 1, down: 2, up_total: 3, down_total: 4, connections: 5, memory: 6 },
            "connection": Connection {
                id: 12, network: "tcp".into(), inbound_type: "socks".into(),
                inbound_tag: "in".into(), source: "127.0.0.1:5000".into(),
                destination: "example.com:443".into(), host: Some("example.com".into()),
                process: None, user: Some("alice".into()), uid: Some(10123),
                packages: vec!["com.example".into()], upload: 4, download: 5,
                start: 1_759_300_000, chains: vec!["b".into(), "sel".into()], rule: None,
            },
            "outbound": Outbound {
                tag: "sel".into(), kind: "Selector".into(), protocol: Some("selector".into()),
                provider: None, udp: true,
                history: vec![Delay { time_ms: millis_since_epoch(at), delay_ms: Some(millis(Duration::ZERO)) },
                              Delay { time_ms: 0, delay_ms: None }],
                group: Some(Group { selected: "b".into(), members: vec!["a".into(), "b".into()], selectable: true }),
            },
            "mode": Mode { mode: "Rule".into(), modes: vec!["Rule".into(), "Global".into()] },
            "log": Log { reset: true, lines: vec![LogLine { level: "info".into(), message: "m".into(), time_ms: 1 }], dropped: 2 },
            "network": NetworkEvent {
                generation: 2,
                reason: "host".into(),
                old: crate::net::network::NetworkState::default(),
                new: crate::net::network::NetworkState::from_json(
                    r#"{"type": "wifi", "interface": "wlan0", "ssid": "home"}"#,
                )
                .unwrap(),
            },
            "capabilities": InstanceCapabilities {
                has_tun: true, opens_tun: false, protects_sockets: true, needs_network: false, has_modes: true,
            },
            "providers": Providers { providers: vec![Provider {
                tag: "sub".into(), source: "remote".into(), members: 3,
                updated_ms: Some(millis_since_epoch(at)), next_update_ms: None,
                failure: Some(Failure { at_ms: 1, error: "http status 503".into() }),
                subscription: Some(Subscription { upload: 1, download: 2, total: 3, expire_ms: None }),
            }] },
            "rule_sets": RuleSets { rule_sets: vec![RuleSet {
                tag: "ads".into(), source: "local".into(), format: Some("clash-yaml".into()),
                behavior: Some("domain".into()), rules: 9, updated_ms: None, next_update_ms: None, failure: None,
            }] },
        });
        let published = r#"{
  "capabilities": {"has_modes": true, "has_tun": true, "needs_network": false, "opens_tun": false, "protects_sockets": true},
  "connection": {"chains": ["b", "sel"], "destination": "example.com:443", "download": 5, "host": "example.com", "id": 12,
                 "inbound_tag": "in", "inbound_type": "socks", "network": "tcp", "packages": ["com.example"],
                 "process": null, "rule": null, "source": "127.0.0.1:5000", "start": 1759300000,
                 "uid": 10123, "upload": 4, "user": "alice"},
  "log": {"dropped": 2, "lines": [{"level": "info", "message": "m", "time_ms": 1}], "reset": true},
  "mode": {"mode": "Rule", "modes": ["Rule", "Global"]},
  "providers": {"providers": [{"failure": {"at_ms": 1, "error": "http status 503"}, "members": 3,
                 "next_update_ms": null, "source": "remote",
                 "subscription": {"download": 2, "expire_ms": null, "total": 3, "upload": 1},
                 "tag": "sub", "updated_ms": 1759300000123}]},
  "rule_sets": {"rule_sets": [{"behavior": "domain", "failure": null, "format": "clash-yaml", "next_update_ms": null,
                 "rules": 9, "source": "local", "tag": "ads", "updated_ms": null}]},
  "network": {"generation": 2, "new": {"interface": "wlan0", "ssid": "home", "type": "wifi"}, "old": {},
              "reason": "host"},
  "outbound": {"group": {"members": ["a", "b"], "selectable": true, "selected": "b"},
               "history": [{"delay_ms": 1, "time_ms": 1759300000123}, {"delay_ms": null, "time_ms": 0}],
               "kind": "Selector", "protocol": "selector", "provider": null, "tag": "sel", "udp": true},
  "state": {"error": "x", "started_at_ms": null, "state": "failed"},
  "status": {"connections": 5, "down": 2, "down_total": 4, "memory": 6, "up": 1, "up_total": 3},
  "traffic": {"connections": 3, "down_total": 2, "memory": 4, "up_total": 1}
}"#;
        let published: serde_json::Value = serde_json::from_str(published).unwrap();
        assert_eq!(snapshot, published, "{:#}", snapshot);
    }
}
