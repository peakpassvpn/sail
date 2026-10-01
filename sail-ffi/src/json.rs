//! The JSON the C ABI answers with: sail's own shape, the control types
//! serialized in snake_case with typed fields. It is the public contract,
//! so the snapshot test below fails on any change to it: change the
//! snapshot, and the C ABI version, on purpose.

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
pub(crate) struct Capabilities {
    pub api_version: u32,
    pub version: &'static str,
    pub features: Vec<&'static str>,
}

/// What an instance can do, as it runs.
#[derive(Serialize)]
pub(crate) struct InstanceCapabilities {
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
pub(crate) struct State {
    /// `idle`, `starting`, `running`, `stopping`, `stopped` or `failed`.
    pub state: &'static str,
    /// Why it failed, for `failed`.
    pub error: Option<String>,
    /// When it last started running, in milliseconds since the epoch.
    pub started_at_ms: Option<u64>,
}

#[derive(Serialize)]
pub(crate) struct Traffic {
    pub up_total: u64,
    pub down_total: u64,
    pub connections: usize,
    /// The process's resident memory, in bytes; 0 where unknown.
    pub memory: u64,
}

impl Traffic {
    pub fn of(traffic: &sail::control::Traffic) -> Self {
        Self {
            up_total: traffic.up_total,
            down_total: traffic.down_total,
            connections: traffic.connections,
            memory: sail::control::resident_memory(),
        }
    }
}

/// A `status` event: the traffic, and its rate since the last.
#[derive(Serialize)]
pub(crate) struct Status {
    /// Bytes a second.
    pub up: u64,
    pub down: u64,
    pub up_total: u64,
    pub down_total: u64,
    pub connections: usize,
    pub memory: u64,
}

#[derive(Serialize)]
pub(crate) struct Connection {
    pub id: u64,
    pub network: String,
    pub inbound_type: String,
    pub inbound_tag: String,
    pub source: String,
    pub destination: String,
    pub host: Option<String>,
    pub process: Option<String>,
    pub user: Option<String>,
    pub upload: u64,
    pub download: u64,
    /// Unix seconds.
    pub start: u32,
    pub chains: Vec<String>,
    pub rule: Option<String>,
}

impl Connection {
    pub fn of(c: &sail::control::ConnectionInfo) -> Self {
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
            upload: c.upload,
            download: c.download,
            start: c.start,
            chains: c.chains.clone(),
            rule: c.rule.clone(),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct Connections {
    pub connections: Vec<Connection>,
}

#[derive(Serialize, PartialEq)]
pub(crate) struct Delay {
    pub time_ms: u64,
    /// None for a test that failed.
    pub delay_ms: Option<u64>,
}

#[derive(Serialize, PartialEq)]
pub(crate) struct Group {
    pub selected: String,
    pub members: Vec<String>,
    pub selectable: bool,
}

#[derive(Serialize, PartialEq)]
pub(crate) struct Outbound {
    pub tag: String,
    pub kind: &'static str,
    pub protocol: Option<String>,
    pub provider: Option<String>,
    pub udp: bool,
    pub history: Vec<Delay>,
    pub group: Option<Group>,
}

impl Outbound {
    pub fn of(o: &sail::control::OutboundInfo) -> Self {
        Self {
            tag: o.tag.clone(),
            kind: o.kind,
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
pub(crate) struct Outbounds {
    pub outbounds: Vec<Outbound>,
}

#[derive(Serialize)]
pub(crate) struct Mode {
    pub mode: String,
    pub modes: Vec<String>,
}

#[derive(Serialize)]
pub(crate) struct LogLine {
    /// `error`, `warn`, `info`, `debug` or `trace`.
    pub level: &'static str,
    pub message: String,
    pub time_ms: u64,
}

impl LogLine {
    pub fn of(line: &sail::app::logger::LogLine) -> Self {
        Self {
            level: match line.level {
                tracing::Level::ERROR => "error",
                tracing::Level::WARN => "warn",
                tracing::Level::INFO => "info",
                tracing::Level::DEBUG => "debug",
                tracing::Level::TRACE => "trace",
            },
            message: line.message.clone(),
            time_ms: millis_since_epoch(line.time),
        }
    }
}

/// A `log` event.
#[derive(Serialize)]
pub(crate) struct Log {
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
            "state": State { state: "failed", error: Some("x".into()), started_at_ms: None },
            "traffic": Traffic { up_total: 1, down_total: 2, connections: 3, memory: 4 },
            "status": Status { up: 1, down: 2, up_total: 3, down_total: 4, connections: 5, memory: 6 },
            "connection": Connection {
                id: 12, network: "tcp".into(), inbound_type: "socks".into(),
                inbound_tag: "in".into(), source: "127.0.0.1:5000".into(),
                destination: "example.com:443".into(), host: Some("example.com".into()),
                process: None, user: Some("alice".into()), upload: 4, download: 5,
                start: 1_759_300_000, chains: vec!["b".into(), "sel".into()], rule: None,
            },
            "outbound": Outbound {
                tag: "sel".into(), kind: "Selector", protocol: Some("selector".into()),
                provider: None, udp: true,
                history: vec![Delay { time_ms: millis_since_epoch(at), delay_ms: Some(millis(Duration::ZERO)) },
                              Delay { time_ms: 0, delay_ms: None }],
                group: Some(Group { selected: "b".into(), members: vec!["a".into(), "b".into()], selectable: true }),
            },
            "mode": Mode { mode: "Rule".into(), modes: vec!["Rule".into(), "Global".into()] },
            "log": Log { reset: true, lines: vec![LogLine { level: "info", message: "m".into(), time_ms: 1 }], dropped: 2 },
            "capabilities": InstanceCapabilities {
                has_tun: true, opens_tun: false, protects_sockets: true, needs_network: false, has_modes: true,
            },
        });
        let published = r#"{
  "capabilities": {"has_modes": true, "has_tun": true, "needs_network": false, "opens_tun": false, "protects_sockets": true},
  "connection": {"chains": ["b", "sel"], "destination": "example.com:443", "download": 5, "host": "example.com", "id": 12,
                 "inbound_tag": "in", "inbound_type": "socks", "network": "tcp", "process": null, "rule": null,
                 "source": "127.0.0.1:5000", "start": 1759300000, "upload": 4, "user": "alice"},
  "log": {"dropped": 2, "lines": [{"level": "info", "message": "m", "time_ms": 1}], "reset": true},
  "mode": {"mode": "Rule", "modes": ["Rule", "Global"]},
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
