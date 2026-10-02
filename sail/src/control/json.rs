//! The JSON hosts are answered with, the C ABI and the management API
//! alike: sail's own shape, the control types serialized in snake_case
//! with typed fields (the Clash API renders Mihomo's from the same types).
//!
//! It carries no version number. It only grows: a field, a type or a
//! string value may be added, and a host ignores what it does not know
//! (the Swift and Kotlin bindings do). Taking a field away, renaming it, or
//! changing its type or meaning breaks hosts: it follows the sail release
//! and goes in the release notes; the management API takes it to a new
//! path (/api/v2). The snapshot test below, which the bindings' tests read
//! too, catches a change made by accident.

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
    /// The sail release.
    pub version: &'static str,
    /// The modules compiled in (`inbound-tun`, `outbound-vless`…): what was
    /// built, not which calls or fields there are. A call a sail lacks
    /// answers that it is unsupported; a field it lacks is absent.
    pub features: Vec<&'static str>,
}

/// What an instance can do, as it runs.
#[derive(Serialize)]
pub struct InstanceCapabilities {
    /// The sail release the instance runs: through a command service
    /// client, the tunnel process's, which may differ from the app's after
    /// an update (an old system extension still running).
    pub version: String,
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
    /// The domain it goes to: the destination's, else the name it was
    /// dialled as (`override_destination`), else the one sniffed.
    pub host: Option<String>,
    /// The domain a sniff found, from a TLS server name or an HTTP Host.
    pub sniff_host: Option<String>,
    /// Where the name it was dialled as came from, `sniff` or
    /// `reverse_mapping`; none where it was dialled as asked.
    pub dial_domain_source: Option<String>,
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
            sniff_host: c.sniff_host.clone(),
            dial_domain_source: c.dial_domain_source.map(str::to_owned),
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

/// A user's limits: what `user_limits` sets, or the management API set
/// since. A field that is `null` limits nothing.
#[derive(Serialize)]
pub struct Limits {
    pub max_connections: Option<u32>,
    pub quota_bytes: Option<u64>,
    /// When it may no longer connect, in milliseconds since the epoch.
    pub expire_at_ms: Option<u64>,
    pub up_mbps: Option<u64>,
    pub down_mbps: Option<u64>,
}

impl Limits {
    pub fn of(l: &crate::user::Limits) -> Self {
        Self {
            max_connections: l.max_connections,
            quota_bytes: l.quota_bytes,
            expire_at_ms: l.expire_at.map(millis_since_epoch),
            up_mbps: l.up_mbps,
            down_mbps: l.down_mbps,
        }
    }
}

/// Bytes up and down, and the TCP connections and UDP sessions there were.
#[derive(Serialize)]
pub struct Counts {
    pub up: u64,
    pub down: u64,
    pub tcp: u64,
    pub udp: u64,
}

impl Counts {
    pub fn of(c: &crate::app::stat_manager::Counts) -> Self {
        Self {
            up: c.up,
            down: c.down,
            tcp: c.tcp,
            udp: c.udp,
        }
    }
}

/// A user, by name, across the inbounds it is in.
#[derive(Serialize)]
pub struct User {
    pub name: String,
    /// The inbounds whose configuration has it.
    pub inbounds: Vec<String>,
    /// Neither over its quota nor expired: it may connect.
    pub active: bool,
    pub over_quota: bool,
    pub expired: bool,
    pub limits: Limits,
    /// Since it was first counted, across restarts with the cache file.
    pub traffic: Counts,
    /// Its live connections.
    pub live: u64,
    /// Up and down together since its quota was last reset.
    pub quota_used: u64,
}

impl User {
    pub fn of(u: &crate::user::UserSnapshot) -> Self {
        Self {
            name: u.name.clone(),
            inbounds: u.inbounds.clone(),
            active: u.status.active(),
            over_quota: u.status.exhausted(),
            expired: u.status.expired(),
            limits: Limits::of(&u.limits),
            traffic: Counts::of(&u.traffic),
            live: u.live as u64,
            quota_used: u.quota_used,
        }
    }
}

#[derive(Serialize)]
pub struct Users {
    pub users: Vec<User>,
}

/// The traffic of each user, inbound and outbound, by name or tag.
#[derive(Serialize)]
pub struct Stats {
    pub users: std::collections::BTreeMap<String, Counts>,
    pub inbounds: std::collections::BTreeMap<String, Counts>,
    pub outbounds: std::collections::BTreeMap<String, Counts>,
}

impl Stats {
    pub fn of(r: &crate::app::stat_manager::TrafficReport) -> Self {
        let by = |list: &[(String, crate::app::stat_manager::Counts)]| {
            list.iter()
                .map(|(k, c)| (k.clone(), Counts::of(c)))
                .collect()
        };
        Self {
            users: by(&r.users),
            inbounds: by(&r.inbounds),
            outbounds: by(&r.outbounds),
        }
    }
}

/// An inbound as it runs.
#[derive(Serialize)]
pub struct Inbound {
    pub tag: String,
    /// Its type, as the configuration has it.
    pub protocol: String,
    pub listen: Option<String>,
    pub listen_port: Option<u16>,
    /// Whether its users and certificate change while it runs.
    pub reloadable: bool,
}

impl Inbound {
    pub fn of(i: &crate::control::InboundInfo) -> Self {
        Self {
            tag: i.tag.clone(),
            protocol: i.protocol.clone(),
            listen: i.listen.clone(),
            listen_port: i.listen_port,
            reloadable: i.reloadable,
        }
    }
}

#[derive(Serialize)]
pub struct Inbounds {
    pub inbounds: Vec<Inbound>,
}

/// The names of an inbound's users; their credentials are not told.
#[derive(Serialize)]
pub struct InboundUsers {
    pub users: Vec<String>,
}

/// What happened to a user: an event of the management API's stream.
#[derive(Serialize)]
pub struct UserEvent {
    /// `shut`: it went over its quota, or past its expiry, and was
    /// disconnected; `removed`: it was taken out of `inbound`, and
    /// disconnected from it.
    pub event: &'static str,
    pub user: String,
    /// For `shut`.
    pub over_quota: bool,
    pub expired: bool,
    /// For `removed`.
    pub inbound: Option<String>,
}

impl UserEvent {
    pub fn of(e: &crate::user::UserEvent) -> Self {
        match e {
            crate::user::UserEvent::Shut { user, status } => Self {
                event: "shut",
                user: user.clone(),
                over_quota: status.exhausted(),
                expired: status.expired(),
                inbound: None,
            },
            crate::user::UserEvent::Removed { user, inbound } => Self {
                event: "removed",
                user: user.clone(),
                over_quota: false,
                expired: false,
                inbound: Some(inbound.clone()),
            },
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
                sniff_host: Some("sni.example.com".into()), dial_domain_source: Some("sniff".into()),
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
                version: "0.15.0".into(), has_tun: true, opens_tun: false, protects_sockets: true,
                needs_network: false, has_modes: true,
            },
            "sail_capabilities": Capabilities { version: "0.15.0", features: vec!["inbound-socks"] },
            "providers": Providers { providers: vec![Provider {
                tag: "sub".into(), source: "remote".into(), members: 3,
                updated_ms: Some(millis_since_epoch(at)), next_update_ms: None,
                failure: Some(Failure { at_ms: 1, error: "http status 503".into() }),
                subscription: Some(Subscription { upload: 1, download: 2, total: 3, expire_ms: None }),
            }] },
            "users": Users { users: vec![User {
                name: "alice".into(), inbounds: vec!["t".into()], active: false, over_quota: true,
                expired: false,
                limits: Limits { max_connections: Some(2), quota_bytes: Some(10), expire_at_ms: Some(millis_since_epoch(at)),
                                 up_mbps: None, down_mbps: Some(5) },
                traffic: Counts { up: 1, down: 2, tcp: 3, udp: 4 }, live: 1, quota_used: 12,
            }] },
            "inbounds": Inbounds { inbounds: vec![Inbound {
                tag: "t".into(), protocol: "trojan".into(), listen: Some("::".into()),
                listen_port: Some(443), reloadable: true,
            }] },
            "user_event": UserEvent {
                event: "removed", user: "alice".into(), over_quota: false, expired: false,
                inbound: Some("t".into()),
            },
            "inbound_users": InboundUsers { users: vec!["alice".into()] },
            "stats": Stats {
                users: [("alice".to_string(), Counts { up: 1, down: 2, tcp: 3, udp: 0 })].into(),
                inbounds: Default::default(), outbounds: Default::default(),
            },
            "rule_sets": RuleSets { rule_sets: vec![RuleSet {
                tag: "ads".into(), source: "local".into(), format: Some("clash-yaml".into()),
                behavior: Some("domain".into()), rules: 9, updated_ms: None, next_update_ms: None, failure: None,
            }] },
        });
        // The published shape: the bindings' tests read it too.
        let published = include_str!("json_snapshot.json");
        let published: serde_json::Value = serde_json::from_str(published).unwrap();
        let mut gone = Vec::new();
        missing("", &published, &snapshot, &mut gone);
        assert!(
            snapshot == published,
            "the JSON hosts read changed. {}Now:\n{:#}",
            if gone.is_empty() {
                "Something was added or a value changed: update json_snapshot.json.\n".to_string()
            } else {
                format!(
                    "Gone or renamed: {}. That breaks hosts: it follows the sail \
                     release and needs a release note.\n",
                    gone.join(", ")
                )
            },
            snapshot
        );
    }

    /// The keys of `published`, as paths, that `now` has no more.
    fn missing(
        at: &str,
        published: &serde_json::Value,
        now: &serde_json::Value,
        gone: &mut Vec<String>,
    ) {
        use serde_json::Value;
        match (published, now) {
            (Value::Object(was), Value::Object(is)) => {
                for (key, value) in was {
                    let path = format!("{}/{}", at, key);
                    match is.get(key) {
                        Some(now) => missing(&path, value, now, gone),
                        None => gone.push(path),
                    }
                }
            }
            (Value::Array(was), Value::Array(is)) => {
                for (n, (value, now)) in was.iter().zip(is).enumerate() {
                    missing(&format!("{}/{}", at, n), value, now, gone);
                }
            }
            _ => {}
        }
    }
}
