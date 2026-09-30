//! sing-box's JSON, sail's own format. The model is written in its shape,
//! so reading it is sorting out what sing-box 1.14 accepts and sail does not
//! implement (see [`upstream`]) before the schema reads the rest.

use anyhow::{anyhow, Result};
use serde_json::Value;

use super::model::Config;

pub mod jsonc;
pub mod upstream;

/// Measured in the default build, whose support tables it writes.
#[cfg(all(
    test,
    feature = "all-endpoints",
    feature = "rule-set",
    feature = "outbound-provider",
    feature = "api",
    feature = "clash-api",
    feature = "dns-doh",
    feature = "dns-h3"
))]
mod registry;

use upstream::Tier;

/// Reads a sing-box configuration.
pub fn parse(s: &str) -> Result<Config> {
    // Comments and trailing commas, as sing-box takes them.
    let s = jsonc::strip(s);
    let mut value: Value = serde_json::from_str(&s).map_err(|e| anyhow!("{}", e))?;
    let warnings = sort_out(&mut value)?;
    let mut config: Config = serde_path_to_error::deserialize(value)
        .map_err(|e| anyhow!("{}: {}", super::model::path(&e), e.inner()))?;
    config.validate()?;
    config.warnings = warnings;
    Ok(config)
}

impl Config {
    /// Parses a JSON configuration: sing-box's, with sail's extensions.
    pub fn from_json(s: &str) -> Result<Self> {
        parse(s)
    }
}

/// Fails on the first field or value sail does not implement and cannot
/// ignore, and drops, with a warning each, those it can.
fn sort_out(value: &mut Value) -> Result<Vec<String>> {
    for (path, values) in upstream::VALUES {
        for (at, found) in find(value, path) {
            let names: Vec<&str> = match &found {
                Value::String(s) => vec![s.as_str()],
                Value::Array(a) => a.iter().filter_map(Value::as_str).collect(),
                _ => vec![],
            };
            if let Some(name) = names.into_iter().find(|n| values.contains(n)) {
                return Err(anyhow!("{}: sail does not implement \"{}\" yet", at, name));
            }
        }
    }
    let mut warnings = services(value)?;
    for group in upstream::GROUPS {
        for path in group.paths {
            for (at, _) in find(value, path) {
                let kind = entry_type(value, path, &at);
                if !group.types.is_empty() && !kind.is_some_and(|k| group.types.contains(&k)) {
                    continue;
                }
                if implemented_for(path, kind) {
                    continue;
                }
                match group.tier {
                    Tier::Unsupported => {
                        return Err(anyhow!("{}: sail does not implement this field yet", at));
                    }
                    Tier::Ignored => {
                        remove(value, &at);
                        warnings.push(format!(
                            "{}: sail does not implement this field; ignored",
                            at
                        ));
                    }
                }
            }
        }
    }
    for path in upstream::SILENT {
        for (at, _) in find(value, path) {
            remove(value, &at);
        }
    }
    for path in upstream::EMPTIED {
        for (at, found) in find(value, path) {
            if found.as_object().is_some_and(|o| o.is_empty()) {
                remove(value, &at);
            }
        }
    }
    Ok(warnings)
}

/// Drops the services sail can do without, with a warning each, and fails
/// on any other.
fn services(value: &mut Value) -> Result<Vec<String>> {
    let Some(Value::Array(services)) = value.get_mut("services") else {
        return Ok(Vec::new());
    };
    let mut warnings = Vec::new();
    for (i, service) in services.iter().enumerate() {
        let kind = service
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !upstream::IGNORED_SERVICES.iter().any(|(k, _)| *k == kind) {
            return Err(anyhow!(
                "services[{}].type: sail does not implement \"{}\" yet",
                i,
                kind
            ));
        }
        warnings.push(format!(
            "services[{}]: sail does not run the {} service; ignored",
            i, kind
        ));
    }
    if let Some(map) = value.as_object_mut() {
        map.remove("services");
    }
    Ok(warnings)
}

/// A step of a concrete path.
#[derive(Debug, Clone, PartialEq)]
enum Step {
    Key(String),
    Index(usize),
}

/// A concrete path, written as the schema's errors write theirs.
#[derive(Debug, Clone, PartialEq)]
struct At(Vec<Step>);

impl std::fmt::Display for At {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        for (i, step) in self.0.iter().enumerate() {
            match step {
                Step::Key(k) if i == 0 => write!(f, "{}", k)?,
                Step::Key(k) => write!(f, ".{}", k)?,
                Step::Index(n) => write!(f, "[{}]", n)?,
            }
        }
        Ok(())
    }
}

/// The values `pattern` names, with where each is.
fn find(value: &Value, pattern: &str) -> Vec<(At, Value)> {
    let mut found = Vec::new();
    let segments: Vec<&str> = pattern.split('.').collect();
    walk(value, &segments, &mut Vec::new(), &mut found);
    found
}

fn walk(value: &Value, segments: &[&str], at: &mut Vec<Step>, found: &mut Vec<(At, Value)>) {
    let Some((segment, rest)) = segments.split_first() else {
        found.push((At(at.clone()), value.clone()));
        return;
    };
    let mut visit = |step: Step, child: &Value| {
        at.push(step);
        walk(child, rest, at, found);
        at.pop();
    };
    match value {
        Value::Object(map) if *segment == "*" => {
            for (k, v) in map {
                visit(Step::Key(k.clone()), v);
            }
        }
        Value::Object(map) => {
            // `key[type]`: the object at `key`, of that type.
            let (key, kind) = match segment.strip_suffix(']').and_then(|s| s.split_once('[')) {
                Some((key, kind)) => (key, Some(kind)),
                None => (*segment, None),
            };
            if let Some(v) = map.get(key) {
                if kind.is_none_or(|k| v.get("type").and_then(Value::as_str) == Some(k)) {
                    visit(Step::Key(key.to_string()), v);
                }
            }
        }
        Value::Array(list) if *segment == "*" => {
            let rules = matches!(at.last(), Some(Step::Key(k)) if k == "rules");
            for (i, v) in list.iter().enumerate() {
                at.push(Step::Index(i));
                match rules {
                    true => walk_rule(v, rest, at, found),
                    false => walk(v, rest, at, found),
                }
                at.pop();
            }
        }
        _ => {}
    }
}

/// `walk` from a rule, and from each rule it combines, however deep.
fn walk_rule(rule: &Value, segments: &[&str], at: &mut Vec<Step>, found: &mut Vec<(At, Value)>) {
    walk(rule, segments, at, found);
    if let Some(Value::Array(rules)) = rule.get("rules") {
        at.push(Step::Key("rules".to_string()));
        for (i, sub) in rules.iter().enumerate() {
            at.push(Step::Index(i));
            walk_rule(sub, segments, at, found);
            at.pop();
        }
        at.pop();
    }
}

/// The type of the entry the field at `at`, found by `path`, is in: the
/// entry the pattern's first `*` stands for, its inbound or outbound.
fn entry_type<'a>(value: &'a Value, path: &str, at: &At) -> Option<&'a str> {
    let depth = path.split('.').position(|s| s == "*")? + 1;
    let mut entry = value;
    for step in at.0.get(..depth)? {
        entry = match (step, entry) {
            (Step::Key(k), Value::Object(map)) => map.get(k)?,
            (Step::Index(i), Value::Array(list)) => list.get(*i)?,
            _ => return None,
        };
    }
    entry.get("type").and_then(Value::as_str)
}

/// Whether sail implements the field `path` names for entries of type
/// `kind`; see `upstream::IMPLEMENTED_FOR`.
fn implemented_for(path: &str, kind: Option<&str>) -> bool {
    upstream::IMPLEMENTED_FOR
        .iter()
        .any(|(p, types)| *p == path && kind.is_some_and(|k| types.contains(&k)))
}

fn remove(value: &mut Value, at: &At) {
    let Some((last, parents)) = at.0.split_last() else {
        return;
    };
    let mut value = value;
    for step in parents {
        value = match (step, value) {
            (Step::Key(k), Value::Object(map)) => match map.get_mut(k) {
                Some(v) => v,
                None => return,
            },
            (Step::Index(i), Value::Array(list)) => match list.get_mut(*i) {
                Some(v) => v,
                None => return,
            },
            _ => return,
        };
    }
    if let (Step::Key(k), Value::Object(map)) = (last, value) {
        map.remove(k);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_inbound_detour_is_only_shadowtls_s() {
        let err =
            parse(r#"{ "inbounds": [{ "type": "socks", "listen_port": 1080, "detour": "x" }] }"#)
                .unwrap_err();
        assert_eq!(
            err.to_string(),
            "inbounds[0].detour: sail does not implement this field yet"
        );
        let config = parse(
            r#"{ "inbounds": [
                { "type": "shadowtls", "listen_port": 443, "detour": "ss" },
                { "type": "shadowsocks", "tag": "ss" }
            ] }"#,
        )
        .unwrap();
        assert_eq!(config.inbounds[0].options["detour"], "ss");
    }

    #[test]
    fn a_field_sail_can_ignore_is_dropped_with_a_warning() {
        let config = parse(
            r#"{
                "$schema": "https://example.com/schema.json",
                "experimental": { "cache_file": { "enabled": true, "store_rdrc": true } },
                "outbounds": [{ "type": "direct", "tcp_fast_open": true }]
            }"#,
        )
        .unwrap();
        assert_eq!(
            config.warnings,
            [
                "experimental.cache_file.store_rdrc: sail does not implement this field; ignored",
                "outbounds[0].tcp_fast_open: sail does not implement this field; ignored",
            ]
        );
        assert!(!config.outbounds[0].options.contains_key("tcp_fast_open"));
    }

    #[test]
    fn a_field_that_would_change_routing_is_an_error() {
        let err = parse(
            r#"{
                "outbounds": [{ "type": "direct" }],
                "route": { "rules": [{ "source_mac_address": "aa:bb:cc:dd:ee:ff", "outbound": "direct" }] }
            }"#,
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "route.rules[0].source_mac_address: sail does not implement this field yet"
        );
    }

    #[test]
    fn a_value_sail_lacks_is_an_error() {
        for (rule, message) in [
            (
                r#"{ "action": "predefined", "port": 53 }"#,
                r#"route.rules[0].action: sail does not implement "predefined" yet"#,
            ),
            (
                r#"{ "action": "sniff", "sniffer": ["tls", "ssh"] }"#,
                r#"route.rules[0].sniffer: sail does not implement "ssh" yet"#,
            ),
        ] {
            let err = parse(&format!(
                r#"{{ "outbounds": [{{ "type": "direct" }}], "route": {{ "rules": [{}] }} }}"#,
                rule
            ))
            .unwrap_err();
            assert_eq!(err.to_string(), message);
        }
    }

    #[test]
    fn the_rules_a_logical_one_combines_are_sorted_out_too() {
        let err = parse(
            r#"{ "outbounds": [{ "type": "direct", "tag": "d" }],
                 "route": { "rules": [{ "type": "logical", "mode": "and", "outbound": "d",
                   "rules": [{ "port": 53 }, { "type": "logical", "mode": "or",
                     "rules": [{ "preferred_by": "d" }] }] }] } }"#,
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "route.rules[0].rules[1].rules[0].preferred_by: sail does not implement this field yet"
        );
        // A response of their own, as sing-box's DNS rules may name.
        parse(
            r#"{ "dns": { "servers": [{ "type": "local" }], "rules": [
                   { "domain": "a", "action": "evaluate", "server": "local" },
                   { "type": "logical", "mode": "and", "server": "local",
                     "rules": [{ "match_response": true, "ip_accept_any": true }] }] } }"#,
        )
        .unwrap();
    }

    #[test]
    fn services_are_dropped_or_refused_by_type() {
        let config = parse(
            r#"{ "outbounds": [{ "type": "direct" }], "services": [
                 { "type": "api", "listen": "0.0.0.0", "listen_port": 9090,
                   "secret": "s", "dashboard": { "enabled": true, "path": "dashboard" } }
               ] }"#,
        )
        .unwrap();
        assert_eq!(
            config.warnings,
            ["services[0]: sail does not run the api service; ignored"]
        );
        let err = parse(
            r#"{ "outbounds": [{ "type": "direct" }], "services": [
                 { "type": "api" }, { "type": "resolved", "listen": "127.0.0.53" }
               ] }"#,
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "services[1].type: sail does not implement \"resolved\" yet"
        );
    }

    #[test]
    fn domain_strategy_and_resolver_options_are_read() {
        let config = parse(
            r#"{ "dns": { "servers": [
                   { "type": "udp", "tag": "u", "server": "1.1.1.1" },
                   { "type": "tls", "tag": "t", "server": "dns.example",
                     "domain_strategy": "ipv4_only",
                     "domain_resolver": { "server": "u", "client_subnet": "1.2.3.0/24" } }
                 ] },
                 "outbounds": [{ "type": "direct", "domain_strategy": "ipv6_only",
                   "domain_resolver": { "server": "u", "timeout": "1s",
                     "disable_cache": true, "rewrite_ttl": 30,
                     "disable_optimistic_cache": true } }],
                 "route": { "default_domain_resolver": { "server": "u",
                   "client_subnet": "2001:db8::/48" } } }"#,
        )
        .unwrap();
        assert!(config.warnings.is_empty(), "{:?}", config.warnings);
        let resolver: crate::config::model::DomainResolver =
            serde_json::from_value(config.outbounds[0].options["domain_resolver"].clone()).unwrap();
        assert!(resolver.disable_optimistic_cache);
        let resolver = config.route.default_domain_resolver.unwrap();
        assert_eq!(resolver.client_subnet, "2001:db8::/48".parse().ok());
    }

    #[test]
    fn a_route_rule_has_no_response_to_match() {
        let err = parse(
            r#"{ "outbounds": [{ "type": "direct" }],
                 "route": { "rules": [{ "ip_accept_any": true, "outbound": "direct" }] } }"#,
        )
        .unwrap_err();
        assert!(
            format!("{:#}", err)
                .contains("route.rules[0].ip_accept_any: unknown field `ip_accept_any`"),
            "{:#}",
            err
        );
    }

    #[test]
    fn http_clients_are_checked() {
        let with = |clients: &str, route: &str| {
            parse(&format!(
                r#"{{ "outbounds": [{{ "type": "direct", "tag": "direct" }}],
                     "http_clients": {}, "route": {} }}"#,
                clients, route
            ))
        };
        let remote = |client: &str| {
            format!(
                r#"{{ "rule_set": [{{ "type": "remote", "tag": "s",
                     "url": "https://example.com/s.srs"{} }}] }}"#,
                client
            )
        };
        let config = with(
            r#"[{ "tag": "c", "version": 2, "idle_timeout": "1m",
                  "headers": { "Authorization": "Bearer t", "X-A": ["1", "2"] } }]"#,
            &remote(r#", "http_client": "c""#),
        )
        .unwrap();
        assert_eq!(
            config.warnings,
            [
                "http_clients[0].version: sail does not implement this field; ignored",
                "http_clients[0].idle_timeout: sail does not implement this field; ignored",
            ]
        );
        assert_eq!(
            config.http_clients[0].header_lines(),
            [
                ("Authorization".to_string(), "Bearer t".to_string()),
                ("X-A".to_string(), "1".to_string()),
                ("X-A".to_string(), "2".to_string()),
            ]
        );
        // In place, its tag names nothing.
        with(
            "[]",
            &remote(r#", "http_client": { "tag": "none", "detour": "direct" }"#),
        )
        .unwrap();
        for (clients, route, message) in [
            (
                r#"[{ "detour": "direct" }]"#,
                "{}".to_string(),
                "http_clients[0].tag: missing",
            ),
            (
                r#"[{ "tag": "c" }, { "tag": "c" }]"#,
                "{}".to_string(),
                "http_clients[1]: another http client is tagged [c]",
            ),
            (
                r#"[{ "tag": "c", "detour": "proxy" }]"#,
                "{}".to_string(),
                "http_clients[0]: detour: outbound [proxy] does not exist",
            ),
            (
                r#"[{ "tag": "c", "detour": "direct", "routing_mark": 1 }]"#,
                "{}".to_string(),
                "http_clients[0]: routing_mark: has no effect with a detour; set it on [direct]",
            ),
            (
                r#"[{ "tag": "c", "headers": { "X-A": "1\r\nX-B: 2" } }]"#,
                "{}".to_string(),
                r#"http_clients[0]: headers: X-A: "1\r\nX-B: 2" breaks the line"#,
            ),
            (
                r#"[{ "tag": "c", "tls": { "enabled": true } }]"#,
                "{}".to_string(),
                "http_clients[0].tls: sail does not implement this field yet",
            ),
            (
                "[]",
                r#"{ "default_http_client": "c" }"#.to_string(),
                "route.default_http_client: http client [c] does not exist",
            ),
            (
                "[]",
                remote(r#", "http_client": "c""#),
                "route.rule_set[0].http_client: http client [c] does not exist",
            ),
            (
                r#"[{ "tag": "c" }]"#,
                remote(r#", "http_client": "c", "download_detour": "direct""#),
                "route.rule_set[0]: http_client: not with download_detour, which it replaces",
            ),
        ] {
            let err = with(clients, &route).unwrap_err();
            assert_eq!(format!("{:#}", err), message, "{} {}", clients, route);
        }
    }

    #[test]
    fn outbound_client_certificates_and_disable_sni_pass_through() {
        let config = parse(
            r#"{ "outbounds": [{ "type": "trojan", "server": "a", "server_port": 443,
                 "password": "p", "tls": { "enabled": true, "disable_sni": true,
                 "client_certificate_path": "c.crt", "client_key_path": "c.key" } }] }"#,
        )
        .unwrap();
        assert!(config.warnings.is_empty());
        let tls = &config.outbounds[0].options["tls"];
        assert_eq!(tls["disable_sni"], true);
        assert_eq!(tls["client_key_path"], "c.key");
        // An inbound verifying clients' certificates is another matter.
        let err = parse(
            r#"{ "inbounds": [{ "type": "trojan", "listen_port": 443, "users": [],
                 "tls": { "enabled": true, "client_certificate_path": ["ca.crt"] } }] }"#,
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "inbounds[0].tls.client_certificate_path: sail does not implement this field yet"
        );
    }

    #[test]
    fn dial_fields_sail_implements_pass_through() {
        let config = parse(
            r#"{ "outbounds": [{ "type": "direct", "inet4_bind_address": "192.0.2.1",
                 "inet6_bind_address": "2001:db8::1" }] }"#,
        )
        .unwrap();
        assert!(config.warnings.is_empty());
        assert!(config.outbounds[0]
            .options
            .contains_key("inet4_bind_address"));
        assert!(config.outbounds[0]
            .options
            .contains_key("inet6_bind_address"));
    }

    #[test]
    fn tcp_keep_alive_fields_are_read() {
        use crate::net::TcpKeepAlive;
        use std::time::Duration;

        let config = parse(
            r#"{ "inbounds": [{ "type": "mixed", "listen_port": 1080,
                   "tcp_keep_alive": "1m", "tcp_keep_alive_interval": "10s" }],
                 "outbounds": [{ "type": "direct", "tcp_keep_alive": "2m",
                   "tcp_keep_alive_interval": "20s" },
                   { "type": "direct", "tag": "off", "disable_tcp_keep_alive": true }] }"#,
        )
        .unwrap();
        assert!(config.warnings.is_empty(), "{:?}", config.warnings);
        assert_eq!(
            config.inbounds[0].tcp_keep_alive(),
            Some(TcpKeepAlive {
                idle: Duration::from_secs(60),
                interval: Duration::from_secs(10),
            })
        );
        let dial = |i: usize| {
            let (_, blocks) =
                crate::transport::layers::Blocks::DIAL.split(&config.outbounds[i].options);
            crate::config::model::parse_options::<crate::transport::layers::OutboundBlocks>(
                "outbound", "t", &blocks,
            )
            .unwrap()
            .dialer("t", &Default::default())
            .unwrap()
            .spec()
            .tcp_keep_alive
        };
        assert_eq!(
            dial(0),
            Some(TcpKeepAlive {
                idle: Duration::from_secs(120),
                interval: Duration::from_secs(20),
            })
        );
        assert_eq!(dial(1), None);
    }

    /// Outbounds, DNS servers, HTTP clients and REALITY's handshake read
    /// the dial fields alike: the same fields, warnings and errors, each
    /// under the place it is at. Built, as `sail -T` builds a
    /// configuration.
    #[cfg(all(
        feature = "outbound-direct",
        feature = "outbound-socks",
        feature = "inbound-vless",
        feature = "inbound-reality"
    ))]
    #[test]
    fn dial_fields_read_alike_in_every_place() {
        use serde_json::{json, Value};

        let load = |place: usize, dial: &Value| -> Result<Vec<String>, String> {
            let mut places = [
                json!({ "type": "socks", "tag": "o", "server": "192.0.2.2", "server_port": 1080 }),
                json!({ "type": "tcp", "tag": "d", "server": "192.0.2.53" }),
                json!({ "tag": "h" }),
                json!({ "server": "192.0.2.1", "server_port": 443 }),
            ];
            places[place]
                .as_object_mut()
                .unwrap()
                .extend(dial.as_object().unwrap().clone());
            let [outbound, server, client, handshake] = places;
            let config = json!({
                "inbounds": [{
                    "type": "vless", "tag": "r", "listen_port": 1443,
                    "users": [{ "uuid": "1b0e0a3e-1c2d-4e5f-8a9b-0c1d2e3f4a5b" }],
                    "tls": { "enabled": true, "server_name": "example.com", "reality": {
                        "enabled": true, "handshake": handshake,
                        "private_key": "11".repeat(32), "short_id": "0123",
                    } },
                }],
                "outbounds": [{ "type": "direct", "tag": "direct" }, outbound],
                "dns": { "servers": [server] },
                "http_clients": [client],
            });
            let config = parse(&config.to_string()).map_err(|e| format!("{:#}", e))?;
            crate::check_config(&config, &Default::default()).map_err(|e| format!("{:#}", e))?;
            Ok(config.warnings)
        };
        let at = [
            "outbounds[1]",
            "dns.servers[0]",
            "http_clients[0]",
            "inbounds[0].tls.reality.handshake",
        ];
        for (place, at) in at.into_iter().enumerate() {
            // What each place took before, and takes still.
            let bound = json!({
                "inet4_bind_address": "127.0.0.1", "inet6_bind_address": "::1",
                "connect_timeout": "3s",
            });
            assert_eq!(load(place, &bound), Ok(vec![]), "{}", at);
            // Ignored, or not implemented, the same everywhere.
            assert_eq!(
                load(place, &json!({ "tcp_fast_open": true })),
                Ok(vec![format!(
                    "{}.tcp_fast_open: sail does not implement this field; ignored",
                    at
                )]),
            );
            assert_eq!(
                load(place, &json!({ "netns": "n" })),
                Err(format!(
                    "{}.netns: sail does not implement this field yet",
                    at
                )),
            );
            // Keepalive: taken wherever sail dials a TCP connection of its
            // own accord.
            let keepalive = json!({ "tcp_keep_alive": "1m", "tcp_keep_alive_interval": "10s" });
            assert_eq!(load(place, &keepalive), Ok(vec![]), "{}", at);
        }
        // A value of the wrong type, and a detour that would leave a field
        // without effect: the same error, after the place.
        let errors = |dial: Value| {
            (0..4)
                .map(|place| load(place, &dial).unwrap_err())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            errors(json!({ "routing_mark": "x" })),
            [
                r#"[o] outbound: routing_mark: invalid type: string "x", expected u32"#,
                r#"[d] dns server: routing_mark: invalid type: string "x", expected u32"#,
                r#"http_clients[0]: routing_mark: invalid type: string "x", expected u32"#,
                r#"[r] inbound: tls.reality.handshake: routing_mark: invalid type: string "x", expected u32"#,
            ]
        );
        assert_eq!(
            errors(json!({ "detour": "direct", "tcp_keep_alive": "1m" })),
            [
                "[o] outbound: tcp_keep_alive: has no effect with a detour; set it on [direct]",
                "dns.servers[d]: tcp_keep_alive: has no effect with a detour; set it on [direct]",
                "http_clients[0]: tcp_keep_alive: has no effect with a detour; set it on [direct]",
                "inbounds[0].tls.reality.handshake.detour: sail does not implement this field yet",
            ]
        );
    }

    #[test]
    fn a_field_sing_box_does_not_know_is_a_mistake() {
        let err = parse(r#"{ "outbounds": [{ "type": "direct" }], "dsn": {} }"#).unwrap_err();
        assert!(err.to_string().contains("dsn"), "{}", err);
    }

    #[test]
    fn listable_fields_take_one_value() {
        let config = parse(
            r#"{
                "outbounds": [{ "type": "direct" }],
                "route": { "rules": [
                    { "action": "sniff", "sniffer": "tls" },
                    { "domain_suffix": "example.com", "port": 443, "outbound": "direct" }
                ] }
            }"#,
        )
        .unwrap();
        assert_eq!(config.route.rules[0].sniffer.len(), 1);
        assert_eq!(config.route.rules[1].domain_suffix, ["example.com"]);
        assert_eq!(config.route.rules[1].port, [443]);
    }

    #[test]
    fn log_fields_are_sing_box_s() {
        let config =
            parse(r#"{ "log": { "disabled": true, "level": "fatal", "timestamp": true } }"#)
                .unwrap();
        assert!(config.log.disabled && config.log.timestamp);
        let err = parse(r#"{ "log": { "level": "none" } }"#).unwrap_err();
        assert!(err.to_string().starts_with("log.level"), "{}", err);
    }
}
