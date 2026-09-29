//! Mihomo's `dns`, as sail's DNS servers and rules, in the order Mihomo
//! answers a query (its `dns/middleware.go` and `dns/resolver.go`):
//!
//! 1. With `enhanced-mode: fake-ip`, A, AAAA, HTTPS and SVCB queries the
//!    fake-ip filter does not keep out get a fake address, or no records;
//!    the instance's own lookups never do.
//! 2. `nameserver-policy`, in order: each key's domains go to its servers.
//! 3. With `fallback`, the domains of `fallback-filter.domain` and
//!    `.geosite` go to the fallback servers; other address queries go to
//!    `nameserver` first, whose answer is kept when it has addresses, none
//!    in `fallback-filter.ipcidr` and, with `geoip`, each at home
//!    (`geoip-code`) or private; else the fallback servers answer.
//! 4. `nameserver` answers the rest.
//!
//! The names outbounds dial resolve as Mihomo resolves them: the proxies'
//! servers through `proxy-server-nameserver`, DIRECT through
//! `direct-nameserver` (after the policy, with
//! `direct-nameserver-follow-policy`), else as a query goes. Servers with
//! domains are resolved through `default-nameserver`.
//!
//! Where sail does otherwise: Mihomo races a list of servers and takes the
//! first answer; sail's `smart_select` asks the one that has answered best
//! and the others when it fails, which gives the same answers at another
//! latency. Within a run of plain domain keys of `nameserver-policy`,
//! Mihomo's domain tree prefers the most specific; sail tries the keys
//! most specific first. `dns.ipv6: false` leaves the instance's own
//! lookups without IPv6 too, where Mihomo still resolves them for the
//! connections it makes. `ecs` always replaces the query's own client
//! subnet, as with `ecs-override`.

use std::collections::{HashMap, HashSet};

use anyhow::{anyhow, Result};
use indexmap::IndexMap;
use serde_json::{json, Map, Value};

use super::fields::{Fields, Tier};
use super::group::Policies;
use super::node::Node;
use super::provider::{domains, Sets};
use super::rule::{domain_rule, not};
use super::Lowered;
use crate::config::rule_set::ClashBehavior;

use Tier::*;

/// The fields of `dns` sail does not implement.
const DNS: &[(&str, Tier)] = &[
    // When and how long answers are waited for, not what they are.
    ("ipv6-timeout", Ignored),
    ("listen-routing-mark", Ignored),
];

/// The query types that get fake addresses, or no records: those whose
/// answers carry addresses.
const FAKE_TYPES: [&str; 4] = ["A", "AAAA", "HTTPS", "SVCB"];

/// The query types the fallback servers take, as Mihomo's `isIPRequest`.
const ADDRESS_TYPES: [&str; 3] = ["A", "AAAA", "CNAME"];

/// What Mihomo resolves the servers' domains with when
/// `default-nameserver` is not given.
const DEFAULT_NAMESERVER: [&str; 4] = ["114.114.114.114", "223.5.5.5", "8.8.8.8", "1.0.0.1"];

/// `nameserver` when it is not given.
const DEFAULT_NAMESERVER_LIST: [&str; 2] = ["https://doh.pub/dns-query", "tls://223.5.5.5:853"];

/// What `fake-ip-filter` keeps out when it is not given.
const DEFAULT_FAKE_IP_FILTER: [&str; 3] = [
    "dns.msftnsci.com",
    "www.msftnsci.com",
    "www.msftconnecttest.com",
];

pub fn lower(
    doc: &mut Fields,
    policies: &Policies,
    sets: &mut Sets,
    out: &mut Lowered,
    warnings: &mut Vec<String>,
) -> Result<()> {
    let ipv6 = doc.bool("ipv6")?.unwrap_or(true);
    let mut dns = doc.map("dns")?;
    let enabled = match dns.as_mut() {
        Some(dns) => dns.bool("enable")?.unwrap_or(false),
        None => false,
    };
    let mut dns = match dns {
        Some(dns) if enabled => dns,
        // Off, as by default, its other fields change nothing: names
        // resolve as the system resolves them, to IPv6 addresses too
        // unless `ipv6: false`.
        _ => {
            out.dns = json!({
                "servers": [{ "type": "local", "tag": "system" }],
                "strategy": if ipv6 { "prefer_ipv4" } else { "ipv4_only" },
            })
            .as_object()
            .cloned()
            .unwrap_or_default();
            return Ok(());
        }
    };
    let mut lowering = Lowering {
        servers: Servers {
            policies,
            list: Vec::new(),
            tags: HashSet::new(),
            selects: HashMap::new(),
            default_nameserver: None,
            resolver: None,
        },
        sets,
        rules: Vec::new(),
        warnings,
    };
    lowering.lower(&mut dns, ipv6, out)?;
    dns.finish(DNS, |_| false, lowering.warnings)
}

/// A list of Mihomo's servers, lowered.
#[derive(Debug, Clone, PartialEq)]
enum Target {
    /// A server, or a smart_select of several, by tag.
    Server(String),
    /// `rcode://`: an answer with this code and no records.
    Rcode(u16),
}

/// A list lowered, and the query types a server of it answers with no
/// records (`disable-qtype-*`), which, answering at once, wins Mihomo's
/// race.
struct Resolved {
    target: Target,
    disabled: Vec<u16>,
}

/// One of Mihomo's servers, lowered.
enum Parsed {
    Server { tag: String, disabled: Vec<u16> },
    Rcode(u16),
}

/// The servers made so far.
struct Servers<'a> {
    policies: &'a Policies,
    list: Vec<Value>,
    tags: HashSet<String>,
    /// The smart_selects made, by their members.
    selects: HashMap<Vec<String>, String>,
    /// `default-nameserver`, and where it is.
    default_nameserver: Option<(Vec<String>, String)>,
    /// What resolves the servers' domains, once made.
    resolver: Option<String>,
}

impl Servers<'_> {
    /// The server list `entries`, at `at`; `respect` is `respect-rules`,
    /// for a server that names no proxy.
    fn list(
        &mut self,
        at: &str,
        entries: &[String],
        respect: bool,
        warnings: &mut Vec<String>,
    ) -> Result<Option<Resolved>> {
        let mut members = Vec::new();
        let mut disabled = Vec::new();
        let mut rcode = None;
        for (i, entry) in entries.iter().enumerate() {
            let parsed = self
                .server(entry, respect, warnings)
                .map_err(|e| anyhow!("{}[{}]: {}", at, i, e))?;
            match parsed {
                Parsed::Rcode(code) => {
                    rcode.get_or_insert(code);
                }
                Parsed::Server { tag, disabled: d } => {
                    for ty in d {
                        if !disabled.contains(&ty) {
                            disabled.push(ty);
                        }
                    }
                    if !members.contains(&tag) {
                        members.push(tag);
                    }
                }
            }
        }
        // As Mihomo's race: an rcode answers at once.
        if let Some(code) = rcode {
            return Ok(Some(Resolved {
                target: Target::Rcode(code),
                disabled: Vec::new(),
            }));
        }
        let target = match members.len() {
            0 => return Ok(None),
            1 => members.remove(0),
            _ => match self.selects.get(&members) {
                Some(tag) => tag.clone(),
                None => {
                    let tag = at.to_string();
                    self.list.push(json!({
                        "type": "smart_select", "tag": tag, "servers": members
                    }));
                    self.selects.insert(members, tag.clone());
                    tag
                }
            },
        };
        Ok(Some(Resolved {
            target: Target::Server(target),
            disabled,
        }))
    }

    /// The server `raw`, as Mihomo's `parseNameServer` reads it.
    fn server(&mut self, raw: &str, respect: bool, warnings: &mut Vec<String>) -> Result<Parsed> {
        let raw = raw.trim();
        let url = if raw == "system" {
            "system://".to_string()
        } else if let Ok(ip) = raw.parse::<std::net::IpAddr>() {
            match ip {
                std::net::IpAddr::V4(_) => format!("udp://{}", raw),
                std::net::IpAddr::V6(_) => format!("udp://[{}]", raw),
            }
        } else if raw.contains("://") {
            raw.to_string()
        } else {
            format!("udp://{}", raw)
        };
        let (base, fragment) = match url.split_once('#') {
            Some((base, fragment)) => (base, percent_decode(fragment)),
            None => (url.as_str(), String::new()),
        };
        let (scheme, rest) = base
            .split_once("://")
            .ok_or_else(|| anyhow!("{:?} is not a server", raw))?;
        let scheme = scheme.to_ascii_lowercase();
        // A query string is dropped, as Mihomo drops it.
        let rest = rest.split('?').next().unwrap_or_default();
        let (host, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        };
        let mut name = String::new();
        let mut params = IndexMap::new();
        for part in fragment.split('&') {
            match part.split_once('=') {
                Some((key, value)) => {
                    params.insert(key.to_string(), value.to_string());
                }
                None => name = part.to_string(),
            }
        }
        let (kind, port) = match scheme.as_str() {
            "udp" => ("udp", 53),
            "tcp" => ("tcp", 53),
            "tls" => ("tls", 853),
            "https" if params.get("h3").map(String::as_str) == Some("true") => ("h3", 443),
            "https" => ("https", 443),
            "quic" => ("quic", 853),
            "system" => return Ok(self.local()),
            "dhcp" if rest == "system" => return Ok(self.local()),
            "rcode" => {
                return rcode(host).map(Parsed::Rcode);
            }
            "http" => {
                return Err(anyhow!(
                    "sail does not implement DNS over plain HTTP; use https://"
                ))
            }
            "dhcp" | "ts" | "tailscale" | "et" | "easytier" => {
                return Err(anyhow!("sail does not implement {}:// servers yet", scheme))
            }
            other => return Err(anyhow!("{:?} is not a scheme Mihomo takes", other)),
        };
        let (address, port) = host_port(host, port)?;
        let mut server = Map::new();
        server.insert("type".into(), json!(kind));
        server.insert("server".into(), json!(address));
        server.insert("server_port".into(), json!(port));
        if matches!(kind, "https" | "h3") && !path.is_empty() {
            server.insert("path".into(), json!(path));
        }
        let mut disabled = Vec::new();
        for (key, value) in &params {
            let on = value == "true";
            match key.as_str() {
                // Read with the scheme.
                "h3" => {}
                "skip-cert-verify" if on && matches!(kind, "tls" | "https" | "h3" | "quic") => {
                    server.insert("tls".into(), json!({ "insecure": true }));
                }
                "skip-cert-verify" => {}
                "ecs" => match value.parse::<crate::config::model::Prefix>() {
                    Ok(prefix) => {
                        server.insert("client_subnet".into(), json!(prefix.to_string()));
                    }
                    Err(_) => warnings.push(format!(
                        "{}: ecs={:?} is no address or prefix; ignored, as by Mihomo",
                        raw, value
                    )),
                },
                // sail's replaces the query's own always.
                "ecs-override" => {}
                "disable-ipv4" if on => disabled.push(1),
                "disable-ipv6" if on => disabled.push(28),
                key if key.starts_with("disable-qtype-") => {
                    if let (true, Ok(ty)) = (on, key["disable-qtype-".len()..].parse::<u16>()) {
                        disabled.push(ty);
                    }
                }
                "disable-ipv4" | "disable-ipv6" => {}
                "disable-reuse" => warnings.push(format!(
                    "{}: disable-reuse: sail does not implement this parameter; ignored",
                    raw
                )),
                "name-cert-verify" => {
                    return Err(anyhow!(
                        "name-cert-verify: sail does not implement this parameter yet"
                    ))
                }
                other => warnings.push(format!(
                    "{}: {}: not a parameter Mihomo takes; ignored",
                    raw, other
                )),
            }
        }
        let mut tag = raw.to_string();
        match name.as_str() {
            "" if respect => {
                server.insert("respect_rules".into(), json!(true));
                // The server Mihomo reads it as.
                tag.push(if fragment.is_empty() { '#' } else { '&' });
                tag.push_str("RULES");
            }
            "" | "DIRECT" => {}
            "RULES" => {
                server.insert("respect_rules".into(), json!(true));
            }
            name if self.policies.has(name) => {
                server.insert("detour".into(), json!(name));
            }
            // As Mihomo: a name no proxy has is an interface's.
            name => {
                server.insert("bind_interface".into(), json!(name));
            }
        }
        if !self.tags.contains(&tag) {
            if address.parse::<std::net::IpAddr>().is_err() {
                let resolver = self.resolver(warnings)?;
                server.insert("domain_resolver".into(), json!(resolver));
            }
            server.insert("tag".into(), json!(tag));
            self.list.push(Value::Object(server));
            self.tags.insert(tag.clone());
        }
        Ok(Parsed::Server { tag, disabled })
    }

    /// The system's resolver, which Mihomo's `system` is.
    fn local(&mut self) -> Parsed {
        let tag = "system".to_string();
        if self.tags.insert(tag.clone()) {
            self.list.push(json!({ "type": "local", "tag": tag }));
        }
        Parsed::Server {
            tag,
            disabled: Vec::new(),
        }
    }

    /// What resolves the servers' domains: `default-nameserver`, or
    /// Mihomo's default for it.
    fn resolver(&mut self, warnings: &mut Vec<String>) -> Result<String> {
        if let Some(tag) = &self.resolver {
            return Ok(tag.clone());
        }
        let (entries, at) = self.default_nameserver.clone().unwrap_or_else(|| {
            (
                DEFAULT_NAMESERVER.iter().map(|s| s.to_string()).collect(),
                "dns.default-nameserver".to_string(),
            )
        });
        // Its own servers are addresses: none of them asks for this again.
        for (i, entry) in entries.iter().enumerate() {
            let pure = entry.trim() == "system"
                || entry.trim().starts_with("system://")
                || entry
                    .split('#')
                    .next()
                    .and_then(|s| {
                        let s = s.split_once("://").map_or(s, |(_, rest)| rest);
                        let host = s.split('/').next().unwrap_or_default();
                        host_port(host, 0).ok()
                    })
                    .is_some_and(|(host, _)| host.parse::<std::net::IpAddr>().is_ok());
            if !pure {
                return Err(anyhow!(
                    "{}[{}]: {:?} is not an address, as Mihomo requires",
                    at,
                    i,
                    entry
                ));
            }
        }
        let resolved = self
            .list(&at, &entries, false, warnings)?
            .ok_or_else(|| anyhow!("{}: no server", at))?;
        let Target::Server(tag) = resolved.target else {
            return Err(anyhow!("{}: an rcode:// server resolves nothing", at));
        };
        self.resolver = Some(tag.clone());
        Ok(tag)
    }
}

/// A server's address and port, `[v6]:port`, `host:port` or `host`.
fn host_port(host: &str, default: u16) -> Result<(String, u16)> {
    let (address, port) = if let Some(rest) = host.strip_prefix('[') {
        let (address, rest) = rest
            .split_once(']')
            .ok_or_else(|| anyhow!("{:?}: a '[' without its ']'", host))?;
        (address, rest.strip_prefix(':'))
    } else {
        match host.rsplit_once(':') {
            Some((address, port)) if !address.contains(':') => (address, Some(port)),
            _ => (host, None),
        }
    };
    if address.is_empty() {
        return Err(anyhow!("{:?}: no address", host));
    }
    let port = match port {
        Some(port) => port
            .parse::<u16>()
            .ok()
            .filter(|p| *p != 0)
            .ok_or_else(|| anyhow!("{:?}: {:?} is not a port", host, port))?,
        None => default,
    };
    Ok((address.to_string(), port))
}

/// The code of `rcode://<name>`.
fn rcode(name: &str) -> Result<u16> {
    Ok(match name {
        "success" => 0,
        "format_error" => 1,
        "server_failure" => 2,
        "name_error" => 3,
        "not_implemented" => 4,
        "refused" => 5,
        other => return Err(anyhow!("rcode://{}: not a code Mihomo takes", other)),
    })
}

/// `%XX` escapes decoded, as Go's URL parser decodes a fragment.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 3 <= bytes.len() {
            if let Some(b) = s
                .get(i + 1..i + 3)
                .and_then(|h| u8::from_str_radix(h, 16).ok())
            {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| s.to_string())
}

/// A rule that holds where any of `conditions` does.
fn any(mut conditions: Vec<Map<String, Value>>) -> Map<String, Value> {
    if conditions.len() == 1 {
        return conditions.remove(0);
    }
    let mut rule = Map::new();
    rule.insert("type".into(), json!("logical"));
    rule.insert("mode".into(), json!("or"));
    rule.insert(
        "rules".into(),
        Value::Array(conditions.into_iter().map(Value::Object).collect()),
    );
    rule
}

/// A rule that holds where all of `conditions` do.
fn all(mut conditions: Vec<Map<String, Value>>) -> Map<String, Value> {
    if conditions.len() == 1 {
        return conditions.remove(0);
    }
    let mut rule = Map::new();
    rule.insert("type".into(), json!("logical"));
    rule.insert("mode".into(), json!("and"));
    rule.insert(
        "rules".into(),
        Value::Array(conditions.into_iter().map(Value::Object).collect()),
    );
    rule
}

fn query_types(types: &[&str]) -> Map<String, Value> {
    let mut rule = Map::new();
    rule.insert("query_type".into(), json!(types));
    rule
}

/// Where a rule sends what it matches: `target`, with the types its
/// servers disable answered first with no records.
fn route(
    rules: &mut Vec<Value>,
    condition: Map<String, Value>,
    resolved: &Resolved,
    extra: &[(&str, Value)],
) {
    if !resolved.disabled.is_empty() {
        let mut types = Map::new();
        types.insert("query_type".into(), json!(resolved.disabled));
        let mut rule = all(vec![condition.clone(), types]);
        rule.insert("action".into(), json!("predefined"));
        rules.push(Value::Object(rule));
    }
    let mut rule = condition;
    match &resolved.target {
        Target::Server(tag) => {
            rule.insert("server".into(), json!(tag));
        }
        Target::Rcode(code) => {
            rule.insert("action".into(), json!("predefined"));
            rule.insert("rcode".into(), json!(code));
        }
    }
    for (key, value) in extra {
        rule.insert(key.to_string(), value.clone());
    }
    rules.push(Value::Object(rule));
}

struct Lowering<'a, 'b> {
    servers: Servers<'a>,
    sets: &'b mut Sets,
    rules: Vec<Value>,
    warnings: &'b mut Vec<String>,
}

impl Lowering<'_, '_> {
    fn lower(&mut self, f: &mut Fields, ipv6: bool, out: &mut Lowered) -> Result<()> {
        self.ignored(f, "prefer-h3", |v| v.as_bool() == Some(true));
        self.ignored(f, "use-hosts", |v| v.as_bool() == Some(true));
        self.ignored(f, "use-system-hosts", |v| v.as_bool() == Some(true));
        self.ignored(f, "fallback-lazy-query", |v| v.as_bool() == Some(true));
        self.ignored(f, "cache-algorithm", |v| {
            v.as_string().is_some_and(|a| a != "lru")
        });
        if let Some(listen) = f.string("listen")?.filter(|l| !l.is_empty()) {
            self.warnings.push(format!(
                "{}: sail has no DNS listener yet; {} is not served",
                f.at("listen"),
                listen
            ));
        }
        let dns_ipv6 = f.bool("ipv6")?.unwrap_or(false);
        let respect = f.bool("respect-rules")?.unwrap_or(false);

        if f.has("default-nameserver") {
            let entries = f.strings("default-nameserver")?;
            if entries.is_empty() {
                return Err(anyhow!(
                    "{}: at least one server",
                    f.at("default-nameserver")
                ));
            }
            self.servers.default_nameserver = Some((entries, f.at("default-nameserver")));
        }

        let nameserver_at = f.at("nameserver");
        let entries = match f.has("nameserver") {
            true => f.strings("nameserver")?,
            false => DEFAULT_NAMESERVER_LIST.map(String::from).to_vec(),
        };
        let main = self
            .servers
            .list(&nameserver_at, &entries, respect, self.warnings)?
            .ok_or_else(|| anyhow!("{}: no server, which Mihomo requires", nameserver_at))?;
        let Target::Server(main_tag) = main.target.clone() else {
            return Err(anyhow!(
                "{}: an rcode:// server as the servers of every other query; sail \
                 does not implement it",
                nameserver_at
            ));
        };

        // Where the proxies' servers resolve.
        let proxy_at = f.at("proxy-server-nameserver");
        let entries = f.strings("proxy-server-nameserver")?;
        let proxy = self
            .servers
            .list(&proxy_at, &entries, false, self.warnings)?;
        if respect && proxy.is_none() {
            return Err(anyhow!(
                "{}: missing, which Mihomo requires with respect-rules",
                proxy_at
            ));
        }
        if let Some(policy) = f.map("proxy-server-nameserver-policy")? {
            if let Some(key) = policy.keys().first() {
                return Err(anyhow!(
                    "{}.{:?}: sail does not implement this field yet",
                    policy.path(),
                    key
                ));
            }
        }
        let default_resolver = match proxy {
            Some(Resolved {
                target: Target::Server(tag),
                ..
            }) => {
                out.route
                    .insert("default_domain_resolver".into(), json!(tag));
                true
            }
            Some(_) => {
                return Err(anyhow!(
                    "{}: an rcode:// server resolves no proxy's server",
                    proxy_at
                ))
            }
            None => false,
        };

        // Where DIRECT resolves.
        let direct_at = f.at("direct-nameserver");
        let entries = f.strings("direct-nameserver")?;
        let direct = self
            .servers
            .list(&direct_at, &entries, false, self.warnings)?;
        let follow = f.bool("direct-nameserver-follow-policy")?.unwrap_or(false);
        let direct_tags: Vec<String> = out
            .outbounds
            .iter()
            .filter(|o| o["type"] == "direct")
            .filter_map(|o| o["tag"].as_str().map(str::to_string))
            .collect();
        let mut direct_rule = None;
        match direct {
            Some(Resolved {
                target: Target::Server(tag),
                ..
            }) if !follow => {
                for o in out.outbounds.iter_mut().filter(|o| o["type"] == "direct") {
                    o["domain_resolver"] = json!(tag);
                }
            }
            Some(resolved) => {
                direct_rule = Some(resolved);
                self.skip_default(out, default_resolver);
            }
            None => self.skip_default(out, default_resolver),
        }

        // 1. Fake IPs.
        let mode = f
            .string("enhanced-mode")?
            .map(|m| m.to_ascii_lowercase())
            .unwrap_or_else(|| "redir-host".to_string());
        match mode.as_str() {
            "fake-ip" => self.fake_ip(f, ipv6)?,
            "redir-host" | "normal" => {
                for key in [
                    "fake-ip-range",
                    "fake-ip-range6",
                    "fake-ip-filter",
                    "fake-ip-filter-mode",
                    "fake-ip-ttl",
                ] {
                    f.take(key);
                }
            }
            other => {
                return Err(anyhow!(
                    "{}: {:?} is none of normal, fake-ip and redir-host",
                    f.at("enhanced-mode"),
                    other
                ))
            }
        }

        // 2. The policy.
        if let Some(mut policy) = f.map("nameserver-policy")? {
            self.policy(&mut policy, respect)?;
        }
        if let Some(resolved) = direct_rule {
            let mut outbound = Map::new();
            outbound.insert("outbound".into(), json!(direct_tags));
            // Their lookups are of addresses alone, which no server here
            // disables but for a family.
            let resolved = Resolved {
                disabled: Vec::new(),
                ..resolved
            };
            route(&mut self.rules, outbound, &resolved, &[]);
        }

        // Those the servers of every other query disable.
        if !main.disabled.is_empty() {
            let mut rule = Map::new();
            rule.insert("query_type".into(), json!(main.disabled));
            rule.insert("action".into(), json!("predefined"));
            self.rules.push(Value::Object(rule));
        }

        // 3. The fallback.
        let fallback_at = f.at("fallback");
        let entries = f.strings("fallback")?;
        let fallback = self
            .servers
            .list(&fallback_at, &entries, respect, self.warnings)?;
        let filter = f.map("fallback-filter")?;
        match fallback {
            Some(fallback) => self.fallback(&main_tag, &fallback, filter)?,
            None => drop(filter),
        }

        // 4. The rest.
        let mut dns = Map::new();
        dns.insert("servers".into(), Value::Array(self.servers.list.clone()));
        dns.insert(
            "rules".into(),
            Value::Array(std::mem::take(&mut self.rules)),
        );
        dns.insert("final".into(), json!(main_tag));
        dns.insert(
            "strategy".into(),
            json!(if ipv6 && dns_ipv6 {
                "prefer_ipv4"
            } else {
                "ipv4_only"
            }),
        );
        // Mihomo's `redir-host` and `fake-ip` both map the addresses
        // answered back to their domains.
        if mode != "normal" {
            dns.insert("reverse_mapping".into(), json!(true));
        }
        if let Some(size) = f.int::<usize>("cache-max-size")?.filter(|s| *s > 0) {
            dns.insert("cache_capacity".into(), json!(size));
        }
        out.dns = dns;
        Ok(())
    }

    /// Takes `key`, which sail does not implement, with a warning where
    /// `matters` says its value changes something.
    fn ignored(&mut self, f: &mut Fields, key: &str, matters: impl Fn(&Node) -> bool) {
        if let Some(value) = f.take(key) {
            if matters(&value) {
                self.warnings.push(format!(
                    "{}: sail does not implement this field; ignored",
                    f.at(key)
                ));
            }
        }
    }

    /// Makes the DIRECT outbounds resolve through the DNS rules, where
    /// the proxies' servers resolve through a default resolver.
    fn skip_default(&self, out: &mut Lowered, default_resolver: bool) {
        if !default_resolver {
            return;
        }
        for o in out.outbounds.iter_mut().filter(|o| o["type"] == "direct") {
            o["skip_default_domain_resolver"] = json!(true);
        }
    }

    /// The conditions of a list of Mihomo's domain entries, at `at`:
    /// patterns, `geosite:a,b` and `rule-set:a,b`, one for each kind there
    /// is.
    fn entries(&mut self, entries: &[String], at: &str) -> Result<Vec<Map<String, Value>>> {
        let mut patterns = Vec::new();
        let mut sets = Vec::new();
        for (i, entry) in entries.iter().enumerate() {
            self.entry(entry, &mut patterns, &mut sets)
                .map_err(|e| anyhow!("{}[{}]: {}", at, i, e))?;
        }
        Ok(self.conditions(patterns, sets))
    }

    /// Sorts `entry` into domain patterns and the tags of rule-sets.
    fn entry(
        &mut self,
        entry: &str,
        patterns: &mut Vec<String>,
        sets: &mut Vec<String>,
    ) -> Result<()> {
        let lower = entry.to_ascii_lowercase();
        if lower.starts_with("geosite:") {
            for name in entry[8..].split(',') {
                sets.push(self.sets.geosite(name.trim())?);
            }
        } else if lower.starts_with("rule-set:") {
            for name in entry[9..].split(',') {
                sets.push(self.domain_set(name.trim())?);
            }
        } else {
            patterns.push(entry.to_string());
        }
        Ok(())
    }

    fn conditions(&self, patterns: Vec<String>, sets: Vec<String>) -> Vec<Map<String, Value>> {
        let mut conditions = Vec::new();
        if !patterns.is_empty() {
            conditions.push(domains(&patterns));
        }
        if !sets.is_empty() {
            let mut rule = Map::new();
            rule.insert("rule_set".into(), json!(sets));
            conditions.push(rule);
        }
        conditions
    }

    /// The rule-provider `name`, which is to match domains.
    fn domain_set(&mut self, name: &str) -> Result<String> {
        if self.sets.provider(name)? == ClashBehavior::Ipcidr {
            return Err(anyhow!(
                "{:?} is a rule-set of IP prefixes, not of domains",
                name
            ));
        }
        Ok(name.to_string())
    }

    /// `enhanced-mode: fake-ip`.
    fn fake_ip(&mut self, f: &mut Fields, ipv6: bool) -> Result<()> {
        let range = match f.string("fake-ip-range")? {
            None => Some("198.18.0.1/16".to_string()),
            Some(r) if r.is_empty() => None,
            Some(r) => Some(r),
        };
        let range6 = f.string("fake-ip-range6")?.filter(|r| !r.is_empty());
        // As Mihomo: without IPv6, no IPv6 range.
        let range6 = range6.filter(|_| ipv6);
        let mut server = Map::new();
        server.insert("type".into(), json!("fakeip"));
        server.insert("tag".into(), json!("fake-ip"));
        for (key, field, range, v6) in [
            ("inet4_range", "fake-ip-range", range, false),
            ("inet6_range", "fake-ip-range6", range6, true),
        ] {
            let Some(range) = range else { continue };
            let network = network(&range, v6).map_err(|e| anyhow!("{}: {}", f.at(field), e))?;
            server.insert(key.into(), json!(network));
        }
        if server.len() == 2 {
            return Err(anyhow!(
                "{}: missing, and so is fake-ip-range6, which fake-ip needs one of",
                f.at("fake-ip-range")
            ));
        }
        let ttl = f.int::<u32>("fake-ip-ttl")?.unwrap_or(1);
        let mode = f
            .string("fake-ip-filter-mode")?
            .map(|m| m.to_ascii_lowercase())
            .unwrap_or_else(|| "blacklist".to_string());
        let filter_at = f.at("fake-ip-filter");
        let filter = match f.has("fake-ip-filter") {
            true => f.strings("fake-ip-filter")?,
            false => DEFAULT_FAKE_IP_FILTER.map(String::from).to_vec(),
        };
        let types = query_types(&FAKE_TYPES);
        let conditions: Vec<Map<String, Value>> = match mode.as_str() {
            "blacklist" => {
                let kept = self.entries(&filter, &filter_at)?;
                if kept.is_empty() {
                    vec![types]
                } else {
                    vec![all(vec![types, not(any(kept))])]
                }
            }
            "whitelist" => {
                let taken = self.entries(&filter, &filter_at)?;
                if taken.is_empty() {
                    vec![]
                } else {
                    vec![all(vec![types, any(taken)])]
                }
            }
            "rule" => self.fake_ip_rules(&filter, &filter_at, types)?,
            other => {
                return Err(anyhow!(
                    "{}: {:?} is none of blacklist, whitelist and rule",
                    f.at("fake-ip-filter-mode"),
                    other
                ))
            }
        };
        if conditions.is_empty() {
            return Ok(());
        }
        self.servers.list.push(Value::Object(server));
        for mut rule in conditions {
            rule.insert("server".into(), json!("fake-ip"));
            rule.insert("rewrite_ttl".into(), json!(ttl));
            self.rules.push(Value::Object(rule));
        }
        Ok(())
    }

    /// `fake-ip-filter-mode: rule`: the rules, in order, give a domain a
    /// fake address (`fake-ip`) or its own (`real-ip`); what none matches
    /// gets a fake one.
    fn fake_ip_rules(
        &mut self,
        filter: &[String],
        at: &str,
        types: Map<String, Value>,
    ) -> Result<Vec<Map<String, Value>>> {
        let mut real: Vec<Map<String, Value>> = Vec::new();
        let mut fake = Vec::new();
        let mut matched_all = false;
        for (i, line) in filter.iter().enumerate() {
            let (condition, target) =
                domain_rule(line, self.sets).map_err(|e| anyhow!("{}[{}]: {}", at, i, e))?;
            let is_fake = match target.to_ascii_lowercase().as_str() {
                "fake-ip" => true,
                "real-ip" => false,
                other => {
                    return Err(anyhow!(
                        "{}[{}]: {:?} is neither fake-ip nor real-ip",
                        at,
                        i,
                        other
                    ))
                }
            };
            match (condition, is_fake) {
                (Some(condition), false) => real.push(condition),
                (None, false) => {
                    matched_all = true;
                    break;
                }
                (condition, true) => {
                    let mut all_of = vec![types.clone()];
                    all_of.extend(condition.clone());
                    if !real.is_empty() {
                        all_of.push(not(any(real.clone())));
                    }
                    fake.push(all(all_of));
                    if condition.is_none() {
                        matched_all = true;
                        break;
                    }
                }
            }
        }
        if !matched_all {
            let mut all_of = vec![types];
            if !real.is_empty() {
                all_of.push(not(any(real)));
            }
            fake.push(all(all_of));
        }
        Ok(fake)
    }

    /// `nameserver-policy`: its keys, as Mihomo's
    /// `parseNameServerPolicy` splits them, each sending its domains to
    /// its servers.
    fn policy(&mut self, policy: &mut Fields, respect: bool) -> Result<()> {
        // A run of plain domain keys, which Mihomo matches as one tree.
        let mut run: Vec<(String, Map<String, Value>, Resolved)> = Vec::new();
        for key in policy.keys() {
            let at = format!("{}.{:?}", policy.path(), key);
            let entries = match policy.take(&key) {
                None => Vec::new(),
                Some(Node::Seq(items)) => items
                    .iter()
                    .enumerate()
                    .map(|(i, n)| {
                        n.as_string()
                            .ok_or_else(|| anyhow!("{}[{}]: a server, not {}", at, i, n.kind()))
                    })
                    .collect::<Result<Vec<_>>>()?,
                Some(n) => vec![n
                    .as_string()
                    .ok_or_else(|| anyhow!("{}: a server, not {}", at, n.kind()))?],
            };
            // No server: no policy, as in Mihomo.
            let Some(resolved) = self.servers.list(&at, &entries, respect, self.warnings)? else {
                continue;
            };
            let lower = key.to_ascii_lowercase();
            if lower.starts_with("geosite:") || lower.starts_with("rule-set:") {
                self.flush(&mut run);
                let (mut patterns, mut sets) = (Vec::new(), Vec::new());
                self.entry(&key, &mut patterns, &mut sets)
                    .map_err(|e| anyhow!("{}: {}", at, e))?;
                let condition = any(self.conditions(patterns, sets));
                route(&mut self.rules, condition, &resolved, &[]);
            } else {
                let patterns: Vec<String> = key.split(',').map(|k| k.trim().to_string()).collect();
                run.push((patterns[0].clone(), domains(&patterns), resolved));
            }
        }
        self.flush(&mut run);
        Ok(())
    }

    /// The rules of a run of plain domain keys, the most specific first, as
    /// Mihomo's domain tree prefers it.
    fn flush(&mut self, run: &mut Vec<(String, Map<String, Value>, Resolved)>) {
        run.sort_by_key(|(pattern, _, _)| std::cmp::Reverse(specificity(pattern)));
        for (_, condition, resolved) in run.drain(..) {
            route(&mut self.rules, condition, &resolved, &[]);
        }
    }

    /// `fallback`, with `fallback-filter`.
    fn fallback(&mut self, main: &str, fallback: &Resolved, filter: Option<Fields>) -> Result<()> {
        let mut filter = match filter {
            Some(filter) => filter,
            None => Fields::of(Node::Null, "dns.fallback-filter")?,
        };
        let geoip = filter.bool("geoip")?.unwrap_or(true);
        let code = filter
            .string("geoip-code")?
            .unwrap_or_else(|| "CN".to_string());
        let cidrs = filter.strings("ipcidr")?;
        let patterns = filter.strings("domain")?;
        let geosite_at = filter.at("geosite");
        let mut sets = Vec::new();
        for (i, name) in filter.strings("geosite")?.iter().enumerate() {
            sets.push(
                self.sets
                    .geosite(name)
                    .map_err(|e| anyhow!("{}[{}]: {}", geosite_at, i, e))?,
            );
        }
        let conditions = self.conditions(patterns, sets);
        filter.finish(&[], |_| false, self.warnings)?;

        let types = query_types(&ADDRESS_TYPES);
        if !conditions.is_empty() {
            route(
                &mut self.rules,
                all(vec![types.clone(), any(conditions)]),
                fallback,
                &[],
            );
        }
        let mut evaluate = types.clone();
        evaluate.insert("action".into(), json!("evaluate"));
        evaluate.insert("server".into(), json!(main));
        self.rules.push(Value::Object(evaluate));
        if !cidrs.is_empty() {
            let mut rule = Map::new();
            rule.insert("match_response".into(), json!(true));
            rule.insert("ip_cidr".into(), json!(cidrs));
            route(&mut self.rules, rule, fallback, &[]);
        }
        // Kept: an answer with addresses, each at home or private.
        let mut keep = Map::new();
        keep.insert("match_response".into(), json!(true));
        if geoip && !code.eq_ignore_ascii_case("lan") {
            keep.insert("ip_match_all".into(), json!(true));
            keep.insert("ip_is_private".into(), json!(true));
            keep.insert("rule_set".into(), json!([self.sets.geoip(&code)?]));
        } else {
            keep.insert("ip_accept_any".into(), json!(true));
        }
        keep.insert("action".into(), json!("respond"));
        self.rules.push(Value::Object(keep));
        route(&mut self.rules, types, fallback, &[]);
        Ok(())
    }
}

/// How specific a domain pattern is, as Mihomo's domain tree ranks them:
/// by its labels, then an exact domain over a `*` label over `+.` and `.`.
fn specificity(pattern: &str) -> (usize, u8) {
    let pattern = pattern.trim();
    let (base, kind) = if let Some(base) = pattern.strip_prefix("+.") {
        (base, 0)
    } else if let Some(base) = pattern.strip_prefix('.') {
        (base, 0)
    } else if pattern.split('.').any(|l| l == "*") {
        (pattern, 1)
    } else {
        (pattern, 2)
    };
    let labels = base.split('.').filter(|l| *l != "*").count();
    (labels, kind)
}

/// The network of `range`, which Mihomo writes with an address in it
/// (`198.18.0.1/16`).
fn network(range: &str, v6: bool) -> Result<String> {
    let prefix: crate::config::model::Prefix = range.parse()?;
    let addr = match prefix.addr {
        std::net::IpAddr::V4(a) if !v6 => {
            let mask = u32::MAX.checked_shl(32 - prefix.len as u32).unwrap_or(0);
            std::net::IpAddr::from((u32::from(a) & mask).to_be_bytes())
        }
        std::net::IpAddr::V6(a) if v6 => {
            let mask = u128::MAX.checked_shl(128 - prefix.len as u32).unwrap_or(0);
            std::net::IpAddr::from((u128::from(a) & mask).to_be_bytes())
        }
        _ => {
            return Err(anyhow!(
                "{:?} is not an {} prefix",
                range,
                if v6 { "IPv6" } else { "IPv4" }
            ))
        }
    };
    Ok(format!("{}/{}", addr, prefix.len))
}
