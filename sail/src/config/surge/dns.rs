//! DNS: the keys of `[General]` and `[Host]`. The servers, `dns-server`
//! and `encrypted-dns-server`, each list asked all at once, as Surge asks
//! it, a `race` of them; the families names resolve to; and `hijack-dns`,
//! the queries to other servers answered here, as are those to Surge's
//! own addresses (`198.18.0.2` to `198.18.0.9`, `fd00:6152::2`).
//!
//! A query answered here, not one sail asks itself, is answered as
//! Surge's DNS responder answers it, in this order:
//!
//! 1. `use-application-dns.net`, Firefox's canary, does not exist.
//! 2. Without `allow-dns-svcb`, HTTPS and SVCB queries are refused as not
//!    implemented, whose hints would pass the fake addresses by.
//! 3. A and AAAA queries get a fake address, of `198.18.0.0/15` (and
//!    `fd00:6152::/96` with `ipv6`), but for the names `always-real-ip`
//!    lists; the addresses are kept across restarts, as Surge keeps them.
//!
//! Then any query, sail's own too:
//!
//! 4. The proxies' servers skip `[Host]` and the system's hosts, as in
//!    Surge.
//! 5. `[Host]`, each line in order, the first that matches answering: an
//!    address or a list of them, another name (a CNAME, looked up again),
//!    or `server:` the servers to ask (as `dns-server` writes them,
//!    `system` for the system's resolver). Its key is a name, a wildcard
//!    (`*` any characters, `?` one, `*.a` not `a` itself) or the names of a
//!    `DOMAIN-SET:` or `RULE-SET:` file.
//! 6. With `read-etc-hosts`, as by default, the system's hosts file.
//! 7. Names ending with `.local`, and those of no dot, go to the system's
//!    resolver.
//! 8. The servers answer the rest.
//!
//! Where sail does otherwise: a name `[Host]` maps and proxies ask for
//! goes to the proxy as the name, whatever `use-local-host-item-for-proxy`
//! says; a fake address is given for either family whichever the query
//! comes over; `pre-matching` rules reject when the connection is made,
//! not at its query.

use anyhow::{anyhow, Result};
use serde_json::{json, Map, Value};

use super::params::Params;
use super::rule::wildcard;
use super::sets::{self, Sets};
use super::text::{self, Line};
use super::Lowered;

/// The fake address server, and its ranges.
const FAKE_IP: &str = "fakeip";
const FAKE_RANGE: &str = "198.18.0.0/15";
const FAKE_RANGE6: &str = "fd00:6152::/96";
/// The hosts server of `[Host]`'s names, and that of the system's.
const HOSTS: &str = "hosts";
const SYSTEM_HOSTS: &str = "system-hosts";
/// The system's resolver.
const SYSTEM: &str = "system";

/// What `[General]` says of DNS that `[Host]` and the rules need, read
/// before them.
pub struct Dns {
    /// The server of every other query.
    main: String,
    ipv6: bool,
    /// `encrypted-dns-follow-outbound-mode`, `-skip-cert-verification`.
    follow: bool,
    insecure: bool,
    /// The server the encrypted ones' names resolve through.
    resolver: Option<String>,
    /// `always-real-ip`: the names, each excluded or not.
    real: Vec<(bool, String)>,
    svcb: bool,
    etc_hosts: bool,
    /// Where `use-local-host-item-for-proxy` is, when it is on.
    local_for_proxy: Option<String>,
}

/// The servers, the families and the rules of `hijack-dns`.
pub fn lower(p: &mut Params, out: &mut Lowered) -> Result<(Vec<Value>, Dns)> {
    let mut servers: Vec<Value> = Vec::new();
    let mut plain = Vec::new();
    let mut encrypted = Vec::new();
    if let Some((value, at)) = p.take_at("dns-server") {
        for entry in value.split(',').map(str::trim).filter(|e| !e.is_empty()) {
            // An encrypted one here is taken as one, as Surge does.
            if entry.contains("://") {
                encrypted.push((entry.to_string(), at.clone()));
                continue;
            }
            let tag = entry.to_string();
            if plain.contains(&tag) {
                continue;
            }
            let server = if entry.eq_ignore_ascii_case("system") {
                json!({ "type": "local", "tag": tag })
            } else {
                let (host, port) = host_port(entry, 53).map_err(|e| anyhow!("{}: {}", at, e))?;
                if host.parse::<std::net::IpAddr>().is_err() {
                    return Err(anyhow!("{}: {:?} is not an IP address", at, entry));
                }
                json!({ "type": "udp", "tag": tag, "server": host, "server_port": port })
            };
            servers.push(server);
            plain.push(tag);
        }
    }
    for key in ["encrypted-dns-server", "doh-server"] {
        if let Some((value, at)) = p.take_at(key) {
            for entry in value.split(',').map(str::trim).filter(|e| !e.is_empty()) {
                encrypted.push((entry.to_string(), at.clone()));
            }
        }
    }
    let follow = p
        .bool("encrypted-dns-follow-outbound-mode")?
        .unwrap_or(false)
        | p.bool("doh-follow-outbound-mode")?.unwrap_or(false);
    let insecure = p
        .bool("encrypted-dns-skip-cert-verification")?
        .unwrap_or(false)
        | p.bool("doh-skip-cert-verification")?.unwrap_or(false);
    let ipv6 = p.bool("ipv6")?.unwrap_or(false);

    let plain = server_list(&mut servers, "dns-server", plain);
    let mut resolver = plain.clone();
    let mut secure = Vec::new();
    for (entry, at) in encrypted {
        if secure.contains(&entry) {
            continue;
        }
        let mut server = encrypted_server(&entry).map_err(|e| anyhow!("{}: {}", at, e))?;
        if follow {
            server.insert("respect_rules".into(), json!(true));
        }
        if insecure {
            server.insert("tls".into(), json!({ "insecure": true }));
        }
        let named = server
            .get("server")
            .and_then(Value::as_str)
            .is_some_and(|h| h.parse::<std::net::IpAddr>().is_err());
        if named {
            // The plain servers resolve the encrypted ones' names.
            let tag = resolver
                .get_or_insert_with(|| {
                    servers.push(json!({ "type": "local", "tag": "system" }));
                    "system".to_string()
                })
                .clone();
            server.insert("domain_resolver".into(), json!(tag));
        }
        servers.push(Value::Object(server));
        secure.push(entry);
    }
    let secure = server_list(&mut servers, "encrypted-dns-server", secure);
    let main = secure.or(plain).unwrap_or_else(|| {
        servers.push(json!({ "type": "local", "tag": "system" }));
        "system".to_string()
    });
    let real = match p.take_at("always-real-ip") {
        Some((value, _)) => host_list(&value),
        None => Vec::new(),
    };
    let settings = Dns {
        main: main.clone(),
        ipv6,
        follow,
        insecure,
        resolver,
        real,
        svcb: p.bool("allow-dns-svcb")?.unwrap_or(false),
        etc_hosts: p.bool("read-etc-hosts")?.unwrap_or(true),
        local_for_proxy: match p.take_at("use-local-host-item-for-proxy") {
            Some((value, at)) if value.eq_ignore_ascii_case("true") => Some(at),
            _ => None,
        },
    };
    let mut dns = Map::new();
    dns.insert("servers".into(), Value::Array(servers));
    dns.insert("final".into(), json!(main));
    // Without `ipv6`, Surge asks for no AAAA records.
    dns.insert(
        "strategy".into(),
        json!(if ipv6 { "prefer_ipv4" } else { "ipv4_only" }),
    );
    out.dns = dns;
    Ok((hijack(p)?, settings))
}

/// The server `tags` are asked as one, as Surge races a list: the tag of
/// a race of them named `name` when there are several.
fn server_list(servers: &mut Vec<Value>, name: &str, tags: Vec<String>) -> Option<String> {
    match tags.len() {
        0 => None,
        1 => tags.into_iter().next(),
        _ => {
            servers.push(json!({ "type": "race", "tag": name, "servers": tags }));
            Some(name.to_string())
        }
    }
}

/// An encrypted server's URL: `https://`, `h3://`, `quic://`, `tls://`
/// or `tcp://` (plain DNS over TCP).
fn encrypted_server(url: &str) -> Result<Map<String, Value>> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| anyhow!("{:?} is not a URL", url))?;
    let (kind, port) = match scheme.to_ascii_lowercase().as_str() {
        "https" => ("https", 443),
        "h3" => ("h3", 443),
        "quic" => ("quic", 853),
        "tls" => ("tls", 853),
        "tcp" => ("tcp", 53),
        other => {
            return Err(anyhow!(
                "{:?}: {} is none of https, h3, quic, tls and tcp",
                url,
                other
            ))
        }
    };
    let (host, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    let (host, port) = host_port(host, port).map_err(|e| anyhow!("{:?}: {}", url, e))?;
    let mut server = Map::new();
    server.insert("type".into(), json!(kind));
    server.insert("tag".into(), json!(url));
    server.insert("server".into(), json!(host));
    server.insert("server_port".into(), json!(port));
    if matches!(kind, "https" | "h3") && !path.is_empty() {
        server.insert("path".into(), json!(path));
    }
    Ok(server)
}

/// `host`, `host:port`, `[v6]` or `[v6]:port`; a bare IPv6 address too.
fn host_port(s: &str, default: u16) -> Result<(String, u16)> {
    let port = |p: &str| {
        p.parse::<u16>()
            .map_err(|_| anyhow!("{:?} is not a port", p))
    };
    if let Some(rest) = s.strip_prefix('[') {
        let (host, rest) = rest
            .split_once(']')
            .ok_or_else(|| anyhow!("{:?}: a '[' without its ']'", s))?;
        return match rest.strip_prefix(':') {
            Some(p) => Ok((host.to_string(), port(p)?)),
            None => Ok((host.to_string(), default)),
        };
    }
    match s.matches(':').count() {
        0 => Ok((s.to_string(), default)),
        1 => {
            let (host, p) = s.split_once(':').expect("a colon");
            Ok((host.to_string(), port(p)?))
        }
        _ => Ok((s.to_string(), default)),
    }
}

/// `hijack-dns`: the DNS queries to these servers, `*` for any, are
/// answered here, before any rule.
fn hijack(p: &mut Params) -> Result<Vec<Value>> {
    let (value, at) = p.take_at("hijack-dns").unwrap_or_default();
    let mut rules = Vec::new();
    for entry in value.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        let (host, port) = host_port(entry, 53).map_err(|e| anyhow!("{}: {}", at, e))?;
        let mut rule = Map::new();
        rule.insert("network".into(), json!("udp"));
        if host != "*" {
            let ip: std::net::IpAddr = host
                .parse()
                .map_err(|_| anyhow!("{}: {:?} is neither an IP address nor *", at, host))?;
            let len = if ip.is_ipv4() { 32 } else { 128 };
            rule.insert("ip_cidr".into(), json!([format!("{}/{}", ip, len)]));
        }
        rule.insert("port".into(), json!([port]));
        rule.insert("action".into(), json!("hijack-dns"));
        rules.push(Value::Object(rule));
    }
    // Surge's own DNS addresses, which its system and clients are given.
    rules.push(json!({
        "network": "udp",
        "ip_cidr": ["198.18.0.2/31", "198.18.0.4/30", "198.18.0.8/31", "fd00:6152::2/128"],
        "port": [53],
        "action": "hijack-dns",
    }));
    Ok(rules)
}

/// A Host List (`always-real-ip`): names and wildcards, each excluded
/// with `-`, the first that matches deciding; a `:port` after one is
/// passed over, as DNS has no port, and so are `<ip-address>` and its
/// like, which name no name.
fn host_list(value: &str) -> Vec<(bool, String)> {
    value
        .split(',')
        .map(str::trim)
        .filter(|e| !e.is_empty() && !e.contains('<'))
        .map(|e| {
            let (excluded, name) = match e.strip_prefix('-') {
                Some(name) => (true, name),
                None => (false, e),
            };
            let name = match name.rsplit_once(':') {
                Some((name, port)) if port.parse::<u16>().is_ok() => name,
                _ => name,
            };
            (excluded, name.to_ascii_lowercase())
        })
        .collect()
}

/// The condition of a name or a wildcard, as `[Host]` and Host Lists have
/// them.
fn name_condition(name: &str) -> Map<String, Value> {
    let mut rule = Map::new();
    if name.contains(['*', '?']) {
        rule.insert("domain_regex".into(), json!([wildcard(name)]));
    } else {
        rule.insert("domain".into(), json!([name.to_ascii_lowercase()]));
    }
    rule
}

fn any(conditions: Vec<Map<String, Value>>) -> Map<String, Value> {
    logical("or", conditions)
}

fn logical(mode: &str, conditions: Vec<Map<String, Value>>) -> Map<String, Value> {
    let mut rule = Map::new();
    rule.insert("type".into(), json!("logical"));
    rule.insert("mode".into(), json!(mode));
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

/// The DNS servers lowered so far.
fn servers(out: &mut Lowered) -> &mut Vec<Value> {
    let servers = out
        .dns
        .entry("servers")
        .or_insert_with(|| Value::Array(Vec::new()));
    match servers {
        Value::Array(list) => list,
        _ => unreachable!("the servers are a list"),
    }
}

fn has_server(out: &mut Lowered, tag: &str) -> bool {
    servers(out).iter().any(|s| s["tag"] == tag)
}

/// The server `[Host]` writes `entry` for, added where it is not yet:
/// `system` (or `syslib`, `force-syslib`) the system's resolver, an
/// address and port, or an encrypted server's URL, as `dns-server` and
/// `encrypted-dns-server` have them.
fn host_server(entry: &str, dns: &mut Dns, out: &mut Lowered) -> Result<String> {
    if matches!(
        entry.to_ascii_lowercase().as_str(),
        "system" | "syslib" | "force-syslib"
    ) {
        if !has_server(out, SYSTEM) {
            servers(out).push(json!({ "type": "local", "tag": SYSTEM }));
        }
        return Ok(SYSTEM.to_string());
    }
    if has_server(out, entry) {
        return Ok(entry.to_string());
    }
    if !entry.contains("://") {
        let (host, port) = host_port(entry, 53)?;
        if host.parse::<std::net::IpAddr>().is_err() {
            return Err(anyhow!("{:?} is not an IP address", entry));
        }
        servers(out)
            .push(json!({ "type": "udp", "tag": entry, "server": host, "server_port": port }));
        return Ok(entry.to_string());
    }
    let mut server = encrypted_server(entry)?;
    if dns.follow {
        server.insert("respect_rules".into(), json!(true));
    }
    if dns.insecure {
        server.insert("tls".into(), json!({ "insecure": true }));
    }
    let named = server
        .get("server")
        .and_then(Value::as_str)
        .is_some_and(|h| h.parse::<std::net::IpAddr>().is_err());
    if named {
        let resolver = match &dns.resolver {
            Some(tag) => tag.clone(),
            None => {
                if !has_server(out, SYSTEM) {
                    servers(out).push(json!({ "type": "local", "tag": SYSTEM }));
                }
                dns.resolver = Some(SYSTEM.to_string());
                SYSTEM.to_string()
            }
        };
        server.insert("domain_resolver".into(), json!(resolver));
    }
    servers(out).push(Value::Object(server));
    Ok(entry.to_string())
}

/// What a `[Host]` line gives its names.
enum Answer {
    /// Addresses, or another name.
    Hosts(Value),
    /// The servers to ask.
    Servers(Vec<String>),
}

/// `[Host]`, and the DNS of `[General]` read before: the DNS rules, in the
/// order the module describes.
pub fn host(
    lines: Vec<Line>,
    mut dns: Dns,
    sets: &mut Sets,
    out: &mut Lowered,
    warnings: &mut Vec<String>,
) -> Result<()> {
    let mut rules: Vec<Value> = Vec::new();
    let mut new_servers: Vec<Value> = Vec::new();
    // 1, 2. Firefox's canary; HTTPS and SVCB.
    rules.push(json!({
        "domain": ["use-application-dns.net"],
        "action": "predefined",
        "rcode": "NXDOMAIN",
    }));
    if !dns.svcb {
        let mut rule = query_types(&["HTTPS", "SVCB"]);
        rule.insert("action".into(), json!("predefined"));
        rule.insert("rcode".into(), json!("NOTIMP"));
        rules.push(Value::Object(rule));
    }
    // 3. Fake addresses, but for always-real-ip's names.
    let mut real = Vec::new();
    let mut excluded = Vec::new();
    for (minus, name) in &dns.real {
        let condition = name_condition(name);
        if *minus {
            excluded.push(condition);
        } else if excluded.is_empty() {
            real.push(condition);
        } else {
            real.push(logical("and", vec![condition, not(any(excluded.clone()))]));
        }
    }
    let mut fake = query_types(&["A", "AAAA"]);
    if !real.is_empty() {
        fake = logical("and", vec![fake, not(any(real))]);
    }
    fake.insert("server".into(), json!(FAKE_IP));
    rules.push(Value::Object(fake));
    let mut fake_server = json!({ "type": "fakeip", "tag": FAKE_IP, "inet4_range": FAKE_RANGE });
    if dns.ipv6 {
        fake_server["inet6_range"] = json!(FAKE_RANGE6);
    }
    new_servers.push(fake_server);
    let mut cache = out.cache_file.take().unwrap_or_default();
    cache.insert("enabled".into(), json!(true));
    cache.insert("store_fakeip".into(), json!(true));
    out.cache_file = Some(cache);

    // 4. The proxies' servers.
    let proxies: Vec<String> = out
        .outbounds
        .iter()
        .filter(|o| {
            !matches!(
                o["type"].as_str().unwrap_or_default(),
                "direct" | "block" | "selector" | "urltest" | "fallback" | "load-balance" | "smart"
            )
        })
        .filter_map(|o| o["tag"].as_str().map(str::to_string))
        .collect();
    let has_hosts = !lines.is_empty() || dns.etc_hosts;
    if has_hosts && !proxies.is_empty() {
        rules.push(json!({ "outbound": proxies, "server": dns.main }));
    }

    // 5. [Host].
    let mut names = Map::new();
    let mut mapped = false;
    for line in lines {
        let at = format!("[Host] {}", line.loc);
        let Some((key, value)) = line
            .text
            .split_once('=')
            .map(|(k, v)| (text::unquote(k), text::unquote(v)))
        else {
            warnings.push(format!(
                "{}: {:?} is not name = value; ignored, as by Surge",
                at, line.text
            ));
            continue;
        };
        let err = |e: anyhow::Error| anyhow!("{}: {}: {}", at, key, e);
        let answer = answer(&value, &mut dns, out).map_err(err)?;
        let set = [
            ("DOMAIN-SET:", sets::Kind::Domains),
            ("RULE-SET:", sets::Kind::Rules),
        ]
        .into_iter()
        .find_map(|(prefix, kind)| {
            key.get(..prefix.len())
                .filter(|p| p.eq_ignore_ascii_case(prefix))
                .map(|_| (kind, key[prefix.len()..].trim().to_string()))
        });
        let mut condition = match &set {
            Some((kind, location)) => {
                let tag = sets.file(*kind, location, None).map_err(err)?;
                let mut rule = Map::new();
                rule.insert("rule_set".into(), json!([tag]));
                rule
            }
            None => name_condition(&key),
        };
        match answer {
            Answer::Servers(tags) => {
                let tag = match <[String; 1]>::try_from(tags) {
                    Ok([one]) => one,
                    Err(tags) => {
                        let tag = format!("server:{}", tags.join(","));
                        if !new_servers.iter().any(|s| s["tag"] == tag.as_str()) {
                            new_servers
                                .push(json!({ "type": "race", "tag": tag, "servers": tags }));
                        }
                        tag
                    }
                };
                condition.insert("server".into(), json!(tag));
            }
            Answer::Hosts(value) => {
                mapped = true;
                let server = if set.is_none() && !key.contains(['*', '?']) {
                    // The first line of a name decides, as in Surge.
                    let name = key.trim_end_matches('.').to_ascii_lowercase();
                    if !names.contains_key(&name) {
                        names.insert(name, value);
                    }
                    HOSTS.to_string()
                } else {
                    // A server of its own, giving any name what the line
                    // gives the names its rule lets through.
                    let tag = format!("{}:{}", HOSTS, key);
                    if !new_servers.iter().any(|s| s["tag"] == tag.as_str()) {
                        new_servers.push(json!({
                            "type": "hosts",
                            "tag": tag,
                            "predefined": any_name(&value),
                        }));
                    }
                    tag
                };
                condition = logical("and", vec![condition, query_types(&["A", "AAAA"])]);
                condition.insert("server".into(), json!(server));
            }
        }
        rules.push(Value::Object(condition));
    }
    if !names.is_empty() {
        new_servers.push(json!({ "type": "hosts", "tag": HOSTS, "predefined": names }));
    }
    if let (Some(at), true) = (&dns.local_for_proxy, mapped) {
        warnings.push(format!(
            "{}: sail sends a proxy the name [Host] maps, not its address; ignored",
            at
        ));
    }

    // 6. The system's hosts.
    if dns.etc_hosts {
        new_servers.push(json!({ "type": "hosts", "tag": SYSTEM_HOSTS }));
        rules.push(json!({
            "query_type": ["A", "AAAA"],
            "action": "evaluate",
            "server": SYSTEM_HOSTS,
        }));
        rules.push(json!({
            "match_response": true,
            "ip_accept_any": true,
            "action": "respond",
        }));
    }

    // 7. Local and simple names.
    if !has_server(out, SYSTEM) {
        new_servers.push(json!({ "type": "local", "tag": SYSTEM }));
    }
    rules.push(json!({
        "type": "logical",
        "mode": "or",
        "rules": [{ "domain_suffix": ["local"] }, { "domain_regex": ["^[^.]+$"] }],
        "server": SYSTEM,
    }));

    for server in new_servers {
        if server["tag"] == HOSTS && has_server(out, HOSTS) {
            return Err(anyhow!("[Host]: a server is tagged {}", HOSTS));
        }
        servers(out).push(server);
    }
    out.dns.insert("rules".into(), Value::Array(rules));
    Ok(())
}

fn not(condition: Map<String, Value>) -> Map<String, Value> {
    let mut rule = logical("and", vec![condition]);
    rule.insert("invert".into(), json!(true));
    rule
}

/// What a `[Host]` value gives: `server:` servers, `script:` (an error),
/// addresses, or another name.
fn answer(value: &str, dns: &mut Dns, out: &mut Lowered) -> Result<Answer> {
    let lower = value.to_ascii_lowercase();
    if lower.starts_with("script:") {
        return Err(anyhow!("sail does not run DNS scripts"));
    }
    if lower.starts_with("server:") {
        let tags = value["server:".len()..]
            .split(',')
            .map(str::trim)
            .filter(|e| !e.is_empty())
            .map(|e| host_server(e, dns, out))
            .collect::<Result<Vec<_>>>()?;
        if tags.is_empty() {
            return Err(anyhow!("server: names no server"));
        }
        return Ok(Answer::Servers(tags));
    }
    let entries: Vec<&str> = value
        .split(',')
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .collect();
    let ips: Vec<&str> = entries
        .iter()
        .copied()
        .filter(|e| e.parse::<std::net::IpAddr>().is_ok())
        .collect();
    match entries.as_slice() {
        [] => Err(anyhow!("no address, name or server")),
        _ if ips.len() == entries.len() => Ok(Answer::Hosts(json!(ips))),
        [name] if crate::sniff::is_domain_name(name.trim_end_matches('.')) => {
            Ok(Answer::Hosts(json!(name)))
        }
        _ => Err(anyhow!(
            "{:?} is neither addresses nor a name nor server:",
            value
        )),
    }
}

/// How many labels a name a wildcard's server answers has at most.
const MAX_LABELS: usize = 32;

/// Names of sail's hosts (Mihomo's patterns) that any name of up to
/// `MAX_LABELS` labels matches, a `*` a label: each given `value`.
fn any_name(value: &Value) -> Map<String, Value> {
    (1..=MAX_LABELS)
        .map(|n| (vec!["*"; n].join("."), value.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_and_ports() {
        assert_eq!(host_port("1.1.1.1", 53).unwrap(), ("1.1.1.1".into(), 53));
        assert_eq!(
            host_port("1.1.1.1:5353", 53).unwrap(),
            ("1.1.1.1".into(), 5353)
        );
        assert_eq!(host_port("[::1]:54", 53).unwrap(), ("::1".into(), 54));
        assert_eq!(
            host_port("2001:db8::1", 53).unwrap(),
            ("2001:db8::1".into(), 53)
        );
        assert!(host_port("a:b", 53).is_err());
    }
}
