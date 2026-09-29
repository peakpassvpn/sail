//! The DNS keys of `[General]`, as far as this stage reads them: the
//! servers, `dns-server` and `encrypted-dns-server`, each list asked all at
//! once as Surge does (sail's `smart_select` asks the one that answers best,
//! which gives the same answers); the families names resolve to; and
//! `hijack-dns`, the queries to other servers answered here.
//!
//! TODO(C.5b): [Host], fake addresses, `always-real-ip`,
//! `allow-dns-svcb`, `read-etc-hosts`, `use-local-host-item-for-proxy`.

use anyhow::{anyhow, Result};
use serde_json::{json, Map, Value};

use super::params::Params;
use super::Lowered;

/// The servers, the families and the rules of `hijack-dns`.
pub fn lower(p: &mut Params, out: &mut Lowered) -> Result<Vec<Value>> {
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
    let mut dns = Map::new();
    dns.insert("servers".into(), Value::Array(servers));
    dns.insert("final".into(), json!(main));
    // Without `ipv6`, Surge asks for no AAAA records.
    dns.insert(
        "strategy".into(),
        json!(if ipv6 { "prefer_ipv4" } else { "ipv4_only" }),
    );
    out.dns = dns;
    hijack(p)
}

/// The server `tags` are asked as one, as Surge races a list: the tag of
/// a smart_select of them named `name` when there are several.
// TODO: a `race` server once DNS has it, answering as Surge does.
fn server_list(servers: &mut Vec<Value>, name: &str, tags: Vec<String>) -> Option<String> {
    match tags.len() {
        0 => None,
        1 => tags.into_iter().next(),
        _ => {
            servers.push(json!({ "type": "smart_select", "tag": name, "servers": tags }));
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
    let Some((value, at)) = p.take_at("hijack-dns") else {
        return Ok(Vec::new());
    };
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
    Ok(rules)
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
