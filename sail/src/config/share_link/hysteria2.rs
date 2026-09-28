//! `hysteria2://auth@host:port/?sni=...&obfs=salamander&obfs-password=...`
//! (or `hy2://`): Hysteria's link. The port may be a list for port hopping,
//! `host:443,5000-6000`, and `mport` adds ranges, as v2rayN writes them.
//! The port is 443 when unset.
//!
//! Deviations from mihomo: `pinSHA256` is an error, for sail cannot pin a
//! certificate's hash, where mihomo checks it; `obfs` other than
//! salamander is an error. `up` and `down` are Mbps, with an optional
//! `Mbps` or `Gbps`.

use anyhow::{anyhow, Result};
use serde_json::{json, Map};

use super::url::{decode_utf8, parse_port, shown, Link};
use super::v2ray::split_list;
use super::Parsed;

pub fn parse(link: &Link) -> Result<Parsed> {
    let mut specs = Vec::new();
    if let Some(ports) = link.port {
        specs.extend(ports.split(',').map(str::to_string));
    }
    if let Some(mport) = link.get("mport") {
        specs.extend(mport.split(',').map(str::to_string));
    }
    let mut ranges = Vec::new();
    for spec in specs.iter().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        match spec.split_once(['-', ':']) {
            Some((start, end)) => {
                let (start, end) = (parse_port(start)?, parse_port(end)?);
                if start > end {
                    return Err(anyhow!("port: a range ends before it starts"));
                }
                ranges.push((start, end));
            }
            None => {
                let port = parse_port(spec)?;
                ranges.push((port, port));
            }
        }
    }
    let port = ranges.first().map(|r| r.0).unwrap_or(443);

    let mut parsed = Parsed::new("hysteria2", link, port);
    if ranges.len() > 1 || ranges.first().is_some_and(|(s, e)| s != e) {
        let ports: Vec<String> = ranges
            .iter()
            .map(|(start, end)| format!("{}:{}", start, end))
            .collect();
        parsed.insert("server_ports", json!(ports));
    }
    let password = match link.userinfo {
        Some(u) if !u.is_empty() => decode_utf8(u, "auth")?,
        _ => link.get("auth").unwrap_or_default().to_string(),
    };
    parsed.insert("password", password);
    if let Some(up) = link.get_any(&["up", "upmbps"]) {
        parsed.insert("up_mbps", mbps("up", up)?);
    }
    if let Some(down) = link.get_any(&["down", "downmbps"]) {
        parsed.insert("down_mbps", mbps("down", down)?);
    }
    match link.get("obfs") {
        None | Some("none") => {}
        Some("salamander") => {
            let password = link
                .get("obfs-password")
                .ok_or_else(|| anyhow!("obfs-password: salamander needs one"))?;
            parsed.insert(
                "obfs",
                json!({ "type": "salamander", "password": password }),
            );
        }
        Some(other) => {
            return Err(anyhow!(
                "obfs: {} is not supported, only salamander",
                shown(other)
            ))
        }
    }
    if link.get("pinSHA256").is_some() {
        return Err(anyhow!("pinSHA256: sail cannot pin a certificate's hash"));
    }
    let mut tls = Map::new();
    tls.insert("enabled".into(), json!(true));
    if let Some(sni) = link.get_any(&["sni", "peer"]) {
        tls.insert("server_name".into(), json!(sni));
    }
    if link.any_flag(&["insecure", "allowInsecure"])? {
        tls.insert("insecure".into(), json!(true));
    }
    if let Some(alpn) = link.get("alpn") {
        tls.insert("alpn".into(), json!(split_list(alpn)));
    }
    parsed.insert("tls", tls);
    Ok(parsed)
}

/// A rate in Mbps: a number, perhaps with `Mbps` or `Gbps` after it.
fn mbps(field: &str, value: &str) -> Result<u64> {
    let v = value.trim().to_ascii_lowercase();
    let (number, factor) = if let Some(n) = v.strip_suffix("gbps").or(v.strip_suffix('g')) {
        (n, 1000)
    } else if let Some(n) = v.strip_suffix("mbps").or(v.strip_suffix('m')) {
        (n, 1)
    } else {
        (v.as_str(), 1)
    };
    number
        .trim()
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(factor))
        .ok_or_else(|| anyhow!("{}: not a rate in Mbps", field))
}
