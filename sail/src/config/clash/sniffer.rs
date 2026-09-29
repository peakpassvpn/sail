//! `sniffer`, as `sniff` rules ahead of every other, one for each
//! protocol sniffed: as Mihomo sniffs before it routes, a connection to an
//! address rather than a name (`parse-pure-ip`, or `force-dns-mapping`), or
//! to a name `force-domain` matches, on the ports of the protocol, and
//! from and to no address `skip-src-address` or `skip-dst-address`
//! matches. A name found that `skip-domain` matches is not taken, through
//! the rule's `skip_rule_set`, a sail extension.
//!
//! Where sail does otherwise: a connection to an address the DNS answered
//! for a name, which Mihomo sniffs with `force-dns-mapping`, is sniffed
//! only while the address stands for no name in sail; where sail's DNS
//! maps it back, it is routed by that name.

use anyhow::{anyhow, Result};
use serde_json::{json, Map, Value};

use super::fields::Fields;
use super::provider::{domains, Sets};
use super::Lowered;
use crate::config::rule_set::ClashBehavior;

/// The tag of the rule-set of `skip-domain`'s own patterns.
const SKIP: &str = "sniffer:skip-domain";

/// The protocols Mihomo sniffs, in the order it tries them, with the ports
/// it sniffs them on unless told, and the network they come over.
const PROTOCOLS: &[(&str, &str, u16, &str)] = &[
    ("TLS", "tls", 443, "tcp"),
    ("HTTP", "http", 80, "tcp"),
    ("QUIC", "quic", 443, "udp"),
];

pub fn lower(
    doc: &mut Fields,
    sets: &mut Sets,
    out: &mut Lowered,
    warnings: &mut Vec<String>,
) -> Result<()> {
    let Some(mut f) = doc.map("sniffer")? else {
        return Ok(());
    };
    if !f.bool("enable")?.unwrap_or(false) {
        // Mihomo reads no more of it.
        for key in f.keys() {
            f.take(&key);
        }
        return Ok(());
    }
    // Mihomo's defaults.
    let parse_pure_ip = f.bool("parse-pure-ip")?.unwrap_or(true);
    let force_dns_mapping = f.bool("force-dns-mapping")?.unwrap_or(true);
    let override_destination = f.bool("override-destination")?.unwrap_or(true);

    // Each protocol with its ports, and whether it connects to the name.
    let mut sniffed: Vec<(usize, Vec<String>, bool)> = Vec::new();
    match f.map("sniff")? {
        Some(mut sniff) if !sniff.keys().is_empty() => {
            for key in sniff.keys() {
                let at = sniff.at(&key);
                let i = protocol(&key)
                    .ok_or_else(|| anyhow!("{}: {:?} is none of TLS, HTTP and QUIC", at, key))?;
                let (ports, overrides) = match sniff.map(&key)? {
                    Some(mut p) => {
                        let ports = p.strings("ports")?;
                        let overrides = p.bool("override-destination")?;
                        p.finish(&[], |_| false, warnings)?;
                        (ports, overrides)
                    }
                    None => (Vec::new(), None),
                };
                sniffed.push((i, ports, overrides.unwrap_or(override_destination)));
            }
            // Deprecated, and passed over once `sniff` is set.
            f.take("sniffing");
            f.take("port-whitelist");
        }
        _ => {
            let ports = f.strings("port-whitelist")?;
            for (j, name) in f.strings("sniffing")?.iter().enumerate() {
                let i = protocol(name).ok_or_else(|| {
                    anyhow!(
                        "{}[{}]: {:?} is none of TLS, HTTP and QUIC",
                        f.at("sniffing"),
                        j,
                        name
                    )
                })?;
                sniffed.push((i, ports.clone(), override_destination));
            }
        }
    }
    // As Mihomo tries them.
    sniffed.sort_by_key(|(i, _, _)| *i);

    let force = domain_conditions(&f.strings("force-domain")?, &f.at("force-domain"), sets)?;
    let skip_domain = f.strings("skip-domain")?;
    let skip_at = f.at("skip-domain");
    let skip_src = ip_conditions(
        &f.strings("skip-src-address")?,
        &f.at("skip-src-address"),
        sets,
        true,
    )?;
    let skip_dst = ip_conditions(
        &f.strings("skip-dst-address")?,
        &f.at("skip-dst-address"),
        sets,
        false,
    )?;
    f.finish(&[], |_| false, warnings)?;

    // Which connections are sniffed at all.
    let mut which = Vec::new();
    if parse_pure_ip || force_dns_mapping {
        which.push(json!({ "ip_cidr": ["0.0.0.0/0", "::/0"] }));
    }
    which.extend(force);
    if which.is_empty() || sniffed.is_empty() {
        return Ok(());
    }
    let mut common = vec![match which.len() {
        1 => which.pop().expect("one"),
        _ => json!({ "type": "logical", "mode": "or", "rules": which }),
    }];
    for mut skip in skip_src.into_iter().chain(skip_dst) {
        skip.insert("invert".into(), json!(true));
        common.push(Value::Object(skip));
    }

    let skip_sets = skip_rule_sets(&skip_domain, &skip_at, sets, out)?;
    let mut rules = Vec::new();
    for (i, ports, overrides) in sniffed {
        let (_, name, default_port, network) = PROTOCOLS[i];
        let mut on = Map::new();
        on.insert("network".into(), json!(network));
        let (port, range) = port_lists(&ports, default_port)?;
        if !port.is_empty() {
            on.insert("port".into(), json!(port));
        }
        if !range.is_empty() {
            on.insert("port_range".into(), json!(range));
        }
        let mut conditions = common.clone();
        conditions.push(Value::Object(on));
        let mut rule = Map::new();
        rule.insert("type".into(), json!("logical"));
        rule.insert("mode".into(), json!("and"));
        rule.insert("rules".into(), Value::Array(conditions));
        rule.insert("action".into(), json!("sniff"));
        rule.insert("sniffer".into(), json!([name]));
        if overrides {
            rule.insert("override_destination".into(), json!(true));
        }
        if !skip_sets.is_empty() {
            rule.insert("skip_rule_set".into(), json!(skip_sets));
        }
        rules.push(Value::Object(rule));
    }
    // Before every other rule, Clash's modes' among them.
    out.rules.splice(0..0, rules);
    Ok(())
}

fn protocol(name: &str) -> Option<usize> {
    PROTOCOLS
        .iter()
        .position(|(p, ..)| p.eq_ignore_ascii_case(name))
}

/// Ports as Mihomo writes them, `443` or `8080-8880`, as sail's `port` and
/// `port_range`; the protocol's own without any.
fn port_lists(ports: &[String], default: u16) -> Result<(Vec<u16>, Vec<String>)> {
    if ports.is_empty() {
        return Ok((vec![default], Vec::new()));
    }
    let (mut port, mut range) = (Vec::new(), Vec::new());
    for p in ports {
        let parse = |s: &str| {
            s.trim()
                .parse::<u16>()
                .map_err(|_| anyhow!("{:?} is not a port", p))
        };
        match p.split_once('-') {
            Some((a, b)) => range.push(format!("{}:{}", parse(a)?, parse(b)?)),
            None => port.push(parse(p)?),
        }
    }
    Ok((port, range))
}

/// The conditions of Mihomo's domain list at `at`: its patterns,
/// `geosite:a,b` and `rule-set:a,b`, each an alternative.
fn domain_conditions(entries: &[String], at: &str, sets: &mut Sets) -> Result<Vec<Value>> {
    let (patterns, tags) = domain_entries(entries, at, sets)?;
    Ok(super::provider::domain_conditions(patterns, tags)
        .into_iter()
        .map(Value::Object)
        .collect())
}

/// Mihomo's domain list at `at`, split into its patterns and the tags of
/// the rule-sets it names.
fn domain_entries(
    entries: &[String],
    at: &str,
    sets: &mut Sets,
) -> Result<(Vec<String>, Vec<String>)> {
    let (mut patterns, mut tags) = (Vec::new(), Vec::new());
    for (i, entry) in entries.iter().enumerate() {
        sets.domain_entry(entry, &mut patterns, &mut tags)
            .map_err(|e| anyhow!("{}[{}]: {}", at, i, e))?;
    }
    Ok((patterns, tags))
}

/// The conditions of Mihomo's address list at `at`, on the source's
/// address or the destination's: prefixes, `geoip:a,b` and `rule-set:a,b`.
fn ip_conditions(
    entries: &[String],
    at: &str,
    sets: &mut Sets,
    source: bool,
) -> Result<Vec<Map<String, Value>>> {
    let (mut prefixes, mut tags) = (Vec::new(), Vec::new());
    for (i, entry) in entries.iter().enumerate() {
        let lower = entry.to_ascii_lowercase();
        if let Some(codes) = lower.strip_prefix("geoip:") {
            for code in codes.split(',') {
                tags.push(
                    sets.geoip(code)
                        .map_err(|e| anyhow!("{}[{}]: {}", at, i, e))?,
                );
            }
        } else if lower.starts_with("rule-set:") {
            for name in entry["rule-set:".len()..].split(',') {
                let behavior = sets
                    .provider(name)
                    .map_err(|e| anyhow!("{}[{}]: {}", at, i, e))?;
                if behavior == ClashBehavior::Domain {
                    return Err(anyhow!(
                        "{}[{}]: rule-provider {:?} is of domains, not IP prefixes",
                        at,
                        i,
                        name
                    ));
                }
                tags.push(name.to_string());
            }
        } else {
            let prefix = entry.split_once('/').and_then(|(ip, len)| {
                let ip = ip.parse::<std::net::IpAddr>().ok()?;
                let len = len.parse::<u8>().ok()?;
                (len <= if ip.is_ipv4() { 32 } else { 128 }).then_some(())
            });
            prefix.ok_or_else(|| anyhow!("{}[{}]: {:?} is not an IP prefix", at, i, entry))?;
            prefixes.push(entry.clone());
        }
    }
    let mut conditions = Vec::new();
    if !prefixes.is_empty() {
        let key = if source { "source_ip_cidr" } else { "ip_cidr" };
        let mut c = Map::new();
        c.insert(key.into(), json!(prefixes));
        conditions.push(c);
    }
    if !tags.is_empty() {
        let mut c = Map::new();
        c.insert("rule_set".into(), json!(tags));
        if source {
            c.insert("rule_set_ip_cidr_match_source".into(), json!(true));
        }
        conditions.push(c);
    }
    Ok(conditions)
}

/// The rule-sets of `skip-domain`: one of its own patterns, and those it
/// names.
fn skip_rule_sets(
    entries: &[String],
    at: &str,
    sets: &mut Sets,
    out: &mut Lowered,
) -> Result<Vec<String>> {
    let (patterns, mut tags) = domain_entries(entries, at, sets)?;
    if !patterns.is_empty() {
        out.rule_sets.push(json!({
            "type": "inline",
            "tag": SKIP,
            "rules": [domains(&patterns)],
        }));
        tags.insert(0, SKIP.to_string());
    }
    Ok(tags)
}
