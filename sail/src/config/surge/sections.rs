//! The sections besides `[General]`, `[Proxy]`, `[Proxy Group]` and
//! `[Rule]`: `[Port Forwarding]`, as direct inbounds; the rest sorted out
//! as sail's policy has it, a warning or an error a section.

use anyhow::{anyhow, Result};
use serde_json::{json, Map, Value};

use super::group::{Policies, Target};
use super::text::{self, Profile};
use super::Lowered;

/// HTTP processing, which sail does not do.
const HTTP: &[&str] = &[
    "MITM",
    "URL Rewrite",
    "Header Rewrite",
    "Body Rewrite",
    "Map Local",
];

/// What means nothing where sail runs, or only in Surge's interface.
const SILENT: &[&str] = &["Replica", "Panel", "Testing", "Keystore"];

/// Surge's own servers, and its networks' settings.
const SERVERS: &[(&str, &str)] = &[
    ("Snell Server", "sail serves no Snell here"),
    ("MTProto", "sail serves no MTProto"),
    ("Ponte", "sail does not implement Surge Ponte"),
    ("DHCP", "sail serves no DHCP"),
    (
        "SSID Setting",
        "sail does not implement settings by network yet (C.5d)",
    ),
];

pub fn lower(
    mut profile: Profile,
    policies: &Policies,
    out: &mut Lowered,
    warnings: &mut Vec<String>,
) -> Result<()> {
    for (name, lines) in profile.take_named("Tailscale") {
        if !lines.is_empty() {
            warnings.push(format!(
                "[Tailscale {}]: sail does not implement Tailscale; ignored",
                name
            ));
        }
    }
    for name in HTTP {
        if !profile.take(name).is_empty() {
            warnings.push(format!("[{}]: sail does not process HTTP; ignored", name));
        }
    }
    script(profile.take("Script"), warnings)?;
    for name in SILENT {
        profile.take(name);
    }
    for (name, why) in SERVERS {
        if !profile.take(name).is_empty() {
            warnings.push(format!("[{}]: {}; ignored", name, why));
        }
    }
    forwarding(profile.take("Port Forwarding"), policies, out)?;
    for section in profile.rest() {
        if !section.lines.is_empty() {
            warnings.push(format!(
                "[{}]: not a section Surge takes; ignored, as by Surge",
                section.name
            ));
        }
    }
    Ok(())
}

/// `[Script]`: those of HTTP, cron, events and panels are warned of, once;
/// a rule's or DNS's decides where traffic goes, and is an error.
fn script(lines: Vec<text::Line>, warnings: &mut Vec<String>) -> Result<()> {
    if lines.is_empty() {
        return Ok(());
    }
    for line in &lines {
        let Some((_, rest)) = text::key_value(&line.text) else {
            continue;
        };
        for part in text::split(&rest, false) {
            if let Some((key, value, _)) = text::param(&part) {
                if key == "type" && matches!(value.as_str(), "rule" | "dns") {
                    return Err(anyhow!(
                        "[Script] {}: sail does not run {} scripts",
                        line.loc,
                        value
                    ));
                }
            }
        }
    }
    warnings.push("[Script]: sail does not run scripts; ignored".to_string());
    Ok(())
}

/// `[Port Forwarding]`: `address:port host:port [policy=name]`, each a
/// direct inbound connecting to its target through the policy, or as the
/// rules say.
fn forwarding(lines: Vec<text::Line>, policies: &Policies, out: &mut Lowered) -> Result<()> {
    let mut rules = Vec::new();
    for line in lines {
        let at = format!("[Port Forwarding] {}", line.loc);
        let mut words = line.text.split_whitespace();
        let (Some(listen), Some(target)) = (words.next(), words.next()) else {
            return Err(anyhow!("{}: not address:port host:port", at));
        };
        let (address, port) =
            host_port(listen).ok_or_else(|| anyhow!("{}: {:?} is not address:port", at, listen))?;
        let (host, target_port) =
            host_port(target).ok_or_else(|| anyhow!("{}: {:?} is not host:port", at, target))?;
        let tag = format!("port-forwarding:{}", listen);
        let mut inbound = Map::new();
        inbound.insert("type".into(), json!("direct"));
        inbound.insert("tag".into(), json!(tag));
        inbound.insert(
            "listen".into(),
            json!(if address.is_empty() {
                "0.0.0.0"
            } else {
                address
            }),
        );
        inbound.insert("listen_port".into(), json!(port));
        inbound.insert("network".into(), json!("tcp"));
        inbound.insert("override_address".into(), json!(host));
        inbound.insert("override_port".into(), json!(target_port));
        out.inbounds.push(Value::Object(inbound));
        for word in words {
            match text::param(word) {
                Some((key, policy, _)) if key == "policy" => {
                    let mut rule = Map::new();
                    rule.insert("inbound".into(), json!([tag]));
                    match policies
                        .target(&policy)
                        .map_err(|e| anyhow!("{}: policy: {}", at, e))?
                    {
                        Target::Outbound(tag) => {
                            rule.insert("outbound".into(), json!(tag));
                        }
                        Target::Reject(_) => {
                            rule.insert("action".into(), json!("reject"));
                        }
                    }
                    rules.push(Value::Object(rule));
                }
                _ => return Err(anyhow!("{}: {:?} is not policy=name", at, word)),
            }
        }
    }
    out.rules.splice(0..0, rules);
    Ok(())
}

/// `host:port`, `[v6]:port`.
fn host_port(s: &str) -> Option<(&str, u16)> {
    let (host, port) = s.rsplit_once(':')?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    Some((host, port.parse().ok()?))
}
