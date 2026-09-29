//! The general fields: the ports Mihomo listens on, who may use them, the
//! mode, the log, and the sections sail reads in later stages.

use anyhow::{anyhow, Result};
use serde_json::{json, Value};

use super::fields::{Fields, Tier};
use super::node::Node;
use super::Lowered;

use Tier::*;

/// The top-level fields Mihomo takes that sail does not implement, or not
/// yet: the sections read here only while they are off are errors when on.
pub const TOP: &[(&str, Tier)] = &[
    // The Clash API, and what it serves.
    ("external-controller", Ignored),
    ("external-controller-tls", Ignored),
    ("external-controller-unix", Ignored),
    ("external-controller-pipe", Ignored),
    ("external-controller-cors", Ignored),
    ("external-controller-routing-mark", Ignored),
    ("external-ui", Ignored),
    ("external-ui-url", Ignored),
    ("external-ui-name", Ignored),
    ("external-doh-server", Ignored),
    ("secret", Ignored),
    ("tls", Ignored),
    ("profile", Ignored),
    // How connections are made and timed, not where they go.
    ("unified-delay", Ignored),
    ("tcp-concurrent", Ignored),
    ("keep-alive-idle", Ignored),
    ("keep-alive-interval", Ignored),
    ("disable-keep-alive", Ignored),
    ("inbound-tfo", Ignored),
    ("inbound-mptcp", Ignored),
    ("find-process-mode", Ignored),
    ("global-ua", Ignored),
    ("etag-support", Ignored),
    ("experimental", Ignored),
    ("ntp", Ignored),
    ("clash-for-android", Ignored),
    // Where the GEO databases come from, for the rules that name them.
    ("geox-url", Ignored),
    ("geo-auto-update", Ignored),
    ("geo-update-interval", Ignored),
    ("geodata-mode", Ignored),
    ("geodata-loader", Ignored),
    ("geosite-matcher", Ignored),
    // Later stages.
    ("hosts", Unsupported),
    ("listeners", Unsupported),
    ("tunnels", Unsupported),
    ("tuic-server", Unsupported),
    ("ss-config", Unsupported),
    ("vmess-config", Unsupported),
    ("iptables", Unsupported),
    ("lan-disallowed-ips", Unsupported),
];

/// The names Mihomo gives its own listeners, which `IN-NAME` matches.
pub const LISTENERS: &[(&str, &str, &str)] = &[
    ("port", "http", "DEFAULT-HTTP"),
    ("socks-port", "socks", "DEFAULT-SOCKS"),
    ("mixed-port", "mixed", "DEFAULT-MIXED"),
    ("redir-port", "redirect", "DEFAULT-REDIR"),
    ("tproxy-port", "tproxy", "DEFAULT-TPROXY"),
];

pub fn lower(doc: &mut Fields, out: &mut Lowered, warnings: &mut Vec<String>) -> Result<()> {
    log(doc, out)?;
    listeners(doc, out, warnings)?;
    mode(doc, out)?;
    if let Some(name) = doc.string("interface-name")? {
        out.route.insert("default_interface".into(), json!(name));
    }
    if let Some(mark) = doc.int::<u32>("routing-mark")? {
        out.route.insert("default_mark".into(), json!(mark));
    }
    off_while_unimplemented(doc, "tun")?;
    off_while_unimplemented(doc, "sniffer")?;
    Ok(())
}

fn log(doc: &mut Fields, out: &mut Lowered) -> Result<()> {
    let level = doc.string("log-level")?;
    match level.as_deref().map(str::to_ascii_lowercase).as_deref() {
        None => {}
        Some("silent") => {
            out.log.insert("disabled".into(), json!(true));
        }
        Some(level @ ("debug" | "info" | "error")) => {
            out.log.insert("level".into(), json!(level));
        }
        Some("warning") => {
            out.log.insert("level".into(), json!("warn"));
        }
        Some(other) => {
            return Err(anyhow!(
                "log-level: {:?} is none of silent, error, warning, info and debug",
                other
            ))
        }
    }
    Ok(())
}

/// The ports, as inbounds under Mihomo's names for them. They listen on the
/// loopback address, but with `allow-lan`, on `bind-address`.
fn listeners(doc: &mut Fields, out: &mut Lowered, warnings: &mut Vec<String>) -> Result<()> {
    let allow_lan = doc.bool("allow-lan")?.unwrap_or(false);
    let bind = doc.string("bind-address")?;
    let listen = match (allow_lan, bind.as_deref()) {
        (false, _) => "127.0.0.1".to_string(),
        (true, None | Some("*")) => "::".to_string(),
        (true, Some(address)) => address
            .parse::<std::net::IpAddr>()
            .map_err(|_| anyhow!("bind-address: {:?} is not an address, nor *", address))?
            .to_string(),
    };
    let allowed = doc.strings("lan-allowed-ips")?;
    if !allowed.is_empty() && !covers_everything(&allowed) {
        return Err(anyhow!(
            "lan-allowed-ips: sail does not implement this field yet, but to allow \
             everyone (0.0.0.0/0 and ::/0)"
        ));
    }
    // As Mihomo: an entry that is not user:password is no user.
    let mut users = Vec::new();
    for (i, credentials) in doc.strings("authentication")?.into_iter().enumerate() {
        match credentials.split_once(':') {
            Some((username, password)) => {
                users.push(json!({ "username": username, "password": password }))
            }
            None if credentials.is_empty() => {}
            None => warnings.push(format!(
                "authentication[{}]: not user:password, and so no user, as in Mihomo",
                i
            )),
        }
    }
    if !doc.strings("skip-auth-prefixes")?.is_empty() {
        warnings.push(
            "skip-auth-prefixes: sail does not implement this field; everyone authenticates"
                .to_string(),
        );
    }
    for (key, kind, tag) in LISTENERS {
        let Some(port) = doc.int::<u16>(key)? else {
            continue;
        };
        if port == 0 {
            continue;
        }
        let mut inbound = json!({
            "type": kind,
            "tag": tag,
            "listen": listen,
            "listen_port": port,
        });
        if !users.is_empty() && matches!(*kind, "http" | "socks" | "mixed") {
            inbound["users"] = Value::Array(users.clone());
        }
        out.inbounds.push(inbound);
    }
    Ok(())
}

fn covers_everything(prefixes: &[String]) -> bool {
    let all = |p: &&String| p.trim() == "0.0.0.0/0" || p.trim() == "::/0";
    prefixes.iter().any(|p| p.trim() == "0.0.0.0/0") && prefixes.iter().all(|p| all(&p))
}

/// Mihomo's `mode`: `rule`, the default, or `global`, all to the `GLOBAL`
/// group, or `direct`. It becomes the Clash mode, which rules at the top
/// match, as sing-box's templates have them.
fn mode(doc: &mut Fields, out: &mut Lowered) -> Result<()> {
    let mode = doc
        .string("mode")?
        .map(|m| m.to_ascii_lowercase())
        .unwrap_or_else(|| "rule".to_string());
    let name = match mode.as_str() {
        "rule" => "Rule",
        "global" => "Global",
        "direct" => "Direct",
        other => {
            return Err(anyhow!(
                "mode: {:?} is none of rule, global and direct",
                other
            ))
        }
    };
    out.mode = Some(name.to_string());
    Ok(())
}

/// A section sail reads in a later stage: off, it changes nothing.
fn off_while_unimplemented(doc: &mut Fields, key: &str) -> Result<()> {
    let at = doc.at(key);
    match doc.take(key) {
        None => Ok(()),
        Some(Node::Map(map)) => match map.get("enable").and_then(Node::as_bool) {
            Some(true) => Err(anyhow!("{}: sail does not implement this section yet", at)),
            _ => Ok(()),
        },
        Some(other) => Err(anyhow!("{}: a map, not {}", at, other.kind())),
    }
}
