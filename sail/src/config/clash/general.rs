//! The general fields: the ports Mihomo listens on, who may use them, the
//! mode, the log, and the sections sail reads in later stages.

use anyhow::{anyhow, Result};
use serde_json::{json, Value};

use super::fields::{Fields, Tier};
use super::Lowered;

use Tier::*;

/// The top-level fields Mihomo takes that sail does not implement, or not
/// yet: the sections read here only while they are off are errors when on.
pub const TOP: &[(&str, Tier)] = &[
    // The Clash API's other listeners, and what it serves besides.
    ("external-controller-tls", Ignored),
    ("external-controller-unix", Ignored),
    ("external-controller-pipe", Ignored),
    ("external-controller-routing-mark", Ignored),
    ("external-doh-server", Ignored),
    ("tls", Ignored),
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
    ("tuic-server", Unsupported),
    ("ss-config", Unsupported),
    ("vmess-config", Unsupported),
    ("iptables", Unsupported),
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
    controller(doc, out, warnings)?;
    profile(doc, out, warnings)?;
    if let Some(name) = doc.string("interface-name")? {
        out.route.insert("default_interface".into(), json!(name));
    }
    if let Some(mark) = doc.int::<u32>("routing-mark")? {
        out.route.insert("default_mark".into(), json!(mark));
    }
    Ok(())
}

/// `profile`, as sing-box's cache file: kept with `store-selected`, as by
/// default, or `store-fake-ip`, fake IPs too with the latter. Where sail
/// does otherwise: the file keeps the selections with it, and Clash's
/// mode, even with `store-selected: false`.
fn profile(doc: &mut Fields, out: &mut Lowered, warnings: &mut Vec<String>) -> Result<()> {
    let (selected, fake_ip) = match doc.map("profile")? {
        None => (true, false),
        Some(mut f) => {
            let selected = f.bool("store-selected")?.unwrap_or(true);
            let fake_ip = f.bool("store-fake-ip")?.unwrap_or(false);
            f.finish(&[], |_| false, warnings)?;
            (selected, fake_ip)
        }
    };
    if selected || fake_ip {
        let mut cache = serde_json::Map::new();
        cache.insert("enabled".into(), json!(true));
        if fake_ip {
            cache.insert("store_fakeip".into(), json!(true));
        }
        out.cache_file = Some(cache);
    }
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
    // Who may use the listeners that authenticate as `authentication`
    // says: those of `lan-allowed-ips`, everyone unless set, but those of
    // `lan-disallowed-ips`.
    if doc.has("lan-allowed-ips") {
        let allowed = prefixes(doc, "lan-allowed-ips")?;
        if !covers_everything(&allowed) {
            out.lan_allowed = Some(allowed);
        }
    }
    out.lan_disallowed = prefixes(doc, "lan-disallowed-ips")?;
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
    // `listeners` take them too, where they name none of their own.
    out.authentication = users.clone();
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
        if matches!(*kind, "http" | "socks" | "mixed") {
            if !users.is_empty() {
                inbound["users"] = Value::Array(users.clone());
            }
            out.lan_inbounds.push(tag.to_string());
        }
        out.inbounds.push(inbound);
    }
    Ok(())
}

/// A list of IP prefixes, checked.
fn prefixes(doc: &mut Fields, key: &str) -> Result<Vec<String>> {
    let at = doc.at(key);
    let prefixes = doc.strings(key)?;
    for (i, prefix) in prefixes.iter().enumerate() {
        let valid = prefix.split_once('/').is_some_and(|(ip, len)| {
            match (ip.parse::<std::net::IpAddr>(), len.parse::<u8>()) {
                (Ok(ip), Ok(len)) => len <= if ip.is_ipv4() { 32 } else { 128 },
                _ => false,
            }
        });
        if !valid {
            return Err(anyhow!("{}[{}]: {:?} is not an IP prefix", at, i, prefix));
        }
    }
    Ok(prefixes)
}

fn covers_everything(prefixes: &[String]) -> bool {
    let all = |p: &&String| p.trim() == "0.0.0.0/0" || p.trim() == "::/0";
    prefixes.iter().any(|p| p.trim() == "0.0.0.0/0") && prefixes.iter().all(|p| all(&p))
}

/// The Clash API, sail's `clash_api`: the plain HTTP listener, its secret
/// (the API refuses a weak one, and says so, and the rest runs), the
/// dashboard and CORS, whose defaults are Mihomo's: any origin, and pages
/// on public addresses may call it. Where the dashboard is downloaded from
/// when unset is sail's default, not Mihomo's (metacubexd).
fn controller(doc: &mut Fields, out: &mut Lowered, warnings: &mut Vec<String>) -> Result<()> {
    let api = &mut out.clash_api;
    if let Some(listen) = doc.string("external-controller")? {
        if !listen.is_empty() {
            api.insert("external_controller".into(), json!(listen));
        }
    }
    if let Some(secret) = doc.string("secret")? {
        if !secret.is_empty() {
            api.insert("secret".into(), json!(secret));
        }
    }
    let ui = doc.string("external-ui")?.filter(|ui| !ui.is_empty());
    let name = doc.string("external-ui-name")?.filter(|n| !n.is_empty());
    match (ui, name) {
        (Some(ui), Some(name)) => {
            if !std::path::Path::new(&name)
                .components()
                .all(|c| matches!(c, std::path::Component::Normal(_)))
            {
                return Err(anyhow!(
                    "external-ui-name: {:?} is not a directory within external-ui",
                    name
                ));
            }
            api.insert(
                "external_ui".into(),
                json!(format!("{}/{}", ui.trim_end_matches('/'), name)),
            );
        }
        (Some(ui), None) => {
            api.insert("external_ui".into(), json!(ui));
        }
        (None, Some(_)) => warnings.push(format!(
            "{}: without external-ui; ignored",
            doc.at("external-ui-name")
        )),
        (None, None) => {}
    }
    if let Some(url) = doc.string("external-ui-url")?.filter(|u| !u.is_empty()) {
        api.insert("external_ui_download_url".into(), json!(url));
    }
    let (origins, private) = match doc.map("external-controller-cors")? {
        Some(mut cors) => {
            let origins = match cors.has("allow-origins") {
                true => Some(cors.strings("allow-origins")?),
                false => None,
            };
            let private = cors.bool("allow-private-network")?;
            cors.finish(&[], |_| false, warnings)?;
            (origins, private)
        }
        None => (None, None),
    };
    // Mihomo's default is `*`, any origin, which sail's empty list is.
    let origins = origins.unwrap_or_default();
    if !origins.is_empty() && !origins.iter().any(|o| o == "*") {
        api.insert("access_control_allow_origin".into(), json!(origins));
    }
    if private.unwrap_or(true) {
        api.insert("access_control_allow_private_network".into(), json!(true));
    }
    Ok(())
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
