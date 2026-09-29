//! `[Proxy]`: each line `Name = type, server, port, key=value, ...` a sing-box
//! outbound, a `wireguard` one an endpoint of its `[WireGuard <name>]`
//! section; the aliases of the built-in policies (`direct`, `reject` and
//! the like) outbounds of theirs.

use std::collections::HashMap;

use anyhow::{anyhow, Result};
use base64::Engine;
use serde_json::{json, Map, Value};

use super::general::keys;
use super::params::{Params, Tier};
use super::text::{self, Line, Profile};
use super::Lowered;

use Tier::*;

/// Surge's own policies, which no proxy may be named but for `DIRECT`,
/// whose line is passed over.
pub const BUILT_IN: &[&str] = &[
    "DIRECT",
    "REJECT",
    "REJECT-DROP",
    "REJECT-NO-DROP",
    "REJECT-TINYGIF",
    "CELLULAR",
    "CELLULAR-ONLY",
    "HYBRID",
    "NO-HYBRID",
];

/// How a policy rejects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    /// `REJECT`, `REJECT-TINYGIF`: rejects, dropping instead once it has
    /// rejected many.
    Plain,
    /// `REJECT-NO-DROP`: never drops.
    NoDrop,
    /// `REJECT-DROP`: drops.
    Drop,
}

/// What a proxy is, for the rules and groups naming it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// An alias of `DIRECT`.
    Direct,
    /// An alias of one of the REJECT policies.
    Reject(Reject),
    /// A proxy, and whether it carries UDP.
    Proxy { udp: bool },
}

/// The proxies, by name.
pub struct Proxies {
    /// In order, as `include-all-proxies` takes them.
    pub names: Vec<String>,
    pub kinds: HashMap<String, Kind>,
    /// Each `underlying-proxy`: where, and what it names.
    pub detours: Vec<(String, String)>,
}

/// The parameters every proxy takes (Surge's common policy parameters),
/// but those read.
const COMMON: &[(&str, Tier)] = &[
    (
        "allow-other-interface",
        Ignored(": without its interface, a connection fails"),
    ),
    ("dns-follow-interface", Silent),
    ("no-error-alert", Silent),
    ("hybrid", Silent),
    ("ecn", Silent),
    ("tos", Ignored("")),
    ("test-url", Silent),
    ("test-timeout", Silent),
    ("test-udp", Silent),
    ("block-quic", Silent),
    ("tfo", Silent),
];

/// The TLS parameters, but those read.
const TLS: &[(&str, Tier)] = &[
    ("server-cert-fingerprint-sha256", Unsupported("")),
    ("server-cert-verify-name", Unsupported("")),
    ("client-cert", Unsupported(" (C.5d)")),
    ("shadow-tls-password", Unsupported(" (C.5d)")),
    ("shadow-tls-sni", Unsupported(" (C.5d)")),
    ("shadow-tls-version", Unsupported(" (C.5d)")),
];

/// Every parameter a proxy line may hold, which a value in a place of the
/// line's own (a password) is not taken for.
const KNOWN: &[&str] = &[
    "interface",
    "ip-version",
    "underlying-proxy",
    "udp-relay",
    "udp-port",
    "skip-cert-verify",
    "sni",
    "alpn",
    "username",
    "password",
    "encrypt-method",
    "obfs",
    "obfs-host",
    "obfs-uri",
    "tls",
    "ws",
    "ws-path",
    "ws-headers",
    "vmess-aead",
    "headers",
    "always-use-connect",
    "download-bandwidth",
    "port-hopping",
    "port-hopping-interval",
    "salamander-password",
    "gecko-password",
    "uuid",
    "token",
    "reuse",
    "section-name",
    "ota",
];

pub fn lower(
    profile: &mut Profile,
    out: &mut Lowered,
    warnings: &mut Vec<String>,
) -> Result<Proxies> {
    let lines = profile.take("Proxy");
    let sections: HashMap<String, Vec<Line>> =
        profile.take_named("WireGuard").into_iter().collect();
    let mut proxies = Proxies {
        names: Vec::new(),
        kinds: HashMap::new(),
        detours: Vec::new(),
    };
    let mut tested = Vec::new();
    let mut used_sections = Vec::new();
    for line in lines {
        one(
            line,
            &sections,
            &mut used_sections,
            &mut tested,
            &mut proxies,
            out,
            warnings,
        )?;
    }
    if !tested.is_empty() {
        warnings.push(format!(
            "[Proxy]: test-url, test-timeout, test-udp of {}: sail tests a group's members with \
             [General] proxy-test-url; ignored",
            tested.join(", ")
        ));
    }
    for (name, lines) in sections {
        if !used_sections.contains(&name) && !lines.is_empty() {
            warnings.push(format!("[WireGuard {}]: no policy names it; ignored", name));
        }
    }
    Ok(proxies)
}

/// A policy a `policy-path` holds: its name, and its outbound, or why
/// sail cannot use it.
pub struct External {
    pub name: String,
    pub outbound: Result<Value>,
}

/// The policies of what a `policy-path` holds, as Surge reads it: a list
/// of `[Proxy]` lines, or a profile whose `[Proxy]` section, with its
/// `[WireGuard <name>]` sections, holds them. None when it is neither, no
/// line of it being a policy. A line that does not read is not taken, as
/// by Surge; the warnings of those that do are `warnings`.
pub fn external(body: &str, warnings: &mut Vec<String>) -> Result<Option<Vec<External>>> {
    let policy = |line: &str| {
        let line = line.trim();
        line.eq_ignore_ascii_case("[Proxy]")
            || text::key_value(line).is_some_and(|(_, rest)| {
                let kind = rest.split(',').next().unwrap_or_default().trim();
                let kind = kind.to_ascii_lowercase();
                TYPES.contains(&kind.as_str()) || TYPES_LATER.contains(&kind.as_str())
            })
    };
    if !body.lines().any(policy) {
        return Ok(None);
    }
    let mut profile = Profile::read_list(body, "Proxy", warnings)?;
    let lines = profile.take("Proxy");
    let sections: HashMap<String, Vec<Line>> =
        profile.take_named("WireGuard").into_iter().collect();
    let mut policies = Vec::new();
    for line in lines {
        let name = text::key_value(&line.text)
            .map(|(name, _)| text::unquote(&name))
            .unwrap_or_default();
        let mut proxies = Proxies {
            names: Vec::new(),
            kinds: HashMap::new(),
            detours: Vec::new(),
        };
        let mut out = Lowered::default();
        let read = one(
            line,
            &sections,
            &mut Vec::new(),
            &mut Vec::new(),
            &mut proxies,
            &mut out,
            warnings,
        );
        let outbound = match read {
            Err(e) => Err(e),
            // `DIRECT`, which names Surge's own.
            Ok(()) if proxies.names.is_empty() => continue,
            Ok(()) if !out.endpoints.is_empty() => Err(anyhow!(
                "sail does not implement WireGuard policies of a policy-path yet"
            )),
            Ok(()) => Ok(out.outbounds.remove(0)),
        };
        policies.push(External { name, outbound });
    }
    Ok(Some(policies))
}

/// A `[Proxy]` line, lowered onto `out` and named in `proxies`; a
/// `wireguard` one of a section of `sections`, which it marks used.
fn one(
    line: Line,
    sections: &HashMap<String, Vec<Line>>,
    used_sections: &mut Vec<String>,
    tested: &mut Vec<String>,
    proxies: &mut Proxies,
    out: &mut Lowered,
    warnings: &mut Vec<String>,
) -> Result<()> {
    let at = format!("[Proxy] {}", line.loc);
    let (name, rest) = text::key_value(&line.text)
        .ok_or_else(|| anyhow!("{}: {:?} is not Name = type, ...", at, line.text))?;
    let name = text::unquote(&name);
    if name == "DIRECT" {
        return Ok(());
    }
    if BUILT_IN.contains(&name.as_str()) {
        return Err(anyhow!("{}: {} is Surge's own policy", at, name));
    }
    if proxies.kinds.contains_key(&name) {
        return Err(anyhow!("{}: another proxy is named {:?}", at, name));
    }
    let at = format!("{}: {}", at, name);
    let read = read(&rest, &at, warnings)?;
    let Read {
        kind,
        mut p,
        positional,
    } = read;
    if p.has("test-url") || p.has("test-timeout") || p.has("test-udp") {
        tested.push(name.clone());
    }
    let proxy = Proxy {
        name: &name,
        at: &at,
        positional,
    };
    let (value, kind_of, known) = match kind.as_str() {
        "direct" => {
            let mut o = obj("direct", &name);
            dial(&mut p, &mut o, false)?;
            (Value::Object(o), Kind::Direct, &[][..])
        }
        "reject" | "reject-tinygif" | "reject-drop" | "reject-no-drop" => {
            let how = match kind.as_str() {
                "reject-drop" => Reject::Drop,
                "reject-no-drop" => Reject::NoDrop,
                _ => Reject::Plain,
            };
            (
                json!({ "type": "block", "tag": name }),
                Kind::Reject(how),
                &[][..],
            )
        }
        "ss" | "custom" => shadowsocks(&proxy, &kind, &mut p, proxies)?,
        "vmess" => vmess(&proxy, &mut p, proxies, warnings)?,
        "trojan" => trojan(&proxy, &mut p, proxies)?,
        "http" | "https" => http(&proxy, &kind, &mut p, proxies)?,
        "socks5" | "socks5-tls" => socks5(&proxy, &kind, &mut p, proxies)?,
        "hysteria2" => hysteria2(&proxy, &mut p, proxies)?,
        "tuic-v5" => tuic(&proxy, &mut p, proxies)?,
        "anytls" => anytls(&proxy, &mut p, proxies, warnings)?,
        "wireguard" => {
            let section = p
                .string("section-name")
                .ok_or_else(|| anyhow!("{}: section-name: missing", at))?;
            let lines = sections.get(&section).cloned().ok_or_else(|| {
                anyhow!("{}: section-name: there is no [WireGuard {}]", at, section)
            })?;
            used_sections.push(section.clone());
            let mut endpoint = wireguard(&section, lines, warnings)?;
            endpoint.insert("tag".into(), json!(name));
            if let Some(via) = p.string("underlying-proxy") {
                if via != "DIRECT" {
                    proxies
                        .detours
                        .push((p.at("underlying-proxy"), via.clone()));
                    endpoint.insert("detour".into(), json!(via));
                }
            }
            if let Some(version) = p.string("ip-version") {
                if let Some(strategy) = ip_version(&version, &p.at("ip-version"))? {
                    endpoint.insert("domain_strategy".into(), json!(strategy));
                }
            }
            p.take_at("interface").into_iter().for_each(|(_, at)| {
                warnings.push(format!(
                    "{}: Surge binds no WireGuard policy to an interface; ignored",
                    at
                ))
            });
            out.endpoints.push(Value::Object(endpoint));
            p.finish(COMMON, "parameter", warnings)?;
            proxies.names.push(name.clone());
            proxies.kinds.insert(name, Kind::Proxy { udp: true });
            return Ok(());
        }
        _ => unreachable!("a type read checks"),
    };
    if let Some((value, at)) = p.take_at("block-quic") {
        if matches!(value.to_ascii_lowercase().as_str(), "on" | "true") {
            warnings.push(format!(
                "{}: sail does not block QUIC; ignored, and QUIC goes through the policy",
                at
            ));
        }
    }
    if let Some((value, at)) = p.take_at("tfo") {
        if matches!(value.to_ascii_lowercase().as_str(), "true" | "on") {
            warnings.push(format!(
                "{}: sail does not implement TCP Fast Open; ignored",
                at
            ));
        }
    }
    let mut all = known.to_vec();
    all.extend_from_slice(COMMON);
    p.finish(&all, "parameter", warnings)?;
    out.outbounds.push(value);
    proxies.names.push(name.clone());
    proxies.kinds.insert(name, kind_of);
    Ok(())
}

/// The policy types sail reads.
const TYPES: &[&str] = &[
    "direct",
    "reject",
    "reject-tinygif",
    "reject-drop",
    "reject-no-drop",
    "ss",
    "custom",
    "vmess",
    "trojan",
    "http",
    "https",
    "socks5",
    "socks5-tls",
    "hysteria2",
    "tuic-v5",
    "anytls",
    "wireguard",
];

/// The policy types Surge takes that sail does not implement yet.
const TYPES_LATER: &[&str] = &[
    "snell",
    "tuic",
    "ssh",
    "trust-tunnel",
    "masque",
    "external",
    "tailscale",
    "h2-connect",
];

/// Whether `key` is a parameter some proxy takes.
fn known(key: &str) -> bool {
    KNOWN.contains(&key) || COMMON.iter().chain(TLS).any(|(k, _)| *k == key)
}

/// A line read: its type, parameters and values in places of their own.
struct Read {
    kind: String,
    p: Params,
    /// Server, port, and what else stands in its place (credentials).
    positional: Vec<String>,
}

/// How many values a type takes in places of their own.
fn places(kind: &str) -> usize {
    match kind {
        "direct" | "reject" | "reject-tinygif" | "reject-drop" | "reject-no-drop" | "wireguard" => {
            0
        }
        "http" | "https" | "socks5" | "socks5-tls" => 4,
        // `custom`: method, password and the module's URL too.
        "custom" => 5,
        _ => 2,
    }
}

fn read(rest: &str, at: &str, warnings: &mut Vec<String>) -> Result<Read> {
    let parts = text::split(rest, false);
    let kind = parts[0].to_ascii_lowercase();
    if kind.is_empty() {
        return Err(anyhow!("{}: no type", at));
    }
    match kind.as_str() {
        kind if TYPES.contains(&kind) => {}
        kind if TYPES_LATER.contains(&kind) => {
            return Err(anyhow!(
                "{}: sail does not implement {} policies yet (C.5d)",
                at,
                kind
            ))
        }
        other => {
            return Err(anyhow!(
                "{}: {:?} is not a policy type Surge takes",
                at,
                other
            ))
        }
    }
    let places = places(&kind);
    let mut positional = Vec::new();
    let mut p = Params::new(at);
    for part in &parts[1..] {
        if part.is_empty() {
            continue;
        }
        let param = text::param(part);
        let in_place =
            positional.len() < places && !param.as_ref().is_some_and(|(key, _, _)| known(key));
        match param {
            Some((key, value, stray)) if !in_place => {
                if stray {
                    warnings.push(format!(
                        "{}: {}: a parameter in quotes; read as {}={}",
                        at, key, key, value
                    ));
                }
                p.insert(&key, value, None);
            }
            _ if positional.len() < places => positional.push(text::unquote(part)),
            _ => {
                return Err(anyhow!(
                    "{}: {:?} is not key=value, and the values in places of their own are \
                     all given",
                    at,
                    part
                ))
            }
        }
    }
    Ok(Read {
        kind,
        p,
        positional,
    })
}

/// A proxy line, as its type's reader takes it.
struct Proxy<'a> {
    name: &'a str,
    at: &'a str,
    positional: Vec<String>,
}

impl Proxy<'_> {
    /// Its server and port.
    fn server(&self, o: &mut Map<String, Value>) -> Result<()> {
        let server = self
            .positional
            .first()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow!("{}: no server", self.at))?;
        let port = self
            .positional
            .get(1)
            .ok_or_else(|| anyhow!("{}: no port", self.at))?;
        let port: u16 = port
            .parse()
            .map_err(|_| anyhow!("{}: {:?} is not a port", self.at, port))?;
        o.insert("server".into(), json!(server));
        o.insert("server_port".into(), json!(port));
        Ok(())
    }

    /// The value in place `i`, or else the parameter `key`.
    fn value(&self, i: usize, p: &mut Params, key: &str) -> Option<String> {
        let param = p.string(key);
        self.positional
            .get(i)
            .cloned()
            .filter(|v| !v.is_empty())
            .or(param)
    }
}

fn obj(kind: &str, tag: &str) -> Map<String, Value> {
    let mut o = Map::new();
    o.insert("type".into(), json!(kind));
    o.insert("tag".into(), json!(tag));
    o
}

/// The common parameters that say how the server is dialled: the
/// interface, the families it resolves to, and, for a proxy, the policy it
/// is dialled through.
fn dial(p: &mut Params, o: &mut Map<String, Value>, proxy: bool) -> Result<()> {
    if let Some(interface) = p.string("interface") {
        o.insert("bind_interface".into(), json!(interface));
    }
    if let Some(version) = p.string("ip-version") {
        if let Some(strategy) = ip_version(&version, &p.at("ip-version"))? {
            o.insert("domain_strategy".into(), json!(strategy));
        }
    }
    if proxy {
        if let Some(via) = p.string("underlying-proxy") {
            if via != "DIRECT" {
                o.insert("detour".into(), json!(via));
            }
        }
    }
    Ok(())
}

fn ip_version(version: &str, at: &str) -> Result<Option<&'static str>> {
    Ok(match version.to_ascii_lowercase().as_str() {
        "dual" => None,
        "v4-only" => Some("ipv4_only"),
        "v6-only" => Some("ipv6_only"),
        "prefer-v4" => Some("prefer_ipv4"),
        "prefer-v6" => Some("prefer_ipv6"),
        _ => {
            return Err(anyhow!(
                "{}: {:?} is none of dual, v4-only, v6-only, prefer-v4 and prefer-v6",
                at,
                version
            ))
        }
    })
}

/// A proxy's server, its dial parameters, and its `underlying-proxy`
/// recorded for the groups to check.
fn remote(
    proxy: &Proxy,
    p: &mut Params,
    o: &mut Map<String, Value>,
    proxies: &mut Proxies,
) -> Result<()> {
    proxy.server(o)?;
    if let Some(via) = p.string("underlying-proxy") {
        if via != "DIRECT" {
            proxies
                .detours
                .push((p.at("underlying-proxy"), via.clone()));
            p.insert("underlying-proxy", via, None);
        }
    }
    dial(p, o, true)
}

/// The TLS parameters, with TLS on: the server name (`sni`, `off` for none),
/// whether the certificate is checked, and ALPN.
fn tls(p: &mut Params, on: bool) -> Result<Option<Value>> {
    let sni = p.take_at("sni");
    let insecure = p.bool("skip-cert-verify")?.unwrap_or(false);
    let alpn = p.list("alpn");
    if !on {
        return Ok(None);
    }
    let mut tls = Map::new();
    tls.insert("enabled".into(), json!(true));
    if let Some((sni, at)) = sni {
        if sni.eq_ignore_ascii_case("off") {
            return Err(anyhow!(
                "{}: off: sail does not implement a handshake without SNI yet",
                at
            ));
        }
        tls.insert("server_name".into(), json!(sni));
    }
    if insecure {
        tls.insert("insecure".into(), json!(true));
    }
    if !alpn.is_empty() {
        tls.insert("alpn".into(), json!(alpn));
    }
    Ok(Some(Value::Object(tls)))
}

/// WebSocket: `ws=true`, `ws-path`, and `ws-headers` as `A:1|B:2`.
fn websocket(p: &mut Params, o: &mut Map<String, Value>) -> Result<()> {
    let on = p.bool("ws")?.unwrap_or(false);
    let path = p.string("ws-path").unwrap_or_else(|| "/".to_string());
    let headers = p.take_at("ws-headers");
    if !on {
        return Ok(());
    }
    let mut transport = Map::new();
    transport.insert("type".into(), json!("ws"));
    transport.insert("path".into(), json!(path));
    if let Some((value, at)) = headers {
        let mut map = Map::new();
        for header in value.split('|').map(str::trim).filter(|h| !h.is_empty()) {
            let (name, value) = header
                .split_once(':')
                .ok_or_else(|| anyhow!("{}: {:?} is not Name:value", at, header))?;
            map.insert(name.trim().to_string(), json!(text::unquote(value)));
        }
        transport.insert("headers".into(), Value::Object(map));
    }
    o.insert("transport".into(), Value::Object(transport));
    Ok(())
}

type Lowering = (Value, Kind, &'static [(&'static str, Tier)]);

fn shadowsocks(
    proxy: &Proxy,
    kind: &str,
    p: &mut Params,
    proxies: &mut Proxies,
) -> Result<Lowering> {
    let mut o = obj("shadowsocks", proxy.name);
    remote(proxy, p, &mut o, proxies)?;
    // `custom`: the method and password in places of their own; the
    // module that was Surge's Shadowsocks goes unread.
    let (method, password) = if kind == "custom" {
        (
            proxy.value(2, p, "encrypt-method"),
            proxy.value(3, p, "password"),
        )
    } else {
        (p.string("encrypt-method"), p.string("password"))
    };
    let method = method.ok_or_else(|| anyhow!("{}: encrypt-method: missing", proxy.at))?;
    o.insert("method".into(), json!(method));
    o.insert("password".into(), json!(password.unwrap_or_default()));
    if p.bool("ota")?.unwrap_or(false) {
        return Err(anyhow!(
            "{}: sail does not implement Shadowsocks one-time auth",
            p.at("ota")
        ));
    }
    let host = p.string("obfs-host");
    let uri = p.string("obfs-uri");
    if let Some((mode, at)) = p.take_at("obfs") {
        let mode = mode.to_ascii_lowercase();
        if !matches!(mode.as_str(), "http" | "tls") {
            return Err(anyhow!("{}: {:?} is neither http nor tls", at, mode));
        }
        let mut spec = format!("obfs={}", mode);
        if let Some(host) = host {
            spec.push_str(&format!(";obfs-host={}", host));
        }
        if let Some(uri) = uri.filter(|_| mode == "http") {
            spec.push_str(&format!(";obfs-uri={}", uri));
        }
        o.insert("plugin".into(), json!("obfs-local"));
        o.insert("plugin_opts".into(), json!(spec));
    }
    let udp = p.bool("udp-relay")?.unwrap_or(false);
    Ok((
        Value::Object(o),
        Kind::Proxy { udp },
        &[("udp-port", Unsupported(""))],
    ))
}

fn vmess(
    proxy: &Proxy,
    p: &mut Params,
    proxies: &mut Proxies,
    warnings: &mut Vec<String>,
) -> Result<Lowering> {
    let mut o = obj("vmess", proxy.name);
    remote(proxy, p, &mut o, proxies)?;
    let uuid = p
        .string("username")
        .ok_or_else(|| anyhow!("{}: username: missing", proxy.at))?;
    o.insert("uuid".into(), json!(uuid));
    let method = p
        .string("encrypt-method")
        .unwrap_or_else(|| "aes-128-gcm".to_string());
    o.insert("security".into(), json!(method));
    if !p.bool("vmess-aead")?.unwrap_or(false) {
        warnings.push(format!(
            "{}: vmess-aead: sail speaks VMess with the AEAD handshake alone, which a server of \
             the older one refuses",
            proxy.at
        ));
    }
    let on = p.bool("tls")?.unwrap_or(false);
    if let Some(tls) = tls(p, on)? {
        o.insert("tls".into(), tls);
    }
    websocket(p, &mut o)?;
    Ok((Value::Object(o), Kind::Proxy { udp: true }, TLS))
}

fn trojan(proxy: &Proxy, p: &mut Params, proxies: &mut Proxies) -> Result<Lowering> {
    let mut o = obj("trojan", proxy.name);
    remote(proxy, p, &mut o, proxies)?;
    let password = p
        .string("password")
        .ok_or_else(|| anyhow!("{}: password: missing", proxy.at))?;
    o.insert("password".into(), json!(password));
    // Always over TLS.
    p.take_at("tls");
    if let Some(tls) = tls(p, true)? {
        o.insert("tls".into(), tls);
    }
    websocket(p, &mut o)?;
    Ok((Value::Object(o), Kind::Proxy { udp: true }, TLS))
}

/// `http`, and `https`, which is over TLS; as is `http` with `tls=true`,
/// as older profiles write it.
fn http(proxy: &Proxy, kind: &str, p: &mut Params, proxies: &mut Proxies) -> Result<Lowering> {
    let mut o = obj("http", proxy.name);
    remote(proxy, p, &mut o, proxies)?;
    credentials(proxy, p, &mut o);
    if let Some((value, at)) = p.take_at("headers") {
        let mut headers = Map::new();
        for header in value.split(';').map(str::trim).filter(|h| !h.is_empty()) {
            if header.contains("<random-string(") {
                return Err(anyhow!(
                    "{}: sail does not implement <random-string()> yet",
                    at
                ));
            }
            let (name, value) = header
                .split_once(':')
                .ok_or_else(|| anyhow!("{}: {:?} is not Name:value", at, header))?;
            headers.insert(name.trim().to_string(), json!(value.trim()));
        }
        o.insert("headers".into(), Value::Object(headers));
    }
    // sail's HTTP proxy asks with CONNECT always.
    p.bool("always-use-connect")?;
    let on = kind == "https" || p.bool("tls")?.unwrap_or(false);
    if let Some(tls) = tls(p, on)? {
        o.insert("tls".into(), tls);
    }
    Ok((Value::Object(o), Kind::Proxy { udp: false }, TLS))
}

/// `socks5`, and `socks5-tls`, which is over TLS.
fn socks5(proxy: &Proxy, kind: &str, p: &mut Params, proxies: &mut Proxies) -> Result<Lowering> {
    let mut o = obj("socks", proxy.name);
    remote(proxy, p, &mut o, proxies)?;
    credentials(proxy, p, &mut o);
    let on = kind == "socks5-tls" || p.bool("tls")?.unwrap_or(false);
    if let Some(tls) = tls(p, on)? {
        o.insert("tls".into(), tls);
    }
    let udp = p.bool("udp-relay")?.unwrap_or(false);
    Ok((Value::Object(o), Kind::Proxy { udp }, TLS))
}

/// A username and password: in places of their own after the port, or
/// as parameters.
fn credentials(proxy: &Proxy, p: &mut Params, o: &mut Map<String, Value>) {
    if let Some(username) = proxy.value(2, p, "username") {
        o.insert("username".into(), json!(username));
    }
    if let Some(password) = proxy.value(3, p, "password") {
        o.insert("password".into(), json!(password));
    }
}

fn hysteria2(proxy: &Proxy, p: &mut Params, proxies: &mut Proxies) -> Result<Lowering> {
    let mut o = obj("hysteria2", proxy.name);
    remote(proxy, p, &mut o, proxies)?;
    let password = p
        .string("password")
        .ok_or_else(|| anyhow!("{}: password: missing", proxy.at))?;
    o.insert("password".into(), json!(password));
    if let Some(mbps) = p.num::<f64>("download-bandwidth")? {
        o.insert("down_mbps".into(), json!((mbps.round() as u64).max(1)));
    }
    if let Some((hops, at)) = p.take_at("port-hopping") {
        // Instead of the port of the line.
        o.remove("server_port");
        let mut ranges = Vec::new();
        for range in hops.split(';').map(str::trim).filter(|r| !r.is_empty()) {
            let (a, b) = range.split_once('-').unwrap_or((range, range));
            let (a, b) = (a.trim().parse::<u16>(), b.trim().parse::<u16>());
            match (a, b) {
                (Ok(a), Ok(b)) if a <= b => ranges.push(format!("{}:{}", a, b)),
                _ => return Err(anyhow!("{}: {:?} is not a port or a range", at, range)),
            }
        }
        o.insert("server_ports".into(), json!(ranges));
    }
    if let Some(seconds) = p.num::<u64>("port-hopping-interval")? {
        o.insert("hop_interval".into(), json!(format!("{}s", seconds)));
    }
    if let Some(password) = p.string("salamander-password") {
        o.insert(
            "obfs".into(),
            json!({ "type": "salamander", "password": password }),
        );
    }
    if let Some(tls) = tls(p, true)? {
        o.insert("tls".into(), tls);
    }
    Ok((
        Value::Object(o),
        Kind::Proxy { udp: true },
        &[
            ("gecko-password", Unsupported("")),
            ("server-cert-fingerprint-sha256", Unsupported("")),
            ("server-cert-verify-name", Unsupported("")),
            ("client-cert", Unsupported(" (C.5d)")),
        ],
    ))
}

fn tuic(proxy: &Proxy, p: &mut Params, proxies: &mut Proxies) -> Result<Lowering> {
    let mut o = obj("tuic", proxy.name);
    remote(proxy, p, &mut o, proxies)?;
    for key in ["uuid", "password"] {
        let value = p
            .string(key)
            .ok_or_else(|| anyhow!("{}: {}: missing", proxy.at, key))?;
        o.insert(key.into(), json!(value));
    }
    if let Some(tls) = tls(p, true)? {
        o.insert("tls".into(), tls);
    }
    Ok((
        Value::Object(o),
        Kind::Proxy { udp: true },
        &[
            ("port-hopping", Unsupported("")),
            ("port-hopping-interval", Silent),
            ("server-cert-fingerprint-sha256", Unsupported("")),
            ("server-cert-verify-name", Unsupported("")),
            ("client-cert", Unsupported(" (C.5d)")),
        ],
    ))
}

fn anytls(
    proxy: &Proxy,
    p: &mut Params,
    proxies: &mut Proxies,
    warnings: &mut Vec<String>,
) -> Result<Lowering> {
    let mut o = obj("anytls", proxy.name);
    remote(proxy, p, &mut o, proxies)?;
    let password = p
        .string("password")
        .ok_or_else(|| anyhow!("{}: password: missing", proxy.at))?;
    o.insert("password".into(), json!(password));
    if p.bool("reuse")? == Some(false) {
        warnings.push(format!(
            "{}: reuse: sail reuses AnyTLS sessions always; ignored",
            proxy.at
        ));
    }
    if let Some(tls) = tls(p, true)? {
        o.insert("tls".into(), tls);
    }
    Ok((Value::Object(o), Kind::Proxy { udp: true }, TLS))
}

/// The keys of a `[WireGuard <name>]` section sail does not implement.
const WIREGUARD: &[(&str, Tier)] = &[(
    "prefer-ipv6",
    Ignored(": the destination's families are as DNS answers"),
)];

/// A `[WireGuard <name>]` section, as a WireGuard endpoint but its tag.
fn wireguard(
    name: &str,
    lines: Vec<Line>,
    warnings: &mut Vec<String>,
) -> Result<Map<String, Value>> {
    let section = format!("WireGuard {}", name);
    let mut peers = Vec::new();
    let mut rest = Vec::new();
    for line in lines {
        // `peer` may be given many times.
        match text::key_value(&line.text) {
            Some((key, value)) if key.eq_ignore_ascii_case("peer") => {
                let at = format!("[{}] {}: peer", section, line.loc);
                for part in text::split(&value, false) {
                    peers.push(peer(&part).map_err(|e| anyhow!("{}: {}", at, e))?);
                }
            }
            _ => rest.push(line),
        }
    }
    let mut p = keys(&section, rest, warnings);
    let mut address = Vec::new();
    for (key, len) in [("self-ip", 32), ("self-ip-v6", 128)] {
        if let Some((ip, at)) = p.take_at(key) {
            let ip: std::net::IpAddr = ip
                .parse()
                .map_err(|_| anyhow!("{}: {:?} is not an IP address", at, ip))?;
            if ip.is_ipv4() != (len == 32) {
                return Err(anyhow!("{}: {} is of the other family", at, ip));
            }
            address.push(format!("{}/{}", ip, len));
        }
    }
    if address.is_empty() {
        return Err(anyhow!(
            "[{}]: self-ip: missing, and so is self-ip-v6",
            section
        ));
    }
    let private_key = p
        .take_at("private-key")
        .ok_or_else(|| anyhow!("[{}]: private-key: missing", section))
        .and_then(|(k, at)| key(&k).map_err(|e| anyhow!("{}: {}", at, e)))?;
    let mut o = Map::new();
    o.insert("type".into(), json!("wireguard"));
    o.insert("address".into(), json!(address));
    o.insert("private_key".into(), json!(private_key));
    if let Some(mtu) = p.num::<u32>("mtu")? {
        o.insert("mtu".into(), json!(mtu));
    }
    // The servers Surge asks inside the tunnel for the names its
    // connections dial; sail's DNS answers them as its rules say.
    if let Some((servers, at)) = p.take_at("dns-server") {
        for server in servers.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            if server != "system" && server.parse::<std::net::IpAddr>().is_err() {
                return Err(anyhow!("{}: {:?} is not an IP address", at, server));
            }
        }
        warnings.push(format!(
            "{}: sail resolves the names the tunnel's connections dial as its DNS says, not \
             through these servers",
            at
        ));
    }
    if peers.is_empty() {
        return Err(anyhow!("[{}]: peer: missing", section));
    }
    o.insert("peers".into(), Value::Array(peers));
    p.finish(WIREGUARD, "key", warnings)?;
    Ok(o)
}

/// A key, in base64 or as 64 hexadecimal digits.
fn key(s: &str) -> Result<String> {
    let s = s.trim();
    if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        let bytes: Vec<u8> = (0..32)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex digits"))
            .collect();
        return Ok(base64::engine::general_purpose::STANDARD.encode(bytes));
    }
    Ok(s.to_string())
}

/// `(public-key = ..., allowed-ips = ..., endpoint = host:port, ...)`.
fn peer(value: &str) -> Result<Value> {
    let inner = value
        .trim()
        .strip_prefix('(')
        .and_then(|v| v.strip_suffix(')'))
        .ok_or_else(|| anyhow!("{:?} is not (key = value, ...)", value))?;
    let mut peer = Map::new();
    for field in text::split(inner, false) {
        if field.is_empty() {
            continue;
        }
        let (key, value) =
            text::key_value(&field).ok_or_else(|| anyhow!("{:?} is not key = value", field))?;
        match key.to_ascii_lowercase().as_str() {
            "public-key" => {
                peer.insert("public_key".into(), json!(self::key(&value)?));
            }
            "preshared-key" => {
                peer.insert("pre_shared_key".into(), json!(self::key(&value)?));
            }
            "allowed-ips" => {
                let ips: Vec<&str> = value
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .collect();
                peer.insert("allowed_ips".into(), json!(ips));
            }
            "endpoint" => {
                let (host, port) = value
                    .rsplit_once(':')
                    .ok_or_else(|| anyhow!("endpoint: {:?} is not host:port", value))?;
                let port: u16 = port
                    .trim()
                    .parse()
                    .map_err(|_| anyhow!("endpoint: {:?} is not a port", port))?;
                let host = host.trim().trim_start_matches('[').trim_end_matches(']');
                peer.insert("address".into(), json!(host));
                peer.insert("port".into(), json!(port));
            }
            "keepalive" => {
                let seconds: u16 = value
                    .parse()
                    .map_err(|_| anyhow!("keepalive: {:?} is not a number of seconds", value))?;
                peer.insert("persistent_keepalive_interval".into(), json!(seconds));
            }
            // WARP's client identifier, the reserved bytes: 1/2/3, six
            // hexadecimal digits or four of base64.
            "client-id" => {
                let reserved = if value.contains('/') {
                    let bytes = value
                        .split('/')
                        .map(|b| b.trim().parse::<u8>())
                        .collect::<std::result::Result<Vec<u8>, _>>()
                        .ok()
                        .filter(|b| b.len() == 3)
                        .ok_or_else(|| anyhow!("client-id: {:?} is not three bytes", value))?;
                    json!(bytes)
                } else {
                    let hex = value.trim_start_matches("0x");
                    if hex.len() == 6 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
                        let bytes: Vec<u8> = (0..3)
                            .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("hex"))
                            .collect();
                        json!(bytes)
                    } else {
                        json!(value)
                    }
                };
                peer.insert("reserved".into(), reserved);
            }
            other => return Err(anyhow!("{:?} is not a peer field Surge takes", other)),
        }
    }
    for (key, name) in [
        ("public_key", "public-key"),
        ("allowed_ips", "allowed-ips"),
        ("address", "endpoint"),
    ] {
        if !peer.contains_key(key) {
            return Err(anyhow!("{}: missing", name));
        }
    }
    Ok(Value::Object(peer))
}
