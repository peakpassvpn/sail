//! `proxies`: each a sing-box outbound, of the fields Mihomo's proxy of its
//! type takes (`adapter/outbound/*.go`).

use std::collections::HashSet;

use anyhow::{anyhow, Result};
use base64::Engine;
use serde_json::{json, Map, Value};

use super::fields::{Fields, Tier};
use super::node::Node;
use super::Lowered;

use Tier::*;

/// The policies Mihomo names itself, which no proxy or group may take.
pub const BUILT_IN: &[&str] = &[
    "DIRECT",
    "REJECT",
    "REJECT-DROP",
    "PASS",
    "COMPATIBLE",
    "GLOBAL",
];

/// What the proxies are, by name.
pub struct Proxies {
    /// In order.
    pub names: Vec<String>,
    /// Those of type `dns`, whose traffic Mihomo answers itself.
    pub dns: HashSet<String>,
}

pub fn lower(doc: &mut Fields, out: &mut Lowered, warnings: &mut Vec<String>) -> Result<Proxies> {
    // Mihomo 1.19 dropped it, and logs an error, but reads on.
    if doc.take("global-client-fingerprint").is_some() {
        warnings.push(
            "global-client-fingerprint: removed from Mihomo; set client-fingerprint directly \
             on the proxy instead; ignored"
                .to_string(),
        );
    }
    let mut proxies = Proxies {
        names: Vec::new(),
        dns: HashSet::new(),
    };
    let mut derived = Vec::new();
    for (i, node) in doc.list("proxies")?.into_iter().enumerate() {
        let f = Fields::of(node, &format!("proxies[{}]", i))?;
        let proxy = Proxy::read(f, warnings)?;
        if BUILT_IN.contains(&proxy.name.as_str()) {
            return Err(anyhow!(
                "proxies[{}].name: {} is Mihomo's own policy",
                i,
                proxy.name
            ));
        }
        if proxies.names.contains(&proxy.name) {
            return Err(anyhow!(
                "proxies[{}].name: another proxy is named {:?}",
                i,
                proxy.name
            ));
        }
        match proxy.outbound {
            Some(endpoint) if proxy.endpoint => out.endpoints.push(endpoint),
            Some(outbound) => out.outbounds.push(outbound),
            None => {
                proxies.dns.insert(proxy.name.clone());
            }
        }
        derived.extend(proxy.derived);
        proxies.names.push(proxy.name);
    }
    for outbound in derived {
        let tag = outbound["tag"].as_str().unwrap_or_default();
        if proxies.names.iter().any(|n| n == tag) {
            return Err(anyhow!(
                "proxies: {:?} is the name of the outbound sail makes for another proxy's plugin",
                tag
            ));
        }
        out.outbounds.push(outbound);
    }
    Ok(proxies)
}

/// A proxy of a provider, as an outbound tagged with its name, or the
/// endpoint a `wireguard` one is. A `dns` one is left out, as sail does
/// not implement it in a provider.
#[cfg(feature = "outbound-provider")]
pub(super) fn lower_one(f: Fields, warnings: &mut Vec<String>) -> Result<Value> {
    let proxy = Proxy::read(f, warnings)?;
    if !proxy.derived.is_empty() {
        return Err(anyhow!(
            "the shadow-tls plugin: sail does not implement it in a provider yet"
        ));
    }
    proxy
        .outbound
        .ok_or_else(|| anyhow!("a dns proxy: sail does not implement it in a provider"))
}

/// A proxy, read.
struct Proxy {
    name: String,
    /// None for a `dns` proxy.
    outbound: Option<Value>,
    /// Whether `outbound` is an endpoint: a `wireguard` proxy's.
    endpoint: bool,
    /// Outbounds it goes through, made for it: a shadow-tls plugin's.
    derived: Vec<Value>,
}

impl Proxy {
    fn read(mut f: Fields, warnings: &mut Vec<String>) -> Result<Self> {
        let name = f
            .string("name")?
            .filter(|n| !n.is_empty())
            .ok_or_else(|| anyhow!("{}.name: missing", f.path()))?;
        let kind = f
            .string("type")?
            .ok_or_else(|| anyhow!("{}.type: missing", f.path()))?
            .to_ascii_lowercase();
        let mut o = Map::new();
        let mut derived = Vec::new();
        let known: &[(&str, Tier)] = match kind.as_str() {
            "direct" => {
                o.insert("type".into(), json!("direct"));
                dial(&mut f, &mut o, false, warnings)?;
                &[]
            }
            "reject" => {
                o.insert("type".into(), json!("block"));
                NO_DIAL
            }
            "dns" => {
                let mut known = NO_DIAL.to_vec();
                known.extend_from_slice(DIAL);
                f.finish(&known, |_| false, warnings)?;
                return Ok(Proxy {
                    name,
                    outbound: None,
                    endpoint: false,
                    derived: Vec::new(),
                });
            }
            "ss" => {
                if let Some(shadow_tls) = shadowsocks(&mut f, &mut o, warnings, &name)? {
                    derived.push(shadow_tls);
                }
                SHADOWSOCKS
            }
            "vmess" => {
                vmess(&mut f, &mut o, warnings)?;
                V2RAY
            }
            "vless" => {
                vless(&mut f, &mut o, warnings)?;
                V2RAY
            }
            "trojan" => {
                trojan(&mut f, &mut o, warnings)?;
                V2RAY
            }
            "hysteria2" => {
                hysteria2(&mut f, &mut o, warnings)?;
                HYSTERIA2
            }
            "tuic" => {
                tuic(&mut f, &mut o, warnings)?;
                TUIC
            }
            "anytls" => {
                anytls(&mut f, &mut o, warnings)?;
                ANYTLS
            }
            "socks5" => {
                socks5(&mut f, &mut o, warnings)?;
                TLS_ONLY
            }
            "http" => {
                http(&mut f, &mut o, warnings)?;
                TLS_ONLY
            }
            "wireguard" => {
                wireguard(&mut f, &mut o, warnings)?;
                WIREGUARD
            }
            "ssr" | "hysteria" | "snell" | "mieru" | "ssh" | "sudoku" | "masque"
            | "trusttunnel" | "shadowquic" | "gost-relay" | "rematch" | "openvpn" | "tailscale"
            | "zerotier" | "easytier" => {
                return Err(anyhow!(
                    "{}.type: sail does not implement \"{}\" yet",
                    f.path(),
                    kind
                ))
            }
            other => {
                return Err(anyhow!(
                    "{}.type: {:?} is not a proxy type Mihomo takes",
                    f.path(),
                    other
                ))
            }
        };
        o.insert("tag".into(), json!(name));
        // UDP is carried either way; see the module's notes.
        f.bool("udp")?;
        let mut known = known.to_vec();
        known.extend_from_slice(DIAL);
        f.finish(&known, |_| false, warnings)?;
        Ok(Proxy {
            name,
            endpoint: o.get("type").is_some_and(|t| t == "wireguard"),
            outbound: Some(Value::Object(o)),
            derived,
        })
    }
}

/// The dial fields of a proxy that dials nothing: REJECT's and a DNS
/// one's, which answer themselves.
const NO_DIAL: &[(&str, Tier)] = &[
    ("dialer-proxy", Ignored),
    ("interface-name", Ignored),
    ("routing-mark", Ignored),
];

/// The dial fields every proxy takes but a direct one's server.
const DIAL: &[(&str, Tier)] = &[
    ("tfo", Ignored),
    ("mptcp", Ignored),
    ("ip-version", Ignored),
];

const TLS: &[(&str, Tier)] = &[("name-cert-verify", Unsupported)];

const SHADOWSOCKS: &[(&str, Tier)] = &[("client-fingerprint", Ignored)];

const V2RAY: &[(&str, Tier)] = &[
    ("name-cert-verify", Unsupported),
    ("shadow-tls-opts", Unsupported),
    ("restls-opts", Unsupported),
    ("jls-opts", Unsupported),
    ("tlsmirror-opts", Unsupported),
    ("mekya-opts", Unsupported),
    ("mkcp-opts", Unsupported),
    ("http-opts", Unsupported),
    ("h2-opts", Unsupported),
    ("xhttp-opts", Unsupported),
    ("ss-opts", Unsupported),
];

const HYSTERIA2: &[(&str, Tier)] = &[
    ("name-cert-verify", Unsupported),
    ("obfs-min-packet-size", Unsupported),
    ("obfs-max-packet-size", Unsupported),
    ("realm-opts", Unsupported),
    ("cwnd", Ignored),
    ("bbr-profile", Ignored),
    ("udp-mtu", Ignored),
    ("handshake-timeout", Ignored),
    ("initial-stream-receive-window", Ignored),
    ("max-stream-receive-window", Ignored),
    ("initial-connection-receive-window", Ignored),
    ("max-connection-receive-window", Ignored),
];

const TUIC: &[(&str, Tier)] = &[
    ("name-cert-verify", Unsupported),
    ("request-timeout", Ignored),
    ("max-udp-relay-packet-size", Ignored),
    ("fast-open", Ignored),
    ("max-open-streams", Ignored),
    ("cwnd", Ignored),
    ("bbr-profile", Ignored),
    ("recv-window-conn", Ignored),
    ("recv-window", Ignored),
    ("disable-mtu-discovery", Ignored),
    ("max-datagram-frame-size", Ignored),
];

const ANYTLS: &[(&str, Tier)] = &[
    ("name-cert-verify", Unsupported),
    ("shadow-tls-opts", Unsupported),
    ("restls-opts", Unsupported),
    ("jls-opts", Unsupported),
    ("client-metadata", Ignored),
    ("disable-reuse", Ignored),
];

const TLS_ONLY: &[(&str, Tier)] = TLS;

const WIREGUARD: &[(&str, Tier)] = &[
    // Another wire format: what goes out would not be WireGuard's.
    ("amnezia-wg-option", Unsupported),
    // sail's own userspace stack.
    ("ip-stack", Ignored),
    // A peer's address is resolved as the endpoint starts.
    ("refresh-server-ip-interval", Ignored),
];

/// The server, and how it is dialled.
fn server(f: &mut Fields, o: &mut Map<String, Value>, w: &mut Vec<String>) -> Result<()> {
    let server = f
        .string("server")?
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("{}.server: missing", f.path()))?;
    let port = f
        .int::<u16>("port")?
        .ok_or_else(|| anyhow!("{}.port: missing", f.path()))?;
    o.insert("server".into(), json!(server));
    o.insert("server_port".into(), json!(port));
    dial(f, o, true, w)
}

/// The dial fields: the interface, the mark, the families its server
/// resolves to, the proxy it is dialled through, and multiplexing.
fn dial(
    f: &mut Fields,
    o: &mut Map<String, Value>,
    remote: bool,
    w: &mut Vec<String>,
) -> Result<()> {
    if let Some(name) = f.string("interface-name")? {
        o.insert("bind_interface".into(), json!(name));
    }
    if let Some(mark) = f.int::<u32>("routing-mark")? {
        o.insert("routing_mark".into(), json!(mark));
    }
    if let Some(version) = f.string("ip-version")? {
        let strategy = match version.to_ascii_lowercase().as_str() {
            "dual" => None,
            "ipv4" => Some("ipv4_only"),
            "ipv6" => Some("ipv6_only"),
            "ipv4-prefer" => Some("prefer_ipv4"),
            "ipv6-prefer" => Some("prefer_ipv6"),
            other => {
                return Err(anyhow!(
                    "{}: {:?} is none of dual, ipv4, ipv6, ipv4-prefer and ipv6-prefer",
                    f.at("ip-version"),
                    other
                ))
            }
        };
        if let Some(strategy) = strategy {
            o.insert("domain_strategy".into(), json!(strategy));
        }
    }
    if let Some(via) = f.string("dialer-proxy")? {
        o.insert("detour".into(), json!(via));
    }
    if remote {
        if let Some(mut smux) = f.map("smux")? {
            if smux.bool("enabled")?.unwrap_or(false) {
                let mut m = Map::new();
                m.insert("enabled".into(), json!(true));
                if let Some(protocol) = smux.string("protocol")? {
                    m.insert("protocol".into(), json!(protocol));
                }
                for (from, to) in [
                    ("max-connections", "max_connections"),
                    ("min-streams", "min_streams"),
                    ("max-streams", "max_streams"),
                ] {
                    if let Some(n) = smux.int::<u32>(from)? {
                        m.insert(to.into(), json!(n));
                    }
                }
                if let Some(padding) = smux.bool("padding")? {
                    m.insert("padding".into(), json!(padding));
                }
                if let Some(mut brutal) = smux.map("brutal-opts")? {
                    if brutal.bool("enabled")?.unwrap_or(false) {
                        return Err(anyhow!(
                            "{}: sail does not implement TCP Brutal yet",
                            brutal.path()
                        ));
                    }
                    drop(brutal);
                }
                smux.finish(
                    &[("statistic", Ignored), ("only-tcp", Unsupported)],
                    |_| false,
                    w,
                )?;
                o.insert("multiplex".into(), Value::Object(m));
            }
        }
    }
    Ok(())
}

/// `tls`, if on: `name_key` names the server name (`servername` for VMess
/// and VLESS, `sni` for the rest); `on` is whether TLS is on without a
/// `tls` field.
/// Mihomo's `fingerprint`: the SHA-256 hash of a whole certificate the
/// server is taken by, sail's `certificate_sha256`, which has Mihomo's
/// meaning: the server's own certificate taken outright, one after it the
/// only CA, with the name checked. A browser's name, which belongs in
/// `client-fingerprint`, is refused as Mihomo refuses it.
fn certificate_pin(f: &mut Fields) -> Result<Option<String>> {
    let at = f.at("fingerprint");
    let Some(pin) = f.string("fingerprint")?.filter(|p| !p.trim().is_empty()) else {
        return Ok(None);
    };
    const BROWSERS: &[&str] = &[
        "chrome",
        "firefox",
        "safari",
        "ios",
        "android",
        "edge",
        "360",
        "qq",
        "random",
        "randomized",
    ];
    if BROWSERS.contains(&pin.as_str()) {
        return Err(anyhow!(
            "{}: `fingerprint` is used for TLS certificate pinning. If you need to specify \
             the browser fingerprint, use `client-fingerprint`",
            at
        ));
    }
    Ok(Some(super::super::certificate_hash(&pin)))
}

fn tls(
    f: &mut Fields,
    o: &mut Map<String, Value>,
    w: &mut Vec<String>,
    name_key: &str,
    on: bool,
) -> Result<()> {
    let enabled = f.bool("tls")?.unwrap_or(on);
    let reality = f.map("reality-opts")?;
    let ech = f.map("ech-opts")?;
    let server_name = f.string(name_key)?;
    let insecure = f.bool("skip-cert-verify")?.unwrap_or(false);
    let alpn = f.strings("alpn")?;
    let client_fingerprint = f.string("client-fingerprint")?;
    let certificate = f.string("certificate")?.filter(|c| !c.is_empty());
    let private_key = f.string("private-key")?.filter(|k| !k.is_empty());
    let pin = certificate_pin(f)?;
    if !enabled {
        return Ok(());
    }
    let mut tls = Map::new();
    tls.insert("enabled".into(), json!(true));
    if let Some(name) = server_name.filter(|n| !n.is_empty()) {
        tls.insert("server_name".into(), json!(name));
    }
    if insecure {
        tls.insert("insecure".into(), json!(true));
    }
    if !alpn.is_empty() {
        tls.insert("alpn".into(), json!(alpn));
    }
    if let Some(pin) = pin {
        tls.insert("certificate_sha256".into(), json!([pin]));
    }
    // The client certificate: PEM, or a path, as Mihomo tells them apart.
    match (certificate, private_key) {
        (None, None) => {}
        (Some(certificate), Some(key)) => {
            for (field, value) in [("client_certificate", certificate), ("client_key", key)] {
                if value.contains("-----BEGIN") {
                    tls.insert(field.into(), json!(value));
                } else {
                    tls.insert(format!("{}_path", field), json!(value));
                }
            }
        }
        (Some(_), None) => return Err(anyhow!("{}: needed with certificate", f.at("private-key"))),
        (None, Some(_)) => return Err(anyhow!("{}: needed with private-key", f.at("certificate"))),
    }
    if let Some(utls) = utls(&f.at("client-fingerprint"), client_fingerprint.as_deref())? {
        tls.insert("utls".into(), utls);
    }
    if let Some(mut r) = reality {
        let key = r
            .string("public-key")?
            .ok_or_else(|| anyhow!("{}: missing", r.at("public-key")))?;
        let mut reality = Map::new();
        reality.insert("enabled".into(), json!(true));
        reality.insert("public_key".into(), json!(key));
        if let Some(id) = r.string("short-id")? {
            reality.insert("short_id".into(), json!(id));
        }
        r.finish(&[("support-x25519mlkem768", Ignored)], |_| false, w)?;
        tls.insert("reality".into(), Value::Object(reality));
    }
    if let Some(mut e) = ech {
        if e.bool("enable")?.unwrap_or(false) {
            let mut ech = Map::new();
            ech.insert("enabled".into(), json!(true));
            if let Some(config) = e.string("config")? {
                ech.insert("config".into(), json!([config]));
            }
            e.finish(&[("query-server-name", Unsupported)], |_| false, w)?;
            tls.insert("ech".into(), Value::Object(ech));
        }
    }
    o.insert("tls".into(), Value::Object(tls));
    Ok(())
}

/// The `utls` block of a `client-fingerprint` (at `at`); none for none.
fn utls(at: &str, fp: Option<&str>) -> Result<Option<Value>> {
    let Some(fp) = fp.filter(|fp| !fp.is_empty() && *fp != "none") else {
        return Ok(None);
    };
    let fp = match fp.to_ascii_lowercase().as_str() {
        fp @ ("chrome" | "firefox" | "safari" | "ios" | "android" | "edge" | "random") => {
            fp.to_string()
        }
        other => {
            return Err(anyhow!(
                "{}: sail has no fingerprint {:?}, only chrome, firefox, safari, ios, \
                 android, edge and random",
                at,
                other
            ))
        }
    };
    Ok(Some(json!({ "enabled": true, "fingerprint": fp })))
}

/// `network` and its options: `tcp`, `ws` (or HTTPUpgrade) and `grpc`.
fn transport(f: &mut Fields, o: &mut Map<String, Value>, w: &mut Vec<String>) -> Result<()> {
    let network = f
        .string("network")?
        .map(|n| n.to_ascii_lowercase())
        .unwrap_or_else(|| "tcp".to_string());
    let ws = f.map("ws-opts")?;
    let grpc = f.map("grpc-opts")?;
    match network.as_str() {
        // `none`, and nothing, are TCP as well: Mihomo dials TCP for any
        // network it has no transport for.
        "tcp" | "none" | "" => {}
        "ws" => {
            let mut transport = Map::new();
            let mut path = "/".to_string();
            let mut headers = Map::new();
            let mut upgrade = false;
            if let Some(mut opts) = ws {
                if let Some(p) = opts.string("path")? {
                    path = p;
                }
                if let Some(mut h) = opts.map("headers")? {
                    for key in h.keys() {
                        if let Some(v) = h.string(&key)? {
                            headers.insert(key, json!(v));
                        }
                    }
                }
                upgrade = opts.bool("v2ray-http-upgrade")?.unwrap_or(false);
                if let Some(n) = opts.int::<u32>("max-early-data")? {
                    if !upgrade && n > 0 {
                        transport.insert("max_early_data".into(), json!(n));
                    }
                }
                if let Some(name) = opts.string("early-data-header-name")? {
                    if !upgrade {
                        transport.insert("early_data_header_name".into(), json!(name));
                    }
                }
                opts.finish(&[("v2ray-http-upgrade-fast-open", Ignored)], |_| false, w)?;
            }
            if upgrade {
                transport.insert("type".into(), json!("httpupgrade"));
                if let Some(host) = headers.remove("Host").or_else(|| headers.remove("host")) {
                    transport.insert("host".into(), host);
                }
            } else {
                transport.insert("type".into(), json!("ws"));
            }
            transport.insert("path".into(), json!(path));
            if !headers.is_empty() {
                transport.insert("headers".into(), Value::Object(headers));
            }
            o.insert("transport".into(), Value::Object(transport));
        }
        "grpc" => {
            let mut transport = Map::new();
            transport.insert("type".into(), json!("grpc"));
            if let Some(mut g) = grpc {
                if let Some(name) = g.string("grpc-service-name")? {
                    transport.insert("service_name".into(), json!(name));
                }
                g.finish(
                    &[
                        ("grpc-user-agent", Ignored),
                        ("ping-interval", Ignored),
                        ("max-connections", Ignored),
                        ("min-streams", Ignored),
                        ("max-streams", Ignored),
                    ],
                    |_| false,
                    w,
                )?;
            }
            o.insert("transport".into(), Value::Object(transport));
        }
        // sing-box's HTTP/2 transport, which sail leaves out by design.
        "h2" => {
            return Err(anyhow!(
                "{}: h2 (HTTP/2) is not supported, by design; grpc and ws (with or without \
                 v2ray-http-upgrade) are",
                f.at("network")
            ))
        }
        "http" | "xhttp" | "kcp" | "quic" => {
            return Err(anyhow!(
                "{}: sail does not implement the {} transport yet",
                f.at("network"),
                network
            ))
        }
        other => {
            return Err(anyhow!(
                "{}: {:?} is not a network Mihomo takes",
                f.at("network"),
                other
            ))
        }
    }
    Ok(())
}

/// A Shadowsocks proxy; with the shadow-tls plugin, also the ShadowTLS
/// outbound it goes through.
fn shadowsocks(
    f: &mut Fields,
    o: &mut Map<String, Value>,
    w: &mut Vec<String>,
    name: &str,
) -> Result<Option<Value>> {
    o.insert("type".into(), json!("shadowsocks"));
    server(f, o, w)?;
    let cipher = f
        .string("cipher")?
        .ok_or_else(|| anyhow!("{}: missing", f.at("cipher")))?;
    o.insert("method".into(), json!(cipher));
    o.insert(
        "password".into(),
        json!(f.string("password")?.unwrap_or_default()),
    );
    let opts = f.map("plugin-opts")?;
    let mut shadow_tls = None;
    match f.string("plugin")?.as_deref() {
        None | Some("") => {}
        Some("obfs") => {
            let mut opts = opts.ok_or_else(|| anyhow!("{}: missing", f.at("plugin-opts")))?;
            let mode = opts
                .string("mode")?
                .ok_or_else(|| anyhow!("{}: missing", opts.at("mode")))?;
            let mut spec = format!("obfs={}", mode);
            if let Some(host) = opts.string("host")? {
                spec.push_str(&format!(";obfs-host={}", host));
            }
            opts.finish(&[], |_| false, w)?;
            o.insert("plugin".into(), json!("obfs-local"));
            o.insert("plugin_opts".into(), json!(spec));
        }
        Some("shadow-tls") => {
            let opts = opts.ok_or_else(|| anyhow!("{}: missing", f.at("plugin-opts")))?;
            shadow_tls = Some(shadow_tls_plugin(f, o, opts, w, name)?);
        }
        Some(other) => {
            return Err(anyhow!(
                "{}: sail does not implement the {} plugin yet, only obfs and shadow-tls",
                f.at("plugin"),
                other
            ))
        }
    }
    if f.bool("udp-over-tcp")?.unwrap_or(false) {
        let version = f.int::<u8>("udp-over-tcp-version")?.unwrap_or(1);
        o.insert(
            "udp_over_tcp".into(),
            json!({ "enabled": true, "version": version }),
        );
    } else {
        f.take("udp-over-tcp-version");
    }
    Ok(shadow_tls)
}

/// The tag of the ShadowTLS outbound made for the proxy `name`.
pub(crate) fn shadow_tls_tag(name: &str) -> String {
    format!("{} (shadow-tls)", name)
}

/// The shadow-tls plugin of a Shadowsocks proxy: a ShadowTLS outbound to
/// its server, which the proxy goes through and which dials as it would.
fn shadow_tls_plugin(
    f: &mut Fields,
    o: &mut Map<String, Value>,
    mut opts: Fields,
    w: &mut Vec<String>,
    name: &str,
) -> Result<Value> {
    // Mihomo's default version is 2.
    let version = opts.int::<u32>("version")?.unwrap_or(2);
    if version != 3 {
        return Err(anyhow!(
            "{}: ShadowTLS v1/v2 are not supported; use version 3",
            opts.at("version")
        ));
    }
    let password = opts
        .string("password")?
        .filter(|p| !p.is_empty())
        .ok_or_else(|| anyhow!("{}: missing", opts.at("password")))?;
    let host = opts
        .string("host")?
        .filter(|h| !h.is_empty())
        .ok_or_else(|| anyhow!("{}: missing", opts.at("host")))?;
    let mut tls = Map::new();
    tls.insert("enabled".into(), json!(true));
    tls.insert("server_name".into(), json!(host));
    if opts.bool("skip-cert-verify")?.unwrap_or(false) {
        tls.insert("insecure".into(), json!(true));
    }
    // Mihomo's default ALPN; an empty list offers none.
    let alpn = match opts.has("alpn") {
        true => opts.strings("alpn")?,
        false => vec!["h2".to_string(), "http/1.1".to_string()],
    };
    if !alpn.is_empty() {
        tls.insert("alpn".into(), json!(alpn));
    }
    // The handshake server's certificate, pinned, as Mihomo's plugin has it.
    if let Some(pin) = certificate_pin(&mut opts)? {
        tls.insert("certificate_sha256".into(), json!([pin]));
    }
    let client_fingerprint = f.string("client-fingerprint")?;
    if let Some(utls) = utls(&f.at("client-fingerprint"), client_fingerprint.as_deref())? {
        tls.insert("utls".into(), utls);
    }
    opts.finish(TLS, |_| false, w)?;
    let tag = shadow_tls_tag(name);
    let mut shadow_tls = Map::new();
    shadow_tls.insert("type".into(), json!("shadowtls"));
    shadow_tls.insert("tag".into(), json!(tag));
    shadow_tls.insert("server".into(), o["server"].clone());
    shadow_tls.insert("server_port".into(), o["server_port"].clone());
    shadow_tls.insert("version".into(), json!(3));
    shadow_tls.insert("password".into(), json!(password));
    shadow_tls.insert("tls".into(), Value::Object(tls));
    // It makes the connections, so it dials as the proxy would.
    for key in [
        "detour",
        "bind_interface",
        "routing_mark",
        "domain_strategy",
    ] {
        if let Some(value) = o.remove(key) {
            shadow_tls.insert(key.into(), value);
        }
    }
    o.insert("detour".into(), json!(tag));
    Ok(Value::Object(shadow_tls))
}

/// The packet encoding of VMess and VLESS: `packet-encoding`, or the older
/// `xudp` and `packet-addr` switches.
fn packet_encoding(f: &mut Fields, o: &mut Map<String, Value>) -> Result<()> {
    let xudp = f.bool("xudp")?.unwrap_or(false);
    let packet_addr = f.bool("packet-addr")?.unwrap_or(false);
    let encoding = match f.string("packet-encoding")?.as_deref() {
        Some("xudp") => Some("xudp"),
        Some("packetaddr" | "packet") => Some("packetaddr"),
        Some("" | "none") => None,
        Some(other) => {
            return Err(anyhow!(
                "{}: {:?} is none of xudp and packetaddr",
                f.at("packet-encoding"),
                other
            ))
        }
        None if xudp => Some("xudp"),
        None if packet_addr => Some("packetaddr"),
        None => None,
    };
    if let Some(encoding) = encoding {
        o.insert("packet_encoding".into(), json!(encoding));
    }
    Ok(())
}

fn vmess(f: &mut Fields, o: &mut Map<String, Value>, w: &mut Vec<String>) -> Result<()> {
    o.insert("type".into(), json!("vmess"));
    server(f, o, w)?;
    let uuid = f
        .string("uuid")?
        .ok_or_else(|| anyhow!("{}: missing", f.at("uuid")))?;
    o.insert("uuid".into(), json!(uuid));
    o.insert(
        "security".into(),
        json!(f.string("cipher")?.unwrap_or_else(|| "auto".to_string())),
    );
    if let Some(alter) = f.int::<u16>("alterId")? {
        o.insert("alter_id".into(), json!(alter));
    }
    if f.bool("global-padding")?.unwrap_or(false) {
        o.insert("global_padding".into(), json!(true));
    }
    if f.bool("authenticated-length")?.unwrap_or(false) {
        return Err(anyhow!(
            "{}: sail does not implement this field yet",
            f.at("authenticated-length")
        ));
    }
    packet_encoding(f, o)?;
    tls(f, o, w, "servername", false)?;
    transport(f, o, w)
}

fn vless(f: &mut Fields, o: &mut Map<String, Value>, w: &mut Vec<String>) -> Result<()> {
    o.insert("type".into(), json!("vless"));
    server(f, o, w)?;
    let uuid = f
        .string("uuid")?
        .ok_or_else(|| anyhow!("{}: missing", f.at("uuid")))?;
    o.insert("uuid".into(), json!(uuid));
    if let Some(flow) = f.string("flow")?.filter(|f| !f.is_empty()) {
        o.insert("flow".into(), json!(flow));
    }
    match f.string("encryption")?.as_deref() {
        None | Some("" | "none") => {}
        Some(_) => {
            return Err(anyhow!(
                "{}: sail does not implement VLESS encryption yet",
                f.at("encryption")
            ))
        }
    }
    packet_encoding(f, o)?;
    if f.has("ws-headers") {
        return Err(anyhow!(
            "{}: the older form of ws-opts.headers; write ws-opts",
            f.at("ws-headers")
        ));
    }
    tls(f, o, w, "servername", false)?;
    transport(f, o, w)
}

fn trojan(f: &mut Fields, o: &mut Map<String, Value>, w: &mut Vec<String>) -> Result<()> {
    o.insert("type".into(), json!("trojan"));
    server(f, o, w)?;
    let password = f
        .string("password")?
        .ok_or_else(|| anyhow!("{}: missing", f.at("password")))?;
    o.insert("password".into(), json!(password));
    tls(f, o, w, "sni", true)?;
    transport(f, o, w)
}

fn hysteria2(f: &mut Fields, o: &mut Map<String, Value>, w: &mut Vec<String>) -> Result<()> {
    o.insert("type".into(), json!("hysteria2"));
    let server = f
        .string("server")?
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("{}.server: missing", f.path()))?;
    o.insert("server".into(), json!(server));
    if let Some(port) = f.int::<u16>("port")? {
        o.insert("server_port".into(), json!(port));
    }
    if let Some(ports) = f.string("ports")? {
        let ranges = ports
            .split([',', '/'])
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .map(|p| match p.split_once('-') {
                Some((a, b)) => format!("{}:{}", a.trim(), b.trim()),
                None => format!("{}:{}", p, p),
            })
            .collect::<Vec<_>>();
        o.insert("server_ports".into(), json!(ranges));
    }
    if !o.contains_key("server_port") && !o.contains_key("server_ports") {
        return Err(anyhow!("{}.port: missing, and so is ports", f.path()));
    }
    dial(f, o, false, w)?;
    if let Some(seconds) = f.int::<u32>("hop-interval")? {
        o.insert("hop_interval".into(), json!(format!("{}s", seconds)));
    }
    for (from, to) in [("up", "up_mbps"), ("down", "down_mbps")] {
        if let Some(rate) = f.string(from)? {
            o.insert(
                to.into(),
                json!(mbps(&rate).map_err(|e| anyhow!("{}: {}", f.at(from), e))?),
            );
        }
    }
    if let Some(password) = f.string("password")? {
        o.insert("password".into(), json!(password));
    }
    let obfs_password = f.string("obfs-password")?;
    match f.string("obfs")?.as_deref() {
        None | Some("") => {}
        Some("salamander") => {
            o.insert(
                "obfs".into(),
                json!({ "type": "salamander", "password": obfs_password.unwrap_or_default() }),
            );
        }
        Some(other) => return Err(anyhow!("{}: {:?} is not salamander", f.at("obfs"), other)),
    }
    tls(f, o, w, "sni", true)
}

/// A rate as Mihomo writes one, in Mbps: a number is in Mbps.
fn mbps(rate: &str) -> Result<u64> {
    let rate = rate.trim();
    let split = rate
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(rate.len());
    let (number, unit) = rate.split_at(split);
    let number: f64 = number
        .trim()
        .parse()
        .map_err(|_| anyhow!("{:?} is not a rate", rate))?;
    let per_mbps = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "m" | "mb" | "mbps" => 1.0,
        "k" | "kb" | "kbps" => 1.0 / 1000.0,
        "g" | "gb" | "gbps" => 1000.0,
        "t" | "tb" | "tbps" => 1_000_000.0,
        "b" | "bps" => 1.0 / 1_000_000.0,
        other => return Err(anyhow!("{:?} is not a unit of rate", other)),
    };
    Ok(((number * per_mbps).round() as u64).max(1))
}

fn tuic(f: &mut Fields, o: &mut Map<String, Value>, w: &mut Vec<String>) -> Result<()> {
    o.insert("type".into(), json!("tuic"));
    server(f, o, w)?;
    if f.has("token") {
        return Err(anyhow!(
            "{}: TUIC v4, which sail does not implement; v5 takes uuid and password",
            f.at("token")
        ));
    }
    for key in ["uuid", "password"] {
        let value = f
            .string(key)?
            .ok_or_else(|| anyhow!("{}: missing", f.at(key)))?;
        o.insert(key.into(), json!(value));
    }
    // A fixed address to dial, the server staying the name TLS checks.
    if let Some(ip) = f.string("ip")? {
        let name = o.insert("server".into(), json!(ip));
        if let Some(Value::String(name)) = name {
            if !f.has("sni") {
                f.map_insert("sni", name);
            }
        }
    }
    if let Some(cc) = f.string("congestion-controller")? {
        o.insert("congestion_control".into(), json!(cc));
    }
    if let Some(mode) = f.string("udp-relay-mode")? {
        o.insert("udp_relay_mode".into(), json!(mode));
    }
    if f.bool("udp-over-stream")?.unwrap_or(false) {
        o.insert("udp_over_stream".into(), json!(true));
    }
    f.take("udp-over-stream-version");
    if f.bool("reduce-rtt")?.unwrap_or(false) {
        o.insert("zero_rtt_handshake".into(), json!(true));
    }
    if let Some(ms) = f.int::<u64>("heartbeat-interval")? {
        o.insert("heartbeat".into(), json!(format!("{}ms", ms)));
    }
    if f.bool("disable-sni")?.unwrap_or(false) {
        return Err(anyhow!(
            "{}: sail does not implement this field yet",
            f.at("disable-sni")
        ));
    }
    tls(f, o, w, "sni", true)
}

fn anytls(f: &mut Fields, o: &mut Map<String, Value>, w: &mut Vec<String>) -> Result<()> {
    o.insert("type".into(), json!("anytls"));
    server(f, o, w)?;
    let password = f
        .string("password")?
        .ok_or_else(|| anyhow!("{}: missing", f.at("password")))?;
    o.insert("password".into(), json!(password));
    for (from, to) in [
        ("idle-session-check-interval", "idle_session_check_interval"),
        ("idle-session-timeout", "idle_session_timeout"),
    ] {
        if let Some(seconds) = f.int::<u64>(from)? {
            o.insert(to.into(), json!(format!("{}s", seconds)));
        }
    }
    if let Some(n) = f.int::<u32>("min-idle-session")? {
        o.insert("min_idle_session".into(), json!(n));
    }
    tls(f, o, w, "sni", true)
}

/// Mihomo's `wireguard` proxy (`adapter/outbound/wireguard.go`), a
/// WireGuard endpoint: its own addresses `ip` and `ipv6` (a /32 and a /128
/// when no prefix is given), and one peer of the server, port and keys
/// given beside them, or those `peers` lists. A peer's `allowed-ips` are,
/// when none are given, all of the families of the endpoint's addresses.
fn wireguard(f: &mut Fields, o: &mut Map<String, Value>, w: &mut Vec<String>) -> Result<()> {
    o.insert("type".into(), json!("wireguard"));
    let mut address = Vec::new();
    let (mut has4, mut has6) = (false, false);
    for (key, len) in [("ip", 32), ("ipv6", 128)] {
        let Some(ip) = f.string(key)?.filter(|ip| !ip.is_empty()) else {
            continue;
        };
        let bare = ip.split('/').next().unwrap_or_default();
        let parsed: std::net::IpAddr = bare
            .parse()
            .map_err(|_| anyhow!("{}: {:?} is not an IP address", f.at(key), ip))?;
        has4 |= parsed.is_ipv4();
        has6 |= parsed.is_ipv6();
        address.push(match ip.contains('/') {
            true => ip,
            false => format!("{}/{}", ip, len),
        });
    }
    if address.is_empty() {
        return Err(anyhow!("{}: missing, and so is ipv6", f.at("ip")));
    }
    o.insert("address".into(), json!(address));
    let private_key = f
        .string("private-key")?
        .ok_or_else(|| anyhow!("{}: missing", f.at("private-key")))?;
    o.insert(
        "private_key".into(),
        json!(wireguard_key(&private_key, &f.at("private-key"))?),
    );
    if let Some(mtu) = f.int::<u32>("mtu")? {
        o.insert("mtu".into(), json!(mtu));
    }
    // sail has no use for it, as sing-box's endpoint has none.
    f.int::<u32>("workers")?;
    let keepalive = f.int::<u16>("persistent-keepalive")?.filter(|k| *k > 0);
    let default_ips = || {
        let mut ips = Vec::new();
        if has4 {
            ips.push("0.0.0.0/0".to_string());
        }
        if has6 {
            ips.push("::/0".to_string());
        }
        ips
    };
    let mut peers = Vec::new();
    let listed = f.list("peers")?;
    if listed.is_empty() {
        peers.push(wireguard_peer(f, keepalive, &default_ips)?);
    } else {
        for key in [
            "server",
            "port",
            "public-key",
            "pre-shared-key",
            "reserved",
            "allowed-ips",
        ] {
            if f.take(key).is_some() {
                w.push(format!(
                    "{}: peers lists the peers; ignored, as by Mihomo",
                    f.at(key)
                ));
            }
        }
        for (i, node) in listed.into_iter().enumerate() {
            let mut peer = Fields::of(node, &format!("{}[{}]", f.at("peers"), i))?;
            peers.push(wireguard_peer(&mut peer, keepalive, &default_ips)?);
            peer.finish(&[], |_| false, w)?;
        }
    }
    o.insert("peers".into(), Value::Array(peers));
    // Mihomo resolves the names its connections dial through these servers,
    // inside the tunnel; sail resolves them as its DNS says.
    let remote = f.bool("remote-dns-resolve")?.unwrap_or(false);
    let servers = f.strings("dns")?;
    if remote && !servers.is_empty() {
        w.push(format!(
            "{}: sail resolves the names the tunnel's connections dial as its DNS says, not \
             through these servers; ignored",
            f.at("dns")
        ));
    }
    dial(f, o, false, w)
}

/// A peer of a `wireguard` proxy: its server, port and keys, from `f`,
/// the proxy itself or an entry of its `peers`.
fn wireguard_peer(
    f: &mut Fields,
    keepalive: Option<u16>,
    default_ips: &dyn Fn() -> Vec<String>,
) -> Result<Value> {
    let mut peer = Map::new();
    let server = f
        .string("server")?
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("{}: missing", f.at("server")))?;
    let port = f
        .int::<u16>("port")?
        .ok_or_else(|| anyhow!("{}: missing", f.at("port")))?;
    peer.insert("address".into(), json!(server));
    peer.insert("port".into(), json!(port));
    let public_key = f
        .string("public-key")?
        .ok_or_else(|| anyhow!("{}: missing", f.at("public-key")))?;
    peer.insert(
        "public_key".into(),
        json!(wireguard_key(&public_key, &f.at("public-key"))?),
    );
    if let Some(psk) = f.string("pre-shared-key")?.filter(|k| !k.is_empty()) {
        peer.insert(
            "pre_shared_key".into(),
            json!(wireguard_key(&psk, &f.at("pre-shared-key"))?),
        );
    }
    let at = f.at("reserved");
    match f.take("reserved") {
        None => {}
        Some(Node::Seq(bytes)) => {
            let bytes = bytes
                .iter()
                .map(|b| match b {
                    Node::Int(n) => u8::try_from(*n).ok(),
                    _ => None,
                })
                .collect::<Option<Vec<u8>>>()
                .ok_or_else(|| anyhow!("{}: not a list of bytes", at))?;
            if bytes.len() != 3 {
                return Err(anyhow!(
                    "{}: {} bytes, where there must be 3",
                    at,
                    bytes.len()
                ));
            }
            peer.insert("reserved".into(), json!(bytes));
        }
        Some(Node::Str(s)) => {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(s.trim())
                .map_err(|_| anyhow!("{}: {:?} is not base64", at, s))?;
            if bytes.len() != 3 {
                return Err(anyhow!(
                    "{}: {} bytes, where there must be 3",
                    at,
                    bytes.len()
                ));
            }
            peer.insert("reserved".into(), json!(bytes));
        }
        Some(n) => return Err(anyhow!("{}: three bytes, not {}", at, n.kind())),
    }
    let mut allowed = f.strings("allowed-ips")?;
    if allowed.is_empty() {
        allowed = default_ips();
    }
    peer.insert("allowed_ips".into(), json!(allowed));
    if let Some(seconds) = keepalive {
        peer.insert("persistent_keepalive_interval".into(), json!(seconds));
    }
    Ok(Value::Object(peer))
}

/// A WireGuard key as Mihomo takes it: 32 bytes, in base64.
fn wireguard_key(key: &str, at: &str) -> Result<String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(key.trim())
        .map_err(|_| anyhow!("{}: not base64", at))?;
    if bytes.len() != 32 {
        return Err(anyhow!("{}: {} bytes, where a key has 32", at, bytes.len()));
    }
    Ok(key.trim().to_string())
}

fn socks5(f: &mut Fields, o: &mut Map<String, Value>, w: &mut Vec<String>) -> Result<()> {
    o.insert("type".into(), json!("socks"));
    server(f, o, w)?;
    credentials(f, o)?;
    tls(f, o, w, "sni", false)?;
    // Without it, what was to go over TLS would go in the clear.
    if o.contains_key("tls") {
        return Err(anyhow!(
            "{}.tls: sail does not implement SOCKS5 over TLS yet",
            f.path()
        ));
    }
    Ok(())
}

fn http(f: &mut Fields, o: &mut Map<String, Value>, w: &mut Vec<String>) -> Result<()> {
    o.insert("type".into(), json!("http"));
    server(f, o, w)?;
    credentials(f, o)?;
    if let Some(mut h) = f.map("headers")? {
        let mut headers = Map::new();
        for key in h.keys() {
            if let Some(v) = h.string(&key)? {
                headers.insert(key, json!(v));
            }
        }
        o.insert("headers".into(), Value::Object(headers));
    }
    tls(f, o, w, "sni", false)
}

fn credentials(f: &mut Fields, o: &mut Map<String, Value>) -> Result<()> {
    if let Some(username) = f.string("username")? {
        o.insert("username".into(), json!(username));
    }
    if let Some(password) = f.string("password")? {
        o.insert("password".into(), json!(password));
    }
    Ok(())
}

/// A value put back in a map, for a reader after this one.
trait MapInsert {
    fn map_insert(&mut self, key: &str, value: String);
}

impl MapInsert for Fields {
    fn map_insert(&mut self, key: &str, value: String) {
        self.put(key, Node::Str(value));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rates_are_in_mbps() {
        assert_eq!(mbps("30").unwrap(), 30);
        assert_eq!(mbps("30 Mbps").unwrap(), 30);
        assert_eq!(mbps("1 Gbps").unwrap(), 1000);
        assert_eq!(mbps("500 Kbps").unwrap(), 1);
        assert!(mbps("fast").is_err());
    }
}
