//! `proxies`: each a sing-box outbound, of the fields Mihomo's proxy of its
//! type takes (`adapter/outbound/*.go`).

use std::collections::HashSet;

use anyhow::{anyhow, Result};
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
    let fingerprint = doc.string("global-client-fingerprint")?;
    let mut proxies = Proxies {
        names: Vec::new(),
        dns: HashSet::new(),
    };
    for (i, node) in doc.list("proxies")?.into_iter().enumerate() {
        let f = Fields::of(node, &format!("proxies[{}]", i))?;
        let proxy = Proxy::read(f, fingerprint.as_deref(), warnings)?;
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
            Some(outbound) => out.outbounds.push(outbound),
            None => {
                proxies.dns.insert(proxy.name.clone());
            }
        }
        proxies.names.push(proxy.name);
    }
    Ok(proxies)
}

/// A proxy of a provider, as an outbound tagged with its name. A `dns` one
/// is left out, as sail does not implement it in a provider.
pub(super) fn lower_one(f: Fields, warnings: &mut Vec<String>) -> Result<Value> {
    let proxy = Proxy::read(f, None, warnings)?;
    proxy
        .outbound
        .ok_or_else(|| anyhow!("a dns proxy: sail does not implement it in a provider"))
}

/// A proxy, read.
struct Proxy {
    name: String,
    /// None for a `dns` proxy.
    outbound: Option<Value>,
}

impl Proxy {
    fn read(mut f: Fields, fingerprint: Option<&str>, warnings: &mut Vec<String>) -> Result<Self> {
        let name = f
            .string("name")?
            .filter(|n| !n.is_empty())
            .ok_or_else(|| anyhow!("{}.name: missing", f.path()))?;
        let kind = f
            .string("type")?
            .ok_or_else(|| anyhow!("{}.type: missing", f.path()))?
            .to_ascii_lowercase();
        let mut o = Map::new();
        let known: &[(&str, Tier)] = match kind.as_str() {
            "direct" => {
                o.insert("type".into(), json!("direct"));
                dial(&mut f, &mut o, false, warnings)?;
                &[]
            }
            "reject" => {
                o.insert("type".into(), json!("block"));
                &[]
            }
            "dns" => {
                f.finish(&[], |_| false, warnings)?;
                return Ok(Proxy {
                    name,
                    outbound: None,
                });
            }
            "ss" => {
                shadowsocks(&mut f, &mut o, warnings)?;
                SHADOWSOCKS
            }
            "vmess" => {
                vmess(&mut f, &mut o, warnings, fingerprint)?;
                V2RAY
            }
            "vless" => {
                vless(&mut f, &mut o, warnings, fingerprint)?;
                V2RAY
            }
            "trojan" => {
                trojan(&mut f, &mut o, warnings, fingerprint)?;
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
                anytls(&mut f, &mut o, warnings, fingerprint)?;
                ANYTLS
            }
            "socks5" => {
                socks5(&mut f, &mut o, warnings, fingerprint)?;
                TLS_ONLY
            }
            "http" => {
                http(&mut f, &mut o, warnings, fingerprint)?;
                TLS_ONLY
            }
            "ssr" | "hysteria" | "snell" | "mieru" | "ssh" | "sudoku" | "masque" | "wireguard"
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
            outbound: Some(Value::Object(o)),
        })
    }
}

/// The dial fields every proxy takes but a direct one's server.
const DIAL: &[(&str, Tier)] = &[
    ("tfo", Ignored),
    ("mptcp", Ignored),
    ("ip-version", Ignored),
];

const TLS: &[(&str, Tier)] = &[
    ("fingerprint", Unsupported),
    ("certificate", Unsupported),
    ("private-key", Unsupported),
    ("name-cert-verify", Unsupported),
];

const SHADOWSOCKS: &[(&str, Tier)] = &[("client-fingerprint", Ignored)];

const V2RAY: &[(&str, Tier)] = &[
    ("fingerprint", Unsupported),
    ("certificate", Unsupported),
    ("private-key", Unsupported),
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
    ("fingerprint", Unsupported),
    ("certificate", Unsupported),
    ("private-key", Unsupported),
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
    ("fingerprint", Unsupported),
    ("certificate", Unsupported),
    ("private-key", Unsupported),
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
    ("fingerprint", Unsupported),
    ("certificate", Unsupported),
    ("private-key", Unsupported),
    ("name-cert-verify", Unsupported),
    ("shadow-tls-opts", Unsupported),
    ("restls-opts", Unsupported),
    ("jls-opts", Unsupported),
    ("client-metadata", Ignored),
    ("disable-reuse", Ignored),
];

const TLS_ONLY: &[(&str, Tier)] = TLS;

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
fn tls(
    f: &mut Fields,
    o: &mut Map<String, Value>,
    w: &mut Vec<String>,
    name_key: &str,
    on: bool,
    fingerprint: Option<&str>,
) -> Result<()> {
    let enabled = f.bool("tls")?.unwrap_or(on);
    let reality = f.map("reality-opts")?;
    let ech = f.map("ech-opts")?;
    let server_name = f.string(name_key)?;
    let insecure = f.bool("skip-cert-verify")?.unwrap_or(false);
    let alpn = f.strings("alpn")?;
    let client_fingerprint = f.string("client-fingerprint")?;
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
    let fp = client_fingerprint.as_deref().or(fingerprint);
    if let Some(fp) = fp.filter(|fp| !fp.is_empty() && *fp != "none") {
        let fp = match fp.to_ascii_lowercase().as_str() {
            fp @ ("chrome" | "firefox" | "safari" | "ios" | "android" | "edge" | "random") => {
                fp.to_string()
            }
            other => {
                return Err(anyhow!(
                    "{}: sail has no fingerprint {:?}, only chrome, firefox, safari, ios, \
                     android, edge and random",
                    f.at("client-fingerprint"),
                    other
                ))
            }
        };
        tls.insert("utls".into(), json!({ "enabled": true, "fingerprint": fp }));
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

/// `network` and its options: `tcp`, `ws` (or HTTPUpgrade) and `grpc`.
fn transport(f: &mut Fields, o: &mut Map<String, Value>, w: &mut Vec<String>) -> Result<()> {
    let network = f
        .string("network")?
        .map(|n| n.to_ascii_lowercase())
        .unwrap_or_else(|| "tcp".to_string());
    let ws = f.map("ws-opts")?;
    let grpc = f.map("grpc-opts")?;
    match network.as_str() {
        "tcp" => {}
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
        "http" | "h2" | "xhttp" | "kcp" | "quic" => {
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

fn shadowsocks(f: &mut Fields, o: &mut Map<String, Value>, w: &mut Vec<String>) -> Result<()> {
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
        Some(other) => {
            return Err(anyhow!(
                "{}: sail does not implement the {} plugin yet, only obfs",
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
    Ok(())
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

fn vmess(
    f: &mut Fields,
    o: &mut Map<String, Value>,
    w: &mut Vec<String>,
    fp: Option<&str>,
) -> Result<()> {
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
    tls(f, o, w, "servername", false, fp)?;
    transport(f, o, w)
}

fn vless(
    f: &mut Fields,
    o: &mut Map<String, Value>,
    w: &mut Vec<String>,
    fp: Option<&str>,
) -> Result<()> {
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
    tls(f, o, w, "servername", false, fp)?;
    transport(f, o, w)
}

fn trojan(
    f: &mut Fields,
    o: &mut Map<String, Value>,
    w: &mut Vec<String>,
    fp: Option<&str>,
) -> Result<()> {
    o.insert("type".into(), json!("trojan"));
    server(f, o, w)?;
    let password = f
        .string("password")?
        .ok_or_else(|| anyhow!("{}: missing", f.at("password")))?;
    o.insert("password".into(), json!(password));
    tls(f, o, w, "sni", true, fp)?;
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
    tls(f, o, w, "sni", true, None)
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
    tls(f, o, w, "sni", true, None)
}

fn anytls(
    f: &mut Fields,
    o: &mut Map<String, Value>,
    w: &mut Vec<String>,
    fp: Option<&str>,
) -> Result<()> {
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
    tls(f, o, w, "sni", true, fp)
}

fn socks5(
    f: &mut Fields,
    o: &mut Map<String, Value>,
    w: &mut Vec<String>,
    fp: Option<&str>,
) -> Result<()> {
    o.insert("type".into(), json!("socks"));
    server(f, o, w)?;
    credentials(f, o)?;
    tls(f, o, w, "sni", false, fp)
}

fn http(
    f: &mut Fields,
    o: &mut Map<String, Value>,
    w: &mut Vec<String>,
    fp: Option<&str>,
) -> Result<()> {
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
    tls(f, o, w, "sni", false, fp)
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
