//! `listeners`: inbounds of their own, each tagged with its name, which
//! `IN-NAME` rules match and `IN-TYPE` ones by its type. One with a `proxy`
//! sends everything to that policy, whatever the rules and the mode say,
//! as Mihomo does: its rule stands before every other but the sniffer's,
//! as Mihomo sniffs before it looks.
//!
//! `tunnels` forward what comes in on an address to a target, through
//! the rules or a `proxy` of their own, as direct inbounds doing so; and so
//! do `tunnel` listeners. `tun` listeners are TUN inbounds, lowered with
//! the top-level `tun` (`tun::lower`).
//!
//! `lan-allowed-ips` and `lan-disallowed-ips` keep to them those who may
//! use the listeners that authenticate as `authentication` says, as
//! Mihomo keeps them: a rule before every other rejects the others' TCP
//! and UDP alike.
//!
//! The proxy listeners (trojan, vless, vmess) serve sing-mux, as all of Mihomo's do,
//! over a websocket at `ws-path` or gRPC under `grpc-service-name` where
//! one is given. The QUIC ones (hysteria2, tuic) do not, where Mihomo's do: no
//! client asks for it over QUIC. Nor does anytls, which is a mux itself.
//!
//! Where sail does otherwise: its SOCKS, mixed and shadowsocks inbounds
//! carry UDP whatever `udp` says, where Mihomo's listeners carry it only
//! with `udp: true`. A websocket listener takes websocket clients alone,
//! where Mihomo's takes v2ray's HTTP upgrade on the same path too. A connection `lan-allowed-ips` keeps out is rejected
//! once its client has asked for a destination, where Mihomo closes it at
//! once.

use anyhow::{anyhow, Result};
use serde_json::{json, Map, Value};

use super::fields::{Fields, Tier};
use super::general::LISTENERS;
use super::group::Policies;
use super::rule::{target, Target};
use super::Lowered;

use Tier::*;

/// Mihomo's listener types sail has, and its inbounds of them.
const TYPES: &[(&str, &str)] = &[
    ("mixed", "mixed"),
    ("socks", "socks"),
    ("http", "http"),
    ("redir", "redirect"),
    ("tproxy", "tproxy"),
    ("shadowsocks", "shadowsocks"),
    ("trojan", "trojan"),
    ("vless", "vless"),
    ("hysteria2", "hysteria2"),
    ("tuic", "tuic"),
    ("anytls", "anytls"),
    ("vmess", "vmess"),
    // A direct inbound to its target, as a `tunnels` entry.
    ("tunnel", "tunnel"),
    // Lowered with the top-level `tun` (`tun::lower`).
    ("tun", "tun"),
];

/// The early data a websocket client may send in `Sec-WebSocket-Protocol`,
/// which Mihomo's listeners read of any size: Xray's 2048 bytes, all that
/// its clients and Mihomo's send.
const WS_EARLY_DATA: usize = 2048;

const FIELDS: &[(&str, Tier)] = &[
    // Which policy what comes in goes to.
    ("rule", Unsupported),
    ("routing-mark", Ignored),
    // TLS, and what shadowsocks is wrapped in.
    ("certificate", Unsupported),
    ("private-key", Unsupported),
    ("client-auth-type", Unsupported),
    ("client-auth-cert", Unsupported),
    ("ech-key", Unsupported),
    ("reality-config", Unsupported),
    ("mux-option", Unsupported),
    ("shadow-tls", Unsupported),
    ("res-tls", Unsupported),
    ("jls-config", Unsupported),
    ("kcp-tun", Unsupported),
    ("ss-option", Unsupported),
    ("xhttp-config", Unsupported),
    ("tlsmirror-config", Unsupported),
    ("mekya-config", Unsupported),
    ("mkcp-config", Unsupported),
    ("simple-obfs", Unsupported),
];

/// The listeners, lowered: their inbounds are out's already.
#[derive(Default)]
pub struct Listeners {
    /// Each one's inbound type, which `IN-TYPE` names, and its name.
    pub kinds: Vec<(String, String)>,
    /// The rules of those with a `proxy`.
    rules: Vec<Value>,
    /// The TUN listeners, by name, for `tun::lower` to make inbounds of
    /// with the top-level `tun`: what is left of each but Mihomo's base
    /// fields.
    pub tuns: Vec<(String, Fields)>,
}

impl Listeners {
    /// Puts their rules before every other, the sniffer's to come.
    pub fn apply(self, out: &mut Lowered) {
        out.rules.extend_front(self.rules);
    }
}

pub fn lower(
    doc: &mut Fields,
    policies: &Policies,
    out: &mut Lowered,
    warnings: &mut Vec<String>,
) -> Result<Listeners> {
    let mut listeners = Listeners::default();
    for (i, node) in doc.list("listeners")?.into_iter().enumerate() {
        let mut f = Fields::of(node, &format!("listeners[{}]", i))?;
        let name = f
            .string("name")?
            .filter(|n| !n.is_empty())
            .ok_or_else(|| anyhow!("{}: missing", f.at("name")))?;
        if LISTENERS.iter().any(|(_, _, tag)| *tag == name)
            || listeners.kinds.iter().any(|(_, n)| *n == name)
        {
            return Err(anyhow!(
                "{}: another listener is named {:?}",
                f.at("name"),
                name
            ));
        }
        let kind = f
            .string("type")?
            .ok_or_else(|| anyhow!("{}: missing", f.at("type")))?
            .to_ascii_lowercase();
        let protocol = TYPES
            .iter()
            .find(|(k, _)| *k == kind)
            .map(|(_, p)| *p)
            .ok_or_else(|| {
                anyhow!(
                    "{}: sail does not implement {:?} listeners yet",
                    f.at("type"),
                    kind
                )
            })?;
        if protocol == "tun" {
            // Mihomo's base fields, of which a TUN has no use for an address.
            f.take("listen");
            f.take("port");
            no_rule(&mut f)?;
            // As `FIELDS` has it for the other listeners.
            if f.take("routing-mark").is_some() {
                warnings.push(format!(
                    "{}: sail does not implement this field; ignored",
                    f.at("routing-mark")
                ));
            }
            if let Some(rule) = proxy_rule(&mut f, &name, policies)? {
                listeners.rules.push(rule);
            }
            listeners.kinds.push((protocol.to_string(), name.clone()));
            listeners.tuns.push((name, f));
            continue;
        }
        let mut inbound = Map::new();
        inbound.insert("type".into(), json!(protocol));
        inbound.insert("tag".into(), json!(name));
        inbound.insert(
            "listen".into(),
            json!(f
                .string("listen")?
                .filter(|l| !l.is_empty())
                .unwrap_or_else(|| "0.0.0.0".into())),
        );
        let port_at = f.at("port");
        let port = f
            .string("port")?
            .ok_or_else(|| anyhow!("{}: missing", port_at))?;
        let port: u16 = port.trim().parse().map_err(|_| {
            anyhow!(
                "{}: {:?}: sail takes one port, not ranges, yet",
                port_at,
                port
            )
        })?;
        inbound.insert("listen_port".into(), json!(port));
        match protocol {
            "mixed" | "socks" | "http" => {
                // None: those of `authentication`; an empty list: anyone.
                let own = f.has("users");
                let users = if own {
                    let users_at = f.at("users");
                    let mut users = Vec::new();
                    for (j, item) in f.list("users")?.into_iter().enumerate() {
                        let mut u = Fields::of(item, &format!("{}[{}]", users_at, j))?;
                        let username = u.string("username")?.unwrap_or_default();
                        let password = u.string("password")?.unwrap_or_default();
                        u.finish(&[], |_| false, warnings)?;
                        users.push(json!({ "username": username, "password": password }));
                    }
                    users
                } else {
                    out.lan_inbounds.push(name.clone());
                    out.authentication.clone()
                };
                if !users.is_empty() {
                    // Mihomo's skip-auth-prefixes, but where it names
                    // users of its own.
                    if !own && !out.skip_auth.is_empty() {
                        inbound.insert("skip_auth_prefixes".into(), json!(out.skip_auth));
                    }
                    inbound.insert("users".into(), Value::Array(users));
                }
            }
            "shadowsocks" => {
                let method = f
                    .string("cipher")?
                    .ok_or_else(|| anyhow!("{}: missing", f.at("cipher")))?;
                let password = f
                    .string("password")?
                    .ok_or_else(|| anyhow!("{}: missing", f.at("password")))?;
                inbound.insert("method".into(), json!(method));
                inbound.insert("password".into(), json!(password));
            }
            "trojan" | "vmess" => {
                let users = users(&mut f, protocol, warnings)?;
                inbound.insert("users".into(), Value::Array(users));
            }
            "vless" => {
                let users = users(&mut f, "vless", warnings)?;
                inbound.insert("users".into(), Value::Array(users));
                // VLESS encryption, Mihomo's and Xray's: none is "none".
                let at = f.at("decryption");
                if let Some(d) = f
                    .string("decryption")?
                    .filter(|d| !d.is_empty() && d != "none")
                {
                    return Err(anyhow!(
                        "{}: {:?}: sail does not implement VLESS encryption",
                        at,
                        d
                    ));
                }
            }
            "hysteria2" => hysteria2(&mut f, out.home.as_deref(), &mut inbound, warnings)?,
            "tuic" => tuic(&mut f, out.home.as_deref(), &mut inbound, warnings)?,
            "tunnel" => {
                inbound.insert("type".into(), json!("direct"));
                let network_at = f.at("network");
                let network = f.strings("network")?;
                if let Some(n) = network
                    .iter()
                    .find(|n| !matches!(n.as_str(), "tcp" | "udp"))
                {
                    return Err(anyhow!("{}: {:?} is neither tcp nor udp", network_at, n));
                }
                let target_at = f.at("target");
                let target = f
                    .string("target")?
                    .ok_or_else(|| anyhow!("{}: missing", target_at))?;
                let (host, port) = split_host_port(&target)
                    .ok_or_else(|| anyhow!("{}: {:?} names no port", target_at, target))?;
                inbound.insert("override_address".into(), json!(host));
                inbound.insert("override_port".into(), json!(port));
                match network.as_slice() {
                    // Mihomo listens on neither: nothing comes in.
                    [] => {
                        warnings.push(format!(
                            "{}: none: Mihomo's tunnel listens on nothing, and sail leaves it \
                             out",
                            network_at
                        ));
                        no_rule(&mut f)?;
                        f.take("proxy");
                        f.finish(FIELDS, |_| false, warnings)?;
                        continue;
                    }
                    [one] => {
                        inbound.insert("network".into(), json!(one));
                    }
                    _ => {}
                }
            }
            "anytls" => {
                inbound.insert("users".into(), Value::Array(named_users(&mut f, warnings)?));
                // Mihomo's is lines, as sail's.
                if let Some(scheme) = f.string("padding-scheme")?.filter(|p| !p.is_empty()) {
                    let lines: Vec<&str> = scheme
                        .lines()
                        .map(str::trim)
                        .filter(|l| !l.is_empty())
                        .collect();
                    inbound.insert("padding_scheme".into(), json!(lines));
                }
                // Mihomo's anytls listener has no REALITY.
                if f.take("reality-config").is_some() {
                    warnings.push(format!(
                        "{}: not a field Mihomo's anytls listener takes; ignored",
                        f.at("reality-config")
                    ));
                }
            }
            _ => {}
        }
        if matches!(protocol, "http" | "trojan" | "vless" | "vmess" | "anytls") {
            tls(&mut f, out.home.as_deref(), &mut inbound, warnings)?;
        }
        if matches!(protocol, "trojan" | "vless" | "anytls") {
            // As Mihomo: none of these but by leave.
            let insecure = f.bool("allow-insecure")?.unwrap_or(false);
            if !inbound.contains_key("tls") && !insecure {
                let or_reality = if protocol == "anytls" {
                    ""
                } else {
                    " or REALITY"
                };
                return Err(anyhow!(
                    "{}: no certificate{}, and not allow-insecure: Mihomo refuses \
                     a {} listener without TLS",
                    f.at("certificate"),
                    or_reality,
                    protocol
                ));
            }
        }
        if matches!(protocol, "trojan" | "vless" | "vmess") {
            carriers(&mut f, &mut inbound, warnings)?;
        }
        // Mihomo's are TCP alone without it; sail's carry UDP all the same.
        let udp = f.bool("udp")?;
        if matches!(protocol, "mixed" | "socks" | "shadowsocks") && udp != Some(true) {
            warnings.push(format!(
                "{}: not true: sail's {} inbound carries UDP all the same",
                f.at("udp"),
                protocol
            ));
        }
        if let Some(rule) = proxy_rule(&mut f, &name, policies)? {
            listeners.rules.push(rule);
        }
        f.finish(FIELDS, |_| false, warnings)?;
        out.inbounds.push(Value::Object(inbound));
        listeners.kinds.push((protocol.to_string(), name));
    }
    for (i, node) in doc.list("tunnels")?.into_iter().enumerate() {
        let at = format!("tunnels[{}]", i);
        let tunnel = tunnel(node, &at, warnings)?;
        let tag = format!("tunnel:{}", tunnel.address);
        if listeners.kinds.iter().any(|(_, n)| *n == tag) {
            return Err(anyhow!(
                "{}: another tunnel listens on {}",
                at,
                tunnel.address
            ));
        }
        let (host, port) = split_host_port(&tunnel.address)
            .ok_or_else(|| anyhow!("{}: {:?} names no port", at, tunnel.address))?;
        let (target_host, target_port) = split_host_port(&tunnel.target)
            .ok_or_else(|| anyhow!("{}: {:?} names no port", at, tunnel.target))?;
        let mut inbound = Map::new();
        inbound.insert("type".into(), json!("direct"));
        inbound.insert("tag".into(), json!(tag));
        inbound.insert(
            "listen".into(),
            json!(if host.is_empty() { "0.0.0.0" } else { host }),
        );
        inbound.insert("listen_port".into(), json!(port));
        if let [one] = tunnel.network.as_slice() {
            inbound.insert("network".into(), json!(one));
        }
        inbound.insert("override_address".into(), json!(target_host));
        inbound.insert("override_port".into(), json!(target_port));
        if let Some(proxy) = tunnel.proxy.filter(|p| !p.is_empty()) {
            let target = match target(&proxy, policies) {
                Ok(Target::Pass | Target::HijackDns) => {
                    return Err(anyhow!("{}.proxy: {:?} is no proxy or group", at, proxy))
                }
                Ok(target) => target,
                Err(e) => return Err(anyhow!("{}.proxy: {}", at, e)),
            };
            let mut rule = Map::new();
            rule.insert("inbound".into(), json!([tag]));
            target.apply(&mut rule);
            listeners.rules.push(Value::Object(rule));
        }
        out.inbounds.push(Value::Object(inbound));
        listeners.kinds.push(("tunnel".to_string(), tag));
    }
    Ok(listeners)
}

/// The rule sending what comes in on listener `name` to its `proxy`, the
/// policy it names, whatever the rules say.
fn proxy_rule(f: &mut Fields, name: &str, policies: &Policies) -> Result<Option<Value>> {
    let Some(proxy) = f.string("proxy")?.filter(|p| !p.is_empty()) else {
        return Ok(None);
    };
    let target = match target(&proxy, policies) {
        Ok(Target::Pass | Target::HijackDns) => {
            return Err(anyhow!(
                "{}: {:?} is no proxy or group",
                f.at("proxy"),
                proxy
            ))
        }
        Ok(target) => target,
        Err(e) => return Err(anyhow!("{}: {}", f.at("proxy"), e)),
    };
    let mut rule = Map::new();
    rule.insert("inbound".into(), json!([name]));
    target.apply(&mut rule);
    Ok(Some(Value::Object(rule)))
}

/// Mihomo's `rule`, a listener's own sub-rules, which sail does not have:
/// an error, as `FIELDS` has it for the other listeners.
fn no_rule(f: &mut Fields) -> Result<()> {
    match f.string("rule")?.filter(|r| !r.is_empty()) {
        Some(_) => Err(anyhow!(
            "{}: sail does not implement this field yet",
            f.at("rule")
        )),
        None => Ok(()),
    }
}

/// A listener's TLS, as Mihomo's `ca.NewTLSKeyPairLoader` takes it: a
/// certificate and its key, each PEM or else a path, which stays in the
/// data directory (`home`) as Mihomo's IsSafePath keeps it. With one of
/// them alone Mihomo listens without TLS, and so does sail. Or REALITY,
/// `reality-config`, never with a certificate, as Mihomo has it. And the
/// client authentication of a certificate's TLS (`client_auth`).
fn tls(
    f: &mut Fields,
    home: Option<&std::path::Path>,
    inbound: &mut Map<String, Value>,
    warnings: &mut Vec<String>,
) -> Result<()> {
    let certificate = f.string("certificate")?.filter(|c| !c.is_empty());
    let key = f.string("private-key")?.filter(|k| !k.is_empty());
    let reality_at = f.at("reality-config");
    let reality = match f.map("reality-config")? {
        Some(r) => reality(r, warnings)?,
        None => None,
    };
    let tls = match (certificate, key, reality) {
        (Some(_), Some(_), Some(_)) => {
            return Err(anyhow!(
                "{}: with a certificate: Mihomo takes one of the two",
                reality_at
            ))
        }
        (_, _, Some(reality)) => Some((reality, false)),
        (None, None, None) => None,
        (Some(certificate), Some(key), None) => {
            let mut tls = Map::new();
            tls.insert("enabled".into(), json!(true));
            for (name, field, value) in [
                ("certificate", "certificate", certificate),
                ("private-key", "key", key),
            ] {
                let (field, value) = pem_or_path(&f.at(name), home, field, value)?;
                tls.insert(field, value);
            }
            Some((Value::Object(tls), true))
        }
        (certificate, _, None) => {
            let (has, lacks) = if certificate.is_some() {
                ("certificate", "private-key")
            } else {
                ("private-key", "certificate")
            };
            warnings.push(format!(
                "{}: without {} Mihomo listens without TLS, and so does sail; ignored",
                f.at(has),
                lacks
            ));
            None
        }
    };
    let with_certificate = matches!(tls, Some((_, true)));
    let auth = client_auth(f, home, with_certificate, warnings)?;
    if let Some((mut tls, _)) = tls {
        if let (Some(auth), Value::Object(tls)) = (auth, &mut tls) {
            tls.extend(auth);
        }
        inbound.insert("tls".into(), tls);
    }
    Ok(())
}

/// `value` as Mihomo reads a certificate or CAs: PEM, else a path, which
/// stays in the data directory (`home`); sail's `field`, or `field_path`.
fn pem_or_path(
    at: &str,
    home: Option<&std::path::Path>,
    field: &str,
    value: String,
) -> Result<(String, Value)> {
    if value.contains("-----BEGIN") {
        Ok((field.to_string(), json!(value)))
    } else if crate::common::path::stays_in(home, &value) {
        Ok((format!("{}_path", field), json!(value)))
    } else {
        Err(anyhow!(
            "{}: {:?} is not in the data directory, which a listener's certificate \
             stays in, as in Mihomo",
            at,
            value
        ))
    }
}

/// How a listener checks its clients' certificates, as Mihomo does:
/// `client-auth-type` is one of sing-box's modes but `no` (another is no
/// authentication to Mihomo, warned of here), and `client-auth-cert` the
/// CAs, PEM or a path; CAs with no mode are require-and-verify. Mihomo
/// reads the CAs only for a mode that verifies, and refuses one without
/// them, and any mode without a certificate (`with_certificate`).
fn client_auth(
    f: &mut Fields,
    home: Option<&std::path::Path>,
    with_certificate: bool,
    warnings: &mut Vec<String>,
) -> Result<Option<Map<String, Value>>> {
    let type_at = f.at("client-auth-type");
    let cas_at = f.at("client-auth-cert");
    let mut mode = match f.string("client-auth-type")?.as_deref() {
        None | Some("" | "none") => None,
        Some(mode @ ("request" | "require-any" | "verify-if-given" | "require-and-verify")) => {
            Some((mode.to_string(), &type_at))
        }
        Some(other) => {
            warnings.push(format!(
                "{}: {:?} is none of Mihomo's, which takes it as no authentication; ignored",
                type_at, other
            ));
            None
        }
    };
    let cas = f.string("client-auth-cert")?.filter(|c| !c.is_empty());
    if cas.is_some() && mode.is_none() {
        mode = Some(("require-and-verify".to_string(), &cas_at));
    }
    let Some((mode, mode_at)) = mode else {
        return Ok(None);
    };
    if !with_certificate {
        return Err(anyhow!(
            "{}: Mihomo checks clients' certificates only with a certificate of its own",
            mode_at
        ));
    }
    let mut auth = Map::new();
    auth.insert("client_authentication".into(), json!(mode));
    let verifies = matches!(mode.as_str(), "verify-if-given" | "require-and-verify");
    match cas {
        Some(cas) if verifies => {
            let (field, value) = pem_or_path(&cas_at, home, "client_certificate", cas)?;
            auth.insert(field, value);
        }
        Some(_) => warnings.push(format!(
            "{}: Mihomo reads no CAs with {}, which verifies nothing; ignored",
            cas_at, mode
        )),
        None if verifies => {
            return Err(anyhow!(
                "{}: missing: Mihomo verifies clients' certificates by it with {}",
                cas_at,
                mode
            ))
        }
        None => {}
    }
    Ok(Some(auth))
}

/// REALITY, as Mihomo's `reality-config`, in place of a certificate; none
/// with no `private-key`, as Mihomo has it. Mihomo's `max-time-difference`
/// is in microseconds, as its code multiplies it, and so it is here: a
/// profile runs as Mihomo runs it, though Xray's same field is in
/// milliseconds, and an Xray value copied gives a window 1000 times
/// shorter.
fn reality(mut r: Fields, warnings: &mut Vec<String>) -> Result<Option<Value>> {
    // What Mihomo requires of the block, private-key among them.
    for key in ["dest", "private-key", "short-id", "server-names"] {
        if !r.has(key) {
            return Err(anyhow!("{}: missing", r.at(key)));
        }
    }
    let key = r.string("private-key")?.unwrap_or_default();
    let dest_at = r.at("dest");
    let dest = r.string("dest")?.unwrap_or_default();
    let short_ids = r.strings("short-id")?;
    let names_at = r.at("server-names");
    let names = r.strings("server-names")?;
    let micros = r.int::<u64>("max-time-difference")?.unwrap_or(0);
    let proxy_at = r.at("proxy");
    let proxy = r.string("proxy")?.filter(|p| !p.is_empty());
    for key in ["limit-fallback-upload", "limit-fallback-download"] {
        let at = r.at(key);
        if let Some(mut limit) = r.map(key)? {
            let mut set = false;
            for rate in ["after-bytes", "bytes-per-sec", "burst-bytes-per-sec"] {
                set |= limit.int::<u64>(rate)?.unwrap_or(0) > 0;
            }
            limit.finish(&[], |_| false, warnings)?;
            if set {
                warnings.push(format!(
                    "{}: sail does not limit what REALITY relays to the site it imitates; \
                     ignored",
                    at
                ));
            }
        }
    }
    r.finish(&[], |_| false, warnings)?;
    if key.is_empty() {
        return Ok(None);
    }
    let (host, port) =
        split_host_port(&dest).ok_or_else(|| anyhow!("{}: {:?} names no port", dest_at, dest))?;
    // The first name is the inbound's, any others sail's extension.
    let Some((name, more)) = names.split_first() else {
        return Err(anyhow!("{}: empty: no client would be taken", names_at));
    };
    if proxy.is_some() {
        return Err(anyhow!(
            "{}: sail does not dial the site REALITY imitates through a proxy yet",
            proxy_at
        ));
    }
    let mut reality = Map::new();
    reality.insert("enabled".into(), json!(true));
    reality.insert(
        "handshake".into(),
        json!({ "server": host, "server_port": port }),
    );
    reality.insert("private_key".into(), json!(key));
    reality.insert("short_id".into(), json!(short_ids));
    if micros > 0 {
        reality.insert("max_time_difference".into(), json!(format!("{}us", micros)));
    }
    if !more.is_empty() {
        reality.insert("server_names".into(), json!(more));
    }
    Ok(Some(
        json!({ "enabled": true, "server_name": name, "reality": reality }),
    ))
}

/// A hysteria2 listener, as Mihomo's `sing_hysteria2` serves one: users a
/// map of names to passwords, its own TLS (`quic_tls`), salamander, rates,
/// and a site for those without a password.
fn hysteria2(
    f: &mut Fields,
    home: Option<&std::path::Path>,
    inbound: &mut Map<String, Value>,
    warnings: &mut Vec<String>,
) -> Result<()> {
    inbound.insert("users".into(), Value::Array(named_users(f, warnings)?));
    inbound.insert("tls".into(), quic_tls(f, home, "hysteria2", warnings)?);

    let obfs_at = f.at("obfs");
    let password_at = f.at("obfs-password");
    let password = f.string("obfs-password")?.unwrap_or_default();
    // Gecko's alone, which sail does not have.
    f.take("obfs-min-packet-size");
    f.take("obfs-max-packet-size");
    match f.string("obfs")?.filter(|o| !o.is_empty()).as_deref() {
        None => {}
        Some(_) if password.is_empty() => {
            return Err(anyhow!(
                "{}: missing, which Mihomo requires with obfs",
                password_at
            ))
        }
        Some("salamander") => {
            inbound.insert(
                "obfs".into(),
                json!({ "type": "salamander", "password": password }),
            );
        }
        Some("gecko") => {
            return Err(anyhow!(
                "{}: \"gecko\": sail does not implement it yet",
                obfs_at
            ))
        }
        Some(other) => {
            return Err(anyhow!(
                "{}: {:?}: Mihomo knows no such obfuscation",
                obfs_at,
                other
            ))
        }
    }

    for (from, to) in [("up", "up_mbps"), ("down", "down_mbps")] {
        let at = f.at(from);
        let Some(rate) = f.string(from)?.filter(|r| !r.is_empty()) else {
            continue;
        };
        match mihomo_mbps(&rate) {
            Some(mbps) => {
                inbound.insert(to.into(), json!(mbps));
            }
            None => warnings.push(format!(
                "{}: {:?}: 0 to Mihomo, which then sets no rate; nor does sail",
                at, rate
            )),
        }
    }
    if f.bool("ignore-client-bandwidth")?.unwrap_or(false) {
        inbound.insert("ignore_client_bandwidth".into(), json!(true));
    }

    let masquerade_at = f.at("masquerade");
    if let Some(site) = f.string("masquerade")?.filter(|m| !m.is_empty()) {
        let scheme = site.split_once("://").map(|(s, _)| s.to_ascii_lowercase());
        match scheme.as_deref() {
            Some("http" | "https") => {
                inbound.insert("masquerade".into(), json!(site));
            }
            Some("file") => {
                return Err(anyhow!(
                    "{}: sail does not serve a directory as the site yet",
                    masquerade_at
                ))
            }
            _ => {
                return Err(anyhow!(
                    "{}: {:?}: Mihomo takes an http, https or file URL",
                    masquerade_at,
                    site
                ))
            }
        }
    }

    let realm_at = f.at("realm-opts");
    if let Some(mut realm) = f.map("realm-opts")? {
        if realm.bool("enable")?.unwrap_or(false) {
            return Err(anyhow!(
                "{}: sail does not implement Hysteria realms",
                realm_at
            ));
        }
    }
    quic_tuning(f, warnings)?;
    // Mihomo's hysteria2 server reads no idle time of its own.
    f.take("max-idle-time");
    Ok(())
}

/// Users as a map of names to passwords, as Mihomo's hysteria2 and anytls
/// listeners take them; of two with one password the last is taken, as
/// Mihomo keys them by it.
fn named_users(f: &mut Fields, warnings: &mut Vec<String>) -> Result<Vec<Value>> {
    let users_at = f.at("users");
    let mut users: Vec<(String, String)> = Vec::new();
    if let Some(mut map) = f.map("users")? {
        for name in map.keys() {
            let password = map.string(&name)?.unwrap_or_default();
            if let Some(j) = users.iter().position(|(_, p)| *p == password) {
                warnings.push(format!(
                    "{}.{}: the password of {:?} too: Mihomo takes one of the two, and sail \
                     this one",
                    users_at, name, users[j].0
                ));
                users.remove(j);
            }
            users.push((name, password));
        }
    }
    Ok(users
        .into_iter()
        .map(|(name, password)| json!({ "name": name, "password": password }))
        .collect())
}

/// A tuic listener, as Mihomo's serves one: TUIC v5, users a map of UUIDs
/// to passwords, each user its UUID to the rules as Mihomo has it, its own
/// TLS (`quic_tls`), 0-RTT, and Mihomo's congestion control and time to
/// authenticate.
fn tuic(
    f: &mut Fields,
    home: Option<&std::path::Path>,
    inbound: &mut Map<String, Value>,
    warnings: &mut Vec<String>,
) -> Result<()> {
    let token_at = f.at("token");
    if !f.strings("token")?.is_empty() {
        return Err(anyhow!(
            "{}: TUIC v4's, which sail does not implement",
            token_at
        ));
    }
    let users_at = f.at("users");
    let mut users: Vec<(String, String)> = Vec::new();
    if let Some(mut map) = f.map("users")? {
        for key in map.keys() {
            let password = map.string(&key)?.unwrap_or_default();
            let uuid = match uuid::Uuid::parse_str(&key) {
                Ok(uuid) => uuid.to_string(),
                Err(_) => {
                    warnings.push(format!(
                        "{}.{}: not a UUID: Mihomo takes it as the nil UUID, and so does \
                         sail: the user is 00000000-0000-0000-0000-000000000000 with its password",
                        users_at, key
                    ));
                    uuid::Uuid::nil().to_string()
                }
            };
            if let Some(j) = users.iter().position(|(u, _)| *u == uuid) {
                warnings.push(format!(
                    "{}.{}: {} again: Mihomo takes one of the two, and sail this one",
                    users_at, key, uuid
                ));
                users.remove(j);
            }
            users.push((uuid, password));
        }
    }
    let users: Vec<Value> = users
        .into_iter()
        .map(|(uuid, password)| json!({ "name": uuid, "uuid": uuid, "password": password }))
        .collect();
    inbound.insert("users".into(), Value::Array(users));
    inbound.insert("tls".into(), quic_tls(f, home, "tuic", warnings)?);

    // Mihomo's quic-go controller where it names none it knows: cubic.
    let cc_at = f.at("congestion-controller");
    let cc = match f.string("congestion-controller")?.as_deref() {
        None | Some("" | "cubic") => "cubic",
        Some("new_reno") => "new_reno",
        Some("bbr" | "bbr_meta_v1" | "bbr_meta_v2") => "bbr",
        Some(other) => {
            warnings.push(format!(
                "{}: {:?} is none of Mihomo's, which then takes cubic, as sail does",
                cc_at, other
            ));
            "cubic"
        }
    };
    inbound.insert("congestion_control".into(), json!(cc));
    let timeout = f
        .int::<u64>("authentication-timeout")?
        .filter(|t| *t > 0)
        .unwrap_or(1000);
    inbound.insert("auth_timeout".into(), json!(format!("{}ms", timeout)));
    // Mihomo's server always takes 0-RTT.
    inbound.insert("zero_rtt_handshake".into(), json!(true));
    for key in ["max-idle-time", "max-udp-relay-packet-size"] {
        let at = f.at(key);
        if f.int::<i64>(key)?.unwrap_or(0) != 0 {
            warnings.push(format!(
                "{}: sail does not tune its QUIC listeners so; ignored",
                at
            ));
        }
    }
    quic_tuning(f, warnings)
}

/// A rate as Mihomo's `StringToBps` reads it, in Mbps: a bare number is
/// Mbps, else a number, maybe K, M, G or T, and bps (bits) or Bps (bytes);
/// anything else is none. Some(0) is no rate.
fn mihomo_mbps(rate: &str) -> Option<u64> {
    let bits_per_sec = match rate.parse::<u64>() {
        Ok(mbps) => mbps.checked_mul(1_000_000)?,
        Err(_) => {
            let number_end = rate.find(|c: char| !c.is_ascii_digit())?;
            let (number, rest) = rate.split_at(number_end);
            let number: u64 = number.parse().ok()?;
            let rest = rest.trim_start();
            let (scale, unit) = match rest.chars().next()? {
                'K' => (1_000, &rest[1..]),
                'M' => (1_000_000, &rest[1..]),
                'G' => (1_000_000_000, &rest[1..]),
                'T' => (1_000_000_000_000, &rest[1..]),
                _ => (1, rest),
            };
            let bytes_per_sec = match unit {
                // Mihomo keeps a rate in bytes, a bit rate's in eighths.
                "bps" => number.checked_mul(scale)? / 8,
                "Bps" => number.checked_mul(scale)?,
                _ => return None,
            };
            bytes_per_sec.checked_mul(8)?
        }
    };
    Some(bits_per_sec.div_ceil(1_000_000)).filter(|m| *m > 0)
}

/// A QUIC listener's TLS, as Mihomo's: a certificate and its key, PEM or
/// a path in the data directory, or without both a self-signed one made
/// at start (`self_signed`), as Mihomo makes one up; `alpn`, h3 unless
/// given; and client authentication.
fn quic_tls(
    f: &mut Fields,
    home: Option<&std::path::Path>,
    protocol: &str,
    warnings: &mut Vec<String>,
) -> Result<Value> {
    let certificate = f.string("certificate")?.filter(|c| !c.is_empty());
    let key = f.string("private-key")?.filter(|k| !k.is_empty());
    let mut tls = Map::new();
    tls.insert("enabled".into(), json!(true));
    match (certificate, key) {
        (Some(certificate), Some(key)) => {
            for (name, field, value) in [
                ("certificate", "certificate", certificate),
                ("private-key", "key", key),
            ] {
                let (field, value) = pem_or_path(&f.at(name), home, field, value)?;
                tls.insert(field, value);
            }
        }
        (None, None) => {
            tls.insert("self_signed".into(), json!(true));
        }
        (certificate, _) => {
            let (has, lacks) = if certificate.is_some() {
                ("certificate", "private-key")
            } else {
                ("private-key", "certificate")
            };
            return Err(anyhow!(
                "{}: without {}: Mihomo refuses a {} listener with one alone",
                f.at(has),
                lacks,
                protocol
            ));
        }
    }
    let alpn = f.strings("alpn")?;
    if !alpn.is_empty() {
        tls.insert("alpn".into(), json!(alpn));
    }
    if let Some(auth) = client_auth(f, home, true, warnings)? {
        tls.extend(auth);
    }
    Ok(Value::Object(tls))
}

/// What Mihomo tunes its QUIC listeners by and sail does not, warned of;
/// and sing-mux, which Mihomo serves on them and sail does not, as no
/// client asks for it over QUIC.
fn quic_tuning(f: &mut Fields, warnings: &mut Vec<String>) -> Result<()> {
    for key in [
        "cwnd",
        "bbr-profile",
        "udp-mtu",
        "initial-stream-receive-window",
        "max-stream-receive-window",
        "initial-connection-receive-window",
        "max-connection-receive-window",
    ] {
        let at = f.at(key);
        let set = match f.take(key) {
            None => false,
            Some(n) => n.as_string().is_some_and(|v| !v.is_empty() && v != "0"),
        };
        if set {
            warnings.push(format!(
                "{}: sail does not tune its QUIC listeners so; ignored",
                at
            ));
        }
    }
    let mux_at = f.at("mux-option");
    if f.take("mux-option").is_some() {
        warnings.push(format!(
            "{}: sail serves no sing-mux over QUIC, which no client asks for; ignored",
            mux_at
        ));
    }
    Ok(())
}

/// A proxy listener's users, by their secret, a trojan user's password or
/// a vless or vmess user's UUID, its `username` the user's name, and a
/// vless user's `flow`; of two with one secret the last is taken, as
/// Mihomo keys them by it.
fn users(f: &mut Fields, protocol: &str, warnings: &mut Vec<String>) -> Result<Vec<Value>> {
    let secret = if protocol == "trojan" {
        "password"
    } else {
        "uuid"
    };
    let at = f.at("users");
    let mut users: Vec<(String, Value)> = Vec::new();
    for (j, item) in f.list("users")?.into_iter().enumerate() {
        let mut u = Fields::of(item, &format!("{}[{}]", at, j))?;
        let value = u
            .string(secret)?
            .ok_or_else(|| anyhow!("{}: missing", u.at(secret)))?;
        let mut user = Map::new();
        if let Some(name) = u.string("username")?.filter(|n| !n.is_empty()) {
            user.insert("name".into(), json!(name));
        }
        user.insert(secret.into(), json!(value));
        if protocol == "vless" {
            if let Some(flow) = u.string("flow")?.filter(|f| !f.is_empty()) {
                user.insert("flow".into(), json!(flow));
            }
        }
        // Mihomo's sing-vmess serves AEAD headers to every user, and the
        // legacy ones too to a user with an alterId.
        let alter_at = u.at("alterId");
        if protocol == "vmess" && u.int::<i64>("alterId")?.unwrap_or(0) != 0 {
            warnings.push(format!(
                "{}: a client with an alterId above 0 cannot connect: sail serves AEAD \
                 headers alone, as with 0",
                alter_at
            ));
        }
        if let Some(k) = users.iter().position(|(v, _)| *v == value) {
            users.remove(k);
            warnings.push(format!(
                "{}: the {} of a user before it: Mihomo takes this one alone, \
                 and so does sail",
                u.at(secret),
                secret
            ));
        }
        u.finish(&[], |_| false, warnings)?;
        users.push((value, Value::Object(user)));
    }
    Ok(users.into_iter().map(|(_, user)| user).collect())
}

/// What a proxy listener carries its protocol in: a websocket at
/// `ws-path`, taking early data as Mihomo's does, or gRPC under
/// `grpc-service-name`; and sing-mux, which Mihomo's serve whatever they
/// say, `mux-option` tuning it.
fn carriers(
    f: &mut Fields,
    inbound: &mut Map<String, Value>,
    warnings: &mut Vec<String>,
) -> Result<()> {
    let ws = f.string("ws-path")?.filter(|p| !p.is_empty());
    let grpc_at = f.at("grpc-service-name");
    let grpc = f.string("grpc-service-name")?.filter(|s| !s.is_empty());
    match (ws, grpc) {
        (Some(_), Some(_)) => {
            return Err(anyhow!(
                "{}: with ws-path: sail does not serve two transports on one port",
                grpc_at
            ))
        }
        (Some(path), None) => {
            inbound.insert(
                "transport".into(),
                json!({ "type": "ws", "path": path,
                    "early_data_header_name": "Sec-WebSocket-Protocol",
                    "max_early_data": WS_EARLY_DATA }),
            );
        }
        (None, Some(name)) => {
            inbound.insert(
                "transport".into(),
                json!({ "type": "grpc", "service_name": name }),
            );
        }
        (None, None) => {}
    }
    let mut multiplex = Map::new();
    multiplex.insert("enabled".into(), json!(true));
    if let Some(mut m) = f.map("mux-option")? {
        if m.bool("padding")?.unwrap_or(false) {
            multiplex.insert("padding".into(), json!(true));
        }
        if let Some(mut b) = m.map("brutal")? {
            // A rate missing, or one Mihomo cannot read, is 0 there, and
            // sing-mux takes the lower of the two ends' rates: brutal does
            // nothing then, and is left off here.
            let enabled = b.bool("enabled")?.unwrap_or(false);
            let mut rates = Vec::new();
            for key in ["up", "down"] {
                let at = b.at(key);
                let rate = b.string(key)?;
                if !enabled {
                    continue;
                }
                match rate.as_deref().map(super::proxy::mbps) {
                    Some(Ok(mbps)) => rates.push(mbps),
                    Some(Err(e)) => warnings.push(format!(
                        "{}: {}: 0 to Mihomo, so brutal does nothing; left off",
                        at, e
                    )),
                    None => warnings.push(format!(
                        "{}: missing: 0 to Mihomo, so brutal does nothing; left off",
                        at
                    )),
                }
            }
            if let [up, down] = rates[..] {
                multiplex.insert(
                    "brutal".into(),
                    json!({ "enabled": true, "up_mbps": up, "down_mbps": down }),
                );
            }
            b.finish(&[], |_| false, warnings)?;
        }
        m.finish(&[], |_| false, warnings)?;
    }
    inbound.insert("multiplex".into(), Value::Object(multiplex));
    Ok(())
}

/// A tunnel, as Mihomo writes one: a map, or `tcp/udp,address,target`
/// with a proxy after it.
struct Tunnel {
    network: Vec<String>,
    address: String,
    target: String,
    proxy: Option<String>,
}

fn tunnel(node: super::node::Node, at: &str, warnings: &mut Vec<String>) -> Result<Tunnel> {
    let tunnel = match node.as_string() {
        Some(line) => {
            let parts: Vec<&str> = line.split(',').map(str::trim).collect();
            if !(3..=4).contains(&parts.len()) {
                return Err(anyhow!(
                    "{}: {:?} is not network,address,target and a proxy",
                    at,
                    line
                ));
            }
            Tunnel {
                network: parts[0].split('/').map(str::to_string).collect(),
                address: parts[1].to_string(),
                target: parts[2].to_string(),
                proxy: parts.get(3).map(|p| p.to_string()),
            }
        }
        None => {
            let mut f = Fields::typed(node, at)?;
            let tunnel = Tunnel {
                network: f.strings("network")?,
                address: f
                    .string("address")?
                    .ok_or_else(|| anyhow!("{}: missing", f.at("address")))?,
                target: f
                    .string("target")?
                    .ok_or_else(|| anyhow!("{}: missing", f.at("target")))?,
                proxy: f.string("proxy")?,
            };
            f.finish(&[], |_| false, warnings)?;
            tunnel
        }
    };
    if tunnel.network.is_empty() {
        return Err(anyhow!("{}: no network", at));
    }
    if let Some(n) = tunnel
        .network
        .iter()
        .find(|n| !matches!(n.as_str(), "tcp" | "udp"))
    {
        return Err(anyhow!("{}: {:?} is neither tcp nor udp", at, n));
    }
    Ok(tunnel)
}

/// `host:port`, `[v6]:port` or `:port`, split.
fn split_host_port(address: &str) -> Option<(&str, u16)> {
    let (host, port) = address.rsplit_once(':')?;
    let port = port.parse().ok()?;
    Some((host.trim_start_matches('[').trim_end_matches(']'), port))
}

/// The rule `lan-allowed-ips` and `lan-disallowed-ips` make, if they keep
/// anyone out.
pub fn lan_rule(out: &Lowered) -> Option<Value> {
    if out.lan_inbounds.is_empty() {
        return None;
    }
    let mut out_of = Vec::new();
    match &out.lan_allowed {
        None => {}
        // No one allowed: every client.
        Some(allowed) if allowed.is_empty() => {
            out_of.push(json!({ "source_ip_cidr": ["0.0.0.0/0", "::/0"] }))
        }
        Some(allowed) => out_of.push(json!({ "source_ip_cidr": allowed, "invert": true })),
    }
    if !out.lan_disallowed.is_empty() {
        out_of.push(json!({ "source_ip_cidr": out.lan_disallowed }));
    }
    if out_of.is_empty() {
        return None;
    }
    Some(json!({
        "type": "logical",
        "mode": "and",
        "rules": [
            { "inbound": out.lan_inbounds },
            { "type": "logical", "mode": "or", "rules": out_of },
        ],
        "action": "reject",
    }))
}
