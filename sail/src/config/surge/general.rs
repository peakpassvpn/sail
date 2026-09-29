//! `[General]`: the log, the proxy services Surge listens with and who may
//! use them, how groups test their members, what UDP to a proxy without it
//! does, and DNS. Its keys are case-insensitive.

use std::net::IpAddr;

use anyhow::{anyhow, Result};
use serde_json::{json, Value};

use super::params::{Params, Tier};
use super::text::{self, Line};
use super::Lowered;

use Tier::*;

/// The keys sail does not implement, or not yet, and those that mean
/// nothing where it runs.
const KEYS: &[(&str, Tier)] = &[
    // Surge's TUN, its VIF, which sail's host sets up, as it does the
    // system's proxy settings.
    (
        "tun-excluded-routes",
        Ignored(": sail's TUN is its host's, which takes the routes to leave out"),
    ),
    (
        "tun-included-routes",
        Ignored(": sail's TUN is its host's, which takes the routes to take"),
    ),
    (
        "bypass-tun",
        Ignored(": sail's TUN is its host's, which takes the routes to leave out"),
    ),
    ("icmp-forwarding", Silent),
    ("ipv6-vif", Silent),
    ("vif-mode", Silent),
    ("skip-proxy", Silent),
    ("exclude-simple-hostnames", Silent),
    ("set-system-socks-proxy", Silent),
    ("compatibility-mode", Silent),
    ("include-all-networks", Silent),
    ("include-local-networks", Silent),
    ("include-apns", Silent),
    ("include-cellular-services", Silent),
    ("hide-vpn-icon", Silent),
    ("auto-suspend", Silent),
    ("enhanced-mode-by-rule", Silent),
    // The device's networks.
    ("wifi-assist", Silent),
    ("all-hybrid", Silent),
    ("subnet-exp-wifi-always-match", Silent),
    ("use-default-policy-if-wifi-not-primary", Silent),
    ("network-framework", Silent),
    // Surge's own interface, APIs and diagnostics.
    ("http-api", Ignored(": sail has no Surge HTTP API")),
    ("http-api-tls", Silent),
    ("http-api-web-dashboard", Silent),
    (
        "external-controller-access",
        Ignored(": sail has no Surge controller"),
    ),
    ("show-error-page", Silent),
    ("show-error-page-for-reject", Silent),
    ("show-error-page-for-reject-skip-proxy", Silent),
    ("debug-cpu-usage", Silent),
    ("debug-memory-usage", Silent),
    ("replica", Silent),
    ("hide-crashlytics-request", Silent),
    ("collapse-policy-group-items", Silent),
    ("tls-provider", Silent),
    ("udp-priority", Silent),
    ("proxy-test-udp", Silent),
    ("gateway-restricted-to-lan", Silent),
    // Where the GeoIP database comes from; sail downloads its own.
    ("geoip-maxmind-url", Silent),
    ("disable-geoip-db-auto-update", Silent),
    // HTTP processing, which sail does not do.
    (
        "force-http-engine-hosts",
        Ignored(": sail does not process HTTP"),
    ),
    ("always-raw-tcp-hosts", Silent),
    ("always-raw-tcp-keywords", Silent),
];

/// What Surge tests proxies with, by default.
const TEST_URL: &str = "http://bing.com/";
const TEST_TIMEOUT: u64 = 5;

/// What UDP to a policy without it does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpFallback {
    Reject,
    Direct,
}

/// What other sections need of `[General]`, and the rules it adds.
pub struct General {
    pub udp_fallback: UdpFallback,
    /// `proxy-test-url`: what groups test their members with.
    pub test_url: String,
    /// `test-timeout`, in seconds.
    pub test_timeout: u64,
    /// The listeners, each its tag and port, which `IN-PORT` matches.
    pub listeners: Vec<(String, u16)>,
    /// The rules before every other: who may use the listeners, and the
    /// DNS queries answered here.
    rules: Vec<Value>,
    /// What DNS `[Host]` is lowered with.
    pub dns: Option<super::dns::Dns>,
}

impl General {
    /// Puts its rules before every other.
    pub fn apply(self, out: &mut Lowered) {
        out.rules.splice(0..0, self.rules);
    }
}

/// The section's lines as keys, lowercase.
pub fn keys(section: &str, lines: Vec<Line>, warnings: &mut Vec<String>) -> Params {
    let mut params = Params::new(format!("[{}]", section));
    for line in lines {
        match text::key_value(&line.text) {
            Some((key, value)) => params.insert(
                &key.to_ascii_lowercase(),
                value,
                Some(format!("[{}] {}", section, line.loc)),
            ),
            None => warnings.push(format!(
                "[{}] {}: {:?} is not key = value; ignored",
                section, line.loc, line.text
            )),
        }
    }
    params
}

pub fn lower(lines: Vec<Line>, out: &mut Lowered, warnings: &mut Vec<String>) -> Result<General> {
    let mut p = keys("General", lines, warnings);
    log(&mut p, out, warnings);
    let mut general = General {
        udp_fallback: UdpFallback::Reject,
        test_url: TEST_URL.to_string(),
        test_timeout: TEST_TIMEOUT,
        listeners: Vec::new(),
        rules: Vec::new(),
        dns: None,
    };
    listeners(&mut p, &mut general, out)?;
    if let Some(url) = p.string("proxy-test-url") {
        general.test_url = url;
    }
    p.take_at("internet-test-url");
    if let Some(seconds) = p.num::<f64>("test-timeout")? {
        general.test_timeout = (seconds.ceil() as u64).max(1);
    }
    if let Some((value, at)) = p.take_at("udp-policy-not-supported-behaviour") {
        general.udp_fallback = match value.to_ascii_uppercase().as_str() {
            "REJECT" => UdpFallback::Reject,
            "DIRECT" => UdpFallback::Direct,
            _ => return Err(anyhow!("{}: {:?} is neither REJECT nor DIRECT", at, value)),
        };
    }
    if let Some((value, at)) = p.take_at("block-quic") {
        match value.to_ascii_lowercase().as_str() {
            "per-policy" | "always-allow" => {}
            "all-proxy" | "all" => warnings.push(format!(
                "{}: sail does not block QUIC; ignored, and QUIC goes where the rules say",
                at
            )),
            _ => warnings.push(format!(
                "{}: {:?} is none of per-policy, all-proxy, all and always-allow; per-policy, \
                 as by Surge",
                at, value
            )),
        }
    }
    let (rules, dns) = super::dns::lower(&mut p, out)?;
    general.rules.extend(rules);
    general.dns = Some(dns);
    p.finish(KEYS, "key", warnings)?;
    Ok(general)
}

fn log(p: &mut Params, out: &mut Lowered, warnings: &mut Vec<String>) {
    let Some((level, at)) = p.take_at("loglevel") else {
        return;
    };
    // Surge's `notify`, its default, tells what happens without each
    // request, as sail's `info` does more of.
    let level = match level.to_ascii_lowercase().as_str() {
        "verbose" => "debug",
        "info" | "notify" => "info",
        "warning" => "warn",
        _ => {
            warnings.push(format!(
                "{}: {:?} is none of verbose, info, notify and warning; notify, as by Surge",
                at, level
            ));
            "info"
        }
    };
    out.log.insert("level".into(), json!(level));
}

/// The HTTP and SOCKS5 proxy services: Surge Mac's `http-listen` and
/// `socks5-listen` (or the older `interface` and `port`, `socks-interface`
/// and `socks-port`); else Surge iOS's, on the loopback address, but on
/// every address with `allow-wifi-access`. With `proxy-restricted-to-lan`,
/// as by default, only clients of private addresses may use them.
fn listeners(p: &mut Params, general: &mut General, out: &mut Lowered) -> Result<()> {
    let mut http = Vec::new();
    let mut socks = Vec::new();
    for (key, list) in [("http-listen", &mut http), ("socks5-listen", &mut socks)] {
        if let Some((value, at)) = p.take_at(key) {
            for entry in value.split(',').map(str::trim).filter(|e| !e.is_empty()) {
                let default = if key == "http-listen" { 6152 } else { 6153 };
                let l = listen(entry, default).map_err(|e| anyhow!("{}: {}", at, e))?;
                if key == "socks5-listen" && l.credentials.is_some() {
                    return Err(anyhow!("{}: Surge's SOCKS5 service takes no password", at));
                }
                list.push(l);
            }
        }
    }
    for (address, port, list) in [
        ("interface", "port", &mut http),
        ("socks-interface", "socks-port", &mut socks),
    ] {
        let address = p.take_at(address);
        let port = p.take_at(port);
        if !list.is_empty() {
            continue;
        }
        if let Some((port, at)) = port {
            let port: u16 = port
                .parse()
                .map_err(|_| anyhow!("{}: {:?} is not a port", at, port))?;
            let ip = match address {
                Some((ip, at)) => ip
                    .parse::<IpAddr>()
                    .map_err(|_| anyhow!("{}: {:?} is not an address", at, ip))?,
                None => IpAddr::from([127, 0, 0, 1]),
            };
            list.push(Listen {
                ip,
                port,
                credentials: None,
            });
        }
    }
    let wifi = p.bool("allow-wifi-access")?.unwrap_or(false);
    let hotspot = p.bool("allow-hotspot-access")?.unwrap_or(false);
    let http_port = p.num::<u16>("wifi-access-http-port")?;
    let socks_port = p.num::<u16>("wifi-access-socks5-port")?;
    let auth = p.take_at("wifi-access-http-auth");
    if http.is_empty()
        && socks.is_empty()
        && (wifi || hotspot || http_port.or(socks_port).is_some())
    {
        let ip: IpAddr = if wifi || hotspot {
            IpAddr::from([0u16; 8])
        } else {
            IpAddr::from([127, 0, 0, 1])
        };
        let credentials = match auth {
            Some((auth, at)) => Some(credentials(&auth).map_err(|e| anyhow!("{}: {}", at, e))?),
            None => None,
        };
        http.push(Listen {
            ip,
            port: http_port.unwrap_or(6152),
            credentials,
        });
        socks.push(Listen {
            ip,
            port: socks_port.unwrap_or(6153),
            credentials: None,
        });
    }
    let restricted = p.bool("proxy-restricted-to-lan")?.unwrap_or(true);
    let mut open = Vec::new();
    for (kind, key, list) in [
        ("http", "http-listen", http),
        ("socks", "socks5-listen", socks),
    ] {
        let many = list.len() > 1;
        for (i, l) in list.into_iter().enumerate() {
            let tag = if many {
                format!("{}#{}", key, i + 1)
            } else {
                key.to_string()
            };
            let mut inbound = json!({
                "type": kind,
                "tag": tag,
                "listen": l.ip.to_string(),
                "listen_port": l.port,
            });
            if let Some((username, password)) = l.credentials {
                inbound["users"] = json!([{ "username": username, "password": password }]);
            }
            if !l.ip.is_loopback() {
                open.push(tag.clone());
            }
            general.listeners.push((tag, l.port));
            out.inbounds.push(inbound);
        }
    }
    if restricted && !open.is_empty() {
        general.rules.push(json!({
            "type": "logical",
            "mode": "and",
            "rules": [
                { "inbound": open },
                { "source_ip_is_private": true, "invert": true },
            ],
            "action": "reject",
        }));
    }
    Ok(())
}

struct Listen {
    ip: IpAddr,
    port: u16,
    credentials: Option<(String, String)>,
}

/// `[user:password@]address[:port]`, the address an IP, in brackets for
/// IPv6 with a port.
fn listen(entry: &str, default_port: u16) -> Result<Listen> {
    let (credentials, address) = match entry.rsplit_once('@') {
        Some((c, a)) => (Some(credentials(c)?), a),
        None => (None, entry),
    };
    let (ip, port) = if let Some(rest) = address.strip_prefix('[') {
        let (ip, rest) = rest
            .split_once(']')
            .ok_or_else(|| anyhow!("{:?}: a '[' without its ']'", entry))?;
        let port = match rest.strip_prefix(':') {
            Some(p) => Some(p),
            None if rest.is_empty() => None,
            None => return Err(anyhow!("{:?} is not address:port", entry)),
        };
        (ip, port)
    } else if address.matches(':').count() == 1 {
        let (ip, port) = address.split_once(':').expect("a colon");
        (ip, Some(port))
    } else {
        (address, None)
    };
    let ip: IpAddr = ip
        .parse()
        .map_err(|_| anyhow!("{:?} is not an IP address", ip))?;
    let port = match port {
        Some(p) => p.parse().map_err(|_| anyhow!("{:?} is not a port", p))?,
        None => default_port,
    };
    Ok(Listen {
        ip,
        port,
        credentials,
    })
}

/// `user:password`. Surge writes a password alone too, for any user, which
/// sail's HTTP inbound cannot take.
fn credentials(s: &str) -> Result<(String, String)> {
    match s.split_once(':') {
        Some((user, password)) => Ok((user.to_string(), password.to_string())),
        None => Err(anyhow!(
            "a password without a user: sail's HTTP service takes user:password"
        )),
    }
}
