//! Every field Surge's manual lists (`fields.json`, from
//! `tools/surge-fields/extract.py`), and how sail's Surge front-end takes
//! each: measured by reading a profile of that field alone, and written to
//! `fields.tiers.json` and the support tables of docs/compat.
//! `SAIL_REGISTRY_UPDATE=1` writes them; otherwise what is written must be
//! what is measured.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde_json::{json, Map, Value};

use super::params::SILENT;

const FIELDS: &str = include_str!("fields.json");

/// How sail takes a field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Tier {
    /// Read, or refused for its value alone.
    Supported,
    /// Passed over without a word: it means nothing where sail runs.
    Silent,
    /// Dropped with a warning.
    Warned,
    /// Refused as not implemented.
    Error,
    /// Warned of as a field Surge does not take: sail lists it nowhere.
    Unknown,
}

impl Tier {
    fn name(self) -> &'static str {
        match self {
            Tier::Supported => "supported",
            Tier::Silent => "silent",
            Tier::Warned => "warned",
            Tier::Error => "error",
            Tier::Unknown => "unknown",
        }
    }
}

/// What sail says when it does not implement something, or drops it.
const NOT_IMPLEMENTED: &[&str] = &[
    "does not implement",
    "sail has no ",
    "not supported",
    "sail does not ",
    "sail cannot ",
    "sail serves no",
    "sail tests ",
    "; ignored",
];

fn not_implemented(message: &str) -> bool {
    NOT_IMPLEMENTED.iter().any(|m| message.contains(m))
}

/// What sail says of a key it lists nowhere.
fn unknown(message: &str) -> bool {
    message.contains("Surge takes") && message.contains("not a ")
}

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const KEY: &str = "YNXtAzepDqRv9H52osJVDQnznT5AL11eVK3Es/ZDvkE=";
const PEER_KEY: &str = "Z1XXLsKYkYxuiYjJIkRvtIKFepCYHTgON+GwPq7SOV4=";

/// A value of `key`, of the kind `kind`, where the manual gives none.
fn sample(key: &str, kind: &str) -> String {
    let value = match key {
        "dns-server" => "1.1.1.1",
        "encrypted-dns-server" => "https://1.1.1.1/dns-query",
        "hijack-dns" => "*:53",
        "always-real-ip"
        | "skip-proxy"
        | "force-http-engine-hosts"
        | "always-raw-tcp-hosts"
        | "sni"
        | "shadow-tls-sni"
        | "server-cert-verify-name"
        | "obfs-host" => "a.example",
        "always-raw-tcp-keywords" => "a",
        "tun-excluded-routes" | "tun-included-routes" => "10.0.0.0/8",
        "http-listen" => "127.0.0.1:6152",
        "socks5-listen" => "127.0.0.1:6153",
        "external-controller-access" | "http-api" => "k@127.0.0.1:6170",
        "proxy-test-url" | "internet-test-url" | "test-url" => "http://a.example/",
        "geoip-maxmind-url" => "https://a.example/country.mmdb",
        "proxy-test-udp" | "test-udp" => "a.example@1.1.1.1",
        "wifi-access-http-auth" => "u:p",
        "compatibility-mode" => "1",
        "interface" => "en0",
        "underlying-proxy" | "default" | "cellular" => "DIRECT",
        "username" => "u",
        "uuid" => UUID,
        "encrypt-method" => "aes-128-gcm",
        "alpn" => "h2",
        "client-cert" => "c",
        "server-cert-fingerprint-sha256" => {
            "0000000000000000000000000000000000000000000000000000000000000000"
        }
        "ws-path" | "obfs-uri" => "/",
        "ws-headers" | "headers" => "X-A:1",
        "port-hopping" => "1000-2000",
        "download-bandwidth" | "port-hopping-interval" | "idle-timeout" | "max-streams" => "10",
        "tos" => "16",
        "version" => "4",
        "local-port" => "1080",
        "exec" => "/bin/true",
        "addresses" => "1.2.3.4",
        "section-name" => "S",
        "interval" | "update-interval" => "600",
        "tolerance" => "100",
        "timeout" => "5",
        "policy-priority" => "\"P:2\"",
        "policy-regex-filter" => ".",
        "policy-path" => "https://a.example/policies.list",
        "include-other-group" => "H",
        "external-policy-modifier" => "\"skip-cert-verify=true\"",
        "external-policy-name-prefix" => "a-",
        "icon-url" => "https://a.example/i.png",
        "mtu" => "1280",
        "self-ip" => "10.0.0.2",
        "self-ip-v6" => "fd00::2",
        "private-key" => KEY,
        "public-key" | "preshared-key" => PEER_KEY,
        "allowed-ips" => "0.0.0.0/0",
        "endpoint" => "a.example:51820",
        "keepalive" => "25",
        "client-id" => "1/2/3",
        "base64" => "AAAA",
        "notification-text" => "x",
        "notification-interval" | "number" => "600",
        "always-capture" => "s",
        _ => match kind {
            "bool" => "true",
            "number" => "1",
            _ => "x",
        },
    };
    value.to_string()
}

/// What each proxy type takes besides its server and port, as the manual's
/// examples write it.
fn proxy_line(kind: &str) -> String {
    let (server, rest) = match kind {
        "direct" | "reject" | "reject-drop" | "reject-no-drop" | "reject-tinygif" => (false, ""),
        "ss" => (true, "encrypt-method=aes-128-gcm, password=p"),
        "vmess" => (true, "username=b831381d-6324-4d53-ad4f-8cda48b30811"),
        "trojan" | "hysteria2" | "anytls" => (true, "password=p"),
        "tuic-v5" => (
            true,
            "uuid=b831381d-6324-4d53-ad4f-8cda48b30811, password=p",
        ),
        "tuic" => (true, "token=p"),
        "snell" => (true, "psk=p, version=4"),
        "ssh" | "masque" | "trust-tunnel" => (true, "username=u, password=p"),
        "wireguard" | "tailscale" => (false, "section-name=S"),
        "external" => (false, "exec=/bin/true, local-port=1080"),
        _ => (true, ""),
    };
    let mut line = format!("P = {}", kind);
    if server {
        line.push_str(", a.example, 443");
    }
    if !rest.is_empty() {
        line.push_str(", ");
        line.push_str(rest);
    }
    line
}

/// The value of a rule of `kind`, as Surge writes one.
fn rule_value(kind: &str) -> &'static str {
    match kind {
        "DOMAIN" | "DOMAIN-SUFFIX" => "a.example",
        "DOMAIN-KEYWORD" => "a",
        "DOMAIN-WILDCARD" => "*.a.example",
        "DOMAIN-SET" => "https://a.example/domains.txt",
        "RULE-SET" => "https://a.example/rules.list",
        "IP-CIDR" => "10.0.0.0/8",
        "IP-CIDR6" => "fd00::/8",
        "GEOIP" => "CN",
        "IP-ASN" => "13335",
        "USER-AGENT" => "a*",
        "URL-REGEX" => "^http://a\\.example/",
        "PROCESS-NAME" | "DEVICE-NAME" | "SCRIPT" => "a",
        "DEST-PORT" => "443",
        "SRC-PORT" => "1000",
        "IN-PORT" => "6152",
        "SRC-IP" => "10.0.0.1",
        "MAC-ADDRESS" => "00:11:22:33:44:55",
        "PROTOCOL" => "HTTP",
        "HOSTNAME-TYPE" => "IPv4",
        "SUBNET" => "SSID:a",
        "CELLULAR-RADIO" => "LTE",
        "CELLULAR-CARRIER" => "310260",
        "AND" | "OR" => "((DOMAIN,a.example),(DEST-PORT,443))",
        "NOT" => "((DOMAIN,a.example))",
        _ => "a",
    }
}

/// A line of each section read as a whole.
fn section_lines(name: &str) -> &'static str {
    match name {
        "Host" => "a.example = 1.2.3.4",
        "Ruleset" => "DOMAIN,a.example",
        "Tailscale" => "auth-key = k",
        "MITM" => "hostname = a.example",
        "URL Rewrite" => "^http://a\\.example http://b.example 302",
        "Header Rewrite" => "http-request ^http://a\\.example header-add X 1",
        "Body Rewrite" => "http-response ^http://a\\.example a b",
        "Map Local" => "^http://a\\.example data-type=text data=\"x\"",
        "Script" => "s = type=cron, cronexp=\"0 * * * *\", script-path=s.js",
        "Panel" => "p = title=x, content=y",
        "Snell Server" => "interface = 0.0.0.0\nport = 6160\npsk = p",
        "MTProto" => {
            "interface = 127.0.0.1\nport = 8443\nsecret = 00000000000000000000000000000000"
        }
        "Ponte" => "server-proxy-name = DIRECT",
        "DHCP" => "max-lease-time = 3600",
        "Port Forwarding" => "0.0.0.0:6841 a.example:80",
        "Replica" => "hide-apple-request = true",
        "Testing" => "download-url = http://a.example/",
        _ => "a = b",
    }
}

/// A profile: its sections, each a name and its lines, in order.
#[derive(Default, Clone)]
struct Profile {
    sections: Vec<(String, Vec<String>)>,
}

impl Profile {
    fn add(&mut self, section: &str, line: impl Into<String>) {
        let line = line.into();
        match self.sections.iter_mut().find(|(s, _)| s == section) {
            Some((_, lines)) => lines.push(line),
            None => self.sections.push((section.to_string(), vec![line])),
        }
    }

    fn text(&self) -> String {
        let mut out = String::new();
        for (name, lines) in &self.sections {
            out.push_str(&format!("[{}]\n", name));
            for line in lines {
                out.push_str(line);
                out.push('\n');
            }
        }
        out
    }
}

/// The WireGuard section every WireGuard policy is measured with, but
/// `key`, which is `value` instead, and the peer's field `peer`.
fn wireguard(p: &mut Profile, key: Option<(&str, &str)>, peer: Option<(&str, &str)>) {
    let mut keys = vec![("private-key", KEY), ("self-ip", "10.0.0.2")];
    if let Some((k, v)) = key {
        keys.retain(|(o, _)| *o != k);
        keys.push((k, v));
    }
    for (k, v) in keys {
        p.add("WireGuard S", format!("{} = {}", k, v));
    }
    let mut fields = vec![
        ("public-key", PEER_KEY),
        ("allowed-ips", "\"0.0.0.0/0\""),
        ("endpoint", "a.example:51820"),
    ];
    if let Some((k, v)) = peer {
        fields.retain(|(o, _)| *o != k);
        fields.push((k, v));
    }
    let fields: Vec<String> = fields
        .iter()
        .map(|(k, v)| format!("{} = {}", k, v))
        .collect();
    p.add("WireGuard S", format!("peer = ({})", fields.join(", ")));
}

/// The profile a field is measured in, without it and with it, and the
/// names a warning of it holds.
fn profiles(field: &str, json: &str, given: Option<&str>) -> (Profile, Profile, Vec<String>) {
    let (head, key) = match field.split_once("].") {
        Some((h, k)) => (format!("{}]", h), Some(k)),
        None => match field.split_once('.') {
            Some((h, k)) if !field.contains('[') => (h.to_string(), Some(k)),
            _ => (field.to_string(), None),
        },
    };
    let (root, selector) = match head.split_once('[') {
        Some((r, s)) => (r.to_string(), Some(s.trim_end_matches(']').to_string())),
        None => (head.clone(), None),
    };
    let leaf = key.map(|k| k.rsplit('.').next().unwrap_or(k));
    let value = leaf.map(|k| given.map_or_else(|| sample(k, json), str::to_string));
    let mut base = Profile::default();
    let mut names: Vec<String> = leaf.map(|k| vec![k.to_string()]).unwrap_or_default();
    // The rules of each: FINAL at least.
    let mut rules = vec!["FINAL,DIRECT".to_string()];
    let mut probe_rules = rules.clone();
    let mut probed;
    match (root.as_str(), selector.as_deref()) {
        ("General", _) => {
            let key = key.expect("a key");
            base.add("General", "loglevel = notify");
            probed = with(&base, "General", format!("{} = {}", key, value.unwrap()));
        }
        ("Proxy", Some(kind)) => {
            let line = proxy_line(kind);
            if kind == "wireguard" {
                wireguard(&mut base, None, None);
            }
            if kind == "tailscale" {
                base.add("Tailscale S", "auth-key = k");
            }
            base.add("Proxy", line.clone());
            probed = match key {
                None | Some("server") | Some("port") => base.clone(),
                Some(key) => {
                    // Shadow TLS takes its three together: version 3, which
                    // needs the SNI.
                    let param = if key.starts_with("shadow-tls-") {
                        "shadow-tls-password=p, shadow-tls-version=3, shadow-tls-sni=a.example"
                            .to_string()
                    } else {
                        format!("{}={}", key, value.clone().unwrap())
                    };
                    let mut p = Profile::default();
                    for (name, lines) in &base.sections {
                        for l in lines {
                            let l = if name == "Proxy" {
                                format!("{}, {}", l, param)
                            } else {
                                l.clone()
                            };
                            p.add(name, l);
                        }
                    }
                    p
                }
            };
        }
        ("Proxy Group", Some(kind)) => {
            let own = if kind == "ssid" { "subnet" } else { kind };
            let mut line = if own == "subnet" {
                format!("G = {}, default = DIRECT", kind)
            } else {
                format!("G = {}, DIRECT", kind)
            };
            // What only a group of a policy-path means anything with.
            if matches!(
                key,
                Some(
                    "external-policy-modifier" | "external-policy-name-prefix" | "update-interval"
                )
            ) {
                line.push_str(", policy-path=https://a.example/policies.list");
            }
            if key == Some("include-other-group") {
                base.add("Proxy Group", "H = select, DIRECT");
            }
            if key == Some("policy-priority") {
                base.add("Proxy", "P = http, a.example, 443");
                line.push_str(", P");
            }
            base.add("Proxy Group", line.clone());
            probed = match key {
                None | Some("default") => base.clone(),
                Some(key) => {
                    let mut p = base.clone();
                    let last = p.sections.iter_mut().find(|(s, _)| s == "Proxy Group");
                    let lines = &mut last.expect("groups").1;
                    let l = lines.last_mut().expect("a group");
                    l.push_str(&format!(", {} = {}", key, value.clone().unwrap()));
                    p
                }
            };
            rules = vec!["FINAL,G".to_string()];
            probe_rules = rules.clone();
        }
        ("Rule", Some(kind)) => {
            let policy = if key == Some("pre-matching") {
                "REJECT"
            } else {
                "DIRECT"
            };
            if kind == "IN-PORT" {
                base.add("General", "http-listen = 127.0.0.1:6152");
            }
            let line = match kind {
                "FINAL" => format!("FINAL,{}", policy),
                _ => format!("{},{},{}", kind, rule_value(kind), policy),
            };
            let with_key = match key {
                None => line.clone(),
                Some(k) if json == "flag" => format!("{},{}", line, k),
                Some(k) => format!("{},{}={}", line, k, value.clone().unwrap()),
            };
            let end = |rule: String| {
                if kind == "FINAL" {
                    vec![rule]
                } else {
                    vec![rule, "FINAL,DIRECT".to_string()]
                }
            };
            rules = end(line);
            probe_rules = end(with_key);
            probed = base.clone();
            names.push(kind.to_string());
        }
        ("WireGuard", _) => {
            let key = key.expect("a key");
            base.add("Proxy", "P = wireguard, section-name=S");
            wireguard(&mut base, None, None);
            let mut p = Profile::default();
            p.add("Proxy", "P = wireguard, section-name=S");
            let value = value.unwrap();
            match key.strip_prefix("peer.") {
                Some(field) => wireguard(&mut p, None, Some((field, &value))),
                None if key == "peer" => wireguard(&mut p, None, None),
                None => wireguard(&mut p, Some((key, &value)), None),
            }
            probed = p;
            names.push("[WireGuard".to_string());
        }
        ("Keystore", _) => {
            base.add(
                "Proxy",
                "P = trojan, a.example, 443, password=p, client-cert=c",
            );
            base.add("Keystore", "c = type=p12, base64=AAAA, password=p");
            probed = base.clone();
            names.push("Keystore".to_string());
        }
        ("SSID Setting", _) => {
            let key = key.expect("a key");
            probed = with(
                &base,
                "SSID Setting",
                format!("SSID:a {}={}", key, value.unwrap()),
            );
            names.push("[SSID Setting".to_string());
        }
        (section, _) => {
            let mut p = base.clone();
            let name = match section {
                "Ruleset" => {
                    probe_rules.insert(0, "RULE-SET,R,DIRECT".to_string());
                    "Ruleset R".to_string()
                }
                "Tailscale" => "Tailscale T".to_string(),
                other => other.to_string(),
            };
            for line in section_lines(section).lines() {
                p.add(&name, line);
            }
            probed = p;
            names.push(format!("[{}", section));
        }
    }
    for r in rules {
        base.add("Rule", r);
    }
    for r in probe_rules {
        probed.add("Rule", r);
    }
    (base, probed, names)
}

/// `base` with `line` added to `section`.
fn with(base: &Profile, section: &str, line: String) -> Profile {
    let mut p = base.clone();
    p.add(section, line);
    p
}

/// What sail makes of a profile: an error, or its warnings; and what it
/// passed over without a word.
fn read(profile: &Profile) -> (Result<Vec<String>, String>, Vec<String>) {
    SILENT.with(|s| s.borrow_mut().clear());
    let read = match super::parse(&profile.text()) {
        Ok(config) => Ok(config.warnings),
        Err(e) => Err(format!("{:#}", e)),
    };
    (read, SILENT.with(|s| s.take()))
}

/// The tier of a field, and what sail said of it.
fn measure(field: &str, kind: &str, given: Option<&str>) -> (Tier, String) {
    let (base, probed, names) = profiles(field, kind, given);
    let (before, _) = read(&base);
    let before = match before {
        Ok(w) => w,
        // The entry itself is refused: every field of it with it.
        Err(e) => {
            let tier = if unknown(&e) {
                Tier::Unknown
            } else if not_implemented(&e) {
                Tier::Error
            } else {
                Tier::Supported
            };
            return (tier, note(&e));
        }
    };
    let (after, silent) = read(&probed);
    match after {
        Err(e) if unknown(&e) => (Tier::Unknown, note(&e)),
        Err(e) if not_implemented(&e) => (Tier::Error, note(&e)),
        Err(e) => (Tier::Supported, note(&e)),
        Ok(warnings) => {
            let of = |w: &&String| names.iter().any(|n| w.contains(n.as_str()));
            let new: Vec<&String> = warnings
                .iter()
                .filter(|w| !before.contains(w))
                .filter(of)
                .collect();
            if let Some(w) = new.iter().find(|w| unknown(w)) {
                return (Tier::Unknown, note(w));
            }
            if let Some(w) = new.iter().find(|w| not_implemented(w)) {
                return (Tier::Warned, note(w));
            }
            if silent.iter().any(|s| of(&s)) {
                return (Tier::Silent, String::new());
            }
            (Tier::Supported, String::new())
        }
    }
}

/// The first line of what sail says, without where: `[Proxy] line 1: P: `.
fn note(s: &str) -> String {
    let mut s = s.lines().next().unwrap_or_default();
    if s.starts_with('[') {
        if let Some(i) = s.find(']') {
            s = &s[i + 1..];
            if let Some(rest) = s.strip_prefix(" line ") {
                s = &rest[rest.find(':').unwrap_or(0)..];
            }
            s = s.trim_start_matches(':').trim_start();
        }
    }
    for name in ["P: ", "G: "] {
        s = s.strip_prefix(name).unwrap_or(s);
    }
    s.to_string()
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

struct Words {
    title: &'static str,
    intro: &'static str,
    summary: &'static str,
    head: &'static str,
    tiers: [&'static str; 5],
}

const EN: Words = Words {
    title: "Surge compatibility",
    intro: "Every field Surge's manual ({surge}) lists, and how sail reads it: measured by \
            reading a profile of that field alone. Supported: read (or refused for its \
            value). Ignored silently: it means nothing where sail runs (Surge's interface, \
            its platforms), and sail passes it over. Warned: dropped with a warning. Error: \
            refused as not implemented.",
    summary: "| Section | Fields | Supported | Ignored silently | Warned | Error |",
    head: "| Field | sail | What sail says |",
    tiers: [
        "Supported",
        "Ignored silently",
        "Warned",
        "Error",
        "Unknown",
    ],
};

const ZH: Words = Words {
    title: "Surge 兼容性",
    intro: "Surge 手册（{surge}）列出的全部字段，以及 sail 如何读取：逐个以只含该字段的配置实测。\
            支持：读取（或仅因取值被拒）。静默忽略：在 sail 运行处无意义（Surge 的界面、平台），\
            sail 不作提示地跳过。警告：丢弃并警告。报错：未实现，拒绝。",
    summary: "| 部分 | 字段 | 支持 | 静默忽略 | 警告 | 报错 |",
    head: "| 字段 | sail | sail 的说明 |",
    tiers: ["支持", "静默忽略", "警告", "报错", "未知"],
};

const GENERATED: &str = "<!-- Generated by `SAIL_REGISTRY_UPDATE=1 cargo test -p sail surge::registry`; do not edit. -->";

/// The section of the tables a field is in: a proxy or group type, the
/// rules, a section read key by key, or the sections read whole.
fn section(field: &str) -> &str {
    if field.starts_with("Rule[") {
        return "Rule";
    }
    if let Some(i) = field.find("].") {
        return &field[..=i];
    }
    if field.contains('[') {
        return field;
    }
    match field.split_once('.') {
        Some((head, _)) => head,
        None => "Sections",
    }
}

fn render(words: &Words, surge: &str, tiers: &BTreeMap<String, (Tier, String)>) -> String {
    let mut out = format!(
        "{}\n\n# {}\n\n{}\n\n",
        GENERATED,
        words.title,
        words.intro.replace("{surge}", surge)
    );
    let mut counts: BTreeMap<&str, [usize; 5]> = BTreeMap::new();
    for (field, (tier, _)) in tiers {
        counts.entry(section(field)).or_default()[*tier as usize] += 1;
    }
    out.push_str(words.summary);
    out.push_str("\n|---|--:|--:|--:|--:|--:|\n");
    let mut all = [0usize; 5];
    for (s, c) in &counts {
        for i in 0..5 {
            all[i] += c[i];
        }
        out.push_str(&format!(
            "| `{}` | {} | {} | {} | {} | {} |\n",
            s,
            c.iter().sum::<usize>(),
            c[0],
            c[1],
            c[2],
            c[3] + c[4]
        ));
    }
    out.push_str(&format!(
        "| **All** | **{}** | **{}** | **{}** | **{}** | **{}** |\n\n",
        all.iter().sum::<usize>(),
        all[0],
        all[1],
        all[2],
        all[3] + all[4]
    ));
    // A type refused as a whole is one row, its fields with it.
    let mut current = "";
    let mut refused: Option<(String, String)> = None;
    for (field, (tier, note)) in tiers {
        let s = section(field);
        if s != current {
            out.push_str(&format!("\n## `{}`\n\n{}\n|---|---|---|\n", s, words.head));
            current = s;
            refused = None;
        }
        let entry = field.split("].").next().unwrap_or(field);
        if let Some((e, n)) = &refused {
            if entry.starts_with(e.as_str()) && *tier == Tier::Error && n == note {
                continue;
            }
        }
        if !field.contains("].") && field.ends_with(']') && *tier == Tier::Error {
            refused = Some((field.trim_end_matches(']').to_string(), note.clone()));
        }
        out.push_str(&format!(
            "| `{}` | {} | {} |\n",
            field,
            words.tiers[*tier as usize],
            note.replace('|', "\\|")
        ));
    }
    out
}

#[test]
fn registry() {
    let inventory: Value = serde_json::from_str(FIELDS).unwrap();
    let surge = inventory["surge"].as_str().unwrap().to_string();
    let mut tiers: BTreeMap<String, (Tier, String)> = BTreeMap::new();
    for f in inventory["fields"].as_array().unwrap() {
        let field = f["path"].as_str().unwrap();
        let kind = f["json"].as_str().unwrap_or("string");
        let given = f.get("sample").and_then(Value::as_str);
        tiers.insert(field.to_string(), measure(field, kind, given));
    }
    let mut stored = Map::new();
    stored.insert("surge".into(), json!(surge));
    let mut by_tier: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (field, (tier, _)) in &tiers {
        by_tier.entry(tier.name()).or_default().push(field);
    }
    stored.insert("tiers".into(), json!(by_tier));
    let files = [
        (
            root().join("sail/src/config/surge/fields.tiers.json"),
            serde_json::to_string_pretty(&Value::Object(stored)).unwrap() + "\n",
        ),
        (
            root().join("docs/compat/surge.md"),
            render(&EN, &surge, &tiers),
        ),
        (
            root().join("docs/compat/zh/surge.md"),
            render(&ZH, &surge, &tiers),
        ),
    ];
    if std::env::var_os("SAIL_REGISTRY_UPDATE").is_some() {
        for (path, text) in &files {
            std::fs::write(path, text).unwrap();
        }
    } else {
        for (path, text) in &files {
            let written = std::fs::read_to_string(path).unwrap_or_default();
            assert!(
                &written == text,
                "{} is not what sail measures (SAIL_REGISTRY_UPDATE=1 writes it)",
                path.display()
            );
        }
    }
    let unknown: Vec<(&String, &String)> = tiers
        .iter()
        .filter(|(_, (t, _))| *t == Tier::Unknown)
        .map(|(f, (_, n))| (f, n))
        .collect();
    assert!(
        unknown.is_empty(),
        "{} fields Surge takes that sail lists nowhere: {:#?}",
        unknown.len(),
        unknown
    );
}
