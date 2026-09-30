//! Every field Mihomo takes (`fields.json`, from
//! `tools/clash-fields/extract.py`), and how sail's Clash front-end takes
//! each: measured by reading a configuration of that field alone, and
//! written to `fields.tiers.json` and the support tables of docs/compat.
//! `SAIL_REGISTRY_UPDATE=1` writes them; otherwise what is written must be
//! what is measured.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde_json::{json, Map, Value};

const FIELDS: &str = include_str!("fields.json");

/// How sail takes a field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Tier {
    /// Read, or refused for its value alone.
    Supported,
    /// Dropped with a warning.
    Warned,
    /// Refused as not implemented.
    Error,
    /// Warned of as a field Mihomo does not take: sail lists it nowhere.
    Unknown,
}

impl Tier {
    fn name(self) -> &'static str {
        match self {
            Tier::Supported => "supported",
            Tier::Warned => "warned",
            Tier::Error => "error",
            Tier::Unknown => "unknown",
        }
    }
}

/// What sail says when it does not implement something.
const NOT_IMPLEMENTED: &[&str] = &[
    "does not implement",
    "sail has no ",
    "not supported",
    "sail does not ",
    "sail cannot ",
    "sail serves no",
];

/// A path's parts: `proxies[vmess].ws-opts.path` is the root `proxies`,
/// the entry's type `vmess`, and the keys `ws-opts`, `path`; `users[]` a
/// list of one entry.
struct Path<'a> {
    root: &'a str,
    selector: Option<&'a str>,
    keys: Vec<&'a str>,
}

fn path(p: &str) -> Path<'_> {
    let (head, rest) = match p.split_once('.') {
        Some((h, r)) => (h, Some(r)),
        None => (p, None),
    };
    let (root, selector) = match head.split_once('[') {
        Some((r, s)) => (r, Some(s.trim_end_matches(']'))),
        None => (head, None),
    };
    Path {
        root,
        selector,
        keys: rest.map(|r| r.split('.').collect()).unwrap_or_default(),
    }
}

/// A sample of a field's kind.
fn sample(kind: &str) -> Value {
    match kind {
        "bool" => json!(true),
        "number" => json!(1),
        "list" => json!(["x"]),
        "object" => json!({}),
        _ => json!("x"),
    }
}

/// What each proxy type needs besides a name, a server and a port.
fn proxy(kind: &str) -> Value {
    let mut p = json!({ "name": "P", "type": kind, "server": "a.example", "port": 443 });
    let extra = match kind {
        "ss" => json!({ "cipher": "aes-128-gcm", "password": "p" }),
        "vmess" => json!({ "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "cipher": "auto" }),
        "vless" => json!({ "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811" }),
        "trojan" | "hysteria2" | "anytls" => json!({ "password": "p" }),
        "tuic" => json!({ "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "password": "p" }),
        "direct" | "dns" | "reject" => json!({ "server": null, "port": null }),
        _ => json!({}),
    };
    merge(&mut p, extra);
    p
}

/// What each listener type needs besides a name and a port.
fn listener(kind: &str) -> Value {
    let mut l = json!({ "name": "L", "type": kind, "port": 10808 });
    let extra = match kind {
        "shadowsocks" => json!({ "cipher": "aes-128-gcm", "password": "p" }),
        "vmess" | "vless" => {
            json!({ "users": [{ "username": "u", "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811" }] })
        }
        "trojan" | "anytls" | "hysteria2" => json!({ "users": { "u": "p" } }),
        "tuic" => json!({ "users": { "b831381d-6324-4d53-ad4f-8cda48b30811": "p" } }),
        "tunnel" => json!({ "network": ["tcp"], "target": "a.example:80" }),
        "tun" => json!({ "port": null }),
        _ => json!({}),
    };
    merge(&mut l, extra);
    l
}

fn merge(into: &mut Value, from: Value) {
    if let (Some(into), Value::Object(from)) = (into.as_object_mut(), from) {
        for (k, v) in from {
            if v.is_null() {
                into.remove(&k);
            } else {
                into.insert(k, v);
            }
        }
    }
}

/// The configuration a field is measured in, but the field.
fn skeleton(p: &Path) -> (Value, Vec<String>) {
    // The keys from the top to the object the field is in.
    let mut at = Vec::new();
    let config = match (p.root, p.selector) {
        ("proxies", Some(kind)) => {
            let mut proxy = proxy(kind);
            // A plugin's options, for that plugin.
            if let Some((key, plugin)) = p.keys.first().and_then(|k| k.split_once('[')) {
                let plugin = plugin.trim_end_matches(']');
                let which = if key == "plugin-opts" {
                    "plugin"
                } else {
                    "obfs"
                };
                merge(&mut proxy, json!({ which: plugin }));
            }
            at.extend(["proxies".to_string(), "0".to_string()]);
            json!({ "proxies": [proxy] })
        }
        ("proxy-groups", Some(kind)) => {
            let kind = if kind == "*" { "select" } else { kind };
            at.extend(["proxy-groups".to_string(), "0".to_string()]);
            json!({ "proxy-groups": [{ "name": "G", "type": kind, "proxies": ["DIRECT"] }] })
        }
        ("proxy-providers", _) => {
            at.extend(["proxy-providers".to_string(), "p".to_string()]);
            json!({ "proxy-providers": { "p": { "type": "http", "url": "https://a.example/p" } } })
        }
        ("rule-providers", _) => {
            at.extend(["rule-providers".to_string(), "r".to_string()]);
            json!({ "rule-providers": { "r": {
                "type": "http", "behavior": "domain", "format": "text",
                "url": "https://a.example/r.txt" } } })
        }
        ("listeners", Some(kind)) => {
            at.extend(["listeners".to_string(), "0".to_string()]);
            json!({ "listeners": [listener(kind)] })
        }
        ("dns", _) => json!({ "dns": { "enable": true, "nameserver": ["1.1.1.1"] } }),
        ("tun", _) => json!({ "tun": { "enable": true } }),
        ("sniffer", _) => json!({ "sniffer": { "enable": true } }),
        _ => json!({}),
    };
    if p.root != "proxies"
        && p.root != "proxy-groups"
        && p.root != "proxy-providers"
        && p.root != "rule-providers"
        && p.root != "listeners"
    {
        at.push(p.root.to_string());
    }
    (config, at)
}

/// `config` with the field set to `value`.
fn with_field(mut config: Value, at: &[String], p: &Path, value: Value) -> Value {
    let mut node = &mut config;
    for key in at {
        node = match node {
            Value::Array(list) => &mut list[key.parse::<usize>().unwrap()],
            Value::Object(map) => map.entry(key.clone()).or_insert_with(|| json!({})),
            _ => unreachable!(),
        };
    }
    let keys: Vec<&str> = p
        .keys
        .iter()
        .map(|k| k.split('[').next().unwrap_or(k))
        .collect();
    if keys.is_empty() {
        // A top-level field.
        return match (p.root, &mut config) {
            (root, Value::Object(map)) if at.len() == 1 => {
                map.insert(root.to_string(), value);
                config
            }
            _ => config,
        };
    }
    for (i, key) in keys.iter().enumerate() {
        let last = i == keys.len() - 1;
        let list = key.ends_with("[]") || p.keys[i].ends_with("[]");
        let key = key.trim_end_matches("[]");
        let map = match node {
            Value::Object(map) => map,
            other => {
                *other = json!({});
                other.as_object_mut().unwrap()
            }
        };
        if last {
            map.insert(key.to_string(), value);
            break;
        }
        let child =
            map.entry(key.to_string()).or_insert_with(
                || {
                    if list {
                        json!([{}])
                    } else {
                        json!({})
                    }
                },
            );
        node = match child {
            Value::Array(items) => {
                if items.is_empty() || !items[0].is_object() {
                    *items = vec![json!({})];
                }
                &mut items[0]
            }
            other => other,
        };
    }
    config
}

/// What sail makes of a configuration: an error, or its warnings.
fn read(config: &Value) -> Result<Vec<String>, String> {
    // JSON is YAML too.
    match super::parse(&config.to_string()) {
        Ok(config) => Ok(config.warnings),
        Err(e) => Err(format!("{:#}", e)),
    }
}

fn not_implemented(message: &str) -> bool {
    NOT_IMPLEMENTED.iter().any(|m| message.contains(m))
}

/// The tier of a field, and what sail said of it.
fn measure(field: &str, kind: &str) -> (Tier, String) {
    let p = path(field);
    let (config, at) = skeleton(&p);
    let base = read(&config);
    if let Err(e) = &base {
        // The entry itself is refused: every field of it with it.
        let tier = if not_implemented(e) {
            Tier::Error
        } else {
            Tier::Supported
        };
        return (tier, first_line(e));
    }
    let before = base.unwrap_or_default();
    // Its own name and those of the objects it is in: a warning of one of
    // these is of it.
    let names: Vec<&str> = std::iter::once(p.root)
        .chain(p.keys.iter().copied())
        .map(|k| k.split('[').next().unwrap_or(k).trim_end_matches("[]"))
        .collect();
    let probed = with_field(config, &at, &p, sample(kind));
    match read(&probed) {
        Err(e) if not_implemented(&e) => (Tier::Error, first_line(&e)),
        Err(e) => (Tier::Supported, first_line(&e)),
        Ok(warnings) => {
            // Only what says it is not taken: a warning of the value
            // ("not user:password") is of a field sail reads.
            let new: Vec<&String> = warnings
                .iter()
                .filter(|w| !before.contains(w))
                .filter(|w| names.iter().any(|n| w.contains(n)))
                .collect();
            if let Some(w) = new.iter().find(|w| w.contains("not a field Mihomo takes")) {
                return (Tier::Unknown, first_line(w));
            }
            match new.iter().find(|w| not_implemented(w)) {
                Some(w) => (Tier::Warned, first_line(w)),
                None => (Tier::Supported, String::new()),
            }
        }
    }
}

fn first_line(s: &str) -> String {
    s.lines().next().unwrap_or_default().to_string()
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

struct Words {
    title: &'static str,
    intro: &'static str,
    summary: &'static str,
    head: &'static str,
    tiers: [&'static str; 4],
}

const EN: Words = Words {
    title: "Clash / Mihomo compatibility",
    intro: "Every field Mihomo {mihomo} takes, and how sail reads it: measured by \
            reading a configuration of that field alone. Supported: read (or refused \
            for its value). Warned: dropped with a warning. Error: refused as not \
            implemented.",
    summary: "| Section | Fields | Supported | Warned | Error |",
    head: "| Field | sail | What sail says |",
    tiers: ["Supported", "Warned", "Error", "Unknown"],
};

const ZH: Words = Words {
    title: "Clash / Mihomo 兼容性",
    intro: "Mihomo {mihomo} 接受的全部字段，以及 sail 如何读取：逐个以只含该字段的配置实测。\
            支持：读取（或仅因取值被拒）。警告：丢弃并警告。报错：未实现，拒绝。",
    summary: "| 部分 | 字段 | 支持 | 警告 | 报错 |",
    head: "| 字段 | sail | sail 的说明 |",
    tiers: ["支持", "警告", "报错", "未知"],
};

const GENERATED: &str = "<!-- Generated by `SAIL_REGISTRY_UPDATE=1 cargo test -p sail clash::registry`; do not edit. -->";

/// The section of the tables a field is in: an entry type, a top-level
/// object, or `general` for the top level's own values.
fn section(field: &str) -> &str {
    let head = field.split('.').next().unwrap_or(field);
    match head.split_once('[') {
        Some((root, _)) if root == "proxy-groups" || root.ends_with("-providers") => root,
        Some(_) => head,
        None if field.contains('.') || TOP_OBJECTS.contains(&head) => head,
        None => "general",
    }
}

/// The top-level fields that are objects of fields.
const TOP_OBJECTS: &[&str] = &[
    "dns",
    "tun",
    "sniffer",
    "ntp",
    "tls",
    "experimental",
    "geox-url",
    "iptables",
    "profile",
    "tuic-server",
    "clash-for-android",
    "external-controller-cors",
];

fn render(words: &Words, mihomo: &str, tiers: &BTreeMap<String, (Tier, String)>) -> String {
    let mut out = format!(
        "{}\n\n# {}\n\n{}\n\n",
        GENERATED,
        words.title,
        words.intro.replace("{mihomo}", mihomo)
    );
    // Counts by section.
    let mut counts: BTreeMap<&str, [usize; 4]> = BTreeMap::new();
    for (field, (tier, _)) in tiers {
        counts.entry(section(field)).or_default()[*tier as usize] += 1;
    }
    out.push_str(words.summary);
    out.push_str("\n|---|--:|--:|--:|--:|\n");
    let mut all = [0usize; 4];
    for (s, c) in &counts {
        for i in 0..4 {
            all[i] += c[i];
        }
        out.push_str(&format!(
            "| `{}` | {} | {} | {} | {} |\n",
            s,
            c.iter().sum::<usize>(),
            c[0],
            c[1],
            c[2] + c[3]
        ));
    }
    out.push_str(&format!(
        "| **All** | **{}** | **{}** | **{}** | **{}** |\n\n",
        all.iter().sum::<usize>(),
        all[0],
        all[1],
        all[2] + all[3]
    ));
    // A refused entry type is one row, its fields with it.
    let mut current = "";
    let mut folded: Option<String> = None;
    for (field, (tier, note)) in tiers {
        let s = section(field);
        if s != current {
            out.push_str(&format!("\n## `{}`\n\n{}\n|---|---|---|\n", s, words.head));
            current = s;
            folded = None;
        }
        let entry = field.split('.').next().unwrap_or(field);
        if entry.contains('[') && *tier == Tier::Error && note.contains(".type:") {
            if folded.as_deref() == Some(entry) {
                continue;
            }
            folded = Some(entry.to_string());
            out.push_str(&format!(
                "| `{}` | {} | {} |\n",
                entry,
                words.tiers[*tier as usize],
                escape(note)
            ));
            continue;
        }
        out.push_str(&format!(
            "| `{}` | {} | {} |\n",
            field,
            words.tiers[*tier as usize],
            escape(note)
        ));
    }
    out
}

fn escape(s: &str) -> String {
    s.replace('|', "\\|")
}

#[test]
fn registry() {
    let inventory: Value = serde_json::from_str(FIELDS).unwrap();
    let mihomo = inventory["mihomo"].as_str().unwrap().to_string();
    let mut tiers: BTreeMap<String, (Tier, String)> = BTreeMap::new();
    for f in inventory["fields"].as_array().unwrap() {
        let field = f["path"].as_str().unwrap();
        let kind = f["json"].as_str().unwrap_or("string");
        tiers.insert(field.to_string(), measure(field, kind));
    }
    let mut stored = Map::new();
    stored.insert("mihomo".into(), json!(mihomo));
    let mut by_tier: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (field, (tier, _)) in &tiers {
        by_tier.entry(tier.name()).or_default().push(field);
    }
    stored.insert("tiers".into(), json!(by_tier));
    let files = [
        (
            root().join("sail/src/config/clash/fields.tiers.json"),
            serde_json::to_string_pretty(&Value::Object(stored)).unwrap() + "\n",
        ),
        (
            root().join("docs/compat/clash.md"),
            render(&EN, &mihomo, &tiers),
        ),
        (
            root().join("docs/compat/zh/clash.md"),
            render(&ZH, &mihomo, &tiers),
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
    let unknown: Vec<&String> = tiers
        .iter()
        .filter(|(_, (t, _))| *t == Tier::Unknown)
        .map(|(f, _)| f)
        .collect();
    assert!(
        unknown.is_empty(),
        "{} fields Mihomo takes that sail lists nowhere: {:?}",
        unknown.len(),
        unknown
    );
}
