//! What a proxy-provider holds, as Mihomo reads it: Clash's YAML, its
//! `proxies`, or else share links, a line each and maybe in base64. Its
//! `filter`, `exclude-filter` and `exclude-type` pick the proxies, by the
//! names and types the subscription gives them, and its `override` then
//! changes them.
//!
//! A proxy of a type, or with a field, sail does not implement is left
//! out, with a warning, where Mihomo would take it; any other mistake fails
//! the whole update, as in Mihomo, and the proxies held before stay.

use anyhow::{anyhow, Result};
use serde_json::{json, Map, Value};

use super::fields::Fields;
use super::node::Node;
use super::proxy;
pub use crate::common::name_filter::NameFilter;

/// The longest name a proxy may have; longer ones are cut.
const MAX_NAME: usize = 256;

/// A provider's choice of proxies, and what it changes in them.
#[derive(Default)]
pub struct Selection {
    pub filters: Vec<NameFilter>,
    pub exclude: Vec<NameFilter>,
    /// Clash types, compared without case.
    pub exclude_types: Vec<String>,
    pub dialer_proxy: Option<String>,
    pub overrides: Override,
}

impl Selection {
    /// A provider's choice, as sail's JSON gives it: `filter` and
    /// `exclude_filter` regular expressions, `exclude_type` Clash types,
    /// `detour` the dialer-proxy, `overrides` in Mihomo's keys.
    pub fn of(
        filter: &[String],
        exclude_filter: &[String],
        exclude_type: &[String],
        detour: Option<&str>,
        overrides: Option<&Map<String, Value>>,
        warnings: &mut Vec<String>,
    ) -> Result<Self> {
        let filters = |patterns: &[String]| {
            patterns
                .iter()
                .map(|p| NameFilter::new(p))
                .collect::<Result<Vec<_>>>()
        };
        Ok(Selection {
            filters: filters(filter).map_err(|e| anyhow!("filter: {}", e))?,
            exclude: filters(exclude_filter).map_err(|e| anyhow!("exclude_filter: {}", e))?,
            exclude_types: exclude_type.to_vec(),
            dialer_proxy: detour.map(str::to_string),
            overrides: match overrides {
                Some(o) => Override::from_json(o, warnings)?,
                None => Override::default(),
            },
        })
    }
}

/// A provider's `override`.
#[derive(Default)]
pub struct Override {
    /// Fields of each proxy, set whatever the subscription says.
    fields: Map<String, Value>,
    names: Vec<(NameFilter, String)>,
    prefix: Option<String>,
    suffix: Option<String>,
}

use super::proxy_provider::{OVERRIDDEN, OVERRIDE_NAMES};

impl Override {
    pub fn read(f: Option<Fields>, warnings: &mut Vec<String>) -> Result<Self> {
        let Some(mut f) = f else {
            return Ok(Override::default());
        };
        let mut o = Override::default();
        for key in OVERRIDDEN {
            if let Some(value) = f.take(key) {
                o.fields.insert(key.to_string(), value.to_json());
            }
        }
        for (i, node) in f.list("proxy-name")?.into_iter().enumerate() {
            let mut e = Fields::of(node, &format!("{}[{}]", f.at("proxy-name"), i))?;
            let pattern = e
                .string("pattern")?
                .ok_or_else(|| anyhow!("{}: missing", e.at("pattern")))?;
            let target = e.string("target")?.unwrap_or_default();
            let filter =
                NameFilter::new(&pattern).map_err(|err| anyhow!("{}: {}", e.at("pattern"), err))?;
            e.finish(&[], |_| false, warnings)?;
            o.names.push((filter, target));
        }
        o.prefix = f.string("additional-prefix")?;
        o.suffix = f.string("additional-suffix")?;
        f.finish(
            &[
                ("name-cert-verify", super::fields::Tier::Unsupported),
                ("override-expr", super::fields::Tier::Unsupported),
            ],
            |_| false,
            warnings,
        )?;
        Ok(o)
    }

    /// An `override` as sail's JSON gives it, an object in Mihomo's own
    /// keys: one Mihomo's does not take is an error there.
    pub fn from_json(value: &Map<String, Value>, warnings: &mut Vec<String>) -> Result<Self> {
        if let Some(key) = value
            .keys()
            .find(|k| !OVERRIDDEN.contains(&k.as_str()) && !OVERRIDE_NAMES.contains(&k.as_str()))
        {
            return Err(anyhow!(
                "override.{}: not a field Mihomo's override takes",
                key
            ));
        }
        let node = json_node(&Value::Object(value.clone()));
        Self::read(Some(Fields::of(node, "override")?), warnings)
    }

    /// The name, changed as `proxy-name`, `additional-prefix` and
    /// `additional-suffix` say.
    fn name(&self, name: &str) -> String {
        let mut name = name.to_string();
        for (filter, target) in &self.names {
            name = filter.replace(&name, target);
        }
        format!(
            "{}{}{}",
            self.prefix.as_deref().unwrap_or(""),
            name,
            self.suffix.as_deref().unwrap_or("")
        )
    }
}

fn json_node(value: &Value) -> Node {
    match value {
        Value::Null => Node::Null,
        Value::Bool(b) => Node::Bool(*b),
        Value::Number(n) => n
            .as_i64()
            .map(Node::Int)
            .unwrap_or_else(|| Node::Float(n.as_f64().unwrap_or(0.0))),
        Value::String(s) => Node::Str(s.clone()),
        Value::Array(items) => Node::Seq(items.iter().map(json_node).collect()),
        Value::Object(m) => Node::Map(m.iter().map(|(k, v)| (k.clone(), json_node(v))).collect()),
    }
}

/// The proxies a provider holds: each its name, and its outbound.
#[derive(Debug)]
pub struct Proxies {
    pub proxies: Vec<(String, Value)>,
    pub warnings: Vec<String>,
}

/// Reads what a provider downloaded, or holds in place.
pub fn read(body: &str, selection: &Selection) -> Result<Proxies> {
    let mut warnings = Vec::new();
    let candidates = match clash_proxies(body)? {
        Some(proxies) => proxies,
        None => share_links(body, &mut warnings),
    };
    select(candidates, selection, warnings)
}

/// Clash proxies a provider holds in place, its `payload`.
pub(super) fn read_clash(items: Vec<Node>, selection: &Selection) -> Result<Proxies> {
    select(clash_candidates(items), selection, Vec::new())
}

/// The proxies `selection` takes of `candidates`, lowered.
fn select(
    candidates: Vec<Candidate>,
    selection: &Selection,
    mut warnings: Vec<String>,
) -> Result<Proxies> {
    // As Mihomo: each filter in turn over the proxies, so that those of the
    // first come first; a name once taken is not taken again.
    let passes: Vec<Option<&NameFilter>> = if selection.filters.is_empty() {
        vec![None]
    } else {
        selection.filters.iter().map(Some).collect()
    };
    let mut taken = std::collections::HashSet::new();
    let mut proxies = Vec::new();
    let mut left_out = 0usize;
    let mut first_left_out = None;
    for filter in passes {
        for candidate in &candidates {
            let name = candidate.name.as_str();
            if selection
                .exclude_types
                .iter()
                .any(|t| t.eq_ignore_ascii_case(&candidate.kind))
            {
                continue;
            }
            if selection
                .exclude
                .iter()
                .any(|f| f.matches(name, &mut warnings))
            {
                continue;
            }
            if let Some(filter) = filter {
                if !filter.matches(name, &mut warnings) {
                    continue;
                }
            }
            if !taken.insert(name.to_string()) {
                continue;
            }
            match candidate.lower(selection) {
                Ok(proxy) => proxies.push(proxy),
                Err(e) if e.to_string().contains("sail does not implement") => {
                    left_out += 1;
                    first_left_out.get_or_insert(format!("{:?}: {}", name, e));
                }
                Err(e) => return Err(anyhow!("proxy {:?}: {}", name, e)),
            }
        }
    }
    if let Some(first) = first_left_out {
        warnings.push(format!(
            "{} proxies left out, as sail does not implement them yet; the first, {}",
            left_out, first
        ));
    }
    if proxies.is_empty() {
        return Err(if selection.filters.is_empty() {
            anyhow!("no proxy sail can use in it")
        } else {
            anyhow!("no proxy matches the filter")
        });
    }
    Ok(Proxies { proxies, warnings })
}

/// A proxy as the subscription gives it.
struct Candidate {
    name: String,
    /// Its Clash type.
    kind: String,
    form: Form,
}

enum Form {
    /// A Clash proxy, still to be lowered.
    Clash(Node),
    /// An outbound, from a share link.
    Outbound(Value),
}

/// The proxies of Clash's YAML: none when it is not that.
fn clash_proxies(body: &str) -> Result<Option<Vec<Candidate>>> {
    let Ok(Node::Map(mut root)) = super::node::parse(body) else {
        return Ok(None);
    };
    let Some(proxies) = root.shift_remove("proxies") else {
        return Ok(None);
    };
    let Node::Seq(items) = proxies else {
        return Err(anyhow!("proxies: a list, not {}", proxies.kind()));
    };
    Ok(Some(clash_candidates(items)))
}

/// Clash proxies, those with a name and a type.
fn clash_candidates(items: Vec<Node>) -> Vec<Candidate> {
    items
        .into_iter()
        .filter_map(|node| {
            let Node::Map(map) = &node else { return None };
            let name = map.get("name")?.as_string()?;
            let kind = map.get("type")?.as_string()?.to_ascii_lowercase();
            Some(Candidate {
                name: cut(name),
                kind,
                form: Form::Clash(node),
            })
        })
        .collect()
}

/// The proxies of share links.
fn share_links(body: &str, warnings: &mut Vec<String>) -> Vec<Candidate> {
    let (outbounds, link_warnings) = crate::config::share_link::parse_subscription(body);
    warnings.extend(link_warnings);
    outbounds
        .into_iter()
        .filter_map(|outbound| {
            let name = outbound.get("tag")?.as_str()?.to_string();
            let kind = match outbound.get("type")?.as_str()? {
                "shadowsocks" => "ss",
                "socks" => "socks5",
                other => other,
            }
            .to_string();
            Some(Candidate {
                name: cut(name),
                kind,
                form: Form::Outbound(outbound),
            })
        })
        .collect()
}

fn cut(mut name: String) -> String {
    if name.len() > MAX_NAME {
        let mut end = MAX_NAME;
        while !name.is_char_boundary(end) {
            end -= 1;
        }
        name.truncate(end);
    }
    name
}

impl Candidate {
    /// The outbound, with the provider's changes, tagged with its name.
    fn lower(&self, selection: &Selection) -> Result<(String, Value)> {
        let name = selection.overrides.name(&self.name);
        let outbound = match &self.form {
            Form::Clash(node) => {
                let Node::Map(map) = node else {
                    unreachable!("a map, taken as one")
                };
                let mut map = map.clone();
                if let Some(via) = &selection.dialer_proxy {
                    map.insert("dialer-proxy".into(), Node::Str(via.clone()));
                }
                for (key, value) in &selection.overrides.fields {
                    map.insert(key.clone(), json_node(value));
                }
                map.insert("name".into(), Node::Str(name.clone()));
                let mut warnings = Vec::new();
                proxy::lower_one(Fields::of(Node::Map(map), "proxy")?, &mut warnings)?
            }
            Form::Outbound(outbound) => {
                let mut outbound = outbound.clone();
                override_outbound(&mut outbound, selection)?;
                outbound["tag"] = json!(name);
                outbound
            }
        };
        Ok((name, outbound))
    }
}

/// The provider's `override` and `dialer-proxy` of an outbound a share link
/// gave, in sing-box's names for them.
fn override_outbound(outbound: &mut Value, selection: &Selection) -> Result<()> {
    let Some(o) = outbound.as_object_mut() else {
        return Ok(());
    };
    if let Some(via) = &selection.dialer_proxy {
        o.insert("detour".into(), json!(via));
    }
    for (key, value) in &selection.overrides.fields {
        match key.as_str() {
            "dialer-proxy" => {
                o.insert("detour".into(), value.clone());
            }
            "interface-name" => {
                o.insert("bind_interface".into(), value.clone());
            }
            "routing-mark" => {
                o.insert("routing_mark".into(), value.clone());
            }
            "skip-cert-verify" => {
                if let Some(Value::Object(tls)) = o.get_mut("tls") {
                    tls.insert("insecure".into(), value.clone());
                }
            }
            "ip-version" => {
                let strategy = match value.as_str() {
                    Some("ipv4") => Some("ipv4_only"),
                    Some("ipv6") => Some("ipv6_only"),
                    Some("ipv4-prefer") => Some("prefer_ipv4"),
                    Some("ipv6-prefer") => Some("prefer_ipv6"),
                    _ => None,
                };
                if let Some(strategy) = strategy {
                    o.insert("domain_strategy".into(), json!(strategy));
                }
            }
            // UDP is carried either way; the rest tunes the connection.
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLASH: &str = r#"
proxies:
  - { name: "🇭🇰 HK 01", type: ss, server: hk.example, port: 443, cipher: aes-128-gcm, password: p }
  - { name: "🇭🇰 HK 02 IPLC", type: trojan, server: hk2.example, port: 443, password: p }
  - { name: "🇯🇵 JP 01", type: vmess, server: jp.example, port: 443, uuid: 00000000-0000-0000-0000-000000000001 }
  - { name: "🇺🇦 Ukraine 01", type: ss, server: ua.example, port: 443, cipher: aes-128-gcm, password: p }
  - { name: "old", type: ssr, server: o.example, port: 1, cipher: none, password: p, protocol: origin, obfs: plain }
  - { name: "🇭🇰 HK 01", type: ss, server: dup.example, port: 443, cipher: aes-128-gcm, password: p }
"#;

    fn names(proxies: &Proxies) -> Vec<&str> {
        proxies.proxies.iter().map(|(n, _)| n.as_str()).collect()
    }

    #[test]
    fn clash_proxies_are_read_and_filtered_as_mihomo_does() {
        let selection = Selection {
            filters: NameFilter::list(Some("(?i)jp`(?!.*Ukraine)(HK|港)")).unwrap(),
            exclude: NameFilter::list(Some("IPLC")).unwrap(),
            ..Default::default()
        };
        let proxies = read(CLASH, &selection).unwrap();
        // The first filter's first, the duplicate name once.
        assert_eq!(names(&proxies), ["🇯🇵 JP 01", "🇭🇰 HK 01"]);
        assert_eq!(proxies.proxies[1].1["server"], "hk.example");
        assert_eq!(proxies.proxies[1].1["tag"], "🇭🇰 HK 01");

        let all = read(CLASH, &Selection::default()).unwrap();
        assert_eq!(all.proxies.len(), 4);
        assert!(
            all.warnings[0].starts_with("1 proxies left out, as sail does not implement them yet"),
            "{:?}",
            all.warnings
        );
    }

    #[test]
    fn exclude_type_and_overrides() {
        let mut warnings = Vec::new();
        let overrides = Override::read(
            Some(
                Fields::of(
                    super::super::node::parse(
                        "{ additional-prefix: 'A|', skip-cert-verify: true, interface-name: en0,\n\
                           proxy-name: [{ pattern: '🇭🇰 ', target: '' }] }",
                    )
                    .unwrap(),
                    "override",
                )
                .unwrap(),
            ),
            &mut warnings,
        )
        .unwrap();
        let selection = Selection {
            exclude_types: vec!["SS".into()],
            dialer_proxy: Some("relay".into()),
            overrides,
            ..Default::default()
        };
        let proxies = read(CLASH, &selection).unwrap();
        assert_eq!(names(&proxies), ["A|HK 02 IPLC", "A|🇯🇵 JP 01"]);
        let trojan = &proxies.proxies[0].1;
        assert_eq!(trojan["detour"], "relay");
        assert_eq!(trojan["bind_interface"], "en0");
        assert_eq!(trojan["tls"]["insecure"], true);
    }

    #[test]
    fn share_links_are_read_too() {
        let links = "trojan://p@a.example:443#A%20HK\nvless://00000000-0000-0000-0000-000000000001@b.example:443?security=tls#B%20JP\n";
        let body = links;
        let selection = Selection {
            filters: NameFilter::list(Some("HK")).unwrap(),
            dialer_proxy: Some("relay".into()),
            ..Default::default()
        };
        let proxies = read(body, &selection).unwrap();
        assert_eq!(names(&proxies), ["A HK"]);
        assert_eq!(proxies.proxies[0].1["detour"], "relay");
    }

    #[test]
    fn nothing_left_is_an_error() {
        let selection = Selection {
            filters: NameFilter::list(Some("nowhere")).unwrap(),
            ..Default::default()
        };
        assert!(read(CLASH, &selection)
            .unwrap_err()
            .to_string()
            .contains("no proxy matches"));
        assert!(read("proxies: []", &Selection::default()).is_err());
        let bad = "proxies:\n  - { name: a, type: ss, server: s, port: 1, password: p }\n";
        assert!(read(bad, &Selection::default())
            .unwrap_err()
            .to_string()
            .contains("cipher"));
    }
}
