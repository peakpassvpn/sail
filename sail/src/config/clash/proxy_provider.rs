//! `proxy-providers`, as sail's outbound providers: `http` ones downloaded
//! as remote providers are, `file` ones read as local, `inline` ones held
//! in place, their `payload` picked and changed here as Mihomo picks and
//! changes what the others hold once read.

use std::collections::HashMap;

use anyhow::{anyhow, Result};
use serde_json::{json, Map, Value};

use super::fields::{Fields, Tier};
use super::node::Node;
use super::Lowered;

use Tier::*;

/// The proxy-providers groups may take members from.
#[derive(Default)]
pub struct Providers {
    /// By name, as Mihomo sorts them for `include-all-providers`.
    pub names: Vec<String>,
    /// The URL of each one's `health-check`, which a group taking it tests
    /// with where it names none of its own, as in Mihomo.
    pub health_urls: HashMap<String, String>,
}

impl Providers {
    pub fn has(&self, name: &str) -> bool {
        self.names.iter().any(|n| n == name)
    }
}

/// The `override` fields that set a proxy's own.
pub const OVERRIDDEN: &[&str] = &[
    "tfo",
    "mptcp",
    "udp",
    "udp-over-tcp",
    "up",
    "down",
    "dialer-proxy",
    "skip-cert-verify",
    "interface-name",
    "routing-mark",
    "ip-version",
];

/// The `override` fields that change proxies' names, or others.
pub const OVERRIDE_NAMES: &[&str] = &[
    "proxy-name",
    "additional-prefix",
    "additional-suffix",
    "name-cert-verify",
    "override-expr",
];

const PROVIDER: &[(&str, Tier)] = &[
    // Groups test their members themselves.
    ("health-check", Ignored),
    ("size-limit", Ignored),
    // Its contents would not read.
    ("age-secret-key", Unsupported),
];

pub fn lower(doc: &mut Fields, out: &mut Lowered, warnings: &mut Vec<String>) -> Result<Providers> {
    let mut providers = Providers::default();
    let Some(mut all) = doc.map("proxy-providers")?.map(Fields::loose) else {
        return Ok(providers);
    };
    for name in all.keys() {
        let at = all.at(&name);
        let mut f = all
            .map(&name)?
            .ok_or_else(|| anyhow!("{}: a map, not nothing", at))?;
        if let Some(url) = health_url(&mut f)? {
            providers.health_urls.insert(name.clone(), url);
        }
        let provider = provider(&name, &mut f, warnings)?;
        f.finish(PROVIDER, |_| false, warnings)?;
        out.outbound_providers.push(provider);
        providers.names.push(name);
    }
    providers.names.sort();
    Ok(providers)
}

/// The URL of a provider's `health-check`, which stays for `finish` to
/// warn of.
fn health_url(f: &mut Fields) -> Result<Option<String>> {
    let Some(node) = f.take("health-check") else {
        return Ok(None);
    };
    let url = match &node {
        Node::Map(m) => m.get("url").and_then(Node::as_string),
        _ => None,
    };
    f.put("health-check", node);
    Ok(url.filter(|u| !u.is_empty()))
}

fn provider(name: &str, f: &mut Fields, warnings: &mut Vec<String>) -> Result<Value> {
    let mut p = Map::new();
    p.insert("tag".into(), json!(name));
    let kind = f
        .string("type")?
        .ok_or_else(|| anyhow!("{}: missing", f.at("type")))?;
    let filter = split(f.string("filter")?, '`');
    let exclude_filter = split(f.string("exclude-filter")?, '`');
    let exclude_type = split(f.string("exclude-type")?, '|');
    let detour = f.string("dialer-proxy")?;
    let overrides = match f.map("override")? {
        None => None,
        // Mihomo passes over a field of it that it does not know.
        Some(mut o) => {
            let mut fields = Map::new();
            for key in o.keys() {
                if OVERRIDDEN.contains(&key.as_str()) || OVERRIDE_NAMES.contains(&key.as_str()) {
                    let value = o.take(&key).expect("one of its keys");
                    fields.insert(key, value.to_json());
                }
            }
            o.finish(&[], |_| false, warnings)?;
            Some(Value::Object(fields))
        }
    };
    let interval = f.int::<u64>("interval")?.filter(|s| *s > 0);
    match kind.as_str() {
        "http" => {
            let url = f
                .string("url")?
                .ok_or_else(|| anyhow!("{}: missing", f.at("url")))?;
            p.insert("type".into(), json!("remote"));
            p.insert("url".into(), json!(url));
            // Where Mihomo keeps its copy; sail keeps its own.
            f.take("path");
            if let Some(seconds) = interval {
                p.insert("update_interval".into(), json!(format!("{}s", seconds)));
            }
            // As Mihomo: directly, unless through the policy `proxy`.
            let via = f.string("proxy")?.unwrap_or_else(|| "DIRECT".to_string());
            match f.map("header")? {
                Some(mut h) => {
                    let mut headers = Map::new();
                    for key in h.keys() {
                        headers.insert(key.clone(), json!(h.strings(&key)?));
                    }
                    p.insert(
                        "http_client".into(),
                        json!({ "detour": via, "headers": headers }),
                    );
                }
                None => {
                    p.insert("download_detour".into(), json!(via));
                }
            }
        }
        "file" => {
            let path = f
                .string("path")?
                .ok_or_else(|| anyhow!("{}: missing", f.at("path")))?;
            p.insert("type".into(), json!("local"));
            p.insert("path".into(), json!(path));
            if let Some(seconds) = interval {
                p.insert("update_interval".into(), json!(format!("{}s", seconds)));
            }
        }
        "inline" => {
            let at = f.at("payload");
            let payload = f.list("payload")?;
            p.insert("type".into(), json!("inline"));
            p.insert(
                "outbounds".into(),
                inline(
                    payload,
                    &filter,
                    &exclude_filter,
                    &exclude_type,
                    detour.as_deref(),
                    overrides.as_ref().and_then(Value::as_object),
                    warnings,
                )
                .map_err(|e| anyhow!("{}: {}", at, e))?,
            );
            return Ok(Value::Object(p));
        }
        other => {
            return Err(anyhow!(
                "{}: {:?} is none of http, file and inline",
                f.at("type"),
                other
            ))
        }
    }
    // What would fail the provider at start fails the configuration here.
    #[cfg(feature = "outbound-provider")]
    super::subscription::Selection::of(
        &filter,
        &exclude_filter,
        &exclude_type,
        detour.as_deref(),
        overrides.as_ref().and_then(Value::as_object),
        &mut Vec::new(),
    )?;
    for (key, list) in [
        ("filter", filter),
        ("exclude_filter", exclude_filter),
        ("exclude_type", exclude_type),
    ] {
        if !list.is_empty() {
            p.insert(key.into(), json!(list));
        }
    }
    if let Some(detour) = detour {
        p.insert("detour".into(), json!(detour));
    }
    if let Some(overrides) = overrides {
        p.insert("override".into(), overrides);
    }
    Ok(Value::Object(p))
}

/// The outbounds of an inline provider's `payload`, picked and changed as
/// its fields say.
#[allow(clippy::too_many_arguments)]
fn inline(
    payload: Vec<Node>,
    filter: &[String],
    exclude_filter: &[String],
    exclude_type: &[String],
    detour: Option<&str>,
    overrides: Option<&Map<String, Value>>,
    warnings: &mut Vec<String>,
) -> Result<Value> {
    #[cfg(feature = "outbound-provider")]
    {
        use super::subscription::{read_clash, Selection};
        let selection = Selection::of(
            filter,
            exclude_filter,
            exclude_type,
            detour,
            overrides,
            warnings,
        )?;
        let proxies = read_clash(payload, &selection)?;
        warnings.extend(proxies.warnings);
        Ok(Value::Array(
            proxies.proxies.into_iter().map(|(_, o)| o).collect(),
        ))
    }
    #[cfg(not(feature = "outbound-provider"))]
    {
        let _ = (
            payload,
            filter,
            exclude_filter,
            exclude_type,
            detour,
            overrides,
            warnings,
        );
        Err(anyhow!(
            "needs the outbound-provider feature, which is not compiled in"
        ))
    }
}

/// A Clash field of several values, as one string: `filter`s split at
/// backquotes, `exclude-type`s at bars.
pub fn split(value: Option<String>, at: char) -> Vec<String> {
    value
        .map(|v| {
            v.split(at)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}
