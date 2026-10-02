//! `rule-providers`, as rule-sets: `http` ones downloaded as remote
//! rule-sets are, `file` ones read as local, `inline` ones held in place;
//! in Mihomo's YAML, text or MRS, of domains, IP prefixes or rules.
//!
//! And the rule-sets `GEOSITE` and `GEOIP` rules name: MetaCubeX's
//! meta-rules-dat publishes each site list and country of the databases
//! Mihomo downloads by default as a rule-set of its own, which sail
//! downloads instead.

use anyhow::{anyhow, Result};
use indexmap::IndexMap;
use serde_json::{json, Map, Value};

use super::fields::{Fields, Tier};
use super::group::Policies;
use super::Lowered;
use crate::config::rule_set::ClashBehavior;

use Tier::*;

/// Where meta-rules-dat's rule-sets are.
const META_RULES: &str = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo";

/// The rule-sets rules may name, and those they name that are made here.
#[derive(Default)]
pub struct Sets {
    /// The rule-providers, by name.
    providers: IndexMap<String, ClashBehavior>,
    /// The GEOSITE and GEOIP sets rules name, by tag: each downloaded.
    geo: IndexMap<String, (String, ClashBehavior)>,
    /// Whether rule-sets may be named at all: not within a classical
    /// rule-provider.
    closed: bool,
    /// The listeners, each its inbound type and name: what `IN-TYPE`
    /// rules name besides Mihomo's own listeners.
    inbounds: Vec<(String, String)>,
}

impl Sets {
    /// None: for a rule-provider's own rules.
    pub fn none() -> Self {
        Sets {
            closed: true,
            ..Default::default()
        }
    }

    /// The behavior of the rule-provider `name`.
    pub fn provider(&self, name: &str) -> Result<ClashBehavior> {
        if self.closed {
            return Err(anyhow!("a rule-provider's rules name no rule-set"));
        }
        self.providers
            .get(name)
            .copied()
            .ok_or_else(|| anyhow!("no rule-provider is named {:?}", name))
    }

    pub fn set_inbounds(&mut self, inbounds: Vec<(String, String)>) {
        self.inbounds = inbounds;
    }

    /// The listeners of inbound type `kind`, by name.
    pub fn inbounds_of<'a>(&'a self, kind: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.inbounds
            .iter()
            .filter(move |(k, _)| k == kind)
            .map(|(_, name)| name.as_str())
    }

    /// The tag of the rule-set of the site list `name`.
    pub fn geosite(&mut self, name: &str) -> Result<String> {
        self.geo_set("geosite", name, ClashBehavior::Domain)
    }

    /// The tag of the rule-set of the country `code`: `LAN` for the
    /// private ranges, as in Mihomo.
    pub fn geoip(&mut self, code: &str) -> Result<String> {
        let code = match code.to_ascii_lowercase().as_str() {
            "lan" => "private".to_string(),
            code => code.to_string(),
        };
        self.geo_set("geoip", &code, ClashBehavior::Ipcidr)
    }

    fn geo_set(&mut self, kind: &str, name: &str, behavior: ClashBehavior) -> Result<String> {
        if self.closed {
            return Err(anyhow!("a rule-provider's rules name no {} list", kind));
        }
        let name = name.to_ascii_lowercase();
        let valid = !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '@' | '!' | '.'));
        if !valid {
            return Err(anyhow!("{:?} is no {} list", name, kind));
        }
        let tag = format!("{}:{}", kind, name);
        let url = format!("{}/{}/{}.mrs", META_RULES, kind, name.replace('!', "%21"));
        self.geo.insert(tag.clone(), (url, behavior));
        Ok(tag)
    }

    /// Sorts an entry of Mihomo's domain lists into `patterns`, and the tags
    /// of the rule-sets it names, `geosite:a,b` and `rule-set:a,b`, into
    /// `tags`.
    pub fn domain_entry(
        &mut self,
        entry: &str,
        patterns: &mut Vec<String>,
        tags: &mut Vec<String>,
    ) -> Result<()> {
        let lower = entry.to_ascii_lowercase();
        if lower.starts_with("geosite:") {
            for name in entry["geosite:".len()..].split(',') {
                tags.push(self.geosite(name.trim())?);
            }
        } else if lower.starts_with("rule-set:") {
            for name in entry["rule-set:".len()..].split(',') {
                let name = name.trim();
                if self.provider(name)? == ClashBehavior::Ipcidr {
                    return Err(anyhow!(
                        "{:?} is a rule-set of IP prefixes, not of domains",
                        name
                    ));
                }
                tags.push(name.to_string());
            }
        } else {
            // Mihomo's domain trie takes `*` as a whole label only.
            let labels = lower.strip_prefix("+.").unwrap_or(&lower);
            if labels.split('.').any(|l| l.contains('*') && l != "*") {
                return Err(anyhow!(
                    "{:?}: \"*\" must be a whole label, as Mihomo takes it",
                    entry
                ));
            }
            patterns.push(entry.to_string());
        }
        Ok(())
    }

    /// The rule-sets of the GEOSITE and GEOIP rules, downloaded directly.
    pub fn into_geo_sets(self) -> Vec<Value> {
        self.geo
            .into_iter()
            .map(|(tag, (url, behavior))| {
                json!({
                    "type": "remote",
                    "tag": tag,
                    "format": "mrs",
                    "behavior": behavior,
                    "url": url,
                    "download_detour": "DIRECT",
                })
            })
            .collect()
    }
}

/// `path-in-bundle` names where Mihomo finds the copy to start with, in a
/// bundle of its own, where sail downloads it.
const PROVIDER: &[(&str, Tier)] = &[
    ("path-in-bundle", Ignored),
    // Read by inline ones alone, and passed over by the others, as Mihomo.
    ("payload", Ignored),
];

pub fn lower(
    doc: &mut Fields,
    policies: &Policies,
    out: &mut Lowered,
    warnings: &mut Vec<String>,
) -> Result<Sets> {
    let mut sets = Sets::default();
    let Some(mut providers) = doc.map("rule-providers")?.map(Fields::loose) else {
        return Ok(sets);
    };
    for name in providers.keys() {
        let at = providers.at(&name);
        let mut f = providers
            .map(&name)?
            .ok_or_else(|| anyhow!("{}: a map, not nothing", at))?;
        let set = provider(&name, &mut f, policies, out.home.as_deref())?;
        f.finish(PROVIDER, |_| false, warnings)?;
        sets.providers.insert(name, set.1);
        out.rule_sets.push(set.0);
    }
    Ok(sets)
}

fn provider(
    name: &str,
    f: &mut Fields,
    policies: &Policies,
    home: Option<&std::path::Path>,
) -> Result<(Value, ClashBehavior)> {
    let behavior = match f.string("behavior")?.as_deref() {
        Some("domain") => ClashBehavior::Domain,
        Some("ipcidr") => ClashBehavior::Ipcidr,
        Some("classical") => ClashBehavior::Classical,
        Some(other) => {
            return Err(anyhow!(
                "{}: {:?} is none of domain, ipcidr and classical",
                f.at("behavior"),
                other
            ))
        }
        None => return Err(anyhow!("{}: missing", f.at("behavior"))),
    };
    let format = match f.string("format")?.as_deref() {
        None | Some("yaml") => "clash-yaml",
        Some("text") => "clash-text",
        Some("mrs") => {
            if behavior == ClashBehavior::Classical {
                return Err(anyhow!(
                    "{}: an mrs rule-provider is of domains or IP prefixes",
                    f.at("format")
                ));
            }
            "mrs"
        }
        Some(other) => {
            return Err(anyhow!(
                "{}: {:?} is none of yaml, text and mrs",
                f.at("format"),
                other
            ))
        }
    };
    let mut set = Map::new();
    set.insert("tag".into(), json!(name));
    let kind = f
        .string("type")?
        .ok_or_else(|| anyhow!("{}: missing", f.at("type")))?;
    match kind.as_str() {
        "http" => {
            let url = f
                .string("url")?
                .ok_or_else(|| anyhow!("{}: missing", f.at("url")))?;
            set.insert("type".into(), json!("remote"));
            set.insert("url".into(), json!(url));
            set.insert("format".into(), json!(format));
            set.insert("behavior".into(), json!(behavior));
            // Where Mihomo keeps its copy; sail keeps its own, but takes
            // no path Mihomo would refuse.
            home_path(f, "path", home)?;
            if let Some(limit) = size_limit(f)? {
                set.insert("size_limit".into(), json!(limit));
            }
            if let Some(seconds) = f.int::<u64>("interval")?.filter(|s| *s > 0) {
                set.insert("update_interval".into(), json!(format!("{}s", seconds)));
            }
            // As Mihomo: directly, unless through the policy `proxy`.
            let via = f.string("proxy")?.unwrap_or_else(|| "DIRECT".to_string());
            if !policies.has(&via) {
                return Err(anyhow!(
                    "{}: no proxy or group is named {:?}",
                    f.at("proxy"),
                    via
                ));
            }
            match f.map("header")? {
                Some(mut h) => {
                    let mut headers = Map::new();
                    for key in h.keys() {
                        headers.insert(key.clone(), json!(h.strings(&key)?));
                    }
                    set.insert(
                        "http_client".into(),
                        json!({ "detour": via, "headers": headers }),
                    );
                }
                None => {
                    set.insert("download_detour".into(), json!(via));
                }
            }
        }
        "file" => {
            let path =
                home_path(f, "path", home)?.ok_or_else(|| anyhow!("{}: missing", f.at("path")))?;
            // A file's is never downloaded, as in Mihomo.
            f.take("size-limit");
            set.insert("type".into(), json!("local"));
            set.insert("path".into(), json!(path));
            set.insert("format".into(), json!(format));
            set.insert("behavior".into(), json!(behavior));
            f.take("interval");
        }
        "inline" => {
            let payload = f.strings("payload")?;
            set.insert("type".into(), json!("inline"));
            set.insert(
                "rules".into(),
                inline(&payload, behavior, &f.at("payload"))?,
            );
        }
        other => {
            return Err(anyhow!(
                "{}: {:?} is none of http, file and inline",
                f.at("type"),
                other
            ))
        }
    }
    Ok((Value::Object(set), behavior))
}

/// The rules of an inline rule-provider, as a rule-set's.
fn inline(payload: &[String], behavior: ClashBehavior, at: &str) -> Result<Value> {
    match behavior {
        ClashBehavior::Domain => Ok(json!([domains(payload)])),
        ClashBehavior::Ipcidr => Ok(json!([{ "ip_cidr": payload }])),
        ClashBehavior::Classical => payload
            .iter()
            .enumerate()
            .map(|(i, line)| {
                super::rule::headless(line)
                    .map(Value::Object)
                    .map_err(|e| anyhow!("{}[{}]: {}", at, i, e))
            })
            .collect::<Result<Vec<_>>>()
            .map(Value::Array),
    }
}

/// Mihomo's domain patterns, as its domain sets match them, as a rule's
/// conditions: `+.a` is a and its subdomains, `.a` its subdomains alone,
/// a `*` label any one label, and anything else the domain itself.
pub fn domains(patterns: &[String]) -> Map<String, Value> {
    let mut rule = Map::new();
    let (mut domain, mut suffix, mut regex) = (Vec::new(), Vec::new(), Vec::new());
    for entry in patterns {
        let entry = entry.trim().to_ascii_lowercase();
        if let Some(base) = entry.strip_prefix("+.") {
            suffix.push(base.to_string());
        } else if entry.starts_with('.') {
            suffix.push(entry);
        } else if entry.split('.').any(|l| l == "*") {
            let labels: Vec<String> = entry
                .split('.')
                .map(|l| {
                    if l == "*" {
                        "[^.]+".to_string()
                    } else {
                        regex_escape(l)
                    }
                })
                .collect();
            regex.push(format!("^{}$", labels.join("\\.")));
        } else if !entry.is_empty() {
            domain.push(entry);
        }
    }
    for (key, list) in [
        ("domain", domain),
        ("domain_suffix", suffix),
        ("domain_regex", regex),
    ] {
        if !list.is_empty() {
            rule.insert(key.into(), json!(list));
        }
    }
    rule
}

/// The conditions of a domain list's `patterns` and rule-sets `tags`, one
/// for each kind there is: any of them holding.
pub fn domain_conditions(patterns: Vec<String>, tags: Vec<String>) -> Vec<Map<String, Value>> {
    let mut conditions = Vec::new();
    if !patterns.is_empty() {
        conditions.push(domains(&patterns));
    }
    if !tags.is_empty() {
        let mut rule = Map::new();
        rule.insert("rule_set".into(), json!(tags));
        conditions.push(rule);
    }
    conditions
}

/// A provider's or rule-provider's `path`, kept where Mihomo keeps it: in
/// `home`, the data directory (Mihomo's home), as its `IsSafePath` has it.
/// A relative path may not climb out of it; an absolute one must be in it,
/// and without a home to tell, one is refused. On Windows a path with a
/// drive or a root, but not both (`C:x`, `\x`), is held to the data
/// directory like an absolute one, which it never lands in.
pub(super) fn home_path(
    f: &mut Fields,
    key: &str,
    home: Option<&std::path::Path>,
) -> Result<Option<String>> {
    let Some(path) = f.string(key)? else {
        return Ok(None);
    };
    if !crate::common::path::stays_in(home, &path) {
        return Err(anyhow!(
            "{}: {:?} is not in the data directory, which a provider's path stays in, \
             as in Mihomo",
            f.at(key),
            path
        ));
    }
    Ok(Some(path))
}

/// Mihomo's `size-limit`: the bytes a download may be, none at 0 or less.
pub(super) fn size_limit(f: &mut Fields) -> Result<Option<u64>> {
    Ok(f.int::<i64>("size-limit")?
        .filter(|n| *n > 0)
        .map(|n| n as u64))
}

fn regex_escape(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if "\\.+*?()|[]{}^$#&-~".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

#[cfg(all(test, windows))]
mod windows_tests {
    use std::path::Path;

    /// Windows paths: one with a drive and a root is held to the data
    /// directory; one with only one of them is refused, since where it
    /// lands depends on the process's current drive and directory.
    #[test]
    fn a_provider_path_on_windows_lands_in_the_data_directory_or_is_refused() {
        let home = Path::new(r"C:\sail\data");
        let config = |path: &str| {
            let yaml = format!(
                "proxy-providers: {{ a: {{ type: file, path: '{path}' }} }}\n\
                 proxy-groups: [{{ name: G, type: select, use: [a] }}]\n"
            );
            super::super::parse_in(&yaml, Some(home))
        };
        for taken in [r"C:\sail\data\a.yaml", r"sub\a.yaml", r".\a.yaml"] {
            let config = config(taken).unwrap_or_else(|e| panic!("{taken}: {e:#}"));
            assert_eq!(config.outbound_providers[0].path.as_deref(), Some(taken));
        }
        for refused in [
            r"C:\Windows\a.yaml",
            r"\\server\share\a.yaml",
            r"\sail\data\a.yaml",
            r"C:a.yaml",
            r"C:sail\data\a.yaml",
            r"sub\..\..\a.yaml",
        ] {
            let err = format!("{:#}", config(refused).unwrap_err());
            assert!(
                err.contains("is not in the data directory"),
                "{refused}: {err}"
            );
        }
    }
}
