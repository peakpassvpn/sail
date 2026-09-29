//! Rule-sets, as sing-box describes them: `route.rule_set`, and the
//! headless rules they hold, inline or in a file of the source format.

use anyhow::{anyhow, Result};
use serde_derive::{Deserialize, Serialize};

use super::model::{duration, listable};

/// Where a rule-set's `{tag}` goes in its path or URL, when one entry
/// names several.
pub const TAG_PLACEHOLDER: &str = "{tag}";

/// A rule-set, or several alike under one entry.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RuleSet {
    #[serde(rename = "type", default)]
    pub kind: RuleSetKind,
    /// One tag, or several, each put in place of `{tag}` in the path or
    /// URL.
    #[serde(with = "listable")]
    pub tag: Vec<String>,
    /// `source` (JSON) or `binary` (`.srs`); from the extension of the
    /// path or URL when unset. A sail extension, for Clash's rule-providers:
    /// `mrs` (Mihomo's binary), `clash-yaml` or `clash-text`, which take a
    /// `behavior`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<RuleSetFormat>,
    /// A sail extension, for the Clash formats: what each line is,
    /// `domain`, `ipcidr` or `classical` (a Clash rule without its target).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub behavior: Option<ClashBehavior>,
    /// `inline`: the rules.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<HeadlessRule>,
    /// `local`: the file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// `remote`: where it is downloaded from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// `remote`: a file to start from before the first download.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_path: Option<String>,
    /// `remote`: how often it is downloaded again; 1d when unset.
    #[serde(default, with = "duration", skip_serializing_if = "Option::is_none")]
    pub update_interval: Option<std::time::Duration>,
    /// `remote`: the outbound it is downloaded through; deprecated in
    /// sing-box for `http_client`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download_detour: Option<String>,
    /// `remote`: the HTTP client it is downloaded with, by tag or in place.
    /// With neither this nor `download_detour`, the default one of
    /// `http_clients` (`route.default_http_client`, or else the first), or
    /// else the default outbound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_client: Option<super::model::HttpClientRef>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleSetKind {
    #[default]
    Inline,
    Local,
    Remote,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RuleSetFormat {
    Source,
    Binary,
    /// Mihomo's binary format.
    Mrs,
    /// Clash's YAML, a `payload` list.
    ClashYaml,
    /// Clash's text, a line each.
    ClashText,
}

impl RuleSetFormat {
    /// Whether it is one of Clash's, which take a behavior.
    pub fn is_clash(self) -> bool {
        matches!(
            self,
            RuleSetFormat::Mrs | RuleSetFormat::ClashYaml | RuleSetFormat::ClashText
        )
    }
}

/// What the lines of a Clash rule-set are.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ClashBehavior {
    /// Domains, as Mihomo writes them: `+.x`, `.x`, `*.x` or `x`.
    Domain,
    /// IP prefixes.
    Ipcidr,
    /// Clash rules without their targets.
    Classical,
}

impl RuleSet {
    /// The format, as given or as the path or URL's extension says.
    pub fn format(&self) -> Option<RuleSetFormat> {
        if self.format.is_some() {
            return self.format;
        }
        let location = self.path.as_deref().or(self.url.as_deref())?;
        // The extension of a URL is its path's, before any query.
        let path = location.split(['?', '#']).next().unwrap_or(location);
        if path.ends_with(".json") {
            Some(RuleSetFormat::Source)
        } else if path.ends_with(".srs") {
            Some(RuleSetFormat::Binary)
        } else if path.ends_with(".mrs") {
            Some(RuleSetFormat::Mrs)
        } else {
            None
        }
    }

    /// `location` for the tag `tag`, `{tag}` put in place.
    pub fn for_tag(location: &str, tag: &str) -> String {
        location.replace(TAG_PLACEHOLDER, tag)
    }

    /// The mistakes one entry can make on its own.
    pub fn check(&self) -> Result<()> {
        if self.tag.is_empty() || self.tag.iter().any(String::is_empty) {
            return Err(anyhow!("tag: missing"));
        }
        let several = self.tag.len() > 1;
        let only = |set: bool, field: &str, kind: &str| {
            if set {
                Err(anyhow!("{}: only a {} rule-set takes one", field, kind))
            } else {
                Ok(())
            }
        };
        match self.kind {
            RuleSetKind::Inline => {
                if several {
                    return Err(anyhow!("tag: an inline rule-set takes one"));
                }
                only(self.format.is_some(), "format", "local or remote")?;
            }
            RuleSetKind::Local => {
                let path = self
                    .path
                    .as_deref()
                    .ok_or_else(|| anyhow!("path: missing"))?;
                if several && !path.contains(TAG_PLACEHOLDER) {
                    return Err(anyhow!("path: several tags need {} in it", TAG_PLACEHOLDER));
                }
                only(!self.rules.is_empty(), "rules", "inline")?;
            }
            RuleSetKind::Remote => {
                let url = self.url.as_deref().ok_or_else(|| anyhow!("url: missing"))?;
                if !url.starts_with("https://") && !url.starts_with("http://") {
                    return Err(anyhow!("url: \"{}\" is not an http(s) URL", url));
                }
                if several && !url.contains(TAG_PLACEHOLDER) {
                    return Err(anyhow!("url: several tags need {} in it", TAG_PLACEHOLDER));
                }
                if let Some(path) = &self.initial_path {
                    if several && !path.contains(TAG_PLACEHOLDER) {
                        return Err(anyhow!(
                            "initial_path: several tags need {} in it",
                            TAG_PLACEHOLDER
                        ));
                    }
                }
                if self.http_client.is_some() && self.download_detour.is_some() {
                    return Err(anyhow!(
                        "http_client: not with download_detour, which it replaces"
                    ));
                }
                if self.update_interval == Some(std::time::Duration::ZERO) {
                    return Err(anyhow!("update_interval: must be more than 0"));
                }
                only(!self.rules.is_empty(), "rules", "inline")?;
            }
        }
        if self.kind != RuleSetKind::Local {
            only(self.path.is_some(), "path", "local")?;
        }
        if self.kind != RuleSetKind::Remote {
            only(self.url.is_some(), "url", "remote")?;
            only(self.initial_path.is_some(), "initial_path", "remote")?;
            only(self.update_interval.is_some(), "update_interval", "remote")?;
            only(self.download_detour.is_some(), "download_detour", "remote")?;
            only(self.http_client.is_some(), "http_client", "remote")?;
        }
        match (self.format().filter(|f| f.is_clash()), self.behavior) {
            (Some(_), None) => {
                return Err(anyhow!("behavior: a Clash format needs one"));
            }
            (None, Some(_)) => {
                return Err(anyhow!("behavior: only for the Clash formats"));
            }
            (Some(RuleSetFormat::Mrs), Some(ClashBehavior::Classical)) => {
                return Err(anyhow!("behavior: an mrs rule-set is domain or ipcidr"));
            }
            _ => {}
        }
        if self.kind != RuleSetKind::Inline && self.format().is_none() {
            return Err(anyhow!(
                "format: set it; the file's extension is neither .json nor .srs"
            ));
        }
        Ok(())
    }
}

/// A rule-set in the source format: a file, or what a download holds.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SourceRuleSet {
    pub version: u8,
    #[serde(default)]
    pub rules: Vec<HeadlessRule>,
}

/// The highest source and binary versions read: sing-box 1.14's.
pub const MAX_VERSION: u8 = 5;

/// A rule of a rule-set: a condition alone, with no action. A plain one
/// matches as a routing rule's conditions do; a logical one (`type:
/// logical`) combines others with `and` or `or`.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HeadlessRule {
    /// `default`, or `logical`.
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,

    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub query_type: Vec<serde_json::Value>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub network: Vec<String>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub domain: Vec<String>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub domain_suffix: Vec<String>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub domain_keyword: Vec<String>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub domain_regex: Vec<String>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub source_ip_cidr: Vec<String>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub ip_cidr: Vec<String>,
    /// A sail extension, as a routing rule's: autonomous systems, of
    /// `asn.mmdb` in the asset directory.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub ip_asn: Vec<u32>,
    /// Sail extensions, as a routing rule's: of a plain HTTP request.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub http_user_agent: Vec<String>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub url_regex: Vec<String>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub source_port: Vec<u16>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub source_port_range: Vec<String>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub port: Vec<u16>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub port_range: Vec<String>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub process_name: Vec<String>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub process_path: Vec<String>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub process_path_regex: Vec<String>,
    /// A sail extension, as Mihomo's `PROCESS-NAME-REGEX`: regular
    /// expressions the program's name, its path's last part, matches.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub process_name_regex: Vec<String>,
    /// Refused as a routing rule's is: no platform sail runs on tells
    /// them yet.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub package_name: Vec<String>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub package_name_regex: Vec<String>,
    /// Conditions sail does not match yet; a rule that sets one is refused
    /// when the rule-set is read.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub network_type: Vec<serde_json::Value>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub network_is_expensive: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub network_is_constrained: bool,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub wifi_ssid: Vec<String>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub wifi_bssid: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_interface_address: Option<serde_json::Value>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub default_interface_address: Vec<String>,

    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub invert: bool,
    /// `logical`: `and` or `or`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// `logical`: the rules combined.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<HeadlessRule>,
}

impl HeadlessRule {
    /// The first condition set that sail does not match yet.
    pub fn unsupported(&self) -> Option<&'static str> {
        [
            ("network_type", !self.network_type.is_empty()),
            ("network_is_expensive", self.network_is_expensive),
            ("network_is_constrained", self.network_is_constrained),
            ("wifi_ssid", !self.wifi_ssid.is_empty()),
            ("wifi_bssid", !self.wifi_bssid.is_empty()),
            (
                "network_interface_address",
                self.network_interface_address.is_some(),
            ),
            (
                "default_interface_address",
                !self.default_interface_address.is_empty(),
            ),
        ]
        .into_iter()
        .find(|(_, set)| *set)
        .map(|(field, _)| field)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule_set(json: serde_json::Value) -> Result<RuleSet> {
        let rule_set: RuleSet = serde_json::from_value(json)?;
        rule_set.check()?;
        Ok(rule_set)
    }

    #[test]
    fn formats_come_from_the_extension() {
        let local = rule_set(serde_json::json!({
            "type": "local", "tag": "cn", "path": "cn.srs"
        }))
        .unwrap();
        assert_eq!(local.format(), Some(RuleSetFormat::Binary));
        let remote = rule_set(serde_json::json!({
            "type": "remote", "tag": ["a", "b"],
            "url": "https://example.com/{tag}.json?raw=1"
        }))
        .unwrap();
        assert_eq!(remote.format(), Some(RuleSetFormat::Source));
        assert_eq!(
            RuleSet::for_tag(remote.url.as_deref().unwrap(), "a"),
            "https://example.com/a.json?raw=1"
        );
    }

    #[test]
    fn mistakes() {
        for (json, message) in [
            (
                serde_json::json!({ "type": "local", "tag": "x", "path": "x.txt" }),
                "format: set it",
            ),
            (
                serde_json::json!({ "type": "local", "tag": ["a", "b"], "path": "x.srs" }),
                "path: several tags need {tag}",
            ),
            (
                serde_json::json!({ "type": "remote", "tag": "x", "url": "ftp://a/x.srs" }),
                "is not an http(s) URL",
            ),
            (
                serde_json::json!({ "tag": "x", "rules": [], "path": "x.srs" }),
                "path: only a local rule-set takes one",
            ),
            (
                serde_json::json!({ "type": "local", "tag": "", "path": "x.srs" }),
                "tag: missing",
            ),
        ] {
            let err = rule_set(json.clone()).unwrap_err().to_string();
            assert!(err.contains(message), "{}: {}", json, err);
        }
    }
}
