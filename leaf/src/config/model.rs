//! The configuration every input format is turned into.
//!
//! JSON is written in this shape directly; other formats (`.conf`) are
//! translated into it. Field names follow sing-box wherever the meaning is
//! the same.
//!
//! What an inbound or outbound takes beyond its type and tag belongs to its
//! protocol: the model keeps it as an untyped map, and the protocol's factory
//! reads it into its own options type when the handler is built. That keeps
//! the whole of a protocol, options included, in the protocol's directory.

use std::collections::{HashMap, HashSet};

use anyhow::{anyhow, Result};
use serde_derive::{Deserialize, Serialize};

/// The options of one inbound or outbound, read by its protocol.
pub type Options = serde_json::Map<String, serde_json::Value>;

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub log: Log,
    /// Environment variables set before anything else is read. Stands in
    /// for runtime options until they are part of the configuration.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub env: HashMap<String, String>,
    #[serde(default)]
    pub dns: Dns,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inbounds: Vec<Inbound>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outbounds: Vec<Outbound>,
    #[serde(default)]
    pub route: Route,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    #[default]
    Info,
    Warn,
    Error,
    /// Logs nothing.
    None,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Full,
    Compact,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Log {
    #[serde(default)]
    pub level: LogLevel,
    /// A file to append to. Logs go to the console when it is not set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
    #[serde(default)]
    pub format: LogFormat,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Dns {
    #[serde(default = "default_dns_servers")]
    pub servers: Vec<String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub hosts: HashMap<String, Vec<String>>,
}

fn default_dns_servers() -> Vec<String> {
    vec!["1.1.1.1".to_string()]
}

impl Default for Dns {
    fn default() -> Self {
        Self {
            servers: default_dns_servers(),
            hosts: HashMap::new(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Inbound {
    #[serde(rename = "type")]
    pub protocol: String,
    /// Defaults to the type.
    #[serde(default)]
    pub tag: String,
    /// The address to listen on; defaults to `127.0.0.1`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen: Option<String>,
    /// The port to listen on. An inbound without one does not listen, and is
    /// only useful as a part of another inbound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_port: Option<u16>,
    #[serde(flatten)]
    pub options: Options,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Outbound {
    #[serde(rename = "type")]
    pub protocol: String,
    /// Defaults to the type.
    #[serde(default)]
    pub tag: String,
    #[serde(flatten)]
    pub options: Options,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Route {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<Rule>,
    /// The outbound for connections no rule matches; defaults to the first
    /// outbound.
    #[serde(rename = "final", default, skip_serializing_if = "Option::is_none")]
    pub final_outbound: Option<String>,
    /// Whether a domain no rule matches is resolved and matched again by its
    /// address.
    #[serde(default)]
    pub domain_resolve: bool,
}

/// A routing rule. It matches when every condition it sets matches, and a
/// condition that lists several values matches when any of them does.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domain: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domain_suffix: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domain_keyword: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ip_cidr: Vec<String>,
    /// Country codes, looked up in `geo.mmdb` in the asset directory.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub geoip: Vec<String>,
    /// Site groups, looked up in `site.dat` in the asset directory.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub geosite: Vec<String>,
    /// `mmdb:<file>:<code>` or `site:<file>:<code>`, for data files other
    /// than the default ones.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub external: Vec<String>,
    /// Ports and port ranges: `443`, `1000-2000`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub port_range: Vec<String>,
    /// `tcp`, `udp`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub network: Vec<String>,
    /// Tags of the inbounds a connection came in through.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inbound: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub process_name: Vec<String>,
    /// Where a matching connection goes.
    pub outbound: String,
}

impl Config {
    /// Fills in what the configuration leaves to defaults, and checks what
    /// can be checked without building anything.
    pub fn validate(&mut self) -> Result<()> {
        for inbound in &mut self.inbounds {
            if inbound.tag.is_empty() {
                inbound.tag = inbound.protocol.clone();
            }
        }
        for outbound in &mut self.outbounds {
            if outbound.tag.is_empty() {
                outbound.tag = outbound.protocol.clone();
            }
        }

        let outbounds: HashSet<&str> = self.outbounds.iter().map(|o| o.tag.as_str()).collect();
        if let Some(tag) = &self.route.final_outbound {
            if !outbounds.contains(tag.as_str()) {
                return Err(anyhow!("route.final: outbound [{}] does not exist", tag));
            }
        }
        for (i, rule) in self.route.rules.iter().enumerate() {
            if !outbounds.contains(rule.outbound.as_str()) {
                return Err(anyhow!(
                    "route.rules[{}]: outbound [{}] does not exist",
                    i,
                    rule.outbound
                ));
            }
        }
        Ok(())
    }

    /// Parses a JSON configuration.
    pub fn from_json(s: &str) -> Result<Self> {
        let de = &mut serde_json::Deserializer::from_str(s);
        let mut config: Config = serde_path_to_error::deserialize(de)
            .map_err(|e| anyhow!("{}: {}", path(&e), e.inner()))?;
        config.validate()?;
        Ok(config)
    }
}

/// Reads the options of the inbound or outbound `tag` into its protocol's
/// options type, naming the field at fault on failure.
pub fn parse_options<T: serde::de::DeserializeOwned>(
    kind: &str,
    tag: &str,
    options: &Options,
) -> Result<T> {
    serde_path_to_error::deserialize(serde_json::Value::Object(options.clone()))
        .map_err(|e| anyhow!("[{}] {}: {}: {}", tag, kind, path(&e), e.inner()))
}

fn path<E>(e: &serde_path_to_error::Error<E>) -> String {
    let path = e.path().to_string();
    if path == "." {
        "options".to_string()
    } else {
        path
    }
}

/// Resolves a certificate or a private key, either of which may be given
/// inline or as a path.
///
/// The two halves of a keypair are configured the same way and have to be read
/// the same way. They were not: a certificate was recognised inline and a key
/// never was, so an inline key became a path under the asset directory made of
/// PEM, and what the operator saw was "no private keys found" about a key that
/// was right there in the configuration.
pub fn resolve_certificate(value: &str) -> String {
    if value.contains("-----BEGIN") {
        return value.to_string();
    }
    let path = std::path::Path::new(value);
    if path.is_absolute() {
        return path.to_string_lossy().to_string();
    }
    std::path::Path::new(&*crate::option::ASSET_LOCATION)
        .join(path)
        .to_string_lossy()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const INLINE_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIGH\n-----END PRIVATE KEY-----\n";

    /// Both halves of a keypair are configured the same way and have to be
    /// read the same way. The key was not: it was always taken for a path, so
    /// an inline one became a filename made of PEM under the asset directory,
    /// and what the operator saw was "no private keys found" about a key that
    /// was right there in the configuration.
    #[test]
    fn an_inline_key_is_not_mistaken_for_a_path() {
        assert_eq!(resolve_certificate(INLINE_KEY), INLINE_KEY);
    }

    /// What counts as absolute is the platform's business, and the test has to
    /// ask the same question the code does. A leading slash is a whole path on
    /// Unix; on Windows it names the root of whichever drive is current, so
    /// `resolve_certificate` resolves it against the asset directory like any
    /// other relative path -- correctly, and to something no assertion written
    /// for Unix would recognise.
    #[test]
    fn an_absolute_path_is_left_alone() {
        let absolute = if cfg!(windows) {
            r"C:\leaf\cert.pem"
        } else {
            "/etc/leaf/cert.pem"
        };
        assert_eq!(resolve_certificate(absolute), absolute);
    }

    /// A relative path is still resolved against the asset directory, which is
    /// what makes `"certificate": "cert.pem"` work in a config file.
    #[test]
    fn a_relative_path_is_resolved_against_the_asset_directory() {
        let resolved = resolve_certificate("cert.pem");
        assert!(
            resolved.ends_with("cert.pem") && resolved != "cert.pem",
            "expected a path under the asset directory, got {}",
            resolved
        );
    }

    #[test]
    fn protocol_options_stay_with_the_entry() {
        let config = Config::from_json(
            r#"{
                "inbounds": [{ "type": "socks", "listen_port": 1080, "users": [] }],
                "outbounds": [{ "type": "shadowsocks", "tag": "ss", "server": "a", "server_port": 1 }]
            }"#,
        )
        .unwrap();
        assert_eq!(config.inbounds[0].tag, "socks");
        assert_eq!(config.inbounds[0].listen_port, Some(1080));
        assert!(config.inbounds[0].options.contains_key("users"));
        assert_eq!(config.outbounds[0].options["server"], "a");
        assert_eq!(config.dns.servers, ["1.1.1.1"]);
    }

    #[test]
    fn an_unknown_top_level_field_is_an_error_that_names_it() {
        let err = Config::from_json(r#"{ "router": {} }"#).unwrap_err();
        assert!(err.to_string().contains("router"), "{}", err);
    }

    #[test]
    fn a_misspelt_rule_field_names_its_path() {
        let err = Config::from_json(
            r#"{
                "outbounds": [{ "type": "direct" }],
                "route": { "rules": [{ "domian": ["a"], "outbound": "direct" }] }
            }"#,
        )
        .unwrap_err();
        assert!(err.to_string().starts_with("route.rules[0]"), "{}", err);
    }

    #[test]
    fn a_rule_to_a_missing_outbound_is_an_error() {
        let err = Config::from_json(
            r#"{
                "outbounds": [{ "type": "direct" }],
                "route": { "rules": [{ "domain": ["a"], "outbound": "proxy" }] }
            }"#,
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "route.rules[0]: outbound [proxy] does not exist"
        );
    }

    #[test]
    fn protocol_options_errors_name_the_entry_and_field() {
        #[derive(serde_derive::Deserialize, Debug)]
        #[serde(deny_unknown_fields)]
        #[allow(dead_code)]
        struct PortOnly {
            server_port: u16,
        }
        let mut options = Options::new();
        options.insert("server_port".into(), serde_json::json!("x"));
        let err = parse_options::<PortOnly>("outbound", "proxy", &options).unwrap_err();
        assert!(
            err.to_string()
                .starts_with("[proxy] outbound: server_port: "),
            "{}",
            err
        );
    }
}
