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
    #[serde(default)]
    pub dns: Dns,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inbounds: Vec<Inbound>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outbounds: Vec<Outbound>,
    #[serde(default)]
    pub route: Route,
    #[serde(default, skip_serializing_if = "Api::is_default")]
    pub api: Api,
}

/// The control API.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Api {
    /// Where the API listens; it is not served when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen: Option<std::net::SocketAddr>,
}

impl Api {
    fn is_default(&self) -> bool {
        *self == Api::default()
    }
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
    /// Which address families names resolve to, and in what order.
    #[serde(default)]
    pub strategy: DnsStrategy,
    /// Answers kept per address family; 512, or 64 on iOS, when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_capacity: Option<usize>,
    /// How long one query to one server may take; 4s when unset.
    #[serde(default, with = "duration", skip_serializing_if = "Option::is_none")]
    pub timeout: Option<std::time::Duration>,
    /// Remembers the domain of each address the DNS answers that pass
    /// through carry, so that connections to the address are routed by the
    /// domain.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub reverse_mapping: bool,
}

/// Which address families names resolve to, as sing-box names them.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DnsStrategy {
    /// IPv4 addresses only.
    #[default]
    Ipv4Only,
    /// IPv6 addresses only.
    Ipv6Only,
    /// Both, IPv4 first.
    PreferIpv4,
    /// Both, IPv6 first.
    PreferIpv6,
}

impl DnsStrategy {
    /// Whether IPv6 destinations are used at all.
    pub fn ipv6(self) -> bool {
        self != DnsStrategy::Ipv4Only
    }
}

fn default_dns_servers() -> Vec<String> {
    vec!["1.1.1.1".to_string()]
}

impl Default for Dns {
    fn default() -> Self {
        Self {
            servers: default_dns_servers(),
            hosts: HashMap::new(),
            strategy: DnsStrategy::default(),
            cache_capacity: None,
            timeout: None,
            reverse_mapping: false,
        }
    }
}

impl Dns {
    pub fn cache_capacity(&self) -> usize {
        self.cache_capacity
            .unwrap_or(if cfg!(target_os = "ios") { 64 } else { 512 })
    }

    pub fn timeout(&self) -> std::time::Duration {
        self.timeout.unwrap_or(std::time::Duration::from_secs(4))
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
    /// How long a UDP session through this inbound lives without traffic;
    /// 30s when unset.
    #[serde(default, with = "duration", skip_serializing_if = "Option::is_none")]
    pub udp_timeout: Option<std::time::Duration>,
    #[serde(flatten)]
    pub options: Options,
}

impl Inbound {
    pub fn udp_timeout(&self) -> std::time::Duration {
        self.udp_timeout
            .unwrap_or(std::time::Duration::from_secs(30))
    }
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
    /// The interface outbounds that name none of their own send through.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_interface: Option<String>,
    /// The routing mark (`SO_MARK`, Linux) of outbounds that set none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_mark: Option<u32>,
    /// Sends outbounds that name no interface of their own through the
    /// system's default interface, found at start. Needed when a TUN inbound
    /// routes everything, or outbound traffic would loop back into it.
    #[serde(default)]
    pub auto_detect_interface: bool,
}

/// A routing rule, matched in order. As in sing-box, the destination
/// conditions (`domain*`, `geosite`, `ip_cidr`, `geoip`, `external`) match
/// when any of them does; the rule matches when that and every other
/// condition it sets match, and a condition listing several values matches
/// when any of them does.
///
/// `route` and `reject` end the matching. `sniff` and `resolve` learn more
/// about the connection and matching goes on with the next rule.
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
    /// Names of the users an inbound authenticated.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub auth_user: Vec<String>,

    #[serde(default)]
    pub action: RuleAction,
    /// `route`: where a matching connection goes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbound: Option<String>,
    /// `sniff`: the protocols to look for; all of them when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sniffer: Vec<Sniffer>,
    /// `sniff`: how long to wait for the first bytes; 300ms when unset.
    #[serde(default, with = "duration", skip_serializing_if = "Option::is_none")]
    pub timeout: Option<std::time::Duration>,
    /// `sniff`: connects to the sniffed domain rather than to the address
    /// the client asked for.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub override_destination: bool,
}

/// What a matching rule does.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    /// Sends the connection to `outbound`.
    #[default]
    Route,
    /// Closes the connection.
    Reject,
    /// Reads the domain from the first bytes of a TCP connection (TLS SNI,
    /// HTTP Host), so that later rules match it.
    Sniff,
    /// Resolves the domain, so that later rules match its addresses.
    Resolve,
}

/// A protocol a `sniff` rule reads the domain from.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Sniffer {
    Tls,
    Http,
}

impl Rule {
    /// Whether the rule sets any condition; one that sets none matches
    /// every connection.
    pub fn has_conditions(&self) -> bool {
        !(self.domain.is_empty()
            && self.domain_suffix.is_empty()
            && self.domain_keyword.is_empty()
            && self.ip_cidr.is_empty()
            && self.geoip.is_empty()
            && self.geosite.is_empty()
            && self.external.is_empty()
            && self.port_range.is_empty()
            && self.network.is_empty()
            && self.inbound.is_empty()
            && self.process_name.is_empty()
            && self.auth_user.is_empty())
    }

    /// The configuration mistakes one rule can make on its own.
    fn check(&self, outbounds: &HashSet<&str>) -> Result<()> {
        let sniff_fields =
            !self.sniffer.is_empty() || self.timeout.is_some() || self.override_destination;
        match self.action {
            RuleAction::Route => {
                let tag = self
                    .outbound
                    .as_ref()
                    .ok_or_else(|| anyhow!("outbound: a route rule needs one"))?;
                if !outbounds.contains(tag.as_str()) {
                    return Err(anyhow!("outbound [{}] does not exist", tag));
                }
            }
            _ if self.outbound.is_some() => {
                return Err(anyhow!("outbound: only a route rule has one"));
            }
            _ => {}
        }
        if sniff_fields && self.action != RuleAction::Sniff {
            return Err(anyhow!(
                "sniffer, timeout and override_destination are for sniff rules"
            ));
        }
        if self.timeout == Some(std::time::Duration::ZERO) {
            return Err(anyhow!("timeout: must be more than 0"));
        }
        // A rule that ends the matching for every connection is `final`.
        if matches!(self.action, RuleAction::Route | RuleAction::Reject) && !self.has_conditions() {
            return Err(anyhow!(
                "the rule has no conditions; route.final is where everything else goes"
            ));
        }
        Ok(())
    }
}

impl Config {
    /// Fills in what the configuration leaves to defaults, and checks what
    /// can be checked without building anything.
    pub fn validate(&mut self) -> Result<()> {
        for inbound in &mut self.inbounds {
            if inbound.tag.is_empty() {
                inbound.tag = inbound.protocol.clone();
            }
            if inbound.udp_timeout == Some(std::time::Duration::ZERO) {
                return Err(anyhow!(
                    "[{}] inbound: udp_timeout: must be more than 0",
                    inbound.tag
                ));
            }
        }
        if self.dns.timeout == Some(std::time::Duration::ZERO) {
            return Err(anyhow!("dns.timeout: must be more than 0"));
        }
        if self.dns.cache_capacity == Some(0) {
            return Err(anyhow!("dns.cache_capacity: must be at least 1"));
        }
        for outbound in &mut self.outbounds {
            if outbound.tag.is_empty() {
                outbound.tag = outbound.protocol.clone();
            }
        }

        if self.route.auto_detect_interface && self.route.default_interface.is_some() {
            return Err(anyhow!(
                "route: set default_interface or auto_detect_interface, not both"
            ));
        }
        // A TUN that takes the default route catches outbound traffic too,
        // unless that is sent through the interface it would have used.
        if let Some(tun) = self.inbounds.iter().find(|i| {
            i.protocol == "tun" && i.options.get("auto") == Some(&serde_json::Value::Bool(true))
        }) {
            if !self.route.auto_detect_interface && self.route.default_interface.is_none() {
                return Err(anyhow!(
                    "[{}] inbound: auto routes all traffic into the TUN; set \
                     route.auto_detect_interface (or route.default_interface) so that \
                     outbound traffic does not loop back into it",
                    tun.tag
                ));
            }
        }

        let outbounds: HashSet<&str> = self.outbounds.iter().map(|o| o.tag.as_str()).collect();
        if let Some(tag) = &self.route.final_outbound {
            if !outbounds.contains(tag.as_str()) {
                return Err(anyhow!("route.final: outbound [{}] does not exist", tag));
            }
        }
        for (i, rule) in self.route.rules.iter().enumerate() {
            rule.check(&outbounds)
                .map_err(|e| anyhow!("route.rules[{}]: {}", i, e))?;
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

/// Parses a duration as sing-box writes them: a sequence of numbers with
/// units, `500ms`, `5s`, `1m30s`, `2h`.
pub fn parse_duration(s: &str) -> Result<std::time::Duration> {
    let invalid = || anyhow!("invalid duration \"{}\", expected e.g. 500ms, 5s, 1m30s", s);
    let mut total = std::time::Duration::ZERO;
    let mut rest = s.trim();
    if rest.is_empty() {
        return Err(invalid());
    }
    while !rest.is_empty() {
        let digits = rest
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .ok_or_else(invalid)?;
        let value: f64 = rest[..digits].parse().map_err(|_| invalid())?;
        rest = &rest[digits..];
        let unit_len = rest
            .find(|c: char| c.is_ascii_digit() || c == '.')
            .unwrap_or(rest.len());
        let seconds = match &rest[..unit_len] {
            "ns" => 1e-9,
            "us" | "µs" => 1e-6,
            "ms" => 1e-3,
            "s" => 1.0,
            "m" => 60.0,
            "h" => 3600.0,
            _ => return Err(invalid()),
        };
        total += std::time::Duration::from_secs_f64(value * seconds);
        rest = &rest[unit_len..];
    }
    Ok(total)
}

/// Serde support for optional durations in the sing-box notation.
pub mod duration {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(
        d: &Option<std::time::Duration>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        match d {
            Some(d) => s.serialize_str(&format!("{}ms", d.as_millis())),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        de: D,
    ) -> Result<Option<std::time::Duration>, D::Error> {
        let s = String::deserialize(de)?;
        super::parse_duration(&s)
            .map(Some)
            .map_err(serde::de::Error::custom)
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn rule_actions_and_their_mistakes() {
        let config = |rules: &str| {
            Config::from_json(&format!(
                r#"{{ "outbounds": [{{ "type": "direct" }}], "route": {{ "rules": {} }} }}"#,
                rules
            ))
        };
        let ok = config(
            r#"[{ "action": "sniff", "sniffer": ["tls"], "timeout": "1s" },
                { "action": "resolve" },
                { "domain": ["a"], "action": "reject" },
                { "ip_cidr": ["10.0.0.0/8"], "outbound": "direct" }]"#,
        )
        .unwrap();
        assert_eq!(ok.route.rules[0].action, RuleAction::Sniff);
        assert_eq!(ok.route.rules[0].sniffer, [Sniffer::Tls]);
        assert_eq!(ok.route.rules[3].action, RuleAction::Route);

        for (rules, message) in [
            (r#"[{ "domain": ["a"] }]"#, "a route rule needs one"),
            (
                r#"[{ "action": "sniff", "outbound": "direct" }]"#,
                "only a route rule",
            ),
            (
                r#"[{ "domain": ["a"], "action": "reject", "sniffer": ["tls"] }]"#,
                "are for sniff rules",
            ),
            (r#"[{ "outbound": "direct" }]"#, "route.final"),
            (r#"[{ "action": "reject" }]"#, "route.final"),
            (r#"[{ "action": "sniff", "sniffer": ["quic"] }]"#, "quic"),
        ] {
            let err = config(rules).unwrap_err().to_string();
            assert!(err.contains(message), "{}: {}", rules, err);
        }
    }

    #[test]
    fn a_tun_taking_the_default_route_needs_an_outbound_interface() {
        let tun =
            r#""inbounds": [{ "type": "tun", "auto": true }], "outbounds": [{ "type": "direct" }]"#;
        let err = Config::from_json(&format!("{{ {} }}", tun)).unwrap_err();
        assert!(
            err.to_string().contains("route.auto_detect_interface"),
            "{}",
            err
        );
        Config::from_json(&format!(
            r#"{{ {}, "route": {{ "auto_detect_interface": true }} }}"#,
            tun
        ))
        .unwrap();
    }

    #[test]
    fn a_default_interface_and_auto_detection_exclude_each_other() {
        let err = Config::from_json(
            r#"{ "route": { "default_interface": "en0", "auto_detect_interface": true } }"#,
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "route: set default_interface or auto_detect_interface, not both"
        );
    }

    #[test]
    fn durations_are_read_as_sing_box_writes_them() {
        use std::time::Duration;
        assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
        assert_eq!(parse_duration("5s").unwrap(), Duration::from_secs(5));
        assert_eq!(parse_duration("1m30s").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_duration("1.5h").unwrap(), Duration::from_secs(5400));
        for bad in ["", "5", "s", "5 s", "5x", "-1s"] {
            assert!(parse_duration(bad).is_err(), "{:?}", bad);
        }
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

    #[test]
    fn dns_api_and_udp_timeout_fields() {
        let config = Config::from_json(
            r#"{
                "dns": { "strategy": "prefer_ipv6", "cache_capacity": 8, "timeout": "2s" },
                "api": { "listen": "127.0.0.1:9090" },
                "inbounds": [{ "type": "socks", "listen_port": 1080, "udp_timeout": "1m" }]
            }"#,
        )
        .unwrap();
        assert_eq!(config.dns.strategy, DnsStrategy::PreferIpv6);
        assert!(config.dns.strategy.ipv6());
        assert_eq!(config.dns.cache_capacity(), 8);
        assert_eq!(config.dns.timeout(), std::time::Duration::from_secs(2));
        assert_eq!(config.api.listen, Some("127.0.0.1:9090".parse().unwrap()));
        assert_eq!(
            config.inbounds[0].udp_timeout(),
            std::time::Duration::from_secs(60)
        );

        let defaults = Config::from_json("{}").unwrap();
        assert_eq!(defaults.dns.strategy, DnsStrategy::Ipv4Only);
        assert_eq!(defaults.dns.timeout(), std::time::Duration::from_secs(4));
        assert_eq!(defaults.api.listen, None);
    }

    #[test]
    fn zero_timeouts_and_capacity_and_env_are_errors() {
        for (json, field) in [
            (r#"{ "dns": { "timeout": "0s" } }"#, "dns.timeout"),
            (
                r#"{ "dns": { "cache_capacity": 0 } }"#,
                "dns.cache_capacity",
            ),
            (
                r#"{ "inbounds": [{ "type": "socks", "udp_timeout": "0s" }] }"#,
                "udp_timeout",
            ),
            (r#"{ "env": { "A": "1" } }"#, "env"),
        ] {
            let err = Config::from_json(json).unwrap_err();
            assert!(err.to_string().contains(field), "{}: {}", json, err);
        }
    }
}
