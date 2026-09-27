//! The configuration the runtime is built from, in sing-box's shape: its
//! JSON is read into it directly, other formats are translated into it.
//! Field names follow sing-box wherever the meaning is the same; what sail
//! adds sits in place, and is marked as an extension where it is declared.
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
    /// Both an inbound and an outbound under one tag, as sing-box's
    /// endpoints: connections routed to the tag go out through it, and
    /// what comes in through it is routed with the tag as its inbound.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<Endpoint>,
    #[serde(default)]
    pub route: Route,
    #[serde(default, skip_serializing_if = "Api::is_default")]
    pub api: Api,
    /// What the configuration sets that sail ignores, one line each; the
    /// start logs them.
    #[serde(skip)]
    pub warnings: Vec<String>,
}

/// The control API; a sail extension.
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
    /// As `error`: sail logs nothing more severe.
    Fatal,
    /// As `error`.
    Panic,
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
    /// Logs nothing.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disabled: bool,
    #[serde(default)]
    pub level: LogLevel,
    /// A file to append to. Logs go to the console when it is not set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
    /// Starts each line with the time.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub timestamp: bool,
    /// A sail extension: `compact` writes the message alone.
    #[serde(default)]
    pub format: LogFormat,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Dns {
    /// The servers, each by its tag. None is the system's resolver alone.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub servers: Vec<DnsServer>,
    /// Which server a query goes to, matched in order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<DnsRule>,
    /// The server of the queries no rule matches; the first one when unset.
    #[serde(rename = "final", default, skip_serializing_if = "Option::is_none")]
    pub final_server: Option<String>,
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

/// A DNS server. What it takes beyond its type and tag belongs to its type,
/// and is read when the DNS client is built, as an outbound's options are.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct DnsServer {
    /// `udp`, `tcp`, `tls`, `https`, `quic`, `h3`, `local`, `hosts`, or
    /// sail's `smart_select`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Defaults to the type.
    #[serde(default)]
    pub tag: String,
    #[serde(flatten)]
    pub options: Options,
}

/// A DNS rule, matched in order against each query. As in a routing rule,
/// the domain conditions match when any of them does; the rule matches
/// when that and every other condition it sets match.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DnsRule {
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub domain: Vec<String>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub domain_suffix: Vec<String>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub domain_keyword: Vec<String>,
    /// A sail extension, as in a routing rule.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub geosite: Vec<String>,
    /// A sail extension, as in a routing rule: `site:<file>:<code>`.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub external: Vec<String>,
    /// Record types, by name (`A`, `AAAA`, `HTTPS`) or number.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub query_type: Vec<serde_json::Value>,
    /// Tags of the inbounds the connection that needs the name came in
    /// through.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub inbound: Vec<String>,
    /// Names of the users an inbound authenticated.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub auth_user: Vec<String>,

    #[serde(default)]
    pub action: DnsRuleAction,
    /// `route`: the server a matching query goes to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    /// `route`: the address families, instead of `dns.strategy`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy: Option<DnsStrategy>,
}

/// What a matching DNS rule does.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DnsRuleAction {
    /// Sends the query to `server`.
    #[default]
    Route,
    /// Answers that the name does not resolve.
    Reject,
}

impl DnsRule {
    /// Whether the rule sets any condition.
    pub fn has_conditions(&self) -> bool {
        !(self.domain.is_empty()
            && self.domain_suffix.is_empty()
            && self.domain_keyword.is_empty()
            && self.geosite.is_empty()
            && self.external.is_empty()
            && self.query_type.is_empty()
            && self.inbound.is_empty()
            && self.auth_user.is_empty())
    }

    fn check(&self, servers: &HashSet<String>) -> Result<()> {
        match self.action {
            DnsRuleAction::Route => {
                let tag = self
                    .server
                    .as_ref()
                    .ok_or_else(|| anyhow!("server: a route rule needs one"))?;
                if !servers.contains(tag) {
                    return Err(anyhow!("server [{}] does not exist", tag));
                }
            }
            DnsRuleAction::Reject => {
                if self.server.is_some() || self.strategy.is_some() {
                    return Err(anyhow!("server and strategy are for route rules"));
                }
            }
        }
        if !self.has_conditions() {
            return Err(anyhow!(
                "the rule has no conditions; dns.final is where everything else goes"
            ));
        }
        Ok(())
    }
}

/// Which address families names resolve to, as sing-box names them.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DnsStrategy {
    /// Both, IPv4 first: sing-box's default.
    #[default]
    PreferIpv4,
    /// Both, IPv6 first.
    PreferIpv6,
    /// IPv4 addresses only.
    Ipv4Only,
    /// IPv6 addresses only.
    Ipv6Only,
}

impl DnsStrategy {
    /// Whether IPv6 destinations are used at all.
    pub fn ipv6(self) -> bool {
        self != DnsStrategy::Ipv4Only
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

    /// Fills in the tags left to defaults, and checks that tags are unique
    /// and `final` names a server.
    fn validate(&mut self) -> Result<()> {
        let mut tags = HashSet::new();
        for (i, server) in self.servers.iter_mut().enumerate() {
            if server.tag.is_empty() {
                server.tag = server.kind.clone();
            }
            if !tags.insert(server.tag.clone()) {
                return Err(anyhow!(
                    "dns.servers[{}]: another server is tagged [{}]",
                    i,
                    server.tag
                ));
            }
        }
        if let Some(tag) = &self.final_server {
            if !tags.contains(tag) {
                return Err(anyhow!("dns.final: server [{}] does not exist", tag));
            }
        }
        for (i, rule) in self.rules.iter().enumerate() {
            rule.check(&tags)
                .map_err(|e| anyhow!("dns.rules[{}]: {}", i, e))?;
        }
        Ok(())
    }
}

/// How long a UDP session lives without traffic when its inbound does not
/// say: sing-box's default.
pub const DEFAULT_UDP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5 * 60);

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
    /// 5m when unset, as in sing-box.
    #[serde(default, with = "duration", skip_serializing_if = "Option::is_none")]
    pub udp_timeout: Option<std::time::Duration>,
    #[serde(flatten)]
    pub options: Options,
}

impl Inbound {
    pub fn udp_timeout(&self) -> std::time::Duration {
        self.udp_timeout.unwrap_or(DEFAULT_UDP_TIMEOUT)
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

/// An endpoint: an outbound, and an inbound, under one tag. Like an
/// outbound's, its options belong to its protocol.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Endpoint {
    #[serde(rename = "type")]
    pub protocol: String,
    /// Defaults to the type.
    #[serde(default)]
    pub tag: String,
    /// How long a UDP session coming in through this endpoint lives
    /// without traffic; 5m when unset, as for an inbound.
    #[serde(default, with = "duration", skip_serializing_if = "Option::is_none")]
    pub udp_timeout: Option<std::time::Duration>,
    #[serde(flatten)]
    pub options: Options,
}

impl Endpoint {
    /// The endpoint as the inbound it also is, for what serves inbounds.
    pub fn as_inbound(&self) -> Inbound {
        Inbound {
            protocol: self.protocol.clone(),
            tag: self.tag.clone(),
            listen: None,
            listen_port: None,
            udp_timeout: self.udp_timeout,
            options: Options::new(),
        }
    }
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
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub domain: Vec<String>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub domain_suffix: Vec<String>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub domain_keyword: Vec<String>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub ip_cidr: Vec<String>,
    /// Country codes, looked up in `geo.mmdb` in the asset directory. A sail
    /// extension: sing-box has dropped its GeoIP and GeoSite databases.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub geoip: Vec<String>,
    /// Site groups, looked up in `site.dat` in the asset directory.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub geosite: Vec<String>,
    /// A sail extension: `mmdb:<file>:<code>` or `site:<file>:<code>`, for
    /// data files other than the default ones.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub external: Vec<String>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub port: Vec<u16>,
    /// Inclusive port ranges, as sing-box writes them: `1000:2000`, `:1024`,
    /// `8000:`.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub port_range: Vec<String>,
    /// `tcp`, `udp`.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub network: Vec<String>,
    /// Tags of the inbounds a connection came in through.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub inbound: Vec<String>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub process_name: Vec<String>,
    /// Names of the users an inbound authenticated.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub auth_user: Vec<String>,

    #[serde(default)]
    pub action: RuleAction,
    /// `route`: where a matching connection goes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbound: Option<String>,
    /// `sniff`: the protocols to look for; all of them when empty.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub sniffer: Vec<Sniffer>,
    /// `sniff`: how long to wait for the first bytes; 300ms when unset.
    #[serde(default, with = "duration", skip_serializing_if = "Option::is_none")]
    pub timeout: Option<std::time::Duration>,
    /// `sniff`, a sail extension: connects to the sniffed domain rather than
    /// to the address the client asked for.
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
            && self.port.is_empty()
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
        self.dns.validate()?;
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
        for endpoint in &mut self.endpoints {
            if endpoint.tag.is_empty() {
                endpoint.tag = endpoint.protocol.clone();
            }
            if endpoint.udp_timeout == Some(std::time::Duration::ZERO) {
                return Err(anyhow!(
                    "[{}] endpoint: udp_timeout: must be more than 0",
                    endpoint.tag
                ));
            }
        }
        // An endpoint is an inbound and an outbound: its tag is taken in
        // both.
        {
            let mut tags: HashMap<&str, &str> = HashMap::new();
            for (kind, tag) in self
                .inbounds
                .iter()
                .map(|i| ("inbound", i.tag.as_str()))
                .chain(self.endpoints.iter().map(|e| ("endpoint", e.tag.as_str())))
            {
                if let Some(other) = tags.insert(tag, kind) {
                    if kind == "endpoint" {
                        return Err(anyhow!(
                            "[{}] endpoint: the tag is taken by an {}",
                            tag,
                            other
                        ));
                    }
                }
            }
            for outbound in &self.outbounds {
                if tags.get(outbound.tag.as_str()) == Some(&"endpoint") {
                    return Err(anyhow!(
                        "[{}] endpoint: the tag is taken by an outbound",
                        outbound.tag
                    ));
                }
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

        let outbounds: HashSet<&str> = self
            .outbounds
            .iter()
            .map(|o| o.tag.as_str())
            .chain(self.endpoints.iter().map(|e| e.tag.as_str()))
            .collect();
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

/// Serde support for lists that sing-box also takes as a single value.
pub mod listable {
    use serde::de::{self, IntoDeserializer};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<T: Serialize, S: Serializer>(v: &[T], s: S) -> Result<S::Ok, S::Error> {
        v.serialize(s)
    }

    pub fn deserialize<'de, T: Deserialize<'de>, D: Deserializer<'de>>(
        de: D,
    ) -> Result<Vec<T>, D::Error> {
        // A visitor rather than an untagged enum, which would hide why the
        // value is wrong behind "did not match any variant".
        struct Visitor<T>(std::marker::PhantomData<T>);

        impl<'de, T: Deserialize<'de>> de::Visitor<'de> for Visitor<T> {
            type Value = Vec<T>;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a value or a list of values")
            }

            fn visit_seq<A: de::SeqAccess<'de>>(self, seq: A) -> Result<Vec<T>, A::Error> {
                Vec::deserialize(de::value::SeqAccessDeserializer::new(seq))
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Vec<T>, E> {
                T::deserialize(v.into_deserializer()).map(|v| vec![v])
            }

            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Vec<T>, E> {
                T::deserialize(v.into_deserializer()).map(|v| vec![v])
            }

            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Vec<T>, E> {
                T::deserialize(v.into_deserializer()).map(|v| vec![v])
            }
        }

        de.deserialize_any(Visitor(std::marker::PhantomData))
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

pub(super) fn path<E>(e: &serde_path_to_error::Error<E>) -> String {
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
        assert!(config.dns.servers.is_empty());
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

        let socks = Config::from_json(r#"{ "inbounds": [{ "type": "socks" }] }"#).unwrap();
        assert_eq!(
            socks.inbounds[0].udp_timeout(),
            std::time::Duration::from_secs(300)
        );

        let defaults = Config::from_json("{}").unwrap();
        assert_eq!(defaults.dns.strategy, DnsStrategy::PreferIpv4);
        assert_eq!(defaults.dns.timeout(), std::time::Duration::from_secs(4));
        assert_eq!(defaults.api.listen, None);
    }

    #[test]
    fn endpoints_take_their_tags_as_inbounds_and_outbounds() {
        let config = Config::from_json(
            r#"{
                "endpoints": [{ "type": "wireguard", "udp_timeout": "2m", "mtu": 1400 }],
                "route": { "final": "wireguard", "rules": [
                    { "inbound": ["wireguard"], "outbound": "wireguard" }
                ] }
            }"#,
        )
        .unwrap();
        let endpoint = &config.endpoints[0];
        assert_eq!(endpoint.tag, "wireguard");
        assert_eq!(endpoint.options["mtu"], 1400);
        assert!(!endpoint.options.contains_key("udp_timeout"));
        let inbound = endpoint.as_inbound();
        assert_eq!(inbound.udp_timeout(), std::time::Duration::from_secs(120));
        assert_eq!(inbound.protocol, "wireguard");

        for (json, message) in [
            (
                r#"{ "inbounds": [{ "type": "socks", "tag": "wg" }],
                     "endpoints": [{ "type": "wireguard", "tag": "wg" }] }"#,
                "[wg] endpoint: the tag is taken by an inbound",
            ),
            (
                r#"{ "outbounds": [{ "type": "direct", "tag": "wg" }],
                     "endpoints": [{ "type": "wireguard", "tag": "wg" }] }"#,
                "[wg] endpoint: the tag is taken by an outbound",
            ),
            (
                r#"{ "endpoints": [{ "type": "wireguard" }, { "type": "wireguard" }] }"#,
                "[wireguard] endpoint: the tag is taken by an endpoint",
            ),
            (
                r#"{ "endpoints": [{ "type": "wireguard", "udp_timeout": "0s" }] }"#,
                "[wireguard] endpoint: udp_timeout: must be more than 0",
            ),
            (
                r#"{ "endpoints": [{ "type": "wireguard" }], "route": { "final": "wg" } }"#,
                "route.final: outbound [wg] does not exist",
            ),
        ] {
            let err = Config::from_json(json).unwrap_err();
            assert_eq!(err.to_string(), message, "{}", json);
        }
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
