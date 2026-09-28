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
    #[serde(default, skip_serializing_if = "Experimental::is_default")]
    pub experimental: Experimental,
    /// The root certificates servers are checked against; the system's
    /// when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<CertificateOptions>,
    /// What the configuration sets that sail ignores, one line each; the
    /// start logs them.
    #[serde(skip)]
    pub warnings: Vec<String>,
}

/// sing-box's top-level `certificate`: a store of root certificates, and
/// certificates of one's own besides.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CertificateOptions {
    #[serde(default)]
    pub store: CertificateStore,
    /// Inline PEM, its lines one to an entry or all in one.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub certificate: Vec<String>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub certificate_path: Vec<String>,
    /// Directories, every file of which holds certificates.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub certificate_directory_path: Vec<String>,
}

/// Which roots: the system's, or Mozilla's or Chrome's included lists
/// (without the certificate authorities of China, as sing-box's), or none.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CertificateStore {
    #[default]
    System,
    Mozilla,
    Chrome,
    None,
}

/// sing-box's `experimental`: what sail takes of it.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Experimental {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clash_api: Option<ClashApi>,
}

impl Experimental {
    fn is_default(&self) -> bool {
        *self == Experimental::default()
    }
}

/// Clash's API: the mode rules match, `Rule` when unset. The API itself
/// is not served yet.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ClashApi {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_mode: Option<String>,
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

/// A DNS rule, matched in order against each query. Its conditions are a
/// routing rule's, matched as they are there, and `query_type` and
/// `outbound` besides; a logical one (`type: logical`) combines others,
/// which take no action of their own.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DnsRule {
    /// `default`, or `logical`.
    #[serde(rename = "type", default, skip_serializing_if = "RuleType::is_default")]
    pub kind: RuleType,
    /// Record types, by name (`A`, `AAAA`, `HTTPS`) or number.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub query_type: Vec<serde_json::Value>,
    /// Tags of the inbounds the connection that needs the name came in
    /// through.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub inbound: Vec<String>,
    /// The mode of Clash's API, as in a routing rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clash_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_version: Option<u8>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub network: Vec<String>,
    /// Names of the users an inbound authenticated.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub auth_user: Vec<String>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub protocol: Vec<String>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub domain: Vec<String>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub domain_suffix: Vec<String>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub domain_keyword: Vec<String>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub domain_regex: Vec<String>,
    /// A sail extension, as in a routing rule.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub geosite: Vec<String>,
    /// A sail extension, as in a routing rule: `site:<file>:<code>`.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub external: Vec<String>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub source_ip_cidr: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub source_ip_is_private: bool,
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
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub package_name: Vec<String>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub package_name_regex: Vec<String>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub user: Vec<String>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub user_id: Vec<i32>,
    /// Tags of the outbounds that dial the name; of the rule itself, not
    /// of a rule a logical one combines.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub outbound: Vec<String>,
    /// Tags of rule-sets, any of whose rules matching matches. Their
    /// `ip_cidr` rules match no query, which has no address yet.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub rule_set: Vec<String>,
    /// The rule-sets' `ip_cidr` match the source address.
    #[serde(
        default,
        alias = "rule_set_ipcidr_match_source",
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub rule_set_ip_cidr_match_source: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub invert: bool,
    /// `logical`: `and` or `or`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<LogicalMode>,
    /// `logical`: the rules combined.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<DnsRule>,

    /// `route` when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<DnsRuleAction>,
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
    /// Its conditions, and those of the rules it combines, as a routing
    /// rule's: they match as those do.
    pub fn conditions(&self) -> Rule {
        Rule {
            kind: self.kind,
            query_type: self.query_type.clone(),
            clash_mode: self.clash_mode.clone(),
            inbound: self.inbound.clone(),
            ip_version: self.ip_version,
            network: self.network.clone(),
            auth_user: self.auth_user.clone(),
            protocol: self.protocol.clone(),
            domain: self.domain.clone(),
            domain_suffix: self.domain_suffix.clone(),
            domain_keyword: self.domain_keyword.clone(),
            domain_regex: self.domain_regex.clone(),
            geosite: self.geosite.clone(),
            external: self.external.clone(),
            source_ip_cidr: self.source_ip_cidr.clone(),
            source_ip_is_private: self.source_ip_is_private,
            source_port: self.source_port.clone(),
            source_port_range: self.source_port_range.clone(),
            port: self.port.clone(),
            port_range: self.port_range.clone(),
            process_name: self.process_name.clone(),
            process_path: self.process_path.clone(),
            process_path_regex: self.process_path_regex.clone(),
            package_name: self.package_name.clone(),
            package_name_regex: self.package_name_regex.clone(),
            user: self.user.clone(),
            user_id: self.user_id.clone(),
            rule_set: self.rule_set.clone(),
            rule_set_ip_cidr_match_source: self.rule_set_ip_cidr_match_source,
            invert: self.invert,
            mode: self.mode,
            rules: self.rules.iter().map(DnsRule::conditions).collect(),
            ..Default::default()
        }
    }

    /// Whether the rule sets any condition.
    pub fn has_conditions(&self) -> bool {
        self.conditions().has_conditions() || !self.outbound.is_empty()
    }

    fn check(&self, servers: &HashSet<String>) -> Result<()> {
        match self.action.unwrap_or_default() {
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
        for (i, rule) in self.rules.iter().enumerate() {
            rule.check_combined()
                .map_err(|e| anyhow!("rules[{}]: {}", i, e))?;
        }
        if !self.has_conditions() {
            return Err(anyhow!(
                "the rule has no conditions; dns.final is where everything else goes"
            ));
        }
        Ok(())
    }

    /// A rule a logical one combines: conditions, and nothing else.
    fn check_combined(&self) -> Result<()> {
        let set = [
            ("action", self.action.is_some()),
            ("server", self.server.is_some()),
            ("strategy", self.strategy.is_some()),
            ("outbound", !self.outbound.is_empty()),
        ];
        if let Some((field, _)) = set.iter().find(|(_, set)| *set) {
            return Err(anyhow!("{}: a rule a logical one combines has none", field));
        }
        for (i, rule) in self.rules.iter().enumerate() {
            rule.check_combined()
                .map_err(|e| anyhow!("rules[{}]: {}", i, e))?;
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

    /// The tags of the servers: `local` alone when none are given, for the
    /// system's resolver then stands in.
    pub fn server_tags(&self) -> HashSet<String> {
        if self.servers.is_empty() {
            return HashSet::from(["local".to_string()]);
        }
        self.servers.iter().map(|s| s.tag.clone()).collect()
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
        let tags = self.server_tags();
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
    /// The rule-sets rules name, by tag.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rule_set: Vec<super::rule_set::RuleSet>,
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
    /// The DNS server that resolves the names outbounds dial, for those
    /// that name no `domain_resolver` of their own. Unset, the DNS rules
    /// decide.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_domain_resolver: Option<DomainResolver>,
}

/// A DNS server that resolves the names something dials: its tag, or
/// `{ "server": tag, "strategy": ... }`.
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct DomainResolver {
    pub server: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy: Option<DnsStrategy>,
}

impl<'de> serde::Deserialize<'de> for DomainResolver {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Full {
            server: String,
            #[serde(default)]
            strategy: Option<DnsStrategy>,
        }
        match serde_json::Value::deserialize(de)? {
            serde_json::Value::String(server) => Ok(DomainResolver {
                server,
                strategy: None,
            }),
            value => {
                let full = Full::deserialize(value).map_err(serde::de::Error::custom)?;
                Ok(DomainResolver {
                    server: full.server,
                    strategy: full.strategy,
                })
            }
        }
    }
}

/// A routing rule, matched in order, as sing-box has it. A default rule
/// sets conditions on the things a connection is known by: of the
/// conditions on one thing (the source's address, its port, the
/// destination's address, its port) any matching will do, and the rule
/// matches when each thing it has conditions on matches and every other
/// condition does. A condition listing several values matches when any of
/// them does. A logical rule (`type: logical`) combines the rules in
/// `rules`, all of them (`mode: and`) or any (`mode: or`); `invert` turns
/// either kind's result around.
///
/// `route`, `reject` and `hijack-dns` end the matching. `route-options`,
/// `sniff` and `resolve` learn more about the connection or say how it is
/// to be carried, and matching goes on with the next rule.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// `default`, or `logical`.
    #[serde(rename = "type", default, skip_serializing_if = "RuleType::is_default")]
    pub kind: RuleType,

    /// Record types, by name (`A`, `AAAA`, `HTTPS`) or number: of a DNS
    /// query, and so never of a connection.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub query_type: Vec<serde_json::Value>,
    /// The mode of Clash's API: matches while it is that, whatever the
    /// case; never without an API.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clash_mode: Option<String>,
    /// Tags of the inbounds a connection came in through.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub inbound: Vec<String>,
    /// 4 or 6: the family of the destination address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_version: Option<u8>,
    /// `tcp`, `udp`.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub network: Vec<String>,
    /// Names of the users an inbound authenticated.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub auth_user: Vec<String>,
    /// The protocols a `sniff` rule found, by sing-box's names: `tls`,
    /// `http`, `quic`, `dns`, `stun`, `bittorrent`, `dtls`.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub protocol: Vec<String>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub domain: Vec<String>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub domain_suffix: Vec<String>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub domain_keyword: Vec<String>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub domain_regex: Vec<String>,
    /// Site groups, looked up in `site.dat` in the asset directory. A sail
    /// extension: sing-box has dropped its GeoIP and GeoSite databases.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub geosite: Vec<String>,
    /// Country codes, looked up in `geo.mmdb` in the asset directory; a
    /// sail extension, as `geosite` is.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub geoip: Vec<String>,
    /// A sail extension: `mmdb:<file>:<code>` or `site:<file>:<code>`, for
    /// data files other than the default ones.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub external: Vec<String>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub source_ip_cidr: Vec<String>,
    /// The source address is not a public one.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub source_ip_is_private: bool,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub ip_cidr: Vec<String>,
    /// The destination address, or one the domain resolved to, is not a
    /// public one.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ip_is_private: bool,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub source_port: Vec<u16>,
    /// Inclusive port ranges, as `port_range` writes them.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub source_port_range: Vec<String>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub port: Vec<u16>,
    /// Inclusive port ranges, as sing-box writes them: `1000:2000`, `:1024`,
    /// `8000:`.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub port_range: Vec<String>,
    /// The name of the program a connection comes from, its path's last
    /// part.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub process_name: Vec<String>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub process_path: Vec<String>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub process_path_regex: Vec<String>,
    /// Android packages; no platform sail runs on tells them yet.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub package_name: Vec<String>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub package_name_regex: Vec<String>,
    /// The user a connection's process runs as, by name and by id; no
    /// platform sail runs on tells them yet.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub user: Vec<String>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub user_id: Vec<i32>,
    /// Tags of rule-sets, any of whose rules matching matches.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub rule_set: Vec<String>,
    /// The rule-sets' `ip_cidr` match the source address, not the
    /// destination.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub rule_set_ip_cidr_match_source: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub invert: bool,
    /// `logical`: `and` or `or`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<LogicalMode>,
    /// `logical`: the rules combined. They take no action of their own.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<Rule>,

    /// `route` when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<RuleAction>,
    /// `route`: where a matching connection goes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbound: Option<String>,
    /// `route`, `route-options`: connects to this address, an IP or a
    /// domain, instead of the one asked for, on the same port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub override_address: Option<String>,
    /// `route`, `route-options`: connects to this port instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub override_port: Option<u16>,
    /// `route`, `route-options`: answers to UDP sent to a domain come back
    /// from the address it resolved to, not from the domain.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub udp_disable_domain_unmapping: bool,
    /// `route`, `route-options`: a direct outbound sends UDP from a
    /// connected socket.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub udp_connect: bool,
    /// `route`, `route-options`: how long a UDP session lasts idle,
    /// instead of its inbound's `udp_timeout`.
    #[serde(default, with = "duration", skip_serializing_if = "Option::is_none")]
    pub udp_timeout: Option<std::time::Duration>,
    /// `route`, `route-options`: sends the TLS ClientHello in pieces, cut
    /// in the server name, each in a TCP segment of its own.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub tls_fragment: bool,
    /// `route`, `route-options`: how long to wait between the pieces;
    /// 500ms when unset.
    #[serde(default, with = "duration", skip_serializing_if = "Option::is_none")]
    pub tls_fragment_fallback_delay: Option<std::time::Duration>,
    /// `route`, `route-options`: sends the TLS ClientHello as several TLS
    /// records, cut in the server name.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub tls_record_fragment: bool,
    /// `reject`: how.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<RejectMethod>,
    /// `reject`: never drops, however many connections the rule rejects.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub no_drop: bool,
    /// `resolve`: the DNS server to ask, rather than the one the DNS rules
    /// pick.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    /// `resolve`: the address families, instead of `dns.strategy`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy: Option<DnsStrategy>,
    /// `sniff`: the protocols to look for; all of them when empty.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub sniffer: Vec<Sniffer>,
    /// `sniff`: how long to wait for the first bytes; 300ms when unset.
    /// `resolve`: how long to wait for the answer; `dns.timeout` when
    /// unset.
    #[serde(default, with = "duration", skip_serializing_if = "Option::is_none")]
    pub timeout: Option<std::time::Duration>,
    /// `sniff`, a sail extension: connects to the sniffed domain rather than
    /// to the address the client asked for.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub override_destination: bool,
}

/// A rule's kind.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleType {
    /// Conditions of its own.
    #[default]
    Default,
    /// Other rules, combined.
    Logical,
}

impl RuleType {
    fn is_default(&self) -> bool {
        *self == RuleType::Default
    }
}

/// How a logical rule combines its rules.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LogicalMode {
    /// All of them match.
    And,
    /// Any of them does.
    Or,
}

/// What a matching rule does.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RuleAction {
    /// Sends the connection to `outbound`.
    #[default]
    Route,
    /// Sets how the connection is carried, and lets the next rules decide
    /// where it goes.
    RouteOptions,
    /// Closes the connection.
    Reject,
    /// Answers the DNS queries the connection carries.
    HijackDns,
    /// Reads the domain from the first bytes of a TCP connection (TLS SNI,
    /// HTTP Host), so that later rules match it.
    Sniff,
    /// Resolves the domain, so that later rules match its addresses; a
    /// domain that does not resolve fails the connection.
    Resolve,
}

/// How a `reject` rule closes a connection.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RejectMethod {
    /// At once; dropped instead when the rule rejects more than 50
    /// connections in 30 seconds, unless `no_drop`.
    #[default]
    Default,
    /// Left unanswered.
    Drop,
    /// With an ICMP message, for ICMP; sail routes none.
    Reply,
}

/// A protocol a `sniff` rule looks for, by sing-box's name. TLS, HTTP and
/// QUIC name the domain too (QUIC's needs the `btls` crypto compiled in);
/// DNS, STUN, BitTorrent and DTLS are only recognized.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Sniffer {
    Tls,
    Http,
    Quic,
    Dns,
    Stun,
    Bittorrent,
    Dtls,
}

impl Rule {
    /// What the rule does.
    pub fn action(&self) -> RuleAction {
        self.action.unwrap_or_default()
    }

    /// The first condition of a default rule the rule sets, by name.
    pub fn first_condition(&self) -> Option<&'static str> {
        [
            ("query_type", !self.query_type.is_empty()),
            ("clash_mode", self.clash_mode.is_some()),
            ("inbound", !self.inbound.is_empty()),
            ("ip_version", self.ip_version.is_some()),
            ("network", !self.network.is_empty()),
            ("auth_user", !self.auth_user.is_empty()),
            ("protocol", !self.protocol.is_empty()),
            ("domain", !self.domain.is_empty()),
            ("domain_suffix", !self.domain_suffix.is_empty()),
            ("domain_keyword", !self.domain_keyword.is_empty()),
            ("domain_regex", !self.domain_regex.is_empty()),
            ("geosite", !self.geosite.is_empty()),
            ("geoip", !self.geoip.is_empty()),
            ("external", !self.external.is_empty()),
            ("source_ip_cidr", !self.source_ip_cidr.is_empty()),
            ("source_ip_is_private", self.source_ip_is_private),
            ("ip_cidr", !self.ip_cidr.is_empty()),
            ("ip_is_private", self.ip_is_private),
            ("source_port", !self.source_port.is_empty()),
            ("source_port_range", !self.source_port_range.is_empty()),
            ("port", !self.port.is_empty()),
            ("port_range", !self.port_range.is_empty()),
            ("process_name", !self.process_name.is_empty()),
            ("process_path", !self.process_path.is_empty()),
            ("process_path_regex", !self.process_path_regex.is_empty()),
            ("package_name", !self.package_name.is_empty()),
            ("package_name_regex", !self.package_name_regex.is_empty()),
            ("user", !self.user.is_empty()),
            ("user_id", !self.user_id.is_empty()),
            ("rule_set", !self.rule_set.is_empty()),
            (
                "rule_set_ip_cidr_match_source",
                self.rule_set_ip_cidr_match_source,
            ),
        ]
        .into_iter()
        .find(|(_, set)| *set)
        .map(|(field, _)| field)
    }

    /// Whether the rule sets any condition; one that sets none matches
    /// every connection.
    pub fn has_conditions(&self) -> bool {
        match self.kind {
            RuleType::Default => self.first_condition().is_some(),
            RuleType::Logical => !self.rules.is_empty(),
        }
    }

    /// The action fields the rule sets, by name, with the actions each
    /// belongs to.
    fn action_fields(&self) -> Vec<(&'static str, &'static [RuleAction])> {
        use RuleAction::*;
        const ROUTE: &[RuleAction] = &[Route, RouteOptions];
        [
            ("action", self.action.is_some(), &[] as &[RuleAction]),
            ("outbound", self.outbound.is_some(), &[Route]),
            ("override_address", self.override_address.is_some(), ROUTE),
            ("override_port", self.override_port.is_some(), ROUTE),
            (
                "udp_disable_domain_unmapping",
                self.udp_disable_domain_unmapping,
                ROUTE,
            ),
            ("udp_connect", self.udp_connect, ROUTE),
            ("udp_timeout", self.udp_timeout.is_some(), ROUTE),
            ("tls_fragment", self.tls_fragment, ROUTE),
            (
                "tls_fragment_fallback_delay",
                self.tls_fragment_fallback_delay.is_some(),
                ROUTE,
            ),
            ("tls_record_fragment", self.tls_record_fragment, ROUTE),
            ("method", self.method.is_some(), &[Reject]),
            ("no_drop", self.no_drop, &[Reject]),
            ("server", self.server.is_some(), &[Resolve]),
            ("strategy", self.strategy.is_some(), &[Resolve]),
            ("sniffer", !self.sniffer.is_empty(), &[Sniff]),
            ("timeout", self.timeout.is_some(), &[Sniff, Resolve]),
            ("override_destination", self.override_destination, &[Sniff]),
        ]
        .into_iter()
        .filter(|(_, set, _)| *set)
        .map(|(field, _, actions)| (field, actions))
        .collect()
    }

    /// The configuration mistakes one rule, at `path`, can make on its
    /// own.
    fn check(&self, path: &str, outbounds: &HashSet<&str>) -> Result<()> {
        self.check_conditions(path, 0)?;
        let action = self.action();
        for (field, actions) in self.action_fields() {
            if !actions.is_empty() && !actions.contains(&action) {
                return Err(anyhow!(
                    "{}.{}: not for a {} rule",
                    path,
                    field,
                    action.name()
                ));
            }
        }
        match action {
            RuleAction::Route => {
                let tag = self
                    .outbound
                    .as_ref()
                    .ok_or_else(|| anyhow!("{}: outbound: a route rule needs one", path))?;
                if !outbounds.contains(tag.as_str()) {
                    return Err(anyhow!("{}: outbound [{}] does not exist", path, tag));
                }
            }
            RuleAction::RouteOptions => {
                if self.action_fields().len() == 1 {
                    return Err(anyhow!(
                        "{}: a route-options rule needs an option to set",
                        path
                    ));
                }
            }
            RuleAction::Reject => match self.method.unwrap_or_default() {
                RejectMethod::Reply => {
                    return Err(anyhow!(
                        "{}.method: reply answers ICMP, which sail does not route",
                        path
                    ))
                }
                RejectMethod::Drop if self.no_drop => {
                    return Err(anyhow!("{}.no_drop: not with method drop", path))
                }
                _ => {}
            },
            RuleAction::HijackDns | RuleAction::Sniff | RuleAction::Resolve => {}
        }
        if self.tls_fragment && self.tls_record_fragment {
            return Err(anyhow!(
                "{}: tls_fragment and tls_record_fragment are exclusive",
                path
            ));
        }
        if self.tls_fragment_fallback_delay.is_some() && !self.tls_fragment {
            return Err(anyhow!(
                "{}.tls_fragment_fallback_delay: only with tls_fragment",
                path
            ));
        }
        for (field, value) in [
            ("timeout", self.timeout),
            ("udp_timeout", self.udp_timeout),
            (
                "tls_fragment_fallback_delay",
                self.tls_fragment_fallback_delay,
            ),
        ] {
            if value == Some(std::time::Duration::ZERO) {
                return Err(anyhow!("{}.{}: must be more than 0", path, field));
            }
        }
        if matches!(self.override_address.as_deref(), Some("")) {
            return Err(anyhow!("{}.override_address: empty", path));
        }
        if self.override_port == Some(0) {
            return Err(anyhow!("{}.override_port: must be more than 0", path));
        }
        // A rule that ends the matching for every connection is `final`.
        if matches!(action, RuleAction::Route | RuleAction::Reject) && !self.has_conditions() {
            return Err(anyhow!(
                "{}: the rule has no conditions; route.final is where everything else goes",
                path
            ));
        }
        Ok(())
    }

    /// The mistakes of a rule's conditions, and of the rules nested in it,
    /// which take no action.
    fn check_conditions(&self, path: &str, depth: usize) -> Result<()> {
        /// Rules nested deeper than this are refused.
        const MAX_DEPTH: usize = 100;
        if depth > MAX_DEPTH {
            return Err(anyhow!("{}: logical rules nested too deep", path));
        }
        if depth > 0 {
            if let Some((field, _)) = self.action_fields().first() {
                return Err(anyhow!(
                    "{}.{}: a nested rule takes no action; the rule it is in acts",
                    path,
                    field
                ));
            }
        }
        match self.kind {
            RuleType::Default => {
                if self.mode.is_some() {
                    return Err(anyhow!("{}.mode: only a logical rule has one", path));
                }
                if !self.rules.is_empty() {
                    return Err(anyhow!("{}.rules: only a logical rule has them", path));
                }
                if depth > 0 && !self.has_conditions() {
                    return Err(anyhow!("{}: the rule has no conditions", path));
                }
                if self.rule_set_ip_cidr_match_source && self.rule_set.is_empty() {
                    return Err(anyhow!(
                        "{}.rule_set_ip_cidr_match_source: only with rule_set",
                        path
                    ));
                }
                if let Some(version) = self.ip_version {
                    if version != 4 && version != 6 {
                        return Err(anyhow!("{}.ip_version: 4 or 6, not {}", path, version));
                    }
                }
            }
            RuleType::Logical => {
                if let Some(field) = self.first_condition() {
                    return Err(anyhow!(
                        "{}.{}: a logical rule's conditions are its rules",
                        path,
                        field
                    ));
                }
                if self.mode.is_none() {
                    return Err(anyhow!("{}.mode: a logical rule needs and or or", path));
                }
                if self.rules.is_empty() {
                    return Err(anyhow!("{}.rules: a logical rule needs some", path));
                }
                for (i, rule) in self.rules.iter().enumerate() {
                    rule.check_conditions(&format!("{}.rules[{}]", path, i), depth + 1)?;
                }
            }
        }
        Ok(())
    }

    /// The rule-sets the rule and the rules nested in it name, each with
    /// where.
    fn rule_sets<'a>(&'a self, path: &str, found: &mut Vec<(String, &'a String)>) {
        for tag in &self.rule_set {
            found.push((path.to_string(), tag));
        }
        for (i, rule) in self.rules.iter().enumerate() {
            rule.rule_sets(&format!("{}.rules[{}]", path, i), found);
        }
    }
}

impl RuleAction {
    /// As the configuration writes it.
    pub fn name(self) -> &'static str {
        match self {
            RuleAction::Route => "route",
            RuleAction::RouteOptions => "route-options",
            RuleAction::Reject => "reject",
            RuleAction::HijackDns => "hijack-dns",
            RuleAction::Sniff => "sniff",
            RuleAction::Resolve => "resolve",
        }
    }
}

impl Config {
    /// A TUN inbound with `auto_route` that sail routes itself, with no
    /// way out for the outbounds: they would loop back into it. A host
    /// that opens the TUN routes it, and keeps its own sockets out.
    pub fn check_tun_route(&self, host_routes: bool) -> Result<()> {
        if host_routes || self.route.auto_detect_interface || self.route.default_interface.is_some()
        {
            return Ok(());
        }
        if let Some(tun) = self.inbounds.iter().find(|i| {
            i.protocol == "tun"
                && i.options.get("auto_route") == Some(&serde_json::Value::Bool(true))
        }) {
            return Err(anyhow!(
                "[{}] inbound: auto_route routes all traffic into the TUN; set \
                 route.auto_detect_interface (or route.default_interface) so that \
                 outbound traffic does not loop back into it",
                tun.tag
            ));
        }
        Ok(())
    }

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
        // The DNS servers named elsewhere.
        let dns_servers = self.dns.server_tags();
        let dns_server = |field: &str, tag: &str| -> Result<()> {
            if dns_servers.contains(tag) {
                Ok(())
            } else {
                Err(anyhow!("{}: dns server [{}] does not exist", field, tag))
            }
        };
        if let Some(resolver) = &self.route.default_domain_resolver {
            dns_server("route.default_domain_resolver", &resolver.server)?;
        }
        for (i, rule) in self.route.rules.iter().enumerate() {
            if let Some(server) = &rule.server {
                dns_server(&format!("route.rules[{}].server", i), server)?;
            }
        }
        for (kind, tag, options) in self
            .outbounds
            .iter()
            .map(|o| ("outbound", &o.tag, &o.options))
            .chain(
                self.endpoints
                    .iter()
                    .map(|e| ("endpoint", &e.tag, &e.options)),
            )
        {
            if let Some(value) = options.get("domain_resolver") {
                let resolver = <DomainResolver as serde::Deserialize>::deserialize(value)
                    .map_err(|e| anyhow!("[{}] {}: domain_resolver: {}", tag, kind, e))?;
                dns_server(
                    &format!("[{}] {}: domain_resolver", tag, kind),
                    &resolver.server,
                )?;
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
            rule.check(&format!("route.rules[{}]", i), &outbounds)?;
        }

        let mut rule_sets = HashSet::new();
        for (i, rule_set) in self.route.rule_set.iter().enumerate() {
            rule_set
                .check()
                .map_err(|e| anyhow!("route.rule_set[{}]: {}", i, e))?;
            for tag in &rule_set.tag {
                if !rule_sets.insert(tag.as_str()) {
                    return Err(anyhow!(
                        "route.rule_set[{}]: another rule-set is tagged [{}]",
                        i,
                        tag
                    ));
                }
            }
            if let Some(detour) = &rule_set.download_detour {
                if !outbounds.contains(detour.as_str()) {
                    return Err(anyhow!(
                        "route.rule_set[{}].download_detour: outbound [{}] does not exist",
                        i,
                        detour
                    ));
                }
            }
        }
        let mut in_route = Vec::new();
        for (i, rule) in self.route.rules.iter().enumerate() {
            rule.rule_sets(&format!("route.rules[{}]", i), &mut in_route);
        }
        let named = in_route
            .into_iter()
            .chain(self.dns.rules.iter().enumerate().flat_map(|(i, r)| {
                r.rule_set
                    .iter()
                    .map(move |t| (format!("dns.rules[{}]", i), t))
            }));
        for (at, tag) in named {
            if !rule_sets.contains(tag.as_str()) {
                return Err(anyhow!(
                    "{}.rule_set: rule-set [{}] does not exist",
                    at,
                    tag
                ));
            }
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
        assert_eq!(ok.route.rules[0].action(), RuleAction::Sniff);
        assert_eq!(ok.route.rules[0].sniffer, [Sniffer::Tls]);
        assert_eq!(ok.route.rules[3].action(), RuleAction::Route);

        for (rules, message) in [
            (r#"[{ "domain": ["a"] }]"#, "a route rule needs one"),
            (
                r#"[{ "action": "sniff", "outbound": "direct" }]"#,
                "route.rules[0].outbound: not for a sniff rule",
            ),
            (
                r#"[{ "domain": ["a"], "action": "reject", "sniffer": ["tls"] }]"#,
                "route.rules[0].sniffer: not for a reject rule",
            ),
            (r#"[{ "outbound": "direct" }]"#, "route.final"),
            (r#"[{ "action": "reject" }]"#, "route.final"),
            (r#"[{ "action": "sniff", "sniffer": ["ssh"] }]"#, "ssh"),
            (
                r#"[{ "action": "route-options" }]"#,
                "route.rules[0]: a route-options rule needs an option",
            ),
            (
                r#"[{ "action": "hijack-dns", "port": 53, "sniffer": "tls" }]"#,
                "route.rules[0].sniffer: not for a hijack-dns rule",
            ),
            (
                r#"[{ "action": "reject", "port": 1, "method": "reply" }]"#,
                "route.rules[0].method: reply",
            ),
            (
                r#"[{ "action": "reject", "port": 1, "method": "drop", "no_drop": true }]"#,
                "route.rules[0].no_drop",
            ),
            (
                r#"[{ "action": "reject", "port": 1, "method": "other" }]"#,
                "route.rules[0].method",
            ),
            (
                r#"[{ "action": "route-options", "tls_fragment": true, "tls_record_fragment": true }]"#,
                "exclusive",
            ),
            (
                r#"[{ "action": "route-options", "tls_fragment_fallback_delay": "1s" }]"#,
                "route.rules[0].tls_fragment_fallback_delay: only with tls_fragment",
            ),
            (
                r#"[{ "action": "route-options", "udp_timeout": "0s" }]"#,
                "route.rules[0].udp_timeout: must be more than 0",
            ),
            (
                r#"[{ "action": "resolve", "override_port": 53 }]"#,
                "route.rules[0].override_port: not for a resolve rule",
            ),
            (
                r#"[{ "port": 1, "ip_version": 5, "outbound": "direct" }]"#,
                "route.rules[0].ip_version: 4 or 6",
            ),
            (r#"[{ "action": "bypass" }]"#, "bypass"),
        ] {
            let err = config(rules).unwrap_err().to_string();
            assert!(err.contains(message), "{}: {}", rules, err);
        }
    }

    /// As sing-box has it: a logical rule's conditions are its rules, and
    /// the rules nested in it take no action; a mistake names its full
    /// path.
    #[test]
    fn logical_rules_and_their_mistakes() {
        let config = |rules: &str| {
            Config::from_json(&format!(
                r#"{{ "outbounds": [{{ "type": "direct" }}], "route": {{ "rules": {} }} }}"#,
                rules
            ))
        };
        let ok = config(
            r#"[{ "type": "logical", "mode": "and", "outbound": "direct", "rules": [
                    { "port": 443 },
                    { "type": "logical", "mode": "or", "invert": true, "rules": [
                        { "domain": "a" }, { "network": "udp", "invert": true }
                    ] }
                ] }]"#,
        )
        .unwrap();
        assert_eq!(ok.route.rules[0].kind, RuleType::Logical);
        assert_eq!(ok.route.rules[0].rules[1].mode, Some(LogicalMode::Or));

        for (rules, message) in [
            (
                r#"[{ "port": 1, "outbound": "direct" }, { "type": "logical", "mode": "and", "outbound": "direct",
                     "rules": [{ "port": 1 }, { "port": 2, "outbound": "direct" }] }]"#,
                "route.rules[1].rules[1].outbound: a nested rule takes no action",
            ),
            (
                r#"[{ "type": "logical", "mode": "and", "outbound": "direct",
                     "rules": [{ "port": 1, "action": "route" }] }]"#,
                "route.rules[0].rules[0].action: a nested rule takes no action",
            ),
            (
                r#"[{ "type": "logical", "mode": "and", "outbound": "direct",
                     "rules": [{ "type": "logical", "mode": "or", "rules": [{ "invert": true }] }] }]"#,
                "route.rules[0].rules[0].rules[0]: the rule has no conditions",
            ),
            (
                r#"[{ "type": "logical", "mode": "and", "port": 1, "outbound": "direct",
                     "rules": [{ "port": 1 }] }]"#,
                "route.rules[0].port: a logical rule's conditions are its rules",
            ),
            (
                r#"[{ "type": "logical", "outbound": "direct", "rules": [{ "port": 1 }] }]"#,
                "route.rules[0].mode",
            ),
            (
                r#"[{ "type": "logical", "mode": "xor", "outbound": "direct", "rules": [{ "port": 1 }] }]"#,
                "mode",
            ),
            (
                r#"[{ "type": "logical", "mode": "or", "outbound": "direct", "rules": [] }]"#,
                "route.rules[0].rules: a logical rule needs some",
            ),
            (
                r#"[{ "mode": "or", "port": 1, "outbound": "direct" }]"#,
                "route.rules[0].mode: only a logical rule has one",
            ),
            (
                r#"[{ "type": "logical", "mode": "or", "outbound": "direct",
                     "rules": [{ "rule_set": "missing" }] }]"#,
                "route.rules[0].rules[0].rule_set: rule-set [missing] does not exist",
            ),
            (
                r#"[{ "type": "nested", "port": 1, "outbound": "direct" }]"#,
                "route.rules[0]",
            ),
        ] {
            let err = config(rules).unwrap_err().to_string();
            assert!(err.contains(message), "{}: {}", rules, err);
        }
    }

    #[test]
    fn a_tun_taking_the_default_route_needs_an_outbound_interface() {
        let tun = r#""inbounds": [{ "type": "tun", "address": "172.19.0.1/30", "auto_route": true }], "outbounds": [{ "type": "direct" }]"#;
        let config = Config::from_json(&format!("{{ {} }}", tun)).unwrap();
        let err = config.check_tun_route(false).unwrap_err();
        assert!(
            err.to_string().contains("route.auto_detect_interface"),
            "{}",
            err
        );
        // A host that opens the TUN routes it.
        config.check_tun_route(true).unwrap();
        Config::from_json(&format!(
            r#"{{ {}, "route": {{ "auto_detect_interface": true }} }}"#,
            tun
        ))
        .unwrap()
        .check_tun_route(false)
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
