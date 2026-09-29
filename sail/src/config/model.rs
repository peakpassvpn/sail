//! The configuration the runtime is built from, in sing-box's shape: its
//! JSON is read into it directly, other formats are translated into it.
//! Field names follow sing-box wherever the meaning is the same; what sail
//! adds sits in place, and is marked as an extension where it is declared.
//!
//! What an inbound or outbound takes beyond its type and tag belongs to its
//! protocol: the model keeps it as an untyped map, and the protocol's factory
//! reads it into its own options type when the handler is built. That keeps
//! the whole of a protocol, options included, in the protocol's directory.

use std::collections::{BTreeMap, HashMap, HashSet};

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
    /// How sail fetches over HTTP, rule-sets for one, by tag.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub http_clients: Vec<HttpClient>,
    /// A sail extension: outbounds given together, downloaded, read from
    /// a file or written in place, that groups take as members, as
    /// Mihomo's proxy groups take a proxy-provider's proxies.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outbound_providers: Vec<OutboundProvider>,
    /// What the configuration sets that sail ignores, one line each; the
    /// start logs them.
    #[serde(skip)]
    pub warnings: Vec<String>,
}

/// An HTTP client: the outbound it fetches through, or, with none, the
/// dial fields it connects with itself.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HttpClient {
    /// Of one in `http_clients`; none inline.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tag: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detour: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind_interface: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inet4_bind_address: Option<std::net::Ipv4Addr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inet6_bind_address: Option<std::net::Ipv6Addr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routing_mark: Option<u32>,
    #[serde(default, with = "duration", skip_serializing_if = "Option::is_none")]
    pub connect_timeout: Option<std::time::Duration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_resolver: Option<DomainResolver>,
    /// sing-box's deprecated field for the families names resolve to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_strategy: Option<DnsStrategy>,
    /// Sent with each request, over sail's own of the same name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, HeaderValues>,
}

/// Its headers, a line each.
pub fn header_lines(headers: &BTreeMap<String, HeaderValues>) -> Vec<(String, String)> {
    headers
        .iter()
        .flat_map(|(name, values)| values.0.iter().map(|v| (name.clone(), v.clone())))
        .collect()
}

/// Checks that each header is one a request can carry: a name, and values
/// that do not break its line. `Connection` is sail's to set.
pub fn check_headers(headers: &BTreeMap<String, HeaderValues>) -> Result<()> {
    for (name, values) in headers {
        let token = |c: char| c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c);
        if name.is_empty() || !name.chars().all(token) {
            return Err(anyhow!("headers: {:?} is no header name", name));
        }
        if name.eq_ignore_ascii_case("connection") {
            return Err(anyhow!("headers: Connection is sail's to set"));
        }
        if let Some(v) = values.0.iter().find(|v| v.contains(['\r', '\n', '\0'])) {
            return Err(anyhow!("headers: {}: {:?} breaks the line", name, v));
        }
    }
    Ok(())
}

/// The values of a header: one, or a list.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(transparent)]
pub struct HeaderValues(#[serde(with = "listable")] pub Vec<String>);

impl HttpClient {
    /// Its headers, a line each.
    pub fn header_lines(&self) -> Vec<(String, String)> {
        header_lines(&self.headers)
    }

    /// The dial options it connects with, when it has no detour: its own,
    /// over `defaults`.
    pub fn dial(&self, defaults: &crate::net::DialOptions) -> crate::net::DialOptions {
        crate::net::DialOptions {
            bind_interface: self.bind_interface.clone(),
            inet4_bind_address: self.inet4_bind_address,
            inet6_bind_address: self.inet6_bind_address,
            routing_mark: self.routing_mark,
            connect_timeout: self
                .connect_timeout
                .unwrap_or(crate::net::dial::DEFAULT_CONNECT_TIMEOUT),
            domain_resolver: self.domain_resolver.clone().map(|resolver| DomainResolver {
                strategy: resolver.strategy.or(self.domain_strategy),
                ..resolver
            }),
            strategy: self.domain_strategy,
            ..Default::default()
        }
        .or(defaults)
    }

    fn check(&self, outbounds: &HashSet<&str>, dns_servers: &HashSet<String>) -> Result<()> {
        if let Some(detour) = &self.detour {
            if !outbounds.contains(detour.as_str()) {
                return Err(anyhow!("detour: outbound [{}] does not exist", detour));
            }
            let dials = self.bind_interface.is_some()
                || self.inet4_bind_address.is_some()
                || self.inet6_bind_address.is_some()
                || self.routing_mark.is_some()
                || self.connect_timeout.is_some()
                || self.domain_resolver.is_some()
                || self.domain_strategy.is_some();
            if dials {
                return Err(anyhow!(
                    "the dial fields have no effect with a detour; set them on [{}]",
                    detour
                ));
            }
        }
        check_headers(&self.headers)?;
        if let Some(resolver) = &self.domain_resolver {
            if !dns_servers.contains(&resolver.server) {
                return Err(anyhow!(
                    "domain_resolver: dns server [{}] does not exist",
                    resolver.server
                ));
            }
        }
        Ok(())
    }
}

/// An HTTP client named by tag, or given in place; in place, its tag is
/// no name, as in sing-box.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(untagged)]
pub enum HttpClientRef {
    Tag(String),
    Inline(HttpClient),
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
    pub cache_file: Option<CacheFileOptions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clash_api: Option<ClashApi>,
}

/// sing-box's `cache_file`: what is kept across restarts. The selections
/// of selector groups and the Clash API's mode, and the fake IPs handed
/// out with `store_fakeip`; nothing without it.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CacheFileOptions {
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub enabled: bool,
    /// `cache.db` when unset. A relative path is in the host's cache
    /// directory, or the data directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// What this configuration keeps is kept apart, under this name, from
    /// what others sharing the file keep.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_id: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub store_fakeip: bool,
    /// The DNS answers kept are kept in the file too, and outlive a
    /// restart.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub store_dns: bool,
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
    /// No answer is kept: each query goes to its server.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disable_cache: bool,
    /// Answers kept are used however old they are, until the cache is full
    /// or cleared.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disable_expire: bool,
    /// How many answers are kept; 1024 when unset, and at least that, as
    /// in sing-box.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_capacity: Option<usize>,
    /// An answer that has expired is still given, for up to its timeout,
    /// while the server is asked again in the background.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub optimistic: Option<Optimistic>,
    /// How long one query to one server may take; 10s when unset, as in
    /// sing-box.
    #[serde(default, with = "duration", skip_serializing_if = "Option::is_none")]
    pub timeout: Option<std::time::Duration>,
    /// Remembers the domain of each address the DNS answers that pass
    /// through carry, so that connections to the address are routed by the
    /// domain.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub reverse_mapping: bool,
    /// The EDNS Client Subnet each query carries, unless a rule says
    /// otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_subnet: Option<Prefix>,
}

/// sing-box's `optimistic`: `true`, or `{ "enabled": true, "timeout": "3d" }`.
#[derive(Serialize, Debug, Clone, Copy, Default, PartialEq)]
pub struct Optimistic {
    pub enabled: bool,
    /// How long after it expired an answer may still be given; 3d when
    /// unset, as in sing-box.
    #[serde(default, with = "duration", skip_serializing_if = "Option::is_none")]
    pub timeout: Option<std::time::Duration>,
}

impl<'de> serde::Deserialize<'de> for Optimistic {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Full {
            #[serde(default)]
            enabled: bool,
            #[serde(default, with = "duration")]
            timeout: Option<std::time::Duration>,
        }
        match <serde_json::Value as serde::Deserialize>::deserialize(de)? {
            serde_json::Value::Bool(enabled) => Ok(Optimistic {
                enabled,
                timeout: None,
            }),
            value => {
                let full = Full::deserialize(value).map_err(serde::de::Error::custom)?;
                Ok(Optimistic {
                    enabled: full.enabled,
                    timeout: full.timeout,
                })
            }
        }
    }
}

/// A DNS server. What it takes beyond its type and tag belongs to its type,
/// and is read when the DNS client is built, as an outbound's options are.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct DnsServer {
    /// `udp`, `tcp`, `tls`, `https`, `quic`, `h3`, `local`, `hosts`, or
    /// sail's `race`.
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
    /// A sail extension, as Mihomo's `PROCESS-NAME-REGEX`: regular
    /// expressions the program's name, its path's last part, matches.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub process_name_regex: Vec<String>,
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
    /// The response of an `evaluate` rule before it, which the rule then
    /// matches: its addresses are what `ip_cidr`, `ip_is_private`,
    /// `ip_accept_any` and the rule-sets' `ip_cidr` match. With none, the
    /// rule matches only inverted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_response: Option<ResponseRef>,
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub ip_cidr: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ip_is_private: bool,
    /// The response has an address.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ip_accept_any: bool,
    /// A sail extension: the rule's conditions on the response's addresses
    /// hold for every one of them, rather than for any; a response without
    /// one they hold for none. Mihomo's fallback filter keeps an answer so.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ip_match_all: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_rcode: Option<Rcode>,
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
    /// `predefined`: the code of the answer, NOERROR when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rcode: Option<Rcode>,
    /// `evaluate`: the name of its response, which `match_response` gives.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    /// `route`, `evaluate` and `route-options`: the query neither comes
    /// from the cache nor goes into it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disable_cache: bool,
    /// An expired answer is not given while it is asked for again, though
    /// `dns.optimistic` is enabled.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disable_optimistic_cache: bool,
    /// The TTL the answer's records carry, in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rewrite_ttl: Option<u32>,
    /// How long the query may take, instead of `dns.timeout`.
    #[serde(default, with = "duration", skip_serializing_if = "Option::is_none")]
    pub timeout: Option<std::time::Duration>,
    /// The EDNS Client Subnet the query carries, instead of
    /// `dns.client_subnet`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_subnet: Option<Prefix>,
    /// The query carries no EDNS Client Subnet, whatever it or
    /// `dns.client_subnet` has.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub remove_client_subnet: bool,
}

/// What a matching DNS rule does.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DnsRuleAction {
    /// Sends the query to `server`.
    #[default]
    Route,
    /// Sends the query to `server` and keeps the response for the rules
    /// after it to match, which goes on with the next rule.
    Evaluate,
    /// Answers with the response kept.
    Respond,
    /// Sets how the query is sent, for the rule that sends it; matching
    /// goes on with the next rule.
    RouteOptions,
    /// Answers that the name does not resolve.
    Reject,
    /// Answers with `rcode` and no records, as sing-box's `predefined`
    /// without its records, which sail does not implement.
    Predefined,
}

impl DnsRuleAction {
    /// As a configuration writes it.
    pub fn name(self) -> &'static str {
        match self {
            DnsRuleAction::Route => "route",
            DnsRuleAction::Evaluate => "evaluate",
            DnsRuleAction::Respond => "respond",
            DnsRuleAction::RouteOptions => "route-options",
            DnsRuleAction::Reject => "reject",
            DnsRuleAction::Predefined => "predefined",
        }
    }
}

/// Which evaluated response a rule matches: `true` for the last one without
/// a tag, or a tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseRef {
    Latest,
    Tag(String),
}

impl<'de> serde::Deserialize<'de> for ResponseRef {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> std::result::Result<Self, D::Error> {
        match <serde_json::Value as serde::Deserialize>::deserialize(de)? {
            serde_json::Value::Bool(true) => Ok(ResponseRef::Latest),
            serde_json::Value::String(tag) if !tag.is_empty() => Ok(ResponseRef::Tag(tag)),
            other => Err(serde::de::Error::custom(format!(
                "true, or the tag of an evaluate rule, not {}",
                other
            ))),
        }
    }
}

impl serde::Serialize for ResponseRef {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        match self {
            ResponseRef::Latest => s.serialize_bool(true),
            ResponseRef::Tag(tag) => s.serialize_str(tag),
        }
    }
}

/// A DNS response code: its number, or its name (`NOERROR`, `NXDOMAIN`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rcode(pub u16);

const RCODES: &[(&str, u16)] = &[
    ("NOERROR", 0),
    ("FORMERR", 1),
    ("SERVFAIL", 2),
    ("NXDOMAIN", 3),
    ("NOTIMP", 4),
    ("REFUSED", 5),
    ("YXDOMAIN", 6),
    ("YXRRSET", 7),
    ("NXRRSET", 8),
    ("NOTAUTH", 9),
    ("NOTZONE", 10),
    ("BADSIG", 16),
    ("BADKEY", 17),
    ("BADTIME", 18),
    ("BADMODE", 19),
    ("BADNAME", 20),
    ("BADALG", 21),
    ("BADTRUNC", 22),
    ("BADCOOKIE", 23),
];

impl<'de> serde::Deserialize<'de> for Rcode {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> std::result::Result<Self, D::Error> {
        match <serde_json::Value as serde::Deserialize>::deserialize(de)? {
            serde_json::Value::Number(n) => n
                .as_u64()
                .and_then(|n| u16::try_from(n).ok())
                .map(Rcode)
                .ok_or_else(|| serde::de::Error::custom(format!("rcode {} is out of range", n))),
            serde_json::Value::String(name) => RCODES
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, code)| Rcode(*code))
                .ok_or_else(|| serde::de::Error::custom(format!("unknown rcode: {}", name))),
            other => Err(serde::de::Error::custom(format!(
                "an rcode, by name or number, not {}",
                other
            ))),
        }
    }
}

impl serde::Serialize for Rcode {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        match RCODES.iter().find(|(_, code)| *code == self.0) {
            Some((name, _)) => s.serialize_str(name),
            None => s.serialize_u16(self.0),
        }
    }
}

/// An IP prefix, or an address, which is a prefix of its whole length.
/// The bits past the prefix are kept, as written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Prefix {
    pub addr: std::net::IpAddr,
    pub len: u8,
}

impl std::str::FromStr for Prefix {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let (addr, len) = match s.split_once('/') {
            Some((addr, len)) => (addr, Some(len)),
            None => (s, None),
        };
        let addr: std::net::IpAddr = addr
            .parse()
            .map_err(|_| anyhow!("{:?} is not an address or prefix", s))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let len = match len {
            Some(len) => len
                .parse::<u8>()
                .ok()
                .filter(|len| *len <= max)
                .ok_or_else(|| anyhow!("{:?}: the prefix length is 0 to {}", s, max))?,
            None => max,
        };
        Ok(Prefix { addr, len })
    }
}

impl std::fmt::Display for Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.len)
    }
}

impl<'de> serde::Deserialize<'de> for Prefix {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> std::result::Result<Self, D::Error> {
        <String as serde::Deserialize>::deserialize(de)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

impl serde::Serialize for Prefix {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
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
            process_name_regex: self.process_name_regex.clone(),
            package_name: self.package_name.clone(),
            package_name_regex: self.package_name_regex.clone(),
            user: self.user.clone(),
            user_id: self.user_id.clone(),
            rule_set: self.rule_set.clone(),
            rule_set_ip_cidr_match_source: self.rule_set_ip_cidr_match_source,
            ip_cidr: self.ip_cidr.clone(),
            ip_is_private: self.ip_is_private,
            ip_accept_any: self.ip_accept_any,
            response_rcode: self.response_rcode.map(|r| r.0),
            invert: self.invert,
            mode: self.mode,
            rules: self.rules.iter().map(DnsRule::conditions).collect(),
            ..Default::default()
        }
    }

    /// Whether the rule sets any condition: that there is a response to
    /// match is one.
    pub fn has_conditions(&self) -> bool {
        self.conditions().has_conditions()
            || !self.outbound.is_empty()
            || self.match_response.is_some()
    }

    /// The response the rule matches, or answers with: `respond` without
    /// `match_response` answers with the last one without a tag.
    pub fn response(&self) -> Option<ResponseRef> {
        match (&self.match_response, self.action.unwrap_or_default()) {
            (Some(response), _) => Some(response.clone()),
            (None, DnsRuleAction::Respond) => Some(ResponseRef::Latest),
            (None, _) => None,
        }
    }

    /// Whether it sets how its query is sent.
    fn has_query_options(&self) -> bool {
        self.disable_cache
            || self.disable_optimistic_cache
            || self.rewrite_ttl.is_some()
            || self.timeout.is_some()
            || self.client_subnet.is_some()
            || self.remove_client_subnet
    }

    fn check(&self, servers: &HashSet<String>, fake_ip: Option<&str>) -> Result<()> {
        use DnsRuleAction::*;
        let action = self.action.unwrap_or_default();
        let fields = [
            (
                "server",
                self.server.is_some(),
                &[Route, Evaluate] as &[DnsRuleAction],
            ),
            ("strategy", self.strategy.is_some(), &[Route]),
            ("tag", self.tag.is_some(), &[Evaluate]),
            ("rcode", self.rcode.is_some(), &[Predefined]),
            (
                "disable_cache",
                self.disable_cache,
                &[Route, Evaluate, RouteOptions],
            ),
            (
                "disable_optimistic_cache",
                self.disable_optimistic_cache,
                &[Route, Evaluate, RouteOptions],
            ),
            (
                "rewrite_ttl",
                self.rewrite_ttl.is_some(),
                &[Route, Evaluate, RouteOptions],
            ),
            (
                "timeout",
                self.timeout.is_some(),
                &[Route, Evaluate, RouteOptions],
            ),
            (
                "client_subnet",
                self.client_subnet.is_some(),
                &[Route, Evaluate, RouteOptions],
            ),
            (
                "remove_client_subnet",
                self.remove_client_subnet,
                &[Route, Evaluate, RouteOptions],
            ),
        ];
        if let Some((field, _, _)) = fields
            .iter()
            .find(|(_, set, actions)| *set && !actions.contains(&action))
        {
            return Err(anyhow!("{}: not with action {}", field, action.name()));
        }
        if matches!(action, Route | Evaluate) {
            let tag = self
                .server
                .as_ref()
                .ok_or_else(|| anyhow!("server: a {} rule needs one", action.name()))?;
            if !servers.contains(tag) {
                return Err(anyhow!("server [{}] does not exist", tag));
            }
            if action == Evaluate && fake_ip == Some(tag.as_str()) {
                return Err(anyhow!(
                    "server: [{}] is the fakeip server, whose answers are not the name's",
                    tag
                ));
            }
        }
        if action == RouteOptions && !self.has_query_options() {
            return Err(anyhow!("a route-options rule sets some option"));
        }
        if self.client_subnet.is_some() && self.remove_client_subnet {
            return Err(anyhow!("client_subnet: not with remove_client_subnet"));
        }
        if self.tag.as_deref() == Some("") {
            return Err(anyhow!("tag: empty"));
        }
        if self.ip_match_all && self.invert {
            return Err(anyhow!("ip_match_all: not with invert"));
        }
        let response_fields = [
            ("ip_cidr", !self.ip_cidr.is_empty()),
            ("ip_is_private", self.ip_is_private),
            ("ip_accept_any", self.ip_accept_any),
            ("ip_match_all", self.ip_match_all),
            ("response_rcode", self.response_rcode.is_some()),
        ];
        if self.match_response.is_none() {
            if let Some((field, _)) = response_fields.iter().find(|(_, set)| *set) {
                return Err(anyhow!(
                    "{}: matches an evaluated response, and needs match_response \
                     (sail does not filter answers as sing-box's legacy DNS rules did)",
                    field
                ));
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
            ("tag", self.tag.is_some()),
            ("rcode", self.rcode.is_some()),
            ("disable_cache", self.disable_cache),
            ("rewrite_ttl", self.rewrite_ttl.is_some()),
            ("timeout", self.timeout.is_some()),
            ("client_subnet", self.client_subnet.is_some()),
            ("remove_client_subnet", self.remove_client_subnet),
        ];
        if self.match_response.is_some() {
            return Err(anyhow!(
                "match_response: sail does not implement it in a logical rule's rules yet"
            ));
        }
        let response_fields = [
            ("ip_cidr", !self.ip_cidr.is_empty()),
            ("ip_is_private", self.ip_is_private),
            ("ip_accept_any", self.ip_accept_any),
            ("ip_match_all", self.ip_match_all),
            ("response_rcode", self.response_rcode.is_some()),
        ];
        if let Some((field, _)) = response_fields.iter().find(|(_, set)| *set) {
            return Err(anyhow!(
                "{}: matches an evaluated response, and needs match_response",
                field
            ));
        }
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
    /// sing-box's: 1024, and a smaller one taken as that.
    pub fn cache_capacity(&self) -> usize {
        self.cache_capacity.unwrap_or(1024).max(1024)
    }

    /// How long after it expired an answer may still be given, when
    /// `optimistic` is enabled.
    pub fn optimistic_timeout(&self) -> Option<std::time::Duration> {
        self.optimistic.filter(|o| o.enabled).map(|o| {
            o.timeout
                .unwrap_or(std::time::Duration::from_secs(3 * 24 * 3600))
        })
    }

    pub fn timeout(&self) -> std::time::Duration {
        self.timeout.unwrap_or(std::time::Duration::from_secs(10))
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
        let fake_ip = self
            .servers
            .iter()
            .find(|s| s.kind == "fakeip")
            .map(|s| s.tag.as_str());
        for (i, rule) in self.rules.iter().enumerate() {
            rule.check(&tags, fake_ip)
                .map_err(|e| anyhow!("dns.rules[{}]: {}", i, e))?;
        }
        self.check_responses()
    }

    /// Checks that each rule matching a response, or answering with one,
    /// has an `evaluate` rule before it that gives it; and that a rule's
    /// own `strategy`, which sing-box keeps for its legacy rules, is not
    /// set alongside them.
    fn check_responses(&self) -> Result<()> {
        let mut latest = false;
        let mut tags = HashSet::new();
        let mut uses_responses = None;
        for (i, rule) in self.rules.iter().enumerate() {
            let at = |e: String| anyhow!("dns.rules[{}]: {}", i, e);
            match rule.response() {
                Some(ResponseRef::Latest) if !latest => {
                    return Err(at(if tags.is_empty() {
                        "the response it matches comes from an evaluate rule before it, and \
                         there is none"
                            .to_string()
                    } else {
                        "the response it matches comes from an evaluate rule without a tag \
                         before it; match_response names a tagged one"
                            .to_string()
                    }));
                }
                Some(ResponseRef::Tag(tag)) if !tags.contains(&tag) => {
                    return Err(at(format!(
                        "match_response: no evaluate rule before it is tagged [{}]",
                        tag
                    )));
                }
                _ => {}
            }
            let action = rule.action.unwrap_or_default();
            if action == DnsRuleAction::Evaluate {
                match &rule.tag {
                    None => latest = true,
                    Some(tag) => {
                        if !tags.insert(tag.clone()) {
                            return Err(at(format!(
                                "tag: another evaluate rule is tagged [{}]",
                                tag
                            )));
                        }
                    }
                }
            }
            if uses_responses.is_none()
                && (rule.response().is_some() || action == DnsRuleAction::Evaluate)
            {
                uses_responses = Some(i);
            }
        }
        if let Some(i) = uses_responses {
            if let Some(j) = self.rules.iter().position(|r| r.strategy.is_some()) {
                return Err(anyhow!(
                    "dns.rules[{}].strategy: not with evaluated responses (dns.rules[{}]), as in \
                     sing-box; set dns.strategy, or an outbound's domain_resolver",
                    j,
                    i
                ));
            }
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
    /// How long an accepted TCP connection is idle before keepalive probes
    /// it; 5m when unset.
    #[serde(default, with = "duration", skip_serializing_if = "Option::is_none")]
    pub tcp_keep_alive: Option<std::time::Duration>,
    /// Between keepalive probes; 75s when unset.
    #[serde(default, with = "duration", skip_serializing_if = "Option::is_none")]
    pub tcp_keep_alive_interval: Option<std::time::Duration>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disable_tcp_keep_alive: bool,
    #[serde(flatten)]
    pub options: Options,
}

impl Inbound {
    pub fn udp_timeout(&self) -> std::time::Duration {
        self.udp_timeout.unwrap_or(DEFAULT_UDP_TIMEOUT)
    }

    /// The keepalive of the TCP connections it accepts.
    pub fn tcp_keep_alive(&self) -> Option<crate::net::dial::TcpKeepAlive> {
        crate::net::dial::tcp_keep_alive(
            self.disable_tcp_keep_alive,
            self.tcp_keep_alive,
            self.tcp_keep_alive_interval,
        )
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
            tcp_keep_alive: None,
            tcp_keep_alive_interval: None,
            disable_tcp_keep_alive: false,
            options: Options::new(),
        }
    }
}

/// Outbounds given together, for groups to take as members (their
/// `providers`): a sail extension, with the semantics of Mihomo's
/// proxy-providers. A subscription or a file holds what Mihomo reads from
/// one: Clash's YAML with its `proxies`, or share links, a line each and
/// maybe in base64. It needs the outbound-provider feature.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OutboundProvider {
    #[serde(rename = "type")]
    pub kind: OutboundProviderKind,
    /// Its members' keys name it, and groups' `providers`.
    pub tag: String,
    /// `remote`: where it is downloaded from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// `local`: the file, in the data directory unless absolute.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// `remote`: how often it is downloaded again, 1d when unset. `local`:
    /// how often the file is read again, never when unset.
    #[serde(default, with = "duration", skip_serializing_if = "Option::is_none")]
    pub update_interval: Option<std::time::Duration>,
    /// `remote`: the outbound it is downloaded through, as a remote
    /// rule-set's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download_detour: Option<String>,
    /// `remote`: the HTTP client it is downloaded with, as a remote
    /// rule-set's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_client: Option<HttpClientRef>,
    /// `remote`, `local`: regular expressions, as Mihomo's `filter`; only
    /// the outbounds whose names match one are taken, those of the first
    /// first.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub filter: Vec<String>,
    /// `remote`, `local`: regular expressions no name taken may match.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub exclude_filter: Vec<String>,
    /// `remote`, `local`: the Clash types (`ss`, `vmess`, ...) not taken,
    /// without case.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub exclude_type: Vec<String>,
    /// `remote`, `local`: what is changed in every outbound taken, in the
    /// keys of Mihomo's `override` (`skip-cert-verify`,
    /// `additional-prefix`, `proxy-name`, ...).
    #[serde(rename = "override", default, skip_serializing_if = "Option::is_none")]
    pub overrides: Option<serde_json::Map<String, serde_json::Value>>,
    /// `remote`, `local`: the outbound every outbound taken dials through,
    /// as Mihomo's `dialer-proxy`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detour: Option<String>,
    /// `inline`: the outbounds, their tags their names as members.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outbounds: Vec<Outbound>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OutboundProviderKind {
    Remote,
    Local,
    Inline,
}

/// The protocols of groups, which take other outbounds as members.
pub const GROUP_PROTOCOLS: &[&str] = &[
    "selector",
    "urltest",
    "fallback",
    "load-balance",
    "smart",
    "tryall",
];

/// The groups that take members from outbound providers too.
pub const PROVIDER_GROUPS: &[&str] = &["selector", "urltest", "fallback", "load-balance", "smart"];

impl OutboundProvider {
    /// The mistakes one provider can make on its own, and those naming what
    /// is not there: `outbounds` and `http_clients` are the tags there are.
    fn check(
        &self,
        outbounds: &HashSet<&str>,
        http_clients: &HashSet<&str>,
        dns_servers: &HashSet<String>,
    ) -> Result<()> {
        use OutboundProviderKind::*;
        if self.tag.is_empty() {
            return Err(anyhow!("tag: missing"));
        }
        let only = |set: bool, field: &str, kinds: &str| {
            if set {
                Err(anyhow!("{}: only a {} provider takes one", field, kinds))
            } else {
                Ok(())
            }
        };
        match self.kind {
            Remote => {
                let url = self.url.as_deref().ok_or_else(|| anyhow!("url: missing"))?;
                if !url.starts_with("https://") && !url.starts_with("http://") {
                    return Err(anyhow!("url: \"{}\" is not an http(s) URL", url));
                }
                if self.http_client.is_some() && self.download_detour.is_some() {
                    return Err(anyhow!(
                        "http_client: not with download_detour, which it replaces"
                    ));
                }
            }
            Local => {
                if self.path.is_none() {
                    return Err(anyhow!("path: missing"));
                }
            }
            Inline => {
                if self.outbounds.is_empty() {
                    return Err(anyhow!("outbounds: missing"));
                }
                let mut names = HashSet::new();
                for (i, outbound) in self.outbounds.iter().enumerate() {
                    if outbound.tag.is_empty() {
                        return Err(anyhow!("outbounds[{}].tag: missing", i));
                    }
                    if !names.insert(outbound.tag.as_str()) {
                        return Err(anyhow!(
                            "outbounds[{}]: another outbound is tagged [{}]",
                            i,
                            outbound.tag
                        ));
                    }
                    if GROUP_PROTOCOLS.contains(&outbound.protocol.as_str())
                        || outbound.protocol == "plugin"
                    {
                        return Err(anyhow!(
                            "outbounds[{}]: a group or a plugin is not a provider's outbound",
                            i
                        ));
                    }
                }
                only(
                    self.update_interval.is_some(),
                    "update_interval",
                    "remote or local",
                )?;
                let selection = [
                    ("filter", !self.filter.is_empty()),
                    ("exclude_filter", !self.exclude_filter.is_empty()),
                    ("exclude_type", !self.exclude_type.is_empty()),
                    ("override", self.overrides.is_some()),
                    ("detour", self.detour.is_some()),
                ];
                for (field, set) in selection {
                    only(set, field, "remote or local")?;
                }
            }
        }
        if self.kind != Remote {
            only(self.url.is_some(), "url", "remote")?;
            only(self.download_detour.is_some(), "download_detour", "remote")?;
            only(self.http_client.is_some(), "http_client", "remote")?;
        }
        if self.kind != Local {
            only(self.path.is_some(), "path", "local")?;
        }
        if self.kind != Inline {
            only(!self.outbounds.is_empty(), "outbounds", "inline")?;
        }
        if self.update_interval == Some(std::time::Duration::ZERO) {
            return Err(anyhow!("update_interval: must be more than 0"));
        }
        for (field, tag) in [
            ("detour", &self.detour),
            ("download_detour", &self.download_detour),
        ] {
            if let Some(tag) = tag {
                if !outbounds.contains(tag.as_str()) {
                    return Err(anyhow!("{}: outbound [{}] does not exist", field, tag));
                }
            }
        }
        match &self.http_client {
            Some(HttpClientRef::Tag(tag)) if !http_clients.contains(tag.as_str()) => {
                Err(anyhow!("http_client: http client [{}] does not exist", tag))
            }
            Some(HttpClientRef::Inline(client)) => client
                .check(outbounds, dns_servers)
                .map_err(|e| anyhow!("http_client: {}", e)),
            _ => Ok(()),
        }
    }
}

/// The members a group takes from outbound providers, after its own
/// `outbounds`, and those it leaves out: a sail extension, as Mihomo's
/// proxy groups take them (`use`, `filter`, `exclude-filter`,
/// `exclude-type`, `empty-fallback`). Of `selector`, `urltest`, `fallback`,
/// `load-balance` and `smart`; it needs the outbound-provider feature.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct GroupProviders {
    /// The outbound providers, by tag, whose outbounds join the group's
    /// own, in this order.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub providers: Vec<String>,
    /// Regular expressions, as Mihomo's `filter`: of the providers'
    /// outbounds, only those whose names match one are members, those of
    /// the first first. The group's own outbounds are not filtered.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub filter: Vec<String>,
    /// Regular expressions no member's name may match, the group's own
    /// outbounds' too.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub exclude_filter: Vec<String>,
    /// The types no member may be of, the group's own outbounds too, in
    /// Mihomo's names for them, without case: `Shadowsocks`, `Vmess`,
    /// `Socks5`, `Direct`, ...
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub exclude_type: Vec<String>,
    /// An outbound, not a group, that is the member while there is none
    /// else. Without it such a group has none, and its connections fail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub empty_fallback: Option<String>,
}

impl GroupProviders {
    /// What the group's options set of it.
    pub fn of(options: &Options) -> Result<Self> {
        serde_path_to_error::deserialize(serde_json::Value::Object(options.clone()))
            .map_err(|e| anyhow!("{}: {}", path(&e), e.inner()))
    }

    /// The first of its fields that is set, if any is.
    pub fn first_set(&self) -> Option<&'static str> {
        [
            ("providers", !self.providers.is_empty()),
            ("filter", !self.filter.is_empty()),
            ("exclude_filter", !self.exclude_filter.is_empty()),
            ("exclude_type", !self.exclude_type.is_empty()),
            ("empty_fallback", self.empty_fallback.is_some()),
        ]
        .into_iter()
        .find_map(|(field, set)| set.then_some(field))
    }

    /// The outbounds a group with `outbounds` of its own is built on: the
    /// empty fallback too.
    pub fn dependencies(&self, mut outbounds: Vec<String>) -> Vec<String> {
        outbounds.extend(self.empty_fallback.clone());
        outbounds
    }

    fn check(&self, providers: &HashSet<&str>, protocols: &HashMap<&str, &str>) -> Result<()> {
        if !cfg!(feature = "outbound-provider") {
            if let Some(field) = self.first_set() {
                return Err(anyhow!(
                    "{}: needs the outbound-provider feature, which is not compiled in",
                    field
                ));
            }
        }
        if let Some(tag) = self
            .providers
            .iter()
            .find(|p| !providers.contains(p.as_str()))
        {
            return Err(anyhow!("providers: provider [{}] does not exist", tag));
        }
        if !self.filter.is_empty() && self.providers.is_empty() {
            return Err(anyhow!(
                "filter: only with providers, as the group's own outbounds are not filtered"
            ));
        }
        if let Some(tag) = &self.empty_fallback {
            match protocols.get(tag.as_str()) {
                None => {
                    return Err(anyhow!("empty_fallback: outbound [{}] does not exist", tag));
                }
                Some(protocol) if GROUP_PROTOCOLS.contains(protocol) => {
                    return Err(anyhow!("empty_fallback: [{}] is a group", tag));
                }
                Some(_) => {}
            }
        }
        Ok(())
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
    /// The HTTP client of what names none, by tag; the first of
    /// `http_clients` when unset, or with none, the default outbound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_http_client: Option<String>,
}

impl Route {
    /// The outbounds its rules may send a connection to, and `final`, or
    /// else the first of `outbounds`, which takes what no rule matches.
    pub fn outbounds<'a>(&'a self, outbounds: &'a [Outbound]) -> Vec<&'a str> {
        let mut tags: Vec<&str> = self
            .rules
            .iter()
            .filter_map(|r| r.outbound.as_deref())
            .collect();
        match &self.final_outbound {
            Some(tag) => tags.push(tag),
            None => tags.extend(outbounds.first().map(|o| o.tag.as_str())),
        }
        tags.sort();
        tags.dedup();
        tags
    }
}

/// A DNS server that resolves the names something dials: its tag, or
/// `{ "server": tag, "strategy": ... }` with how the queries are sent, as a
/// DNS rule's route options say it.
#[derive(Serialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct DomainResolver {
    pub server: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy: Option<DnsStrategy>,
    #[serde(default, with = "duration", skip_serializing_if = "Option::is_none")]
    pub timeout: Option<std::time::Duration>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disable_cache: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disable_optimistic_cache: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rewrite_ttl: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_subnet: Option<Prefix>,
}

impl<'de> serde::Deserialize<'de> for DomainResolver {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Full {
            server: String,
            #[serde(default)]
            strategy: Option<DnsStrategy>,
            #[serde(default, with = "duration")]
            timeout: Option<std::time::Duration>,
            #[serde(default)]
            disable_cache: bool,
            #[serde(default)]
            disable_optimistic_cache: bool,
            #[serde(default)]
            rewrite_ttl: Option<u32>,
            #[serde(default)]
            client_subnet: Option<Prefix>,
        }
        match <serde_json::Value as serde::Deserialize>::deserialize(de)? {
            serde_json::Value::String(server) => Ok(DomainResolver {
                server,
                ..Default::default()
            }),
            value => {
                let full = Full::deserialize(value).map_err(serde::de::Error::custom)?;
                Ok(DomainResolver {
                    server: full.server,
                    strategy: full.strategy,
                    timeout: full.timeout,
                    disable_cache: full.disable_cache,
                    disable_optimistic_cache: full.disable_optimistic_cache,
                    rewrite_ttl: full.rewrite_ttl,
                    client_subnet: full.client_subnet,
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
    /// A DNS rule's: the response it matches has an address.
    #[serde(skip)]
    pub ip_accept_any: bool,
    /// A DNS rule's: the response it matches has this code.
    #[serde(skip)]
    pub response_rcode: Option<u16>,
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
    /// A sail extension, as Mihomo's `PROCESS-NAME-REGEX`: regular
    /// expressions the program's name, its path's last part, matches.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub process_name_regex: Vec<String>,
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
    /// `sniff`, a sail extension: a domain found that one of these
    /// rule-sets matches is not taken, neither matched nor connected to, as
    /// Mihomo's sniffer `skip-domain` has it.
    #[serde(default, with = "listable", skip_serializing_if = "Vec::is_empty")]
    pub skip_rule_set: Vec<String>,
    /// `resolve`, a sail extension: a domain that does not resolve, or not in
    /// time, has no addresses, and matching goes on, as Mihomo's IP rules
    /// have it; rather than the connection failing, as in sing-box.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ignore_failure: bool,
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
    /// As sing-box 1.13: lets the kernel carry the connection past the
    /// proxy where TUN's auto_redirect matches it before it is set up.
    /// Elsewhere it routes to `outbound` like `route`, and without one the
    /// rule is skipped.
    Bypass,
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
            ("ip_accept_any", self.ip_accept_any),
            ("response_rcode", self.response_rcode.is_some()),
            ("source_port", !self.source_port.is_empty()),
            ("source_port_range", !self.source_port_range.is_empty()),
            ("port", !self.port.is_empty()),
            ("port_range", !self.port_range.is_empty()),
            ("process_name", !self.process_name.is_empty()),
            ("process_path", !self.process_path.is_empty()),
            ("process_path_regex", !self.process_path_regex.is_empty()),
            ("process_name_regex", !self.process_name_regex.is_empty()),
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
        const ROUTE: &[RuleAction] = &[Route, RouteOptions, Bypass];
        [
            ("action", self.action.is_some(), &[] as &[RuleAction]),
            ("outbound", self.outbound.is_some(), &[Route, Bypass]),
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
            ("ignore_failure", self.ignore_failure, &[Resolve]),
            ("override_destination", self.override_destination, &[Sniff]),
            ("skip_rule_set", !self.skip_rule_set.is_empty(), &[Sniff]),
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
            RuleAction::Bypass => {
                if let Some(tag) = &self.outbound {
                    if !outbounds.contains(tag.as_str()) {
                        return Err(anyhow!("{}: outbound [{}] does not exist", path, tag));
                    }
                }
            }
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
        let ends_matching = matches!(action, RuleAction::Route | RuleAction::Reject)
            || (action == RuleAction::Bypass && self.outbound.is_some());
        if ends_matching && !self.has_conditions() {
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
            RuleAction::Bypass => "bypass",
        }
    }
}

impl Config {
    /// Whether a TUN inbound with `auto_route`, which sail routes itself,
    /// would take sail's own traffic too: nothing but binding to the
    /// physical interface keeps it out, unless a host that opens the TUN
    /// routes it, or `auto_redirect` marks sail's sockets.
    pub fn tun_takes_own_traffic(&self, host_routes: bool) -> bool {
        !host_routes
            && self.inbounds.iter().any(|i| {
                i.protocol == "tun"
                    && i.options.get("auto_route") == Some(&serde_json::Value::Bool(true))
                    && i.options.get("auto_redirect") != Some(&serde_json::Value::Bool(true))
            })
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

        let mut http_clients = HashSet::new();
        for (i, client) in self.http_clients.iter().enumerate() {
            if client.tag.is_empty() {
                return Err(anyhow!("http_clients[{}].tag: missing", i));
            }
            if !http_clients.insert(client.tag.as_str()) {
                return Err(anyhow!(
                    "http_clients[{}]: another http client is tagged [{}]",
                    i,
                    client.tag
                ));
            }
            client
                .check(&outbounds, &dns_servers)
                .map_err(|e| anyhow!("http_clients[{}]: {}", i, e))?;
        }
        if let Some(tag) = &self.route.default_http_client {
            if !http_clients.contains(tag.as_str()) {
                return Err(anyhow!(
                    "route.default_http_client: http client [{}] does not exist",
                    tag
                ));
            }
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
            match &rule_set.http_client {
                Some(HttpClientRef::Tag(tag)) if !http_clients.contains(tag.as_str()) => {
                    return Err(anyhow!(
                        "route.rule_set[{}].http_client: http client [{}] does not exist",
                        i,
                        tag
                    ));
                }
                Some(HttpClientRef::Inline(client)) => client
                    .check(&outbounds, &dns_servers)
                    .map_err(|e| anyhow!("route.rule_set[{}].http_client: {}", i, e))?,
                _ => {}
            }
        }
        let mut providers = HashSet::new();
        for (i, provider) in self.outbound_providers.iter().enumerate() {
            if !cfg!(feature = "outbound-provider") {
                return Err(anyhow!(
                    "outbound_providers: need the outbound-provider feature, which is not \
                     compiled in"
                ));
            }
            provider
                .check(&outbounds, &http_clients, &dns_servers)
                .map_err(|e| anyhow!("outbound_providers[{}]: {}", i, e))?;
            if !providers.insert(provider.tag.as_str()) {
                return Err(anyhow!(
                    "outbound_providers[{}]: another provider is tagged [{}]",
                    i,
                    provider.tag
                ));
            }
        }
        let protocols: HashMap<&str, &str> = self
            .outbounds
            .iter()
            .map(|o| (o.tag.as_str(), o.protocol.as_str()))
            .chain(
                self.endpoints
                    .iter()
                    .map(|e| (e.tag.as_str(), e.protocol.as_str())),
            )
            .collect();
        let mut users: HashMap<&str, Vec<String>> = HashMap::new();
        for group in self
            .outbounds
            .iter()
            .filter(|o| PROVIDER_GROUPS.contains(&o.protocol.as_str()))
        {
            let members = GroupProviders::of(&group.options)
                .and_then(|m| m.check(&providers, &protocols).map(|()| m))
                .map_err(|e| anyhow!("[{}] outbound: {}", group.tag, e))?;
            users.insert(group.tag.as_str(), members.providers);
        }
        // A provider's outbounds dialling through a group of them would go
        // round in a loop.
        for provider in &self.outbound_providers {
            if let Some(detour) = &provider.detour {
                if users
                    .get(detour.as_str())
                    .is_some_and(|p| p.contains(&provider.tag))
                {
                    return Err(anyhow!(
                        "outbound_providers: [{}]: detour: [{}] takes its members from it",
                        provider.tag,
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
        let part =
            std::time::Duration::try_from_secs_f64(value * seconds).map_err(|_| invalid())?;
        total = total.checked_add(part).ok_or_else(invalid)?;
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
            (
                r#"[{ "port": 1, "action": "bypass", "outbound": "proxy" }]"#,
                "route.rules[0]: outbound [proxy] does not exist",
            ),
            (
                r#"[{ "action": "bypass", "outbound": "direct" }]"#,
                "route.final",
            ),
            (
                r#"[{ "port": 1, "action": "bypass", "method": "drop" }]"#,
                "route.rules[0].method: not for a bypass rule",
            ),
            (
                r#"[{ "port": 1, "outbound": "direct", "ignore_failure": true }]"#,
                "route.rules[0].ignore_failure: not for a route rule",
            ),
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
    fn a_tun_taking_the_default_route_takes_sail_s_own_traffic() {
        let tun = |extra: &str| {
            Config::from_json(&format!(
                r#"{{ "inbounds": [{{ "type": "tun", "address": "172.19.0.1/30", "auto_route": true{} }}], "outbounds": [{{ "type": "direct" }}] }}"#,
                extra
            ))
            .unwrap()
        };
        assert!(tun("").tun_takes_own_traffic(false));
        // A host that opens the TUN routes it.
        assert!(!tun("").tun_takes_own_traffic(true));
        // auto_redirect keeps sail's own sockets out by their mark.
        assert!(!tun(r#", "auto_redirect": true"#).tun_takes_own_traffic(false));
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
    fn duration_overflow_is_an_error() {
        // One component can overflow Duration during the float conversion.
        assert!(parse_duration("222222222222222222222s").is_err());
        assert!(parse_duration(&format!("{}s", "9".repeat(400))).is_err());

        // Individually representable components can overflow when combined.
        assert!(parse_duration("10000000000000000000s10000000000000000000s").is_err());
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
        // Less than sing-box's least, 1024, is taken as that.
        assert_eq!(config.dns.cache_capacity(), 1024);
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
        assert_eq!(defaults.dns.timeout(), std::time::Duration::from_secs(10));
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

    /// A configuration of a direct outbound `d` and the group `group`, with
    /// the outbound providers `providers`.
    fn with_providers(providers: &str, group: &str) -> Result<Config> {
        Config::from_json(&format!(
            r#"{{ "outbounds": [{{ "type": "direct", "tag": "d" }}, {}],
                  "outbound_providers": [{}] }}"#,
            group, providers
        ))
    }

    const REMOTE: &str = r#"{ "type": "remote", "tag": "p", "url": "https://example.com/s",
        "filter": ["HK", "JP"], "exclude_type": "vmess", "detour": "d",
        "override": { "skip-cert-verify": true, "additional-prefix": "A|" } }"#;

    #[cfg(feature = "outbound-provider")]
    #[test]
    fn outbound_providers_and_the_groups_that_take_them() {
        let group = r#"{ "type": "selector", "tag": "g", "providers": ["p"], "filter": "HK",
            "exclude_type": ["Direct"], "empty_fallback": "d" }"#;
        let config = with_providers(REMOTE, group).unwrap();
        assert_eq!(config.outbound_providers[0].filter, ["HK", "JP"]);
        let members = GroupProviders::of(&config.outbounds[1].options).unwrap();
        assert_eq!(members.providers, ["p"]);
        assert_eq!(members.dependencies(Vec::new()), ["d"]);

        let local = r#"{ "type": "local", "tag": "p", "path": "p.yaml", "update_interval": "1m" }"#;
        let inline =
            r#"{ "type": "inline", "tag": "p", "outbounds": [{ "type": "direct", "tag": "a" }] }"#;
        let taking = r#"{ "type": "urltest", "tag": "g", "providers": "p" }"#;
        with_providers(local, taking).unwrap();
        with_providers(inline, taking).unwrap();

        for (providers, group, error) in [
            (
                REMOTE,
                r#"{ "type": "selector", "tag": "g", "providers": ["q"] }"#,
                "[g] outbound: providers: provider [q] does not exist",
            ),
            (
                REMOTE,
                r#"{ "type": "selector", "tag": "g", "outbounds": ["d"], "filter": "HK" }"#,
                "[g] outbound: filter: only with providers",
            ),
            (
                REMOTE,
                r#"{ "type": "fallback", "tag": "g", "providers": "p", "empty_fallback": "x" }"#,
                "[g] outbound: empty_fallback: outbound [x] does not exist",
            ),
            (
                REMOTE,
                r#"{ "type": "fallback", "tag": "g", "providers": "p", "empty_fallback": "g" }"#,
                "[g] outbound: empty_fallback: [g] is a group",
            ),
            (
                &REMOTE.replace(r#""detour": "d""#, r#""detour": "g""#),
                r#"{ "type": "load-balance", "tag": "g", "providers": "p" }"#,
                "[p]: detour: [g] takes its members from it",
            ),
            (
                &format!("{}, {}", REMOTE, REMOTE),
                r#"{ "type": "direct", "tag": "g" }"#,
                "outbound_providers[1]: another provider is tagged [p]",
            ),
            (
                r#"{ "type": "remote", "tag": "p" }"#,
                r#"{ "type": "direct", "tag": "g" }"#,
                "outbound_providers[0]: url: missing",
            ),
            (
                r#"{ "type": "local", "tag": "p", "path": "a", "url": "https://a" }"#,
                r#"{ "type": "direct", "tag": "g" }"#,
                "url: only a remote provider takes one",
            ),
            (
                r#"{ "type": "inline", "tag": "p", "filter": "HK",
                  "outbounds": [{ "type": "direct", "tag": "a" }] }"#,
                r#"{ "type": "direct", "tag": "g" }"#,
                "filter: only a remote or local provider takes one",
            ),
            (
                r#"{ "type": "inline", "tag": "p",
                  "outbounds": [{ "type": "selector", "tag": "a", "outbounds": ["d"] }] }"#,
                r#"{ "type": "direct", "tag": "g" }"#,
                "outbounds[0]: a group or a plugin is not a provider's outbound",
            ),
            (
                r#"{ "type": "remote", "tag": "p", "url": "https://a", "detour": "x" }"#,
                r#"{ "type": "direct", "tag": "g" }"#,
                "detour: outbound [x] does not exist",
            ),
        ] {
            let err = with_providers(providers, group).unwrap_err();
            assert!(err.to_string().contains(error), "{}: {}", error, err);
        }
    }

    #[cfg(not(feature = "outbound-provider"))]
    #[test]
    fn outbound_providers_need_their_feature() {
        let err = with_providers(REMOTE, r#"{ "type": "direct", "tag": "g" }"#).unwrap_err();
        assert!(
            err.to_string().contains("outbound-provider feature"),
            "{}",
            err
        );
        let err = with_providers(
            "",
            r#"{ "type": "selector", "tag": "g", "outbounds": ["d"],
            "exclude_filter": "x" }"#,
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("[g] outbound: exclude_filter: needs the outbound-provider feature"),
            "{}",
            err
        );
    }
}
