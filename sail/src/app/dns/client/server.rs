//! The servers of `dns.servers`, as sing-box describes them: each with a
//! type, a tag and the options of its type, and the dial fields of the
//! connections it makes.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use serde_derive::Deserialize;

use super::upstream::{Protocol, Upstream};
use crate::config::model::{listable, parse_options, DnsServer, Prefix};
use crate::net::dial::DialFields;
use crate::net::DialDefaults;
use crate::runtime::RuntimeEnv;
use crate::transport::layers::OutboundTls;

/// One server, built from its configuration.
pub(super) struct Server {
    pub tag: String,
    pub kind: Kind,
    /// The EDNS Client Subnet its queries carry, over any they have.
    pub client_subnet: Option<Prefix>,
}

pub(super) enum Kind {
    /// Plain DNS over UDP.
    Udp { address: Address, dialer: Dialer },
    /// Plain DNS over TCP, each message prefixed with its length; the
    /// connections are kept as DoT's are.
    Tcp {
        address: Address,
        dialer: Dialer,
        pool: super::upstream::StreamPool,
    },
    /// DoT, DoH, DoQ or DoH3.
    Upstream(Arc<Upstream>),
    /// The system's resolver; with dial fields, the system's servers,
    /// asked through its dialer.
    Local(Box<Local>),
    /// Multicast DNS, asked on the link.
    Mdns(super::mdns::Mdns),
    /// Addresses given for names: files in the hosts format, and names
    /// given in place.
    Hosts(Hosts),
    /// Fake IPs, which the connections to come back as their domains.
    FakeIp(Arc<super::fakeip::FakeIpStore>),
    /// A sail extension: the member that answers best, chosen again as they
    /// fare.
    /// Asks its members all at once, and takes the first to answer well,
    /// as Mihomo and Surge ask a list of servers; a sail extension.
    Race { members: Vec<String> },
}

/// Where a server is: an address, or a domain its resolver resolves.
#[derive(Debug, Clone)]
pub(super) struct Address {
    pub host: String,
    pub port: u16,
    /// The server that resolves `host`, and how, when it is a domain.
    pub resolver: Option<Resolver>,
}

/// A server's `domain_resolver`.
pub(super) type Resolver = crate::config::model::DomainResolver;

impl Address {
    pub fn ip(&self) -> Option<IpAddr> {
        self.host.parse().ok()
    }

    /// The address, when `host` is one.
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        self.ip().map(|ip| SocketAddr::new(ip, self.port))
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.ip() {
            Some(IpAddr::V6(ip)) => write!(f, "[{}]:{}", ip, self.port),
            _ => write!(f, "{}:{}", self.host, self.port),
        }
    }
}

/// How a server's connections are made: through the outbound `detour`
/// names, through the one the routing rules pick (`respect_rules`), or
/// directly with its own dial fields.
#[derive(Debug, Clone)]
pub(super) struct Dialer {
    pub detour: Option<String>,
    pub respect_rules: bool,
    /// The server's domain, which the routing rules see with
    /// `respect_rules`.
    pub domain: Option<String>,
    pub dial: crate::net::Dialer,
}

impl Dialer {
    /// Whether it dials with its own dialer: its sockets, or its detour's
    /// (`dial` goes through that), not the outbound the rules pick.
    pub fn is_direct(&self) -> bool {
        !self.respect_rules
    }
}

/// The dial fields a server implements: all that sail does but
/// `skip_default_domain_resolver`, a server's name resolving through its
/// own `domain_resolver` alone.
const DIAL: &[&str] = &[
    "detour",
    "bind_interface",
    "inet4_bind_address",
    "inet6_bind_address",
    "routing_mark",
    "connect_timeout",
    "disable_tcp_keep_alive",
    "tcp_keep_alive",
    "tcp_keep_alive_interval",
    "domain_resolver",
    "domain_strategy",
];

/// The dial fields a server takes, and what the remote ones take besides.
#[derive(Deserialize, Debug, Default)]
#[serde(deny_unknown_fields)]
struct RemoteOptions {
    #[serde(default)]
    server: Option<String>,
    #[serde(default)]
    server_port: Option<u16>,
    /// `https` and `h3`.
    #[serde(default)]
    path: Option<String>,
    /// `tls`, `https`, `quic` and `h3`.
    #[serde(default)]
    tls: Option<OutboundTls>,
    /// A sail extension, as Mihomo's `respect-rules`: the connections go
    /// through the outbound the routing rules pick for them, as for a
    /// connection from the inbound `dnsclient` to the server, its domain
    /// known.
    #[serde(default)]
    respect_rules: bool,
    /// A sail extension: the EDNS Client Subnet its queries carry, over
    /// any they have, as Mihomo's `ecs` with `ecs-override`.
    #[serde(default)]
    client_subnet: Option<Prefix>,
    #[serde(flatten)]
    dial: DialFields,
    /// `https` and `h3`: `POST`, the default, or `GET` (RFC 8484 §4.1).
    #[serde(default)]
    method: Option<String>,
    /// `https` and `h3`: sent with each request; a `Host` one is the
    /// host the requests name.
    #[serde(default)]
    headers: std::collections::BTreeMap<String, crate::config::model::HeaderValues>,
}

#[derive(Deserialize, Debug, Default)]
#[serde(deny_unknown_fields)]
struct HostsOptions {
    /// Files in the hosts format; the system's own when neither these nor
    /// `predefined` are given.
    #[serde(default, with = "listable")]
    path: Vec<String>,
    /// Names, and their addresses. A sail extension, as Mihomo's `hosts`
    /// has it: a name may be a pattern, `+.a` for a and the names under
    /// it, `.a` for those under it alone, a `*` label for any one label;
    /// and it may be given another name, whose addresses it takes.
    #[serde(default)]
    predefined: HashMap<String, serde_json::Value>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct FakeIpOptions {
    #[serde(default)]
    inet4_range: Option<String>,
    #[serde(default)]
    inet6_range: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct RaceOptions {
    #[serde(with = "listable")]
    servers: Vec<String>,
}

#[derive(Deserialize, Debug, Default)]
#[serde(deny_unknown_fields)]
struct MdnsOptions {
    /// The interfaces to ask on; all that are up and take multicast when
    /// none are named.
    #[serde(default, with = "listable")]
    interface: Vec<String>,
}

#[derive(Deserialize, Debug, Default)]
#[serde(deny_unknown_fields)]
struct LocalOptions {
    #[serde(flatten)]
    dial: DialFields,
}

/// The dial fields a local server takes: those of a socket to the
/// system's servers, which are addresses, with no name to resolve.
const LOCAL_DIAL: &[&str] = &[
    "detour",
    "bind_interface",
    "inet4_bind_address",
    "inet6_bind_address",
    "routing_mark",
    "connect_timeout",
    "disable_tcp_keep_alive",
    "tcp_keep_alive",
    "tcp_keep_alive_interval",
];

/// A local server, as sing-box's: it answers the names of the system's
/// hosts file itself, and asks mDNS for `.local` names off Apple's
/// systems, whose resolver asks it.
pub(super) struct Local {
    /// With dial fields: the system's servers, which it asks itself.
    pub dialed: Option<LocalDialed>,
    pub hosts: Hosts,
    pub mdns: super::mdns::Mdns,
}

impl Local {
    /// Whether it asks mDNS for `host`.
    pub fn asks_mdns(&self, host: &str) -> bool {
        !cfg!(target_vendor = "apple") && super::mdns::is_local_domain(host)
    }
}

/// A local server with dial fields: the system's servers, and how they
/// are reached.
pub(super) struct LocalDialed {
    pub dialer: Dialer,
    pub servers: super::system::SystemServers,
}

impl Server {
    /// Builds `config`; `defaults` are the instance's dial options.
    /// Builds `config`; `defaults` are the instance's dial options. A
    /// fakeip server with the ranges of `fake_ips` takes it over.
    pub fn new(
        config: &DnsServer,
        defaults: &DialDefaults,
        env: &RuntimeEnv,
        fake_ips: Option<&Arc<super::fakeip::FakeIpStore>>,
    ) -> Result<Self> {
        let tag = &config.tag;
        let err = |e: anyhow::Error| anyhow!("dns.servers[{}]: {}", tag, e);
        let mut client_subnet = None;
        let kind = match config.kind.as_str() {
            "udp" => {
                let o = remote(config)?;
                client_subnet = o.client_subnet;
                no_path_or_tls(&o, "udp")?;
                let (address, dialer) = address_and_dialer(o, 53, tag, defaults).map_err(err)?;
                Kind::Udp { address, dialer }
            }
            "tcp" => {
                let o = remote(config)?;
                client_subnet = o.client_subnet;
                no_path_or_tls(&o, "tcp")?;
                let (address, dialer) = address_and_dialer(o, 53, tag, defaults).map_err(err)?;
                Kind::Tcp {
                    address,
                    dialer,
                    pool: Default::default(),
                }
            }
            "tls" | "https" | "quic" | "h3" => {
                let protocol = Protocol::of(&config.kind);
                let mut o = remote(config)?;
                client_subnet = o.client_subnet;
                if o.path.is_some() && !matches!(protocol, Protocol::Https | Protocol::H3) {
                    return Err(err(anyhow!("path: only https and h3 servers take one")));
                }
                let path = o.path.take();
                let get = match o.method.take() {
                    None => false,
                    Some(m) if !matches!(protocol, Protocol::Https | Protocol::H3) => {
                        return Err(err(anyhow!(
                            "method: only https and h3 servers take one, not {:?}",
                            m
                        )))
                    }
                    Some(m) if m.eq_ignore_ascii_case("POST") => false,
                    Some(m) if m.eq_ignore_ascii_case("GET") => true,
                    Some(m) => {
                        return Err(err(anyhow!("method: GET or POST, not {:?}", m)));
                    }
                };
                let tls = o.tls.take();
                let headers = std::mem::take(&mut o.headers);
                let (address, dialer) =
                    address_and_dialer(o, protocol.default_port(), tag, defaults).map_err(err)?;
                Kind::Upstream(Arc::new(
                    Upstream::new(protocol, address, dialer, path, &headers, tls.as_ref(), env)
                        .map_err(err)?
                        .with_get(get),
                ))
            }
            "local" => {
                let o: LocalOptions = parse_options("dns server", tag, &config.options)?;
                let dialed = if o.dial == DialFields::default() {
                    None
                } else {
                    o.dial.check(LOCAL_DIAL).map_err(err)?;
                    let dial = defaults
                        .dialer(&o.dial, None)
                        .map_err(|e| err(anyhow!("[{}] dns server: {}", tag, e)))?;
                    Some(LocalDialed {
                        dialer: Dialer {
                            detour: o.dial.detour.clone(),
                            respect_rules: false,
                            domain: None,
                            dial,
                        },
                        servers: Default::default(),
                    })
                };
                // A system without a hosts file has no names in it.
                let hosts = hosts(HostsOptions::default(), env).unwrap_or_default();
                Kind::Local(Box::new(Local {
                    dialed,
                    hosts,
                    mdns: Default::default(),
                }))
            }
            "mdns" => {
                let o: MdnsOptions = parse_options("dns server", tag, &config.options)?;
                Kind::Mdns(super::mdns::Mdns {
                    interfaces: o.interface,
                })
            }
            "hosts" => {
                let o: HostsOptions = parse_options("dns server", tag, &config.options)?;
                Kind::Hosts(hosts(o, env).map_err(err)?)
            }
            "fakeip" => {
                let o: FakeIpOptions = parse_options("dns server", tag, &config.options)?;
                let ranges = (o.inet4_range.clone(), o.inet6_range.clone());
                let store = match fake_ips.filter(|s| s.ranges == ranges) {
                    Some(store) => {
                        // To the cache file the reload put in place.
                        store.sync();
                        store.clone()
                    }
                    None => Arc::new(
                        super::fakeip::FakeIpStore::new(
                            o.inet4_range.as_deref(),
                            o.inet6_range.as_deref(),
                            env.cache_file.clone(),
                        )
                        .map_err(err)?,
                    ),
                };
                Kind::FakeIp(store)
            }
            "race" => {
                let o: RaceOptions = parse_options("dns server", tag, &config.options)?;
                if o.servers.len() < 2 {
                    return Err(err(anyhow!("servers: a race takes two or more")));
                }
                Kind::Race { members: o.servers }
            }
            other => {
                return Err(anyhow!(
                    "dns.servers[{}]: unknown server type \"{}\"",
                    tag,
                    other
                ))
            }
        };
        Ok(Self {
            tag: tag.clone(),
            kind,
            client_subnet,
        })
    }

    /// The servers this one needs: the one that resolves its address, and
    /// a race's members.
    pub fn needs(&self) -> Vec<&str> {
        match &self.kind {
            Kind::Udp { address, .. } | Kind::Tcp { address, .. } => {
                address.resolver.iter().map(|r| r.server.as_str()).collect()
            }
            Kind::Upstream(u) => u
                .address
                .resolver
                .iter()
                .map(|r| r.server.as_str())
                .collect(),
            Kind::Race { members } => members.iter().map(String::as_str).collect(),
            Kind::Local(_) | Kind::Mdns(_) | Kind::Hosts(_) | Kind::FakeIp(_) => vec![],
        }
    }

    /// Whether it prefers `host`, a name it answers for itself, as
    /// sing-box's servers do for `preferred_by`: a hosts server its names,
    /// a local server the names of the hosts file and of mDNS, an mDNS
    /// server those of mDNS. A server that learns names of its own, such as
    /// the domains an interface is given, adds them here.
    pub fn prefers(&self, host: &str) -> bool {
        match &self.kind {
            Kind::Hosts(hosts) => hosts.get(host).is_some(),
            Kind::Local(local) => {
                local.hosts.get(host).is_some() || super::mdns::is_local_domain(host)
            }
            Kind::Mdns(_) => super::mdns::is_local_domain(host),
            Kind::Udp { .. }
            | Kind::Tcp { .. }
            | Kind::Upstream(_)
            | Kind::FakeIp(_)
            | Kind::Race { .. } => false,
        }
    }
}

impl std::fmt::Display for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}]", self.tag)
    }
}

/// Checks what the servers name of each other: that each exists, that no
/// race is a member of another, and that no server needs itself,
/// however far round.
pub(super) fn check(servers: &HashMap<String, Arc<Server>>) -> Result<()> {
    for server in servers.values() {
        for needed in server.needs() {
            let Some(other) = servers.get(needed) else {
                return Err(anyhow!(
                    "dns.servers[{}]: server [{}] does not exist",
                    server.tag,
                    needed
                ));
            };
            if matches!(server.kind, Kind::Race { .. }) && matches!(other.kind, Kind::Race { .. }) {
                return Err(anyhow!(
                    "dns.servers[{}]: [{}] is a race too, and cannot be a member",
                    server.tag,
                    needed
                ));
            }
        }
    }
    // A server needing itself would wait on itself for ever.
    fn visit<'a>(
        servers: &'a HashMap<String, Arc<Server>>,
        tag: &'a str,
        path: &mut Vec<&'a str>,
        done: &mut HashSet<&'a str>,
    ) -> Result<()> {
        if done.contains(tag) {
            return Ok(());
        }
        if let Some(i) = path.iter().position(|t| *t == tag) {
            let mut cycle: Vec<&str> = path[i..].to_vec();
            cycle.push(tag);
            return Err(anyhow!(
                "dns.servers: [{}] need each other to be reached",
                cycle.join("] -> [")
            ));
        }
        path.push(tag);
        if let Some(server) = servers.get(tag) {
            for needed in server.needs() {
                visit(servers, needed, path, done)?;
            }
        }
        path.pop();
        done.insert(tag);
        Ok(())
    }
    let mut done = HashSet::new();
    let mut tags: Vec<&str> = servers.keys().map(String::as_str).collect();
    tags.sort();
    for tag in tags {
        visit(servers, tag, &mut Vec::new(), &mut done)?;
    }
    Ok(())
}

fn remote(config: &DnsServer) -> Result<RemoteOptions> {
    parse_options("dns server", &config.tag, &config.options)
}

fn no_path_or_tls(o: &RemoteOptions, kind: &str) -> Result<()> {
    if o.path.is_some() {
        return Err(anyhow!("path: a {} server takes none", kind));
    }
    if o.tls.is_some() {
        return Err(anyhow!("tls: a {} server takes none", kind));
    }
    if !o.headers.is_empty() {
        return Err(anyhow!("headers: only https and h3 servers take them"));
    }
    if o.method.is_some() {
        return Err(anyhow!("method: only https and h3 servers take one"));
    }
    Ok(())
}

/// Where a remote server is, and how its connections are made.
fn address_and_dialer(
    o: RemoteOptions,
    default_port: u16,
    tag: &str,
    defaults: &DialDefaults,
) -> Result<(Address, Dialer)> {
    let host = o
        .server
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("server: missing"))?;
    let port = match o.server_port {
        Some(0) => return Err(anyhow!("server_port: must not be 0")),
        Some(port) => port,
        None => default_port,
    };
    let resolver = o.dial.domain_resolver();
    let is_ip = host.parse::<IpAddr>().is_ok();
    if !is_ip && resolver.is_none() {
        return Err(anyhow!(
            "server: \"{}\" is a domain; set domain_resolver to the server that resolves it",
            host
        ));
    }
    if is_ip && resolver.is_some() {
        return Err(anyhow!(
            "domain_resolver: the server is an address, with nothing to resolve"
        ));
    }
    let own = DialFields {
        // Its own address resolves through `resolver`, and nothing else.
        domain_resolver: None,
        domain_strategy: None,
        ..o.dial.clone()
    };
    if o.dial.detour.is_some() && o.respect_rules {
        return Err(anyhow!(
            "respect_rules: not with a detour, which the rules would pick"
        ));
    }
    o.dial.check(DIAL)?;
    if let (true, Some(field)) = (o.respect_rules, o.dial.socket_field()) {
        return Err(anyhow!(
            "{}: has no effect with respect_rules; set it on the outbounds",
            field
        ));
    }
    let dial = defaults
        .dialer(&own, None)
        .map_err(|e| anyhow!("[{}] dns server: {}", tag, e))?;
    Ok((
        Address {
            host: host.to_ascii_lowercase(),
            port,
            resolver,
        },
        Dialer {
            detour: o.dial.detour,
            respect_rules: o.respect_rules,
            domain: (!is_ip).then(|| host.to_ascii_lowercase()),
            dial,
        },
    ))
}

/// What a hosts server has for a name.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum Host {
    Ips(Vec<IpAddr>),
    /// Another name, whose addresses it takes.
    Alias(String),
}

/// The names a hosts server answers for: as given, and as patterns.
#[derive(Debug, Default)]
pub(super) struct Hosts {
    names: HashMap<String, Host>,
    /// Patterns, the most specific first.
    patterns: Vec<(Pattern, Host)>,
}

/// A pattern of names, as Mihomo's hosts take them.
#[derive(Debug)]
enum Pattern {
    /// The base, and the names under it: `+.a`.
    AndUnder(String),
    /// The names under the base alone: `.a`.
    Under(String),
    /// Labels, `None` for any one: `*.a`.
    Labels(Vec<Option<String>>),
}

impl Pattern {
    fn of(name: &str) -> Option<Self> {
        if let Some(base) = name.strip_prefix("+.") {
            Some(Pattern::AndUnder(base.to_string()))
        } else if let Some(base) = name.strip_prefix('.') {
            Some(Pattern::Under(base.to_string()))
        } else if name.split('.').any(|l| l == "*") {
            Some(Pattern::Labels(
                name.split('.')
                    .map(|l| (l != "*").then(|| l.to_string()))
                    .collect(),
            ))
        } else {
            None
        }
    }

    fn matches(&self, name: &str) -> bool {
        let under = |base: &str| {
            name.len() > base.len()
                && name.ends_with(base)
                && name.as_bytes()[name.len() - base.len() - 1] == b'.'
        };
        match self {
            Pattern::AndUnder(base) => name == base || under(base),
            Pattern::Under(base) => under(base),
            Pattern::Labels(labels) => {
                let names: Vec<&str> = name.split('.').collect();
                names.len() == labels.len()
                    && labels
                        .iter()
                        .zip(names)
                        .all(|(l, n)| l.as_deref().is_none_or(|l| l == n))
            }
        }
    }

    /// How specific it is: labels given, then a `*` over a `+.`.
    fn specificity(&self) -> (usize, u8) {
        match self {
            Pattern::AndUnder(base) | Pattern::Under(base) => (base.split('.').count(), 0),
            Pattern::Labels(labels) => (labels.iter().flatten().count(), 1),
        }
    }
}

/// How many aliases a name is followed through at most.
const MAX_ALIASES: usize = 8;

impl Hosts {
    /// What it has for `name`: as given, or else the most specific pattern
    /// that matches.
    pub(super) fn get(&self, name: &str) -> Option<&Host> {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        self.names.get(&name).or_else(|| {
            self.patterns
                .iter()
                .find(|(p, _)| p.matches(&name))
                .map(|(_, host)| host)
        })
    }

    /// The addresses `name` has here, through its aliases; or, where they
    /// lead to a name it has none for, that name.
    pub(super) fn resolve(&self, name: &str) -> Option<Host> {
        let mut host = self.get(name)?.clone();
        for _ in 0..MAX_ALIASES {
            match &host {
                Host::Ips(_) => return Some(host),
                Host::Alias(other) => match self.get(other) {
                    Some(next) => host = next.clone(),
                    None => return Some(host),
                },
            }
        }
        Some(host)
    }
}

/// The names a hosts server answers for.
fn hosts(o: HostsOptions, env: &RuntimeEnv) -> Result<Hosts> {
    let mut names: HashMap<String, Host> = HashMap::new();
    let paths = if o.path.is_empty() && o.predefined.is_empty() {
        system_hosts_file().into_iter().collect()
    } else {
        o.path.iter().map(|p| env.data_path(p)).collect::<Vec<_>>()
    };
    for path in paths {
        let text = std::fs::read_to_string(&path).map_err(|e| anyhow!("path: {}: {}", path, e))?;
        for (name, ip) in parse_hosts(&text) {
            match names.entry(name).or_insert_with(|| Host::Ips(Vec::new())) {
                Host::Ips(ips) if !ips.contains(&ip) => ips.push(ip),
                _ => {}
            }
        }
    }
    let mut patterns = Vec::new();
    for (name, value) in o.predefined {
        let values: Vec<String> =
            listable::deserialize(value).map_err(|e| anyhow!("predefined.{}: {}", name, e))?;
        let host = match values.as_slice() {
            [one] if one.parse::<IpAddr>().is_err() => {
                Host::Alias(one.trim_end_matches('.').to_ascii_lowercase())
            }
            _ => Host::Ips(
                values
                    .iter()
                    .map(|v| {
                        v.parse::<IpAddr>()
                            .map_err(|_| anyhow!("predefined.{}: invalid address \"{}\"", name, v))
                    })
                    .collect::<Result<Vec<_>>>()?,
            ),
        };
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        match Pattern::of(&name) {
            Some(pattern) => patterns.push((pattern, host)),
            None => {
                names.insert(name, host);
            }
        }
    }
    patterns.sort_by_key(|(p, _)| std::cmp::Reverse(p.specificity()));
    Ok(Hosts { names, patterns })
}

fn system_hosts_file() -> Option<String> {
    if cfg!(windows) {
        std::env::var("SystemRoot")
            .ok()
            .map(|root| format!("{}\\System32\\drivers\\etc\\hosts", root))
    } else {
        Some("/etc/hosts".to_string())
    }
}

/// The names and addresses of a file in the hosts format: an address, then
/// names, `#` starting a comment.
fn parse_hosts(text: &str) -> Vec<(String, IpAddr)> {
    let mut entries = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or_default();
        let mut fields = line.split_whitespace();
        let Some(ip) = fields.next().and_then(|ip| ip.parse::<IpAddr>().ok()) else {
            continue;
        };
        for name in fields {
            entries.push((name.trim_end_matches('.').to_ascii_lowercase(), ip));
        }
    }
    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_take_patterns_and_aliases_as_mihomo_does() {
        let o: HostsOptions = serde_json::from_value(serde_json::json!({ "predefined": {
            "exact.example": "10.0.0.1",
            "+.plus.example": ["10.0.0.2", "::2"],
            ".under.example": "10.0.0.3",
            "*.star.example": "10.0.0.4",
            "a.star.example": "10.0.0.5",
            "alias.example": "exact.example",
            "far.example": "elsewhere.example",
        } }))
        .unwrap();
        let hosts = hosts(o, &RuntimeEnv::default()).unwrap();
        let ips = |s: &[&str]| Some(Host::Ips(s.iter().map(|s| s.parse().unwrap()).collect()));
        assert_eq!(hosts.resolve("Exact.Example."), ips(&["10.0.0.1"]));
        assert_eq!(hosts.resolve("plus.example"), ips(&["10.0.0.2", "::2"]));
        assert_eq!(hosts.resolve("a.b.plus.example"), ips(&["10.0.0.2", "::2"]));
        assert_eq!(hosts.resolve("under.example"), None);
        assert_eq!(hosts.resolve("a.under.example"), ips(&["10.0.0.3"]));
        assert_eq!(hosts.resolve("b.star.example"), ips(&["10.0.0.4"]));
        assert_eq!(hosts.resolve("a.b.star.example"), None);
        // Given as it is, before any pattern.
        assert_eq!(hosts.resolve("a.star.example"), ips(&["10.0.0.5"]));
        // Through an alias; or to the name it leads to.
        assert_eq!(hosts.resolve("alias.example"), ips(&["10.0.0.1"]));
        assert_eq!(
            hosts.resolve("far.example"),
            Some(Host::Alias("elsewhere.example".into()))
        );
    }

    #[test]
    fn hosts_files_are_read_as_the_system_reads_them() {
        let entries = parse_hosts(
            "# comment\n127.0.0.1 localhost Local.Example.\n::1 localhost # v6\nbad line\n",
        );
        assert_eq!(
            entries,
            [
                ("localhost".to_string(), "127.0.0.1".parse().unwrap()),
                ("local.example".to_string(), "127.0.0.1".parse().unwrap()),
                ("localhost".to_string(), "::1".parse().unwrap()),
            ]
        );
    }

    /// A server's TCP connections take sing-box's keepalive fields.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn its_tcp_connections_get_the_keepalive_it_sets() {
        use crate::net::dial::fields::keepalive_dialled;
        use crate::net::TcpKeepAlive;
        use std::time::Duration;

        let dial = |fields: serde_json::Value| {
            let mut options = serde_json::json!({ "server": "127.0.0.1" });
            options
                .as_object_mut()
                .unwrap()
                .extend(fields.as_object().unwrap().clone());
            let config = DnsServer {
                kind: "tcp".to_string(),
                tag: "d".to_string(),
                options: options.as_object().unwrap().clone(),
            };
            let (_, dialer) =
                address_and_dialer(remote(&config).unwrap(), 53, "d", &DialDefaults::default())
                    .unwrap();
            dialer.dial
        };
        let set = dial(serde_json::json!({
            "tcp_keep_alive": "40s", "tcp_keep_alive_interval": "7s",
        }));
        assert_eq!(
            keepalive_dialled(&set).await,
            Some(TcpKeepAlive {
                idle: Duration::from_secs(40),
                interval: Duration::from_secs(7),
            })
        );
        let off = dial(serde_json::json!({ "disable_tcp_keep_alive": true }));
        assert_eq!(keepalive_dialled(&off).await, None);
        let unset = dial(serde_json::json!({}));
        assert_eq!(keepalive_dialled(&unset).await, Some(TcpKeepAlive::DEFAULT));
    }

    /// A server dials with its dialer: its dial fields over the instance's
    /// defaults, whose host protects its sockets.
    #[cfg(unix)]
    #[tokio::test]
    async fn it_dials_with_its_own_dialer_over_the_defaults() {
        let (mut defaults, protected) = crate::net::dial::recording::defaults();
        defaults.route.routing_mark = Some(7);
        let config = DnsServer {
            kind: "udp".to_string(),
            tag: "d".to_string(),
            options: serde_json::json!({ "server": "127.0.0.1", "connect_timeout": "3s" })
                .as_object()
                .unwrap()
                .clone(),
        };
        let (_, dialer) = address_and_dialer(remote(&config).unwrap(), 53, "d", &defaults).unwrap();
        assert_eq!(dialer.dial.spec().routing_mark, Some(7));
        assert_eq!(
            dialer.dial.connect_timeout(),
            std::time::Duration::from_secs(3)
        );
        dialer
            .dial
            .udp_socket(&"127.0.0.1:53".parse().unwrap())
            .await
            .unwrap();
        assert_eq!(protected.count(), 1);
    }
}
