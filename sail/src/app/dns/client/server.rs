//! The servers of `dns.servers`, as sing-box describes them: each with a
//! type, a tag and the options of its type, and the dial fields of the
//! connections it makes.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use serde_derive::Deserialize;

use super::upstream::{Protocol, Upstream};
use super::ServerSelectorState;
use crate::config::model::{listable, parse_options, DnsServer};
use crate::net::DialOptions;
use crate::runtime::RuntimeEnv;
use crate::transport::layers::OutboundTls;

/// One server, built from its configuration.
pub(super) struct Server {
    pub tag: String,
    pub kind: Kind,
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
    /// The system's resolver.
    Local,
    /// Addresses given for names: files in the hosts format, and names
    /// given in place.
    Hosts(HashMap<String, Vec<IpAddr>>),
    /// Fake IPs, which the connections to come back as their domains.
    FakeIp(Arc<super::fakeip::FakeIpStore>),
    /// A sail extension: the member that answers best, chosen again as they
    /// fare.
    SmartSelect {
        members: Vec<String>,
        state: Mutex<ServerSelectorState>,
    },
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
/// names, or directly with its own dial fields.
#[derive(Debug, Clone)]
pub(super) struct Dialer {
    pub detour: Option<String>,
    pub dial: Arc<DialOptions>,
}

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
    #[serde(default)]
    detour: Option<String>,
    #[serde(default)]
    bind_interface: Option<String>,
    #[serde(default)]
    inet4_bind_address: Option<std::net::Ipv4Addr>,
    #[serde(default)]
    inet6_bind_address: Option<std::net::Ipv6Addr>,
    #[serde(default)]
    routing_mark: Option<u32>,
    #[serde(default, with = "crate::config::model::duration")]
    connect_timeout: Option<std::time::Duration>,
    #[serde(default)]
    domain_resolver: Option<Resolver>,
    /// sing-box's deprecated field for the families the server's name
    /// resolves to, which the resolver's own `strategy` goes before.
    #[serde(default)]
    domain_strategy: Option<crate::config::model::DnsStrategy>,
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
struct SmartSelectOptions {
    #[serde(with = "listable")]
    servers: Vec<String>,
}

#[derive(Deserialize, Debug, Default)]
#[serde(deny_unknown_fields)]
struct LocalOptions {}

impl Server {
    /// Builds `config`; `defaults` are the instance's dial options.
    /// Builds `config`; `defaults` are the instance's dial options. A
    /// fakeip server with the ranges of `fake_ips` takes it over.
    pub fn new(
        config: &DnsServer,
        defaults: &DialOptions,
        env: &RuntimeEnv,
        tuning: &crate::runtime::options::Dns,
        fake_ips: Option<&Arc<super::fakeip::FakeIpStore>>,
    ) -> Result<Self> {
        let tag = &config.tag;
        let err = |e: anyhow::Error| anyhow!("dns.servers[{}]: {}", tag, e);
        let kind = match config.kind.as_str() {
            "udp" => {
                let o = remote(config)?;
                no_path_or_tls(&o, "udp")?;
                let (address, dialer) = address_and_dialer(o, 53, tag, defaults).map_err(err)?;
                Kind::Udp { address, dialer }
            }
            "tcp" => {
                let o = remote(config)?;
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
                if o.path.is_some() && !matches!(protocol, Protocol::Https | Protocol::H3) {
                    return Err(err(anyhow!("path: only https and h3 servers take one")));
                }
                let path = o.path.take();
                let tls = o.tls.take();
                let headers = std::mem::take(&mut o.headers);
                let (address, dialer) =
                    address_and_dialer(o, protocol.default_port(), tag, defaults).map_err(err)?;
                Kind::Upstream(Arc::new(
                    Upstream::new(protocol, address, dialer, path, &headers, tls.as_ref(), env)
                        .map_err(err)?,
                ))
            }
            "local" => {
                let _: LocalOptions = parse_options("dns server", tag, &config.options)?;
                Kind::Local
            }
            "hosts" => {
                let o: HostsOptions = parse_options("dns server", tag, &config.options)?;
                Kind::Hosts(hosts(o, env).map_err(err)?)
            }
            "fakeip" => {
                let o: FakeIpOptions = parse_options("dns server", tag, &config.options)?;
                let ranges = (o.inet4_range.clone(), o.inet6_range.clone());
                let store = match fake_ips.filter(|s| s.ranges == ranges) {
                    Some(store) => store.clone(),
                    None => Arc::new(
                        super::fakeip::FakeIpStore::new(
                            o.inet4_range.as_deref(),
                            o.inet6_range.as_deref(),
                        )
                        .map_err(err)?,
                    ),
                };
                Kind::FakeIp(store)
            }
            "smart_select" => {
                let o: SmartSelectOptions = parse_options("dns server", tag, &config.options)?;
                if o.servers.len() < 2 {
                    return Err(err(anyhow!("servers: a smart_select takes two or more")));
                }
                Kind::SmartSelect {
                    members: o.servers,
                    state: Mutex::new(ServerSelectorState {
                        tuning: tuning.clone(),
                        ..Default::default()
                    }),
                }
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
        })
    }

    /// The servers this one needs: the one that resolves its address, and
    /// a smart_select's members.
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
            Kind::SmartSelect { members, .. } => members.iter().map(String::as_str).collect(),
            Kind::Local | Kind::Hosts(_) | Kind::FakeIp(_) => vec![],
        }
    }
}

impl std::fmt::Display for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}]", self.tag)
    }
}

/// Checks what the servers name of each other: that each exists, that no
/// smart_select is a member of another, and that no server needs itself,
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
            if matches!(server.kind, Kind::SmartSelect { .. })
                && matches!(other.kind, Kind::SmartSelect { .. })
            {
                return Err(anyhow!(
                    "dns.servers[{}]: [{}] is a smart_select too, and cannot be a member",
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
    Ok(())
}

/// Where a remote server is, and how its connections are made.
fn address_and_dialer(
    o: RemoteOptions,
    default_port: u16,
    tag: &str,
    defaults: &DialOptions,
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
    let resolver = o.domain_resolver.map(|resolver| Resolver {
        strategy: resolver.strategy.or(o.domain_strategy),
        ..resolver
    });
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
    let own = DialOptions {
        bind_interface: o.bind_interface,
        inet4_bind_address: o.inet4_bind_address,
        inet6_bind_address: o.inet6_bind_address,
        routing_mark: o.routing_mark,
        connect_timeout: o
            .connect_timeout
            .unwrap_or(crate::net::dial::DEFAULT_CONNECT_TIMEOUT),
        protect: None,
        ipv6: false,
        // Its own address resolves through `resolver`, and nothing else.
        domain_resolver: None,
        strategy: None,
        outbound: None,
        // DNS servers do not take sing-box's keepalive fields yet.
        ..Default::default()
    };
    if let Some(detour) = &o.detour {
        let set = own.bind_interface.is_some()
            || own.inet4_bind_address.is_some()
            || own.inet6_bind_address.is_some()
            || own.routing_mark.is_some()
            || o.connect_timeout.is_some();
        if set {
            return Err(anyhow!(
                "the dial fields have no effect with a detour; set them on [{}]",
                detour
            ));
        }
    }
    crate::transport::layers::check_dial_platform("dns server", tag, &own)?;
    Ok((
        Address {
            host: host.to_ascii_lowercase(),
            port,
            resolver,
        },
        Dialer {
            detour: o.detour,
            dial: Arc::new(own.or(defaults)),
        },
    ))
}

/// The names a hosts server answers for.
fn hosts(o: HostsOptions, env: &RuntimeEnv) -> Result<HashMap<String, Vec<IpAddr>>> {
    let mut hosts: HashMap<String, Vec<IpAddr>> = HashMap::new();
    let paths = if o.path.is_empty() && o.predefined.is_empty() {
        system_hosts_file().into_iter().collect()
    } else {
        o.path.iter().map(|p| env.data_path(p)).collect::<Vec<_>>()
    };
    for path in paths {
        let text = std::fs::read_to_string(&path).map_err(|e| anyhow!("path: {}: {}", path, e))?;
        for (name, ip) in parse_hosts(&text) {
            let ips = hosts.entry(name).or_default();
            if !ips.contains(&ip) {
                ips.push(ip);
            }
        }
    }
    for (name, value) in o.predefined {
        let values: Vec<String> =
            listable::deserialize(value).map_err(|e| anyhow!("predefined.{}: {}", name, e))?;
        let ips = values
            .iter()
            .map(|v| {
                v.parse::<IpAddr>()
                    .map_err(|_| anyhow!("predefined.{}: invalid address \"{}\"", name, v))
            })
            .collect::<Result<Vec<_>>>()?;
        hosts.insert(name.to_ascii_lowercase(), ips);
    }
    Ok(hosts)
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
}
