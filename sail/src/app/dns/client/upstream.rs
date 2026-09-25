//! Encrypted DNS upstreams given as URLs in `dns.servers`: DNS over TLS
//! (`tls://`, RFC 7858), over QUIC (`quic://`, RFC 9250) and over HTTP/3
//! (`h3://`, RFC 8484 on HTTP/3).
//!
//! Each upstream keeps its connections for the next query, so that the
//! handshake is paid once, not per query: DoT keeps idle connections to
//! take again, DoQ and DoH3 keep one QUIC connection and open a stream per
//! query on it.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{anyhow, Result};
use hickory_proto::rr::Name;

#[cfg(feature = "tls")]
mod dot;
#[cfg(feature = "quic")]
mod quic;
#[cfg(feature = "quic")]
mod socket;

/// The largest DNS message: its length is a 16-bit field in DoT and DoQ.
const MAX_MESSAGE_LEN: usize = u16::MAX as usize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Protocol {
    /// DNS over TLS.
    Tls,
    /// DNS over QUIC.
    Quic,
    /// DNS over HTTP/3.
    H3,
}

impl Protocol {
    fn scheme(self) -> &'static str {
        match self {
            Self::Tls => "tls",
            Self::Quic => "quic",
            Self::H3 => "h3",
        }
    }

    fn default_port(self) -> u16 {
        match self {
            Self::Tls | Self::Quic => 853,
            Self::H3 => 443,
        }
    }
}

/// One encrypted upstream, and the connections it keeps.
pub(super) struct Upstream {
    pub protocol: Protocol,
    /// The name the server's certificate is checked against, and sent as
    /// SNI: a domain, or an IP address.
    pub host: String,
    pub port: u16,
    /// The request path, for DoH3.
    pub path: String,
    /// Where to connect, instead of resolving `host` with the system
    /// resolver.
    pub bootstrap_ip: Option<IpAddr>,
    /// Whether it is reached directly rather than through the outbound the
    /// router picks.
    pub is_direct: bool,
    state: State,
}

/// The connections an upstream keeps between queries.
enum State {
    #[cfg(feature = "tls")]
    Tls(dot::Pool),
    #[cfg(feature = "quic")]
    Quic(quic::Pool),
    #[cfg(feature = "dns-h3")]
    H3(quic::Pool),
}

impl fmt::Debug for Upstream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Upstream({})", self)
    }
}

impl fmt::Display for Upstream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_direct {
            write!(f, "direct:")?;
        }
        write!(f, "{}://", self.protocol.scheme())?;
        match self.host.parse::<IpAddr>() {
            Ok(IpAddr::V6(ip)) => write!(f, "[{}]", ip)?,
            _ => write!(f, "{}", self.host)?,
        }
        write!(f, ":{}", self.port)?;
        if self.protocol == Protocol::H3 {
            write!(f, "{}", self.path)?;
        }
        if let Some(ip) = self.bootstrap_ip {
            write!(f, "@{}", ip)?;
        }
        Ok(())
    }
}

impl Upstream {
    /// `server` without its `direct:` prefix, when it has a scheme this
    /// module knows; `None` otherwise.
    pub fn parse(server: &str, is_direct: bool) -> Option<Result<Self>> {
        let (scheme, rest) = server.split_once("://")?;
        let protocol = match scheme.to_ascii_lowercase().as_str() {
            "tls" => Protocol::Tls,
            "quic" => Protocol::Quic,
            "h3" => Protocol::H3,
            _ => return None,
        };
        Some(Self::parse_rest(protocol, rest, is_direct))
    }

    /// `host[:port][/path][@bootstrap_ip]`, the path for DoH3 only. As for
    /// DoH, the bootstrap address comes last, so a path cannot contain `@`.
    fn parse_rest(protocol: Protocol, rest: &str, is_direct: bool) -> Result<Self> {
        let (rest, bootstrap_ip) = match rest.rsplit_once('@') {
            Some((rest, ip)) => {
                if ip.is_empty() {
                    return Err(anyhow!("empty bootstrap ip"));
                }
                let ip = ip
                    .parse::<IpAddr>()
                    .map_err(|e| anyhow!("invalid bootstrap ip {:?}: {}", ip, e))?;
                (rest, Some(ip))
            }
            None => (rest, None),
        };
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        };
        let path = match protocol {
            Protocol::H3 if path.is_empty() => "/dns-query".to_string(),
            Protocol::H3 => {
                Self::check_path(path)?;
                path.to_string()
            }
            _ if path.is_empty() => String::new(),
            _ => return Err(anyhow!("{}:// takes no path", protocol.scheme())),
        };
        let (host, port) = Self::parse_authority(authority, protocol.default_port())?;
        let state = State::new(protocol)?;
        Ok(Self {
            protocol,
            host,
            port,
            path,
            bootstrap_ip,
            is_direct,
            state,
        })
    }

    /// `host`, `host:port`, `[v6]` or `[v6]:port`.
    fn parse_authority(authority: &str, default_port: u16) -> Result<(String, u16)> {
        if authority.is_empty() {
            return Err(anyhow!("empty host"));
        }
        let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
            let (ip, after) = rest
                .split_once(']')
                .ok_or_else(|| anyhow!("unclosed [ in host"))?;
            let ip = ip
                .parse::<std::net::Ipv6Addr>()
                .map_err(|e| anyhow!("invalid ipv6 host {:?}: {}", ip, e))?;
            let port = match after {
                "" => None,
                _ => Some(
                    after
                        .strip_prefix(':')
                        .ok_or_else(|| anyhow!("unexpected {:?} after host", after))?,
                ),
            };
            (ip.to_string(), port)
        } else {
            match authority.split_once(':') {
                Some((host, port)) => (host.to_string(), Some(port)),
                None => (authority.to_string(), None),
            }
        };
        let port = match port {
            None => default_port,
            Some(port) => port
                .parse::<u16>()
                .ok()
                .filter(|port| *port != 0)
                .ok_or_else(|| anyhow!("invalid port {:?}", port))?,
        };
        if host.parse::<IpAddr>().is_err() {
            if host.is_empty() {
                return Err(anyhow!("empty host"));
            }
            // The same check as for a DoH domain, and no more than a
            // hostname allows.
            if !host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
            {
                return Err(anyhow!("invalid host {:?}", host));
            }
            Name::from_str(&format!("{}.", host))
                .map_err(|e| anyhow!("invalid host {:?}: {}", host, e))?;
        }
        Ok((host.to_ascii_lowercase(), port))
    }

    /// A path as a request carries it: no query, since the message goes in
    /// the body of a POST, and nothing to escape.
    fn check_path(path: &str) -> Result<()> {
        let valid = path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:%/".contains(&b));
        if !valid {
            return Err(anyhow!("invalid path {:?}", path));
        }
        Ok(())
    }

    /// The query's ID, which DoQ and DoH3 send as 0 and give back.
    fn message_id(request: &[u8]) -> Result<[u8; 2]> {
        match request {
            [a, b, ..] if request.len() >= 12 => Ok([*a, *b]),
            _ => Err(anyhow!("dns query too short")),
        }
    }
}

impl State {
    fn new(protocol: Protocol) -> Result<Self> {
        match protocol {
            #[cfg(feature = "tls")]
            Protocol::Tls => Ok(Self::Tls(dot::Pool::default())),
            #[cfg(feature = "quic")]
            Protocol::Quic => Ok(Self::Quic(quic::Pool::new(quic::Kind::Doq))),
            #[cfg(feature = "dns-h3")]
            Protocol::H3 => Ok(Self::H3(quic::Pool::new(quic::Kind::H3))),
            #[allow(unreachable_patterns)]
            _ => Err(anyhow!(
                "{}:// is not supported by this build",
                protocol.scheme()
            )),
        }
    }
}

impl super::DnsClient {
    /// Sends `request` to `upstream` and returns the answer, as it came, but
    /// with the query's ID.
    // Without the tls and quic features no upstream parses, and nothing
    // follows the match.
    #[allow(unreachable_code)]
    pub(super) async fn exchange_upstream(
        &self,
        upstream: &Upstream,
        request: &[u8],
        is_direct: bool,
    ) -> Result<Vec<u8>> {
        let id = Upstream::message_id(request)?;
        let is_direct = is_direct || upstream.is_direct;
        let addr = self
            .resolve_bootstrap_addr(&upstream.host, upstream.port, upstream.bootstrap_ip)
            .await?;
        let response: Vec<u8> = match &upstream.state {
            #[cfg(feature = "tls")]
            State::Tls(pool) => {
                self.exchange_dot(upstream, pool, addr, is_direct, request)
                    .await?
            }
            #[cfg(feature = "quic")]
            State::Quic(pool) => {
                self.exchange_quic(upstream, pool, addr, is_direct, request)
                    .await?
            }
            #[cfg(feature = "dns-h3")]
            State::H3(pool) => {
                self.exchange_quic(upstream, pool, addr, is_direct, request)
                    .await?
            }
            // No upstream kind is compiled in, so there is no state.
            #[cfg(not(any(feature = "tls", feature = "quic", feature = "dns-h3")))]
            _ => match upstream.state {},
        };
        if response.len() < 12 {
            return Err(anyhow!("dns response too short"));
        }
        if response[..2] != id {
            return Err(anyhow!("dns response for another query"));
        }
        Ok(response)
    }

    /// How long a query may take on a connection kept from before, which
    /// may have died without a word: the rest of the query's time is left
    /// for a new connection.
    fn reused_connection_timeout(&self) -> Duration {
        self.timeout / 2
    }
}
