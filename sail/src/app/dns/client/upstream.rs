//! Encrypted DNS upstreams given as URLs in `dns.servers`: DNS over TLS
//! (`tls://`, RFC 7858), over HTTPS (`https://`, or `doh:` for short,
//! RFC 8484), over QUIC (`quic://`, RFC 9250) and over HTTP/3 (`h3://`,
//! RFC 8484 on HTTP/3).
//!
//! Each upstream keeps its connections for the next query, so that the
//! handshake is paid once, not per query: DoT keeps idle connections to
//! take again, DoH keeps one HTTP/2 connection, or idle HTTP/1.1 ones when
//! the server does not speak HTTP/2, and DoQ and DoH3 keep one QUIC
//! connection and open a stream per query on it.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;
#[cfg(feature = "tls")]
use std::time::Duration;

use anyhow::{anyhow, Result};
use hickory_proto::rr::Name;

#[cfg(feature = "dns-doh")]
mod doh;
#[cfg(feature = "tls")]
mod dot;
#[cfg(feature = "quic")]
mod quic;
#[cfg(feature = "quic")]
mod socket;

/// The largest DNS message: its length is a 16-bit field in DoT and DoQ,
/// and DoH answers are held to it too.
#[cfg(any(feature = "quic", feature = "dns-doh"))]
const MAX_MESSAGE_LEN: usize = u16::MAX as usize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Protocol {
    /// DNS over TLS.
    Tls,
    /// DNS over HTTPS, on HTTP/2 or HTTP/1.1.
    Https,
    /// DNS over QUIC.
    Quic,
    /// DNS over HTTP/3.
    H3,
}

impl Protocol {
    fn scheme(self) -> &'static str {
        match self {
            Self::Tls => "tls",
            Self::Https => "https",
            Self::Quic => "quic",
            Self::H3 => "h3",
        }
    }

    fn default_port(self) -> u16 {
        match self {
            Self::Tls | Self::Quic => 853,
            Self::Https | Self::H3 => 443,
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
    /// The request path, for DoH and DoH3.
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
    #[cfg(feature = "dns-doh")]
    Https(doh::Pool),
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
        if self.has_path() {
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
    /// module knows; `None` otherwise. `doh:x` is `https://x`.
    pub fn parse(server: &str, is_direct: bool) -> Option<Result<Self>> {
        if server
            .get(..4)
            .is_some_and(|s| s.eq_ignore_ascii_case("doh:"))
        {
            return Some(Self::parse_rest(Protocol::Https, &server[4..], is_direct));
        }
        let (scheme, rest) = server.split_once("://")?;
        let protocol = match scheme.to_ascii_lowercase().as_str() {
            "tls" => Protocol::Tls,
            "https" => Protocol::Https,
            "quic" => Protocol::Quic,
            "h3" => Protocol::H3,
            _ => return None,
        };
        Some(Self::parse_rest(protocol, rest, is_direct))
    }

    /// `host[:port][/path][@bootstrap_ip]`, the path for DoH and DoH3 only.
    /// The bootstrap address comes last, so a path cannot contain `@`.
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
            Protocol::Https | Protocol::H3 if path.is_empty() => "/dns-query".to_string(),
            Protocol::Https | Protocol::H3 => {
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

    fn has_path(&self) -> bool {
        matches!(self.protocol, Protocol::Https | Protocol::H3)
    }

    /// The URI a DoH or DoH3 query is posted to.
    #[cfg(any(feature = "dns-doh", feature = "dns-h3"))]
    fn uri(&self) -> String {
        format!("https://{}{}", self.authority(), self.path)
    }

    /// `host[:port]` as an HTTP request names the server: the port only
    /// when it is not 443.
    #[cfg(any(feature = "dns-doh", feature = "dns-h3"))]
    fn authority(&self) -> String {
        let host = match self.host.parse::<IpAddr>() {
            Ok(IpAddr::V6(ip)) => format!("[{}]", ip),
            _ => self.host.clone(),
        };
        if self.port == 443 {
            host
        } else {
            format!("{}:{}", host, self.port)
        }
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

    /// The query's ID, which DoH, DoQ and DoH3 send as 0 and give back.
    #[cfg(any(feature = "tls", feature = "quic", feature = "dns-h3"))]
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
            #[cfg(feature = "dns-doh")]
            Protocol::Https => Ok(Self::Https(doh::Pool::default())),
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
    #[cfg(any(feature = "tls", feature = "quic", feature = "dns-h3"))]
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
            #[cfg(feature = "dns-doh")]
            State::Https(pool) => {
                self.exchange_doh(upstream, pool, addr, is_direct, request)
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
        };
        if response.len() < 12 {
            return Err(anyhow!("dns response too short"));
        }
        if response[..2] != id {
            return Err(anyhow!("dns response for another query"));
        }
        Ok(response)
    }

    /// Without the tls and quic features no upstream parses, so there is
    /// never one to send to.
    #[cfg(not(any(feature = "tls", feature = "quic", feature = "dns-h3")))]
    pub(super) async fn exchange_upstream(
        &self,
        upstream: &Upstream,
        _request: &[u8],
        _is_direct: bool,
    ) -> Result<Vec<u8>> {
        match upstream.state {}
    }

    /// How long a query may take on a connection kept from before, which
    /// may have died without a word: the rest of the query's time is left
    /// for a new connection.
    #[cfg(feature = "tls")]
    fn reused_connection_timeout(&self) -> Duration {
        self.timeout / 2
    }
}
