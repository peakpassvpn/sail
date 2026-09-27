//! Encrypted DNS servers: DNS over TLS (`tls`, RFC 7858), over HTTPS
//! (`https`, RFC 8484), over QUIC (`quic`, RFC 9250) and over HTTP/3
//! (`h3`, RFC 8484 on HTTP/3).
//!
//! Each server keeps its connections for the next query, so that the
//! handshake is paid once, not per query: DoT keeps idle connections to
//! take again, DoH keeps one HTTP/2 connection, or idle HTTP/1.1 ones when
//! the server does not speak HTTP/2, and DoQ and DoH3 keep one QUIC
//! connection and open a stream per query on it.

use std::fmt;
#[cfg(feature = "tls")]
use std::time::Duration;
use std::time::Instant;

use anyhow::{anyhow, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::server::{Address, Dialer};
use crate::adapter::AnyStream;
use crate::runtime::RuntimeEnv;
use crate::transport::layers::OutboundTls;

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

/// Idle connections kept per server: as many as queries that ran at once,
/// up to this.
const MAX_IDLE: usize = 4;
/// How long a connection is kept idle. Servers close theirs after some
/// seconds (RFC 7766 §6.2.3 suggests 10), and a connection they closed
/// costs a failed query before a new one.
const IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// The idle connections of a server that sends its messages on a stream:
/// TCP, DoT, and DoH on HTTP/1.1.
#[derive(Default)]
pub(super) struct StreamPool {
    idle: std::sync::Mutex<Vec<(AnyStream, Instant)>>,
}

impl StreamPool {
    /// The connection idle for the least time, if one is still fresh.
    pub(super) fn take(&self) -> Option<AnyStream> {
        let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        idle.retain(|(_, since)| now.saturating_duration_since(*since) < IDLE_TIMEOUT);
        idle.pop().map(|(stream, _)| stream)
    }

    pub(super) fn put(&self, stream: AnyStream) {
        let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        if idle.len() >= MAX_IDLE {
            idle.remove(0);
        }
        idle.push((stream, Instant::now()));
    }
}

/// Writes `request` and reads the answer that follows, each prefixed with
/// its length (RFC 1035 §4.2.2).
pub(super) async fn exchange_framed(stream: &mut AnyStream, request: &[u8]) -> Result<Vec<u8>> {
    let len = u16::try_from(request.len()).map_err(|_| anyhow!("dns query too long"))?;
    let mut buf = Vec::with_capacity(2 + request.len());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(request);
    stream.write_all(&buf).await?;
    stream.flush().await?;
    let len = stream.read_u16().await? as usize;
    let mut response = vec![0u8; len];
    stream.read_exact(&mut response).await?;
    Ok(response)
}

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
    /// The protocol of a server type, which the caller has matched.
    pub fn of(kind: &str) -> Self {
        match kind {
            "tls" => Self::Tls,
            "https" => Self::Https,
            "quic" => Self::Quic,
            _ => Self::H3,
        }
    }

    fn scheme(self) -> &'static str {
        match self {
            Self::Tls => "tls",
            Self::Https => "https",
            Self::Quic => "quic",
            Self::H3 => "h3",
        }
    }

    pub fn default_port(self) -> u16 {
        match self {
            Self::Tls | Self::Quic => 853,
            Self::Https | Self::H3 => 443,
        }
    }
}

/// One encrypted server, and the connections it keeps.
pub(super) struct Upstream {
    pub protocol: Protocol,
    pub address: Address,
    /// The name the server's certificate is checked against, and sent as
    /// SNI: `tls.server_name`, or else the server's address.
    pub server_name: String,
    /// The request path, for DoH and DoH3.
    pub path: String,
    #[cfg_attr(not(any(feature = "tls", feature = "quic")), allow(dead_code))]
    pub dialer: Dialer,
    /// The certificates trusted instead of the bundled roots: inline PEM,
    /// or a path.
    #[cfg_attr(not(any(feature = "tls", feature = "quic")), allow(dead_code))]
    pub(super) certificate: Option<String>,
    #[cfg_attr(not(any(feature = "tls", feature = "quic")), allow(dead_code))]
    pub(super) insecure: bool,
    /// The ClientHello of DoT and DoH, `tls.utls`: none for DoT and Chrome's
    /// for DoH when unset.
    #[cfg(feature = "tls")]
    fingerprint: Option<crate::transport::tls::Fingerprint>,
    /// The TLS client of DoT and DoH, built on first use.
    #[cfg(feature = "tls")]
    tls_client: std::sync::OnceLock<std::result::Result<crate::transport::tls::TlsClient, String>>,
    state: State,
}

/// The connections an upstream keeps between queries.
enum State {
    #[cfg(feature = "tls")]
    Tls(StreamPool),
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
        write!(f, "{}://{}", self.protocol.scheme(), self.address)?;
        if self.has_path() {
            write!(f, "{}", self.path)?;
        }
        if self.server_name != self.address.host {
            write!(f, " ({})", self.server_name)?;
        }
        Ok(())
    }
}

impl Upstream {
    pub fn new(
        protocol: Protocol,
        address: Address,
        dialer: Dialer,
        path: Option<String>,
        tls: Option<&OutboundTls>,
        env: &RuntimeEnv,
    ) -> Result<Self> {
        let path = match path {
            Some(path) => {
                Self::check_path(&path)?;
                path
            }
            None if matches!(protocol, Protocol::Https | Protocol::H3) => "/dns-query".into(),
            None => String::new(),
        };
        let mut server_name = address.host.clone();
        let mut certificate = None;
        let mut insecure = false;
        #[allow(unused_mut)]
        let mut utls = None;
        if let Some(tls) = tls {
            if tls.reality.is_some() {
                return Err(anyhow!("tls.reality: not for a dns server"));
            }
            if tls.ech.is_some() {
                return Err(anyhow!("tls.ech: not for a dns server"));
            }
            if tls.alpn.is_some() {
                return Err(anyhow!(
                    "tls.alpn: a {} server offers its own",
                    protocol.scheme()
                ));
            }
            if let Some(name) = tls.server_name.as_ref().filter(|n| !n.is_empty()) {
                server_name = name.clone();
            }
            certificate = crate::transport::layers::trusted_certificate(tls, env);
            insecure = tls.insecure;
            utls = tls.utls.as_ref();
        }
        if matches!(protocol, Protocol::Quic | Protocol::H3) && utls.is_some() {
            return Err(anyhow!("tls.utls: not for a {} server", protocol.scheme()));
        }
        #[cfg(feature = "tls")]
        let fingerprint = match utls {
            Some(utls) if !utls.enabled => None,
            Some(utls) => Some(
                crate::transport::tls::Fingerprint::from_name(&utls.fingerprint)
                    .map_err(|e| anyhow!("tls.utls.fingerprint: {}", e))?,
            ),
            None if protocol == Protocol::Https => Some(crate::transport::tls::Fingerprint::Chrome),
            None => None,
        };
        #[cfg(feature = "tls")]
        if let Some(certificate) = &certificate {
            crate::transport::tls::client::load_certificates(certificate)
                .map_err(|e| anyhow!("tls.certificate: {}", e))?;
        }
        let state = State::new(protocol)?;
        Ok(Self {
            protocol,
            address,
            server_name,
            path,
            dialer,
            certificate,
            insecure,
            #[cfg(feature = "tls")]
            fingerprint,
            #[cfg(feature = "tls")]
            tls_client: Default::default(),
            state,
        })
    }

    /// The TLS client of DoT and DoH.
    #[cfg(feature = "tls")]
    fn tls_client(&self) -> Result<&crate::transport::tls::TlsClient> {
        self.tls_client
            .get_or_init(|| {
                crate::transport::tls::TlsClient::new(
                    &[],
                    self.certificate.as_deref(),
                    self.insecure,
                    self.fingerprint,
                )
                .map_err(|e| e.to_string())
            })
            .as_ref()
            .map_err(|e| anyhow!("tls client: {}", e))
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
        let host = match self.server_name.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V6(ip)) => format!("[{}]", ip),
            _ => self.server_name.clone(),
        };
        if self.address.port == 443 {
            host
        } else {
            format!("{}:{}", host, self.address.port)
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
            Protocol::Tls => Ok(Self::Tls(StreamPool::default())),
            #[cfg(feature = "dns-doh")]
            Protocol::Https => Ok(Self::Https(doh::Pool::default())),
            #[cfg(feature = "quic")]
            Protocol::Quic => Ok(Self::Quic(quic::Pool::new(quic::Kind::Doq))),
            #[cfg(feature = "dns-h3")]
            Protocol::H3 => Ok(Self::H3(quic::Pool::new(quic::Kind::H3))),
            #[allow(unreachable_patterns)]
            _ => Err(anyhow!(
                "a {} server is not supported by this build",
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
    ) -> Result<Vec<u8>> {
        let id = Upstream::message_id(request)?;
        let addr = self.server_addr(&upstream.address).await?;
        let response: Vec<u8> = match &upstream.state {
            #[cfg(feature = "tls")]
            State::Tls(pool) => self.exchange_dot(upstream, pool, addr, request).await?,
            #[cfg(feature = "dns-doh")]
            State::Https(pool) => self.exchange_doh(upstream, pool, addr, request).await?,
            #[cfg(feature = "quic")]
            State::Quic(pool) => self.exchange_quic(upstream, pool, addr, request).await?,
            #[cfg(feature = "dns-h3")]
            State::H3(pool) => self.exchange_quic(upstream, pool, addr, request).await?,
        };
        if response.len() < 12 {
            return Err(anyhow!("dns response too short"));
        }
        if response[..2] != id {
            return Err(anyhow!("dns response for another query"));
        }
        Ok(response)
    }

    /// Without the tls and quic features no encrypted server builds, so
    /// there is never one to send to.
    #[cfg(not(any(feature = "tls", feature = "quic", feature = "dns-h3")))]
    pub(super) async fn exchange_upstream(
        &self,
        upstream: &Upstream,
        _request: &[u8],
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
