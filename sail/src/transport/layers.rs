//! The blocks a protocol can be carried over -- `tls`, `transport`,
//! `multiplex` -- its dial fields and `detour`, and how they become layers
//! around it.
//!
//! In a configuration they are fields of the protocol's own entry, as in
//! sing-box. Inside, an outbound with layers is a chain of handlers,
//! `[tls, ws, vless]`; chains are not something a configuration names. A
//! detour is not a layer: it is the outbound's dialer, which dials through
//! the outbound it names in place of a socket.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use futures::future::AbortHandle;
use serde_derive::Deserialize;

use crate::adapter::{AnyInboundHandler, AnyOutboundHandler};
use crate::app::SyncDnsClient;
use crate::config::model::{parse_options, Options};
use crate::net::dial::DialFields;
use crate::net::{DialDefaults, Dialer, InboundDialer, InstanceDial};
use crate::runtime::RuntimeEnv;

/// Which blocks a protocol can be configured with.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Blocks {
    /// The dial fields, `DialFields`, but `detour`.
    pub dial: bool,
    pub detour: bool,
    pub tls: bool,
    pub transport: bool,
    pub multiplex: bool,
}

impl Blocks {
    pub const NONE: Blocks = Blocks {
        dial: false,
        detour: false,
        tls: false,
        transport: false,
        multiplex: false,
    };

    /// How its sockets are opened, and nothing else: for an outbound that
    /// dials its destination itself.
    pub const DIAL: Blocks = Blocks {
        dial: true,
        ..Blocks::NONE
    };

    /// How it dials its server, or through which outbound.
    pub const DIALER: Blocks = Blocks {
        dial: true,
        detour: true,
        ..Blocks::NONE
    };

    /// Everything: a proxy protocol carried over a stream.
    pub const ALL: Blocks = Blocks {
        dial: true,
        detour: true,
        tls: true,
        transport: true,
        multiplex: true,
    };

    fn keys(&self) -> impl Iterator<Item = &'static str> {
        let with_dial = self.dial;
        let dial = DialFields::names()
            .iter()
            .copied()
            .filter(move |name| with_dial && *name != "detour");
        [
            (self.detour, "detour"),
            (self.tls, "tls"),
            (self.transport, "transport"),
            (self.multiplex, "multiplex"),
        ]
        .into_iter()
        .filter_map(|(on, key)| on.then_some(key))
        .chain(dial)
    }

    /// Moves the blocks this protocol takes out of `options`, leaving what
    /// belongs to the protocol itself. A block it does not take stays, and
    /// is reported as an unknown field of the protocol.
    pub fn split(&self, options: &Options) -> (Options, Options) {
        let mut protocol = options.clone();
        let mut blocks = Options::new();
        for key in self.keys() {
            if let Some(value) = protocol.remove(key) {
                blocks.insert(key.to_string(), value);
            }
        }
        (protocol, blocks)
    }
}

/// A string, or a list of strings as sing-box allows in the same place.
#[derive(Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum Listable {
    One(String),
    Many(Vec<String>),
}

/// A secret, a private key: read as the value is, printed as none.
#[derive(Deserialize, Clone)]
#[serde(transparent)]
pub struct Secret<T>(pub T);

impl<T> std::fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

impl Listable {
    pub fn into_vec(self) -> Vec<String> {
        match self {
            Listable::One(s) => vec![s],
            Listable::Many(v) => v,
        }
    }

    /// The lines of an inline PEM, or the like, as one string.
    pub fn joined(self) -> String {
        self.into_vec().join("\n")
    }
}

// ---------------------------------------------------------------------------
// Outbound blocks
// ---------------------------------------------------------------------------

#[derive(Deserialize, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct OutboundBlocks {
    /// How it dials its server, `detour` among them.
    #[serde(flatten)]
    pub dial: DialFields,
    #[serde(default)]
    pub tls: Option<OutboundTls>,
    #[serde(default)]
    pub transport: Option<OutboundTransport>,
    #[serde(default)]
    pub multiplex: Option<OutboundMultiplex>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct OutboundTls {
    #[serde(default)]
    pub enabled: bool,
    /// Defaults to the server's address.
    #[serde(default)]
    pub server_name: Option<String>,
    /// Sends no SNI. The certificate is still verified against
    /// `server_name`, unless `insecure`.
    #[serde(default)]
    pub disable_sni: bool,
    #[serde(default)]
    pub insecure: bool,
    #[serde(default)]
    pub alpn: Option<Listable>,
    /// The lowest TLS version to negotiate, `1.0` to `1.3`; unset, 1.2.
    #[serde(default)]
    pub min_version: Option<String>,
    /// The highest; unset, 1.3.
    #[serde(default)]
    pub max_version: Option<String>,
    /// An inline PEM certificate to trust.
    #[serde(default)]
    pub certificate: Option<Listable>,
    /// A PEM certificate to trust, by path.
    #[serde(default)]
    pub certificate_path: Option<String>,
    /// The SHA-256 hashes, base64, of the public keys to take a server's
    /// certificate by, in place of the certificates trusted, the name and
    /// `insecure`.
    #[serde(default)]
    pub certificate_public_key_sha256: Option<Listable>,
    /// A sail extension, Mihomo's `fingerprint`: the SHA-256 hashes, hex,
    /// of whole certificates (DER) to take a server by, in place of the
    /// certificates trusted and `insecure`. A hash of the server's own
    /// certificate takes it outright: no CA and no name are checked, so
    /// that exact certificate is trusted for any server name. A hash of a
    /// certificate sent after it, an intermediate or a root, is the only
    /// CA the server's certificate is verified by, with the server name.
    #[serde(default)]
    pub certificate_sha256: Option<Listable>,
    /// An inline PEM certificate, its chain after it, presented when the
    /// server asks for one; with `client_key`.
    #[serde(default)]
    pub client_certificate: Option<Listable>,
    /// `client_certificate`, by path.
    #[serde(default)]
    pub client_certificate_path: Option<String>,
    /// The inline PEM key of the client certificate.
    #[serde(default)]
    pub client_key: Option<Secret<Listable>>,
    /// `client_key`, by path.
    #[serde(default)]
    pub client_key_path: Option<String>,
    #[serde(default)]
    pub ech: Option<OutboundEch>,
    #[serde(default)]
    pub reality: Option<OutboundReality>,
    /// The browser the ClientHello imitates. Unset, it is Chrome's.
    #[serde(default)]
    pub utls: Option<OutboundUtls>,
}

/// Unlike sing-box, a browser fingerprint is on by default: set
/// `enabled: false` for BoringSSL's own ClientHello.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct OutboundUtls {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_fingerprint")]
    pub fingerprint: String,
}

fn default_true() -> bool {
    true
}

fn default_fingerprint() -> String {
    "chrome".to_string()
}

impl OutboundTls {
    /// The ClientHello fingerprint, or None for BoringSSL's own.
    #[cfg(any(
        feature = "outbound-tls",
        feature = "outbound-reality",
        feature = "outbound-shadowtls"
    ))]
    pub(crate) fn fingerprint(
        &self,
        tag: &str,
    ) -> Result<Option<crate::transport::tls::Fingerprint>> {
        use crate::transport::tls::Fingerprint;
        match &self.utls {
            None => Ok(Some(Fingerprint::Chrome)),
            Some(utls) if !utls.enabled => Ok(None),
            Some(utls) => Fingerprint::from_name(&utls.fingerprint)
                .map(Some)
                .map_err(|e| anyhow!("[{}] outbound: tls.utls.fingerprint: {}", tag, e)),
        }
    }

    /// The versions and the pinned keys or certificates set, checked
    /// against each other and against the certificate to trust, which pins
    /// replace, as in sing-box. Errors name the field, under `tls`.
    #[cfg(feature = "tls")]
    #[cfg_attr(
        not(any(
            feature = "outbound-tls",
            feature = "quic",
            feature = "outbound-shadowtls",
            feature = "outbound-reality"
        )),
        allow(dead_code)
    )]
    pub(crate) fn client_options(&self) -> Result<crate::transport::tls::ClientOptions> {
        use crate::transport::tls::{
            CertificatePins, ClientOptions, Pins, PublicKeyPins, TlsVersionRange,
        };
        let versions =
            TlsVersionRange::parse(self.min_version.as_deref(), self.max_version.as_deref())?;
        let keys = match &self.certificate_public_key_sha256 {
            Some(hashes) => PublicKeyPins::parse(&hashes.clone().into_vec())?,
            None => None,
        };
        let certificates = match &self.certificate_sha256 {
            Some(hashes) => CertificatePins::parse(&hashes.clone().into_vec())?,
            None => None,
        };
        let pins = match (keys, certificates) {
            (Some(_), Some(_)) => {
                return Err(anyhow!(
                    "certificate_sha256: not with certificate_public_key_sha256"
                ))
            }
            (Some(keys), None) => Some(Pins::PublicKeys(keys)),
            (None, Some(certificates)) => Some(Pins::Certificates(certificates)),
            (None, None) => None,
        };
        if pins.is_some() && (self.certificate.is_some() || self.certificate_path.is_some()) {
            let field = match pins {
                Some(Pins::Certificates(_)) => "certificate_sha256",
                _ => "certificate_public_key_sha256",
            };
            return Err(anyhow!(
                "{}: not with certificate or certificate_path",
                field
            ));
        }
        Ok(ClientOptions { versions, pins })
    }

    /// `client_options`, as a handshake over TCP takes them beside REALITY,
    /// ECH and the browser fingerprint, each as sing-box does. `context`
    /// begins the warnings, such as `[tag] outbound`.
    ///
    /// REALITY verifies the server by its own means and offers the
    /// browser's versions: both are ignored. ECH is TLS 1.3 only: a range
    /// set below it is an error, where sing-box fails every handshake. With
    /// `utls` enabled, as with sing-box's uTLS, the browser's versions are
    /// offered whatever the range. With no `utls` block, where sing-box's
    /// own TLS would negotiate the range, it is negotiated, in a ClientHello
    /// that is then not quite the browser's.
    #[cfg(feature = "tls")]
    #[cfg_attr(
        not(any(
            feature = "outbound-tls",
            feature = "outbound-shadowtls",
            feature = "outbound-reality"
        )),
        allow(dead_code)
    )]
    pub(crate) fn stream_options(
        &self,
        context: &str,
    ) -> Result<crate::transport::tls::ClientOptions> {
        use crate::transport::tls::options::Version;
        use crate::transport::tls::{ClientOptions, Fingerprint, Pins, TlsVersionRange};
        let mut options = self.client_options()?;
        let versions = options.versions;
        if self.reality.as_ref().is_some_and(|r| r.enabled) {
            if versions.is_set() {
                tracing::warn!(
                    "{}: tls.min_version, tls.max_version: ignored with tls.reality, whose \
                     handshake offers the browser's versions",
                    context
                );
            }
            if let Some(pins) = &options.pins {
                let field = match pins {
                    Pins::PublicKeys(_) => "certificate_public_key_sha256",
                    Pins::Certificates(_) => "certificate_sha256",
                };
                tracing::warn!(
                    "{}: tls.{}: ignored with tls.reality, which verifies the server by its \
                     public_key",
                    context,
                    field
                );
            }
            return Ok(ClientOptions::default());
        }
        if self.ech.as_ref().is_some_and(|e| e.enabled) {
            for (field, version) in [("min_version", versions.min), ("max_version", versions.max)] {
                if version.is_some_and(|v| v < Version::Tls13) {
                    return Err(anyhow!(
                        "{}: ECH is TLS 1.3 only: 1.3, or unset, with tls.ech",
                        field
                    ));
                }
            }
        }
        let (lowest, highest) = Fingerprint::VERSIONS;
        match &self.utls {
            Some(utls) if utls.enabled => {
                if !versions.is(lowest, highest) {
                    tracing::warn!(
                        "{}: tls.min_version, tls.max_version: ignored with tls.utls, which \
                         offers the browser's TLS {} to {}",
                        context,
                        lowest,
                        highest
                    );
                }
                options.versions = TlsVersionRange::default();
            }
            Some(_) => {}
            None if !versions.is(lowest, highest) => tracing::warn!(
                "{}: tls.min_version, tls.max_version: the ClientHello, offering TLS {} to {}, \
                 is no longer the one the default browser fingerprint sends",
                context,
                versions.lowest(),
                versions.highest()
            ),
            None => {}
        }
        Ok(options)
    }

    /// Whether a client certificate or its key is set.
    pub(crate) fn has_client_certificate(&self) -> bool {
        self.client_certificate.is_some()
            || self.client_certificate_path.is_some()
            || self.client_key.is_some()
            || self.client_key_path.is_some()
    }

    /// The client certificate and its key, inline or by path; none when
    /// neither is set. Errors name the field, under `tls`.
    #[cfg(feature = "tls")]
    #[cfg_attr(
        not(any(
            feature = "outbound-tls",
            feature = "quic",
            feature = "outbound-shadowtls"
        )),
        allow(dead_code)
    )]
    pub(crate) fn client_identity(
        &self,
        env: &RuntimeEnv,
    ) -> Result<Option<crate::transport::tls::client::Identity>> {
        use crate::transport::tls::client::{load_certificates, load_private_key, Identity};
        let certificate = pem_source(
            "client_certificate",
            &self.client_certificate,
            &self.client_certificate_path,
            env,
        )?;
        let inline_key = self.client_key.as_ref().map(|k| k.0.clone());
        let key = pem_source("client_key", &inline_key, &self.client_key_path, env)?;
        let (certificate, key) = match (certificate, key) {
            (None, None) => return Ok(None),
            (Some(certificate), Some(key)) => (certificate, key),
            (Some(_), None) => return Err(anyhow!("client_key: needed with client_certificate")),
            (None, Some(_)) => return Err(anyhow!("client_certificate: needed with client_key")),
        };
        let chain =
            load_certificates(&certificate).map_err(|e| anyhow!("client_certificate: {}", e))?;
        // The error names no inline key: it holds none of it.
        let key = load_private_key(&key).map_err(|e| anyhow!("client_key: {}", e))?;
        Identity::new(chain, key)
            .map(Some)
            .map_err(|e| anyhow!("client_key: {}", e))
    }
}

/// The PEM of `field`, inline or by path (`field`_path), as the TLS
/// loaders take it: inline PEM, or a path. Inline, it must be PEM, so
/// that it is never read as a path, nor echoed in an error.
#[cfg(feature = "tls")]
#[cfg_attr(
    not(any(
        feature = "outbound-tls",
        feature = "quic",
        feature = "outbound-shadowtls"
    )),
    allow(dead_code)
)]
fn pem_source(
    field: &str,
    inline: &Option<Listable>,
    path: &Option<String>,
    env: &RuntimeEnv,
) -> Result<Option<String>> {
    match (inline, path) {
        (Some(_), Some(_)) => Err(anyhow!(
            "{}: set at most one of {} and {}_path",
            field,
            field,
            field
        )),
        (Some(inline), None) => {
            let pem = inline.clone().joined();
            if !pem.contains("-----BEGIN") {
                return Err(anyhow!("{}: not PEM", field));
            }
            Ok(Some(pem))
        }
        (None, Some(path)) if path.is_empty() => Err(anyhow!("{}_path: cannot be empty", field)),
        (None, Some(path)) => Ok(Some(env.data_path(path))),
        (None, None) => Ok(None),
    }
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct OutboundEch {
    #[serde(default)]
    pub enabled: bool,
    /// An ECHConfigList, base64 or PEM. Looked up in DNS when not set.
    #[serde(default)]
    pub config: Option<Listable>,
    /// Never look the ECHConfigList up in DNS.
    #[serde(default)]
    pub disable_dns_lookup: bool,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct OutboundReality {
    #[serde(default)]
    pub enabled: bool,
    pub public_key: String,
    #[serde(default)]
    pub short_id: String,
}

#[derive(Deserialize, Debug)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum OutboundTransport {
    Ws {
        #[serde(default = "default_path")]
        path: String,
        #[serde(default)]
        headers: HashMap<String, String>,
        /// How many of the first bytes to carry in the upgrade request.
        #[serde(default)]
        max_early_data: usize,
        /// The header they go in; unset, they go in the path.
        #[serde(default)]
        early_data_header_name: Option<String>,
    },
    #[serde(rename = "httpupgrade")]
    HttpUpgrade {
        /// Unset, the server's address.
        #[serde(default)]
        host: Option<String>,
        #[serde(default = "default_path")]
        path: String,
        #[serde(default)]
        headers: HashMap<String, String>,
    },
    Grpc {
        #[serde(default = "default_service_name")]
        service_name: String,
        /// Unset, no keepalive pings.
        #[serde(default, with = "crate::config::model::duration")]
        idle_timeout: Option<std::time::Duration>,
        #[serde(default, with = "crate::config::model::duration")]
        ping_timeout: Option<std::time::Duration>,
        /// Whether a connection carrying no calls is pinged too.
        #[serde(default)]
        permit_without_stream: bool,
    },
    /// sing-box's HTTP/2 transport: not supported.
    Http(serde::de::IgnoredAny),
    /// Its TLS parameters come from the `tls` block.
    Quic {},
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct OutboundMultiplex {
    #[serde(default)]
    pub enabled: bool,
    /// sing-box's multiplex, above the protocol: `h2mux`, the default as in
    /// sing-box, `smux` or `yamux`. Or `amux`, sail's own, below the
    /// protocol, which is to be removed.
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default)]
    pub max_connections: Option<usize>,
    #[serde(default)]
    pub min_streams: Option<usize>,
    #[serde(default)]
    pub max_streams: Option<usize>,
    #[serde(default)]
    pub padding: bool,
    /// sing-mux only: TCP Brutal, negotiated on each new connection.
    #[serde(default)]
    pub brutal: Option<MultiplexBrutal>,
    /// amux only.
    #[serde(default)]
    pub max_accepts: Option<usize>,
    #[serde(default)]
    pub concurrency: Option<usize>,
    #[serde(default)]
    pub max_recv_bytes: Option<usize>,
    #[serde(default)]
    pub max_lifetime: Option<u64>,
}

impl OutboundMultiplex {
    fn is_amux(&self) -> bool {
        self.protocol.as_deref() == Some("amux")
    }
}

/// The sing-mux client `mux` configures.
#[allow(unused_variables)]
fn sing_mux_options(tag: &str, mux: &OutboundMultiplex) -> Result<SingMuxOptions> {
    let amux_only = [
        ("max_accepts", mux.max_accepts.is_some()),
        ("concurrency", mux.concurrency.is_some()),
        ("max_recv_bytes", mux.max_recv_bytes.is_some()),
        ("max_lifetime", mux.max_lifetime.is_some()),
    ];
    if let Some((field, _)) = amux_only.iter().find(|(_, set)| *set) {
        return Err(anyhow!(
            "[{}] outbound: multiplex.{}: only for the amux protocol",
            tag,
            field
        ));
    }
    #[cfg(feature = "mux")]
    {
        use crate::transport::mux::{client::ClientOptions, Protocol};
        let name = mux.protocol.as_deref().unwrap_or("h2mux");
        let protocol = Protocol::from_name(name).ok_or_else(|| {
            anyhow!(
                "[{}] outbound: multiplex.protocol: unknown protocol \"{}\", \
                 one of smux, yamux, h2mux, amux",
                tag,
                name
            )
        })?;
        let brutal = match &mux.brutal {
            Some(brutal) => brutal
                .rates()
                .map_err(|e| anyhow!("[{}] outbound: multiplex: {}", tag, e))?,
            None => None,
        };
        ClientOptions::new(
            protocol,
            mux.padding,
            mux.max_connections,
            mux.min_streams,
            mux.max_streams,
            brutal,
        )
        .map_err(|e| anyhow!("[{}] outbound: multiplex: {}", tag, e))
    }
    #[cfg(not(feature = "mux"))]
    Err(not_compiled(tag, "outbound", "multiplex", "mux"))
}

#[cfg(feature = "mux")]
type SingMuxOptions = crate::transport::mux::client::ClientOptions;
#[cfg(not(feature = "mux"))]
type SingMuxOptions = ();

fn default_path() -> String {
    "/".to_string()
}

fn default_service_name() -> String {
    "TunService".to_string()
}

impl OutboundBlocks {
    pub fn parse(tag: &str, blocks: &Options) -> Result<Self> {
        let mut parsed: Self = parse_options("outbound", tag, blocks)?;
        parsed.transport_alpn(tag)?;
        Ok(parsed)
    }

    /// Settles the ALPN of TLS under a transport that speaks one version of
    /// HTTP. Offered anything else -- as a browser's ClientHello offers `h2`
    /// before `http/1.1` -- a server may well pick it, and the transport's
    /// first request is then in a language the connection does not speak.
    /// Unset, it is the transport's own, as sing-box sets it; set, it must
    /// include it.
    fn transport_alpn(&mut self, tag: &str) -> Result<()> {
        let wanted = match &self.transport {
            Some(OutboundTransport::Ws { .. } | OutboundTransport::HttpUpgrade { .. }) => {
                "http/1.1"
            }
            Some(OutboundTransport::Grpc { .. }) => "h2",
            _ => return Ok(()),
        };
        let Some(tls) = self.tls.as_mut().filter(|t| t.enabled) else {
            return Ok(());
        };
        match &tls.alpn {
            None => tls.alpn = Some(Listable::One(wanted.to_string())),
            Some(alpn) if !alpn.clone().into_vec().iter().any(|p| p == wanted) => {
                return Err(anyhow!(
                    "[{}] outbound: tls.alpn: the transport speaks {}, which is not offered",
                    tag,
                    wanted
                ))
            }
            Some(_) => {}
        }
        Ok(())
    }

    /// Whether TLS (or REALITY) is on.
    pub fn has_tls(&self) -> bool {
        self.tls().is_some()
    }

    fn tls(&self) -> Option<&OutboundTls> {
        self.tls.as_ref().filter(|t| t.enabled)
    }

    fn multiplex(&self) -> Option<&OutboundMultiplex> {
        self.multiplex.as_ref().filter(|m| m.enabled)
    }

    /// The dialer of the outbound `tag` of `protocol`: its dial fields,
    /// checked against each other and the platform, over `defaults`;
    /// through `detour`, the outbound its `detour` names, built already.
    pub fn dialer(
        &self,
        tag: &str,
        protocol: &str,
        defaults: &DialDefaults,
        detour: Option<AnyOutboundHandler>,
    ) -> Result<Dialer> {
        self.dial
            .check(crate::net::dial::fields::IMPLEMENTED)
            .map_err(|e| anyhow!("[{}] outbound: {}", tag, e))?;
        let dial = DialFields {
            udp_fragment_default: UDP_FRAGMENT_BY_DEFAULT.contains(&protocol),
            ..self.dial.clone()
        };
        defaults
            .outbound_dialer(&dial, tag, detour)
            .map_err(|e| anyhow!("[{}] outbound: {}", tag, e))
    }
}

/// The protocols whose UDP may be fragmented unless `udp_fragment` says
/// otherwise, as in sing-box: direct, which relays the datagrams it is
/// given, and the QUIC ones, which size their packets themselves. Every
/// other outbound's UDP has "don't fragment" set. redirect, sail's direct
/// to one fixed address, is as direct.
const UDP_FRAGMENT_BY_DEFAULT: &[&str] = &["direct", "redirect", "hysteria2", "tuic"];

/// What layering an outbound needs from where it is built.
pub struct OutboundLayering<'a> {
    pub tag: &'a str,
    /// The protocol's own options, for the server the layers dial.
    pub options: &'a Options,
    pub dns_client: &'a SyncDnsClient,
    pub abort_handles: &'a mut Vec<AbortHandle>,
    /// How the outbound dials: its dial fields over the instance's
    /// defaults, or its detour, from `OutboundBlocks::dialer`.
    pub dialer: Dialer,
    pub env: &'a RuntimeEnv,
}

/// The server a protocol's options name, which the layers under it dial.
fn server(tag: &str, options: &Options, dialer: &Dialer) -> Result<(String, u16)> {
    let server = options
        .get("server")
        .and_then(|v| v.as_str())
        .map(str::to_owned);
    let port = options
        .get("server_port")
        .and_then(|v| v.as_u64())
        .and_then(|p| u16::try_from(p).ok());
    server_address(tag, server, port, dialer)
}

/// The server an outbound dials: its `server` and `server_port`. Through a
/// detour both may be left out, as sing-box requires neither
/// (option/outbound.go:183): the address is then empty, as sing-box's
/// `ServerOptions.Build` makes it (option/outbound.go:188), and the detour
/// is handed it. ShadowTLS, the detour this is for, dials its own server
/// whatever it is handed (protocol/shadowtls/outbound.go:90); the
/// protocol over it still names the session's destination.
pub fn server_address(
    tag: &str,
    server: Option<String>,
    port: Option<u16>,
    dialer: &Dialer,
) -> Result<(String, u16)> {
    match (server, port) {
        (Some(server), Some(port)) => Ok((server, port)),
        (Some(_), None) => Err(anyhow!("[{}] outbound: missing field `server_port`", tag)),
        (None, port) if dialer.detour().is_some() => Ok((String::new(), port.unwrap_or(0))),
        (None, _) => Err(anyhow!(
            "[{}] outbound: missing field `server`; only an outbound with a detour may leave it out",
            tag
        )),
    }
}

/// Puts `core` inside the layers `blocks` configure.
pub fn outbound(
    core: AnyOutboundHandler,
    blocks: &OutboundBlocks,
    layering: OutboundLayering<'_>,
) -> Result<AnyOutboundHandler> {
    layered(core, blocks, layering, true)
}

/// `outbound`, or without the transport block when not `with_transport`:
/// the layers beneath the transport, for a transport that dials through
/// them itself.
fn layered(
    core: AnyOutboundHandler,
    blocks: &OutboundBlocks,
    layering: OutboundLayering<'_>,
    with_transport: bool,
) -> Result<AnyOutboundHandler> {
    let tag = layering.tag;
    let transport = blocks.transport.as_ref().filter(|_| with_transport);

    if let Some(OutboundTransport::Http(_)) = transport {
        return Err(anyhow!(
            "[{}] outbound: transport: type http (HTTP/2) is not supported; grpc is",
            tag
        ));
    }
    // gRPC multiplexes its streams over connections it keeps, and so is not
    // a layer dialled anew for every stream: it holds a `Connector` over
    // the layers beneath it -- its dialer, tls -- and comes first
    // in the chain, asking for nothing to be dialled.
    if let Some(OutboundTransport::Grpc {
        service_name,
        idle_timeout,
        ping_timeout,
        permit_without_stream,
    }) = transport
    {
        if blocks.multiplex().is_some() {
            return Err(anyhow!(
                "[{}] outbound: multiplex: not supported over the grpc transport",
                tag
            ));
        }
        let connector = Connector::build(blocks, layering, false)?;
        let grpc = grpc_outbound(
            tag,
            service_name,
            connector,
            *idle_timeout,
            *ping_timeout,
            *permit_without_stream,
        )?;
        return chain_outbound(tag, vec![grpc, core]);
    }

    let dialer = layering.dialer;
    let mut actors: Vec<AnyOutboundHandler> = Vec::new();
    // sing-mux runs above everything else, over connections of the whole.
    let mut sing_mux = None;
    let quic = matches!(transport, Some(OutboundTransport::Quic {}));
    if quic {
        if blocks.multiplex().is_some() {
            return Err(anyhow!(
                "[{}] outbound: multiplex: not supported over the quic transport",
                tag
            ));
        }
        let tls = blocks.tls().ok_or_else(|| {
            anyhow!(
                "[{}] outbound: transport: quic needs the tls block enabled",
                tag
            )
        })?;
        let (address, port) = server(tag, layering.options, &dialer)?;
        actors.push(quic_outbound(
            tag,
            tls,
            address,
            port,
            layering.dns_client,
            &dialer,
            layering.env,
        )?);
    } else {
        let mut under_mux = Vec::new();
        if let Some(tls) = blocks.tls() {
            under_mux.push(tls_outbound(tag, tls, layering.dns_client, layering.env)?);
        }
        if let Some(OutboundTransport::Ws {
            path,
            headers,
            max_early_data,
            early_data_header_name,
        }) = transport
        {
            under_mux.push(ws_outbound(
                tag,
                path,
                headers,
                *max_early_data,
                early_data_header_name.as_deref(),
                layering.env,
            )?);
        }
        if let Some(OutboundTransport::HttpUpgrade {
            host,
            path,
            headers,
        }) = transport
        {
            under_mux.push(httpupgrade_outbound(tag, host, path, headers)?);
        }
        match blocks.multiplex() {
            None => actors.extend(under_mux),
            Some(mux) if !mux.is_amux() => {
                sing_mux = Some(sing_mux_options(tag, mux)?);
                actors.extend(under_mux);
            }
            Some(mux) => {
                actors.push(amux_outbound(
                    tag,
                    mux,
                    server(tag, layering.options, &dialer)?,
                    under_mux,
                    layering.dns_client,
                    &dialer,
                    layering.env,
                    layering.abort_handles,
                )?);
            }
        }
    }

    // What it asks to have dialled comes with its dialer, which goes
    // through its detour if it has one.
    let whole = if actors.is_empty() {
        core
    } else {
        actors.push(core);
        chain_outbound(tag, actors)?
    };
    match sing_mux {
        Some(options) => sing_mux_outbound(
            tag,
            whole,
            layering.dns_client,
            options,
            &layering.env.options.mux,
            layering.abort_handles,
        ),
        None => Ok(whole),
    }
}

#[allow(unused_variables)]
// Without `mux` nothing is pushed onto the handles.
#[cfg_attr(not(feature = "mux"), allow(clippy::ptr_arg))]
fn sing_mux_outbound(
    tag: &str,
    whole: AnyOutboundHandler,
    dns_client: &SyncDnsClient,
    options: SingMuxOptions,
    tuning: &crate::runtime::options::Mux,
    abort_handles: &mut Vec<AbortHandle>,
) -> Result<AnyOutboundHandler> {
    #[cfg(feature = "mux")]
    return Ok(crate::transport::mux::client::outbound(
        tag,
        whole,
        dns_client.clone(),
        options,
        tuning.into(),
        abort_handles,
    ));
    #[cfg(not(feature = "mux"))]
    Err(not_compiled(tag, "outbound", "multiplex", "mux"))
}

/// Opens connections to a protocol's server through the layers its blocks
/// configure: its dialer (dial fields or detour), tls, transport.
///
/// For a protocol whose connections outlive the streams on them, such as a
/// session pool, and which therefore cannot be one more handler in a chain
/// that dials anew for every stream. Its factory asks for one with
/// `OutboundFactory::over_connector`.
#[derive(Clone)]
pub struct Connector {
    /// The layers around a handler that only hands the connection over.
    layers: AnyOutboundHandler,
    dns_client: SyncDnsClient,
    tls: bool,
}

impl Connector {
    pub fn new(blocks: &OutboundBlocks, layering: OutboundLayering<'_>) -> Result<Self> {
        Self::build(blocks, layering, true)
    }

    /// Through the layers `blocks` configure, the transport too unless not
    /// `with_transport`.
    fn build(
        blocks: &OutboundBlocks,
        layering: OutboundLayering<'_>,
        with_transport: bool,
    ) -> Result<Self> {
        let (server, port) = server(layering.tag, layering.options, &layering.dialer)?;
        let dns_client = layering.dns_client.clone();
        let handover = crate::adapter::outbound::HandlerBuilder::default()
            .tag(layering.tag.to_owned())
            .stream_handler(Arc::new(Handover {
                server,
                port,
                dialer: layering.dialer.clone(),
            }))
            .build();
        Ok(Connector {
            layers: layered(handover, blocks, layering, with_transport)?,
            dns_client,
            tls: blocks.tls().is_some(),
        })
    }

    /// Connections made by `handler` as a whole, protocol and all, for
    /// sing-mux, whose connections are those of the outbound it serves.
    /// They count as not over TLS: `tls` is for a protocol that insists on
    /// its own.
    #[cfg_attr(not(feature = "mux"), allow(dead_code))]
    pub(crate) fn around(handler: AnyOutboundHandler, dns_client: SyncDnsClient) -> Self {
        Connector {
            layers: handler,
            dns_client,
            tls: false,
        }
    }

    /// Whether the connections are made over TLS (or REALITY).
    pub fn tls(&self) -> bool {
        self.tls
    }

    /// The layers hear of a change of network, for the connections they
    /// keep.
    pub fn network_changed(&self, change: &crate::net::network::NetworkChange) {
        self.layers.network_changed(change);
    }

    /// A new connection to the server, for `sess`.
    pub async fn connect(
        &self,
        sess: &crate::session::Session,
    ) -> std::io::Result<crate::adapter::AnyStream> {
        let stream =
            crate::net::connect_stream_outbound(sess, self.dns_client.clone(), &self.layers)
                .await?;
        self.layers.stream()?.handle(sess, None, stream).await
    }

    /// A new connection, as `connect` makes it, and the TCP connection
    /// under it, for TCP Brutal to be set on, when that is dialled here
    /// rather than inside a handler.
    #[cfg(feature = "mux")]
    pub(crate) async fn connect_on_socket(
        &self,
        sess: &crate::session::Session,
    ) -> std::io::Result<(
        crate::adapter::AnyStream,
        Option<crate::transport::mux::brutal::Socket>,
    )> {
        let crate::adapter::OutboundConnect::Proxy(
            crate::session::Network::Tcp,
            addr,
            port,
            dialer,
        ) = self.layers.stream()?.connect_addr()
        else {
            return Ok((self.connect(sess).await?, None));
        };
        // Through a detour there is no TCP connection of its own.
        if dialer.detour().is_some() {
            return Ok((self.connect(sess).await?, None));
        }
        let tcp = dialer.tcp(&self.dns_client, &addr, port).await?;
        let socket = crate::transport::mux::brutal::Socket::of(&socket2::SockRef::from(&tcp)).ok();
        let stream = self
            .layers
            .stream()?
            .handle(sess, None, Some(Box::new(tcp)))
            .await?;
        Ok((stream, socket))
    }
}

/// The innermost layer of a `Connector`: asks for the server to be dialled,
/// and hands over what the layers around it made of that.
struct Handover {
    server: String,
    port: u16,
    dialer: Dialer,
}

#[async_trait::async_trait]
impl crate::adapter::OutboundStreamHandler for Handover {
    fn connect_addr(&self) -> crate::adapter::OutboundConnect {
        crate::adapter::OutboundConnect::Proxy(
            crate::session::Network::Tcp,
            self.server.clone(),
            self.port,
            self.dialer.clone(),
        )
    }

    async fn handle<'a>(
        &'a self,
        _sess: &'a crate::session::Session,
        _lhs: Option<&mut crate::adapter::AnyStream>,
        stream: Option<crate::adapter::AnyStream>,
    ) -> std::io::Result<crate::adapter::AnyStream> {
        stream.ok_or_else(|| std::io::Error::other("no connection to the server"))
    }
}

/// An outbound running `actors` in order, each over the one before.
pub fn chain_outbound(tag: &str, actors: Vec<AnyOutboundHandler>) -> Result<AnyOutboundHandler> {
    #[cfg(feature = "outbound-chain")]
    {
        use crate::adapter::outbound::HandlerBuilder;
        use crate::protocol::group::chain::outbound::{DatagramHandler, StreamHandler};
        Ok(HandlerBuilder::default()
            .tag(tag.to_owned())
            .stream_handler(Arc::new(StreamHandler {
                actors: actors.clone(),
            }))
            .datagram_handler(Arc::new(DatagramHandler { actors }))
            .build())
    }
    #[cfg(not(feature = "outbound-chain"))]
    {
        let _ = actors;
        Err(not_compiled(tag, "outbound", "layers", "outbound-chain"))
    }
}

#[allow(dead_code)]
fn not_compiled(tag: &str, kind: &str, what: &str, feature: &str) -> anyhow::Error {
    anyhow!(
        "[{}] {}: {} need the {} feature, which is not compiled in",
        tag,
        kind,
        what,
        feature
    )
}

/// The certificate to trust: inline, or by path.
#[cfg_attr(
    not(any(
        feature = "outbound-tls",
        feature = "quic",
        feature = "outbound-shadowtls"
    )),
    allow(dead_code)
)]
pub(crate) fn trusted_certificate(tls: &OutboundTls, env: &RuntimeEnv) -> Option<String> {
    match (&tls.certificate, &tls.certificate_path) {
        (Some(inline), _) => Some(inline.clone().joined()),
        (None, Some(path)) => Some(env.data_path(path)),
        (None, None) => None,
    }
}

#[allow(unused_variables)]
fn tls_outbound(
    tag: &str,
    tls: &OutboundTls,
    dns_client: &SyncDnsClient,
    env: &RuntimeEnv,
) -> Result<AnyOutboundHandler> {
    #[allow(unused_imports)]
    use crate::adapter::outbound::HandlerBuilder;
    let server_name = tls.server_name.clone().unwrap_or_default();
    if let Some(reality) = tls.reality.as_ref().filter(|r| r.enabled) {
        // REALITY's ClientHello carries the name of the site it imitates,
        // and its server asks for no certificate.
        if tls.disable_sni {
            return Err(anyhow!(
                "[{}] outbound: tls.disable_sni: not with tls.reality",
                tag
            ));
        }
        if tls.has_client_certificate() {
            return Err(anyhow!(
                "[{}] outbound: tls.client_certificate: not with tls.reality",
                tag
            ));
        }
        #[cfg(feature = "outbound-reality")]
        tls.stream_options(&format!("[{}] outbound", tag))
            .map_err(|e| anyhow!("[{}] outbound: tls.{}", tag, e))?;
        #[cfg(feature = "outbound-reality")]
        return Ok(HandlerBuilder::default()
            .tag(format!("{}/reality", tag))
            .stream_handler(Arc::new(
                crate::transport::reality::StreamHandler::new(
                    server_name,
                    &reality.public_key,
                    &reality.short_id,
                    tls.fingerprint(tag)?.ok_or_else(|| {
                        anyhow!(
                            "[{}] outbound: tls.reality: needs a browser fingerprint, \
                             tls.utls cannot be disabled",
                            tag
                        )
                    })?,
                )
                .map_err(|e| anyhow!("[{}] outbound: tls.reality: {}", tag, e))?,
            ))
            .build());
        #[cfg(not(feature = "outbound-reality"))]
        return Err(not_compiled(
            tag,
            "outbound",
            "tls.reality",
            "outbound-reality",
        ));
    }
    #[cfg(feature = "outbound-tls")]
    {
        let ech = tls.ech.as_ref().filter(|e| e.enabled);
        // The outer ClientHello names the ECH config's public name.
        if ech.is_some() && tls.disable_sni {
            return Err(anyhow!(
                "[{}] outbound: tls.disable_sni: not with tls.ech",
                tag
            ));
        }
        let ech_config_list = match ech.and_then(|e| e.config.clone()) {
            Some(config) => Some(ech_config_list(tag, config)?),
            None => None,
        };
        let identity = tls
            .client_identity(env)
            .map_err(|e| anyhow!("[{}] outbound: tls.{}", tag, e))?;
        let options = tls
            .stream_options(&format!("[{}] outbound", tag))
            .map_err(|e| anyhow!("[{}] outbound: tls.{}", tag, e))?;
        // Browsers send the name of a domain: a ClientHello without it is
        // one no browser sends, whatever it imitates otherwise.
        if tls.disable_sni && tls.utls.as_ref().is_some_and(|u| u.enabled) {
            tracing::warn!(
                "[{}] outbound: tls.disable_sni: the ClientHello, with no SNI, is no longer \
                 the one tls.utls's browser sends",
                tag
            );
        }
        let handler = crate::transport::tls::outbound::StreamHandler::new(
            server_name,
            tls.alpn.clone().map(Listable::into_vec).unwrap_or_default(),
            trusted_certificate(tls, env),
            tls.insecure,
            tls.fingerprint(tag)?,
            tls.disable_sni,
            identity.as_ref(),
            ech.is_some(),
            ech.is_some_and(|e| e.disable_dns_lookup),
            ech_config_list,
            dns_client.clone(),
            &env.tls_roots.get()?,
            &options,
        )?;
        Ok(HandlerBuilder::default()
            .tag(format!("{}/tls", tag))
            .stream_handler(Arc::new(handler))
            .build())
    }
    #[cfg(not(feature = "outbound-tls"))]
    Err(not_compiled(tag, "outbound", "tls", "outbound-tls"))
}

/// An ECHConfigList as the TLS handler takes it: base64, from base64 or from
/// PEM (`-----BEGIN ECH CONFIGS-----`, as sing-box writes it).
#[cfg_attr(not(feature = "outbound-tls"), allow(dead_code))]
fn ech_config_list(tag: &str, config: Listable) -> Result<String> {
    let base64: String = config
        .into_vec()
        .iter()
        .flat_map(|chunk| chunk.lines())
        .map(str::trim)
        .filter(|line| !line.starts_with("-----"))
        .collect();
    if base64.is_empty() {
        return Err(anyhow!(
            "[{}] outbound: tls.ech.config: cannot be empty",
            tag
        ));
    }
    Ok(base64)
}

#[allow(unused_variables)]
fn ws_outbound(
    tag: &str,
    path: &str,
    headers: &HashMap<String, String>,
    max_early_data: usize,
    early_data_header_name: Option<&str>,
    env: &RuntimeEnv,
) -> Result<AnyOutboundHandler> {
    #[cfg(feature = "outbound-ws")]
    {
        use crate::transport::ws::{outbound::StreamHandler, EarlyData};
        let invalid = |e: anyhow::Error| anyhow!("[{}] outbound: transport: {}", tag, e);
        let early_data = EarlyData::new(max_early_data, early_data_header_name).map_err(invalid)?;
        let handler = StreamHandler::new(
            path.to_string(),
            headers,
            env.options.ws.half_close,
            early_data,
        )
        .map_err(invalid)?;
        Ok(crate::adapter::outbound::HandlerBuilder::default()
            .tag(format!("{}/ws", tag))
            .stream_handler(Arc::new(handler))
            .build())
    }
    #[cfg(not(feature = "outbound-ws"))]
    Err(not_compiled(tag, "outbound", "transport ws", "outbound-ws"))
}

#[allow(unused_variables)]
fn httpupgrade_outbound(
    tag: &str,
    host: &Option<String>,
    path: &str,
    headers: &HashMap<String, String>,
) -> Result<AnyOutboundHandler> {
    #[cfg(feature = "outbound-httpupgrade")]
    {
        let handler = crate::transport::httpupgrade::outbound::StreamHandler::new(
            host.clone(),
            path.to_string(),
            headers,
        )
        .map_err(|e| anyhow!("[{}] outbound: transport: {}", tag, e))?;
        Ok(crate::adapter::outbound::HandlerBuilder::default()
            .tag(format!("{}/httpupgrade", tag))
            .stream_handler(Arc::new(handler))
            .build())
    }
    #[cfg(not(feature = "outbound-httpupgrade"))]
    Err(not_compiled(
        tag,
        "outbound",
        "transport httpupgrade",
        "outbound-httpupgrade",
    ))
}

#[allow(unused_variables)]
fn grpc_outbound(
    tag: &str,
    service_name: &str,
    connector: Connector,
    idle_timeout: Option<std::time::Duration>,
    ping_timeout: Option<std::time::Duration>,
    permit_without_stream: bool,
) -> Result<AnyOutboundHandler> {
    #[cfg(feature = "outbound-grpc")]
    {
        use crate::transport::grpc::{outbound::Keepalive, DEFAULT_PING_TIMEOUT};
        let handler = crate::transport::grpc::outbound::StreamHandler::new(
            service_name,
            connector,
            Keepalive {
                idle_timeout: idle_timeout.filter(|d| !d.is_zero()),
                ping_timeout: ping_timeout.unwrap_or(DEFAULT_PING_TIMEOUT),
                permit_without_stream,
            },
        )
        .map_err(|e| anyhow!("[{}] outbound: transport: {}", tag, e))?;
        Ok(crate::adapter::outbound::HandlerBuilder::default()
            .tag(format!("{}/grpc", tag))
            .stream_handler(Arc::new(handler))
            .build())
    }
    #[cfg(not(feature = "outbound-grpc"))]
    Err(not_compiled(
        tag,
        "outbound",
        "transport grpc",
        "outbound-grpc",
    ))
}

#[allow(unused_variables)]
fn quic_outbound(
    tag: &str,
    tls: &OutboundTls,
    address: String,
    port: u16,
    dns_client: &SyncDnsClient,
    dialer: &Dialer,
    env: &RuntimeEnv,
) -> Result<AnyOutboundHandler> {
    #[cfg(feature = "outbound-quic")]
    return Ok(crate::adapter::outbound::HandlerBuilder::default()
        .tag(format!("{}/quic", tag))
        .stream_handler(Arc::new(
            crate::transport::quic::outbound::StreamHandler::new(
                tls,
                address,
                port,
                dns_client.clone(),
                dialer.clone(),
                env,
            )
            .map_err(|e| anyhow!("[{}] outbound: transport quic: {}", tag, e))?,
        ))
        .build());
    #[cfg(not(feature = "outbound-quic"))]
    Err(not_compiled(
        tag,
        "outbound",
        "transport quic",
        "outbound-quic",
    ))
}

#[allow(unused_variables)]
// Without `outbound-amux` nothing is pushed onto the handles.
#[cfg_attr(not(feature = "outbound-amux"), allow(clippy::ptr_arg))]
#[allow(clippy::too_many_arguments)]
fn amux_outbound(
    tag: &str,
    mux: &OutboundMultiplex,
    (address, port): (String, u16),
    actors: Vec<AnyOutboundHandler>,
    dns_client: &SyncDnsClient,
    dialer: &Dialer,
    env: &RuntimeEnv,
    abort_handles: &mut Vec<AbortHandle>,
) -> Result<AnyOutboundHandler> {
    let sing_mux_only = [
        ("max_connections", mux.max_connections.is_some()),
        ("min_streams", mux.min_streams.is_some()),
        ("max_streams", mux.max_streams.is_some()),
        ("padding", mux.padding),
        ("brutal", mux.brutal.as_ref().is_some_and(|b| b.enabled)),
    ];
    if let Some((field, _)) = sing_mux_only.iter().find(|(_, set)| *set) {
        return Err(anyhow!(
            "[{}] outbound: multiplex.{}: not for the amux protocol",
            tag,
            field
        ));
    }
    #[cfg(feature = "outbound-amux")]
    {
        let (stream, mut handles) = crate::transport::amux::outbound::StreamHandler::new(
            address,
            port,
            actors,
            mux.max_accepts.unwrap_or(8),
            mux.concurrency.unwrap_or(2),
            mux.max_recv_bytes.unwrap_or(0),
            mux.max_lifetime.unwrap_or(0),
            dns_client.clone(),
            dialer.clone(),
            (&env.options.mux).into(),
            format!("outbound={}", tag),
        );
        abort_handles.append(&mut handles);
        Ok(crate::adapter::outbound::HandlerBuilder::default()
            .tag(format!("{}/amux", tag))
            .stream_handler(Arc::new(stream))
            .build())
    }
    #[cfg(not(feature = "outbound-amux"))]
    Err(not_compiled(tag, "outbound", "multiplex", "outbound-amux"))
}

// ---------------------------------------------------------------------------
// Inbound blocks
// ---------------------------------------------------------------------------

#[derive(Deserialize, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct InboundBlocks {
    #[serde(default)]
    pub tls: Option<InboundTls>,
    #[serde(default)]
    pub transport: Option<InboundTransport>,
    #[serde(default)]
    pub multiplex: Option<InboundMultiplex>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct InboundTls {
    #[serde(default)]
    pub enabled: bool,
    /// An inline PEM certificate.
    #[serde(default)]
    pub certificate: Option<Listable>,
    #[serde(default)]
    pub certificate_path: Option<String>,
    /// An inline PEM key.
    #[serde(default)]
    pub key: Option<Listable>,
    #[serde(default)]
    pub key_path: Option<String>,
    #[serde(default)]
    pub alpn: Option<Listable>,
    /// The lowest TLS version to accept, `1.0` to `1.3`; unset, 1.2.
    #[serde(default)]
    pub min_version: Option<String>,
    /// The highest; unset, 1.3.
    #[serde(default)]
    pub max_version: Option<String>,
    /// The name REALITY clients must ask for; only REALITY uses it, and
    /// without REALITY it is ignored with a warning, as sing-box ignores it.
    #[serde(default)]
    pub server_name: Option<String>,
    #[serde(default)]
    pub reality: Option<InboundReality>,
}

/// A REALITY server in place of a certificate: clients it does not know
/// are relayed to `handshake`.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct InboundReality {
    #[serde(default)]
    pub enabled: bool,
    pub handshake: RealityHandshake,
    /// X25519, hex or base64url.
    pub private_key: String,
    pub short_id: Listable,
    /// How far a client's clock may be from ours, e.g. `1m`. Unset, any
    /// time is accepted, as in sing-box.
    #[serde(default, with = "crate::config::model::duration")]
    pub max_time_difference: Option<std::time::Duration>,
}

/// The site REALITY imitates, dialed for every connection, with sing-box's
/// dial fields over the instance's defaults; of which it implements all
/// that sail does but `detour`: inbounds do not reach the outbounds yet.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct RealityHandshake {
    pub server: String,
    pub server_port: u16,
    #[serde(flatten)]
    pub dial: DialFields,
}

/// The dial fields a handshake server is dialled with, REALITY's and
/// ShadowTLS's.
pub(crate) const HANDSHAKE_DIAL: &[&str] = &[
    "bind_interface",
    "inet4_bind_address",
    "inet6_bind_address",
    "routing_mark",
    "connect_timeout",
    "disable_tcp_keep_alive",
    "tcp_keep_alive",
    "tcp_keep_alive_interval",
    "domain_resolver",
    "skip_default_domain_resolver",
    "domain_strategy",
    "bind_address_no_port",
    "reuse_addr",
    "tcp_fast_open",
    "udp_fragment",
    "network_strategy",
    "network_type",
    "fallback_network_type",
    "fallback_delay",
];

impl RealityHandshake {
    /// The dialer of the handshake: its own dial fields, over the
    /// instance's defaults as they are when it dials.
    #[cfg_attr(not(feature = "inbound-reality"), allow(dead_code))]
    fn dialer(&self, tag: &str, dial: &InstanceDial) -> Result<InboundDialer> {
        let context = |e: anyhow::Error| anyhow!("[{}] inbound: tls.reality.handshake: {}", tag, e);
        self.dial.check(HANDSHAKE_DIAL).map_err(context)?;
        dial.dialer(&self.dial).map_err(context)
    }
}

#[derive(Deserialize, Debug)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum InboundTransport {
    Ws {
        #[serde(default = "default_path")]
        path: String,
        /// The header a trusted reverse proxy in front puts the client's
        /// address in, such as `X-Forwarded-For`. Unset, no header is
        /// believed: anyone can send one.
        #[serde(default)]
        forwarded_header: Option<String>,
        /// The most early data a client may send in its upgrade request.
        #[serde(default)]
        max_early_data: usize,
        /// The header it comes in; unset, it comes in the path.
        #[serde(default)]
        early_data_header_name: Option<String>,
    },
    #[serde(rename = "httpupgrade")]
    HttpUpgrade {
        /// The `Host` a request must carry; unset, any.
        #[serde(default)]
        host: Option<String>,
        #[serde(default = "default_path")]
        path: String,
        /// Added to the response.
        #[serde(default)]
        headers: HashMap<String, String>,
    },
    Grpc {
        #[serde(default = "default_service_name")]
        service_name: String,
        /// Unset, no keepalive pings.
        #[serde(default, with = "crate::config::model::duration")]
        idle_timeout: Option<std::time::Duration>,
        #[serde(default, with = "crate::config::model::duration")]
        ping_timeout: Option<std::time::Duration>,
    },
    /// sing-box's HTTP/2 transport: not supported.
    Http(serde::de::IgnoredAny),
    /// Its certificate comes from the `tls` block.
    Quic {},
}

/// An inbound's `multiplex` block: sing-box's, which configures its
/// sing-mux server, or with `protocol: "amux"` the amux layer below the
/// protocol.
///
/// sing-mux is served, as by sing-box, only where this block enables it:
/// with no block, a connection to the magic destination is refused. amux
/// takes the block's place, so an inbound with amux serves no sing-mux.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct InboundMultiplex {
    #[serde(default)]
    pub enabled: bool,
    /// `amux`; unset, sing-mux, which sing-box's block has no field for:
    /// its server takes smux, yamux and h2mux alike.
    #[serde(default)]
    pub protocol: Option<String>,
    /// sing-mux: refuse connections that are not padded.
    #[serde(default)]
    pub padding: bool,
    /// sing-mux: TCP Brutal for clients that ask for it; Linux only.
    #[serde(default)]
    pub brutal: Option<MultiplexBrutal>,
}

/// sing-box's `brutal` block of `multiplex`: the rates this end sends
/// (`up_mbps`) and receives (`down_mbps`) at, in megabits per second.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct MultiplexBrutal {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub up_mbps: u64,
    #[serde(default)]
    pub down_mbps: u64,
}

impl MultiplexBrutal {
    /// The rates, if enabled, checked as sing-box checks them.
    #[cfg(feature = "mux")]
    fn rates(&self) -> std::result::Result<Option<crate::transport::mux::brutal::Brutal>, String> {
        if !self.enabled {
            return Ok(None);
        }
        crate::transport::mux::brutal::Brutal::from_mbps(self.up_mbps, self.down_mbps).map(Some)
    }
}

/// What an inbound's `multiplex` block asks for.
enum InboundMux<'a> {
    /// sing-mux, not served.
    Off,
    /// sing-mux, padded only or not, with TCP Brutal or not.
    SingMux {
        padding: bool,
        brutal: Option<&'a MultiplexBrutal>,
    },
    Amux(&'a InboundMultiplex),
}

impl InboundMultiplex {
    /// What the block asks for, checked whether it is enabled or not.
    fn mode(&self, tag: &str) -> Result<InboundMux<'_>> {
        let brutal = self.brutal.as_ref().filter(|b| b.enabled);
        match self.protocol.as_deref() {
            None => {}
            Some("amux") if self.padding => {
                return Err(anyhow!(
                    "[{}] inbound: multiplex.padding: only for sing-mux, not amux",
                    tag
                ));
            }
            Some("amux") if brutal.is_some() => {
                return Err(anyhow!(
                    "[{}] inbound: multiplex.brutal: only for sing-mux, not amux",
                    tag
                ));
            }
            Some("amux") => {}
            Some(protocol) => {
                return Err(anyhow!(
                    "[{}] inbound: multiplex.protocol: unsupported protocol \"{}\"; \
                     amux is, and unset is sing-mux",
                    tag,
                    protocol
                ))
            }
        }
        Ok(match (self.enabled, self.protocol.is_some()) {
            (false, _) => InboundMux::Off,
            (true, false) => InboundMux::SingMux {
                padding: self.padding,
                brutal,
            },
            (true, true) => InboundMux::Amux(self),
        })
    }
}

impl InboundBlocks {
    pub fn parse(tag: &str, blocks: &Options) -> Result<Self> {
        parse_options("inbound", tag, blocks)
    }

    /// Whether TLS (or REALITY) is on.
    pub fn has_tls(&self) -> bool {
        self.tls.as_ref().is_some_and(|t| t.enabled)
    }
}

#[cfg_attr(not(any(feature = "inbound-tls", feature = "quic")), allow(dead_code))]
impl InboundTls {
    /// `min_version` and `max_version`, errors as the inbound `tag`'s.
    #[cfg(feature = "tls")]
    #[cfg_attr(
        not(any(feature = "inbound-tls", feature = "quic", feature = "inbound-reality")),
        allow(dead_code)
    )]
    pub(crate) fn versions(&self, tag: &str) -> Result<crate::transport::tls::TlsVersionRange> {
        crate::transport::tls::TlsVersionRange::parse(
            self.min_version.as_deref(),
            self.max_version.as_deref(),
        )
        .map_err(|e| anyhow!("[{}] inbound: tls.{}", tag, e))
    }

    /// The certificate to present: inline, or by path.
    pub(crate) fn certificate(&self, tag: &str, env: &RuntimeEnv) -> Result<String> {
        match (&self.certificate, &self.certificate_path) {
            (Some(inline), None) => Ok(inline.clone().joined()),
            (None, Some(path)) => Ok(env.data_path(path)),
            _ => Err(anyhow!(
                "[{}] inbound: tls: set exactly one of certificate and certificate_path",
                tag
            )),
        }
    }

    /// The key of the certificate: inline, or by path.
    pub(crate) fn key(&self, tag: &str, env: &RuntimeEnv) -> Result<String> {
        match (&self.key, &self.key_path) {
            (Some(inline), None) => Ok(inline.clone().joined()),
            (None, Some(path)) => Ok(env.data_path(path)),
            _ => Err(anyhow!(
                "[{}] inbound: tls: set exactly one of key and key_path",
                tag
            )),
        }
    }
}

/// Puts `core` inside the layers `blocks` configure.
pub fn inbound(
    core: AnyInboundHandler,
    blocks: &InboundBlocks,
    ctx: &crate::adapter::registry::InboundContext<'_>,
) -> Result<AnyInboundHandler> {
    let tag = ctx.tag;
    let env = ctx.env;
    let tls = blocks.tls.as_ref().filter(|t| t.enabled);
    let mode = match &blocks.multiplex {
        Some(multiplex) => multiplex.mode(tag)?,
        None => InboundMux::Off,
    };
    let mux = match mode {
        InboundMux::Amux(amux) => Some(amux),
        _ => None,
    };
    let sing_mux = match mode {
        InboundMux::Off => None,
        InboundMux::SingMux { padding, brutal } => Some((padding, brutal)),
        InboundMux::Amux(_) => None,
    };
    let mut actors: Vec<AnyInboundHandler> = Vec::new();

    if let Some(InboundTransport::Http(_)) = &blocks.transport {
        return Err(anyhow!(
            "[{}] inbound: transport: type http (HTTP/2) is not supported; grpc is",
            tag
        ));
    }
    // Every call of a gRPC connection is a stream of its own, and the
    // multiplex layer takes one stream to multiplex.
    if matches!(blocks.transport, Some(InboundTransport::Grpc { .. })) && mux.is_some() {
        return Err(anyhow!(
            "[{}] inbound: multiplex: not supported over the grpc transport",
            tag
        ));
    }
    if matches!(blocks.transport, Some(InboundTransport::Quic {})) {
        if mux.is_some() {
            return Err(anyhow!(
                "[{}] inbound: multiplex: not supported over the quic transport",
                tag
            ));
        }
        let tls = tls.ok_or_else(|| {
            anyhow!(
                "[{}] inbound: transport: quic needs the tls block enabled",
                tag
            )
        })?;
        let core = sing_mux_inbound(tag, core, sing_mux)?;
        return quic_inbound(ctx, tls, core);
    } else {
        let mut under_mux = Vec::new();
        if let Some(tls) = tls {
            let alpn = match &tls.alpn {
                Some(alpn) => alpn.clone().into_vec(),
                None => default_inbound_alpn(blocks.transport.as_ref()),
            };
            under_mux.push(tls_inbound(tag, tls, alpn, env, ctx.dial)?);
        }
        if let Some(InboundTransport::Ws {
            path,
            forwarded_header,
            max_early_data,
            early_data_header_name,
        }) = &blocks.transport
        {
            under_mux.push(ws_inbound(
                tag,
                path,
                forwarded_header,
                *max_early_data,
                early_data_header_name.as_deref(),
                env,
            )?);
        }
        if let Some(InboundTransport::HttpUpgrade {
            host,
            path,
            headers,
        }) = &blocks.transport
        {
            under_mux.push(httpupgrade_inbound(tag, host, path, headers)?);
        }
        if let Some(InboundTransport::Grpc {
            service_name,
            idle_timeout,
            ping_timeout,
        }) = &blocks.transport
        {
            under_mux.push(grpc_inbound(
                tag,
                service_name,
                *idle_timeout,
                *ping_timeout,
            )?);
        }
        match mux {
            Some(mux) => actors.push(amux_inbound(tag, mux, under_mux, env)?),
            None => actors.extend(under_mux),
        }
    }

    let handler = if actors.is_empty() {
        core
    } else {
        actors.push(core);
        chain_inbound(tag, actors, env)?
    };
    sing_mux_inbound(tag, handler, sing_mux)
}

/// `handler`, serving sing-mux as `serve` says: not at all if `None`,
/// else padded only or not, and with TCP Brutal for clients that ask or
/// not.
#[allow(unused_variables)]
fn sing_mux_inbound(
    tag: &str,
    handler: AnyInboundHandler,
    serve: Option<(bool, Option<&MultiplexBrutal>)>,
) -> Result<AnyInboundHandler> {
    #[cfg(feature = "mux")]
    {
        use crate::transport::mux::{
            brutal,
            inbound::{with_policy, Policy},
        };
        let policy = match serve {
            None => Policy::Refuse,
            Some((false, _)) => Policy::Serve,
            Some((true, _)) => Policy::ServePadded,
        };
        let brutal = match serve.and_then(|(_, brutal)| brutal) {
            Some(block) => block
                .rates()
                .map_err(|e| anyhow!("[{}] inbound: multiplex: {}", tag, e))?,
            None => None,
        };
        // As sing-mux's server refuses to start.
        if brutal.is_some() && !brutal::AVAILABLE {
            return Err(anyhow!(
                "[{}] inbound: multiplex: TCP Brutal is only supported on Linux",
                tag
            ));
        }
        Ok(with_policy(handler, policy, brutal))
    }
    // Without the feature there is no sing-mux server to refuse.
    #[cfg(not(feature = "mux"))]
    match serve {
        None => Ok(handler),
        Some(_) => Err(not_compiled(tag, "inbound", "multiplex", "mux")),
    }
}

#[allow(unused_variables)]
fn chain_inbound(
    tag: &str,
    actors: Vec<AnyInboundHandler>,
    env: &RuntimeEnv,
) -> Result<AnyInboundHandler> {
    #[cfg(feature = "inbound-chain")]
    {
        use crate::adapter::{AnyInboundDatagramHandler, AnyInboundStreamHandler};
        use crate::protocol::group::chain::inbound::{Accept, DatagramHandler, StreamHandler};
        let accept = Accept::from(&env.options.inbound);
        let stream = actors[0].stream().is_ok().then(|| {
            Arc::new(StreamHandler {
                actors: actors.clone(),
                accept,
            }) as AnyInboundStreamHandler
        });
        let datagram = actors[0].datagram().is_ok().then(|| {
            Arc::new(DatagramHandler {
                actors: actors.clone(),
                accept,
            }) as AnyInboundDatagramHandler
        });
        Ok(Arc::new(crate::adapter::inbound::Handler::new(
            tag.to_owned(),
            stream,
            datagram,
        )))
    }
    #[cfg(not(feature = "inbound-chain"))]
    Err(not_compiled(tag, "inbound", "layers", "inbound-chain"))
}

/// The ALPN an inbound's TLS offers when `tls.alpn` is unset: what the
/// transport inside it speaks, so that clients defaulting the same way
/// agree.
fn default_inbound_alpn(transport: Option<&InboundTransport>) -> Vec<String> {
    match transport {
        Some(InboundTransport::Ws { .. } | InboundTransport::HttpUpgrade { .. }) => {
            vec!["http/1.1".to_string()]
        }
        Some(InboundTransport::Grpc { .. }) => vec!["h2".to_string()],
        // QUIC has its own TLS; bare TLS carries no application protocol.
        // `http` is refused before TLS is built.
        Some(InboundTransport::Quic {} | InboundTransport::Http(_)) | None => Vec::new(),
    }
}

#[allow(unused_variables)]
fn tls_inbound(
    tag: &str,
    tls: &InboundTls,
    alpn: Vec<String>,
    env: &RuntimeEnv,
    dial: &InstanceDial,
) -> Result<AnyInboundHandler> {
    if let Some(reality) = tls.reality.as_ref().filter(|r| r.enabled) {
        // REALITY negotiates no ALPN, as Xray's does not by default.
        if tls.alpn.is_some() {
            return Err(anyhow!(
                "[{}] inbound: tls.alpn: not supported with tls.reality",
                tag
            ));
        }
        return reality_inbound(tag, tls, reality, dial);
    }
    // `server_name` is for REALITY; without it, it is ignored, as sing-box
    // sets it where Go's TLS server never reads it, and server configs
    // copied from clients carry it.
    if tls.server_name.is_some() {
        tracing::warn!(
            "[{}] inbound: tls.server_name: a server does not use it; ignored, as sing-box",
            tag
        );
    }
    #[cfg(feature = "inbound-tls")]
    {
        let handler = crate::transport::tls::inbound::StreamHandler::new(
            tls.certificate(tag, env)?,
            tls.key(tag, env)?,
            alpn,
            tls.versions(tag)?,
        )
        .map_err(|e| anyhow!("[{}] inbound: tls: {}", tag, e))?;
        Ok(Arc::new(crate::adapter::inbound::Handler::new(
            format!("{}/tls", tag),
            Some(Arc::new(handler)),
            None,
        )))
    }
    #[cfg(not(feature = "inbound-tls"))]
    Err(not_compiled(tag, "inbound", "tls", "inbound-tls"))
}

#[allow(unused_variables)]
fn reality_inbound(
    tag: &str,
    tls: &InboundTls,
    reality: &InboundReality,
    dial: &InstanceDial,
) -> Result<AnyInboundHandler> {
    if tls.certificate.is_some()
        || tls.certificate_path.is_some()
        || tls.key.is_some()
        || tls.key_path.is_some()
    {
        return Err(anyhow!(
            "[{}] inbound: tls.reality: takes no certificate or key",
            tag
        ));
    }
    #[cfg(feature = "inbound-reality")]
    {
        // REALITY's handshake is TLS 1.3, as sing-box's server (Xray's)
        // makes it; a range that allows it changes nothing.
        tls.versions(tag)?
            .require_tls13("REALITY")
            .map_err(|e| anyhow!("[{}] inbound: tls.{}", tag, e))?;
        let server_name = tls
            .server_name
            .clone()
            .ok_or_else(|| anyhow!("[{}] inbound: tls.server_name: tls.reality needs it", tag))?;
        let handler = crate::transport::reality::inbound::Handler::new(
            server_name,
            &reality.private_key,
            &reality.short_id.clone().into_vec(),
            reality.max_time_difference,
            (
                reality.handshake.server.clone(),
                reality.handshake.server_port,
            ),
            reality.handshake.dialer(tag, dial)?,
        )
        .map_err(|e| anyhow!("[{}] inbound: tls.reality: {}", tag, e))?;
        Ok(Arc::new(crate::adapter::inbound::Handler::new(
            format!("{}/reality", tag),
            Some(Arc::new(handler)),
            None,
        )))
    }
    #[cfg(not(feature = "inbound-reality"))]
    Err(not_compiled(
        tag,
        "inbound",
        "tls.reality",
        "inbound-reality",
    ))
}

#[allow(unused_variables)]
fn ws_inbound(
    tag: &str,
    path: &str,
    forwarded_header: &Option<String>,
    max_early_data: usize,
    early_data_header_name: Option<&str>,
    env: &RuntimeEnv,
) -> Result<AnyInboundHandler> {
    #[cfg(feature = "inbound-ws")]
    {
        use crate::transport::ws::{inbound::StreamHandler, EarlyData};
        let early_data = EarlyData::new(max_early_data, early_data_header_name)
            .map_err(|e| anyhow!("[{}] inbound: transport: {}", tag, e))?;
        Ok(Arc::new(crate::adapter::inbound::Handler::new(
            format!("{}/ws", tag),
            Some(Arc::new(StreamHandler::new(
                path.to_string(),
                forwarded_header.clone(),
                env.options.ws.half_close,
                early_data,
            ))),
            None,
        )))
    }
    #[cfg(not(feature = "inbound-ws"))]
    Err(not_compiled(tag, "inbound", "transport ws", "inbound-ws"))
}

#[allow(unused_variables)]
fn httpupgrade_inbound(
    tag: &str,
    host: &Option<String>,
    path: &str,
    headers: &HashMap<String, String>,
) -> Result<AnyInboundHandler> {
    #[cfg(feature = "inbound-httpupgrade")]
    {
        let handler = crate::transport::httpupgrade::inbound::StreamHandler::new(
            host.clone(),
            path.to_string(),
            headers,
        )
        .map_err(|e| anyhow!("[{}] inbound: transport: {}", tag, e))?;
        Ok(Arc::new(crate::adapter::inbound::Handler::new(
            format!("{}/httpupgrade", tag),
            Some(Arc::new(handler)),
            None,
        )))
    }
    #[cfg(not(feature = "inbound-httpupgrade"))]
    Err(not_compiled(
        tag,
        "inbound",
        "transport httpupgrade",
        "inbound-httpupgrade",
    ))
}

#[allow(unused_variables)]
fn grpc_inbound(
    tag: &str,
    service_name: &str,
    idle_timeout: Option<std::time::Duration>,
    ping_timeout: Option<std::time::Duration>,
) -> Result<AnyInboundHandler> {
    #[cfg(feature = "inbound-grpc")]
    {
        let handler = crate::transport::grpc::inbound::StreamHandler::new(
            service_name,
            idle_timeout,
            ping_timeout,
        )
        .map_err(|e| anyhow!("[{}] inbound: transport: {}", tag, e))?;
        Ok(Arc::new(crate::adapter::inbound::Handler::new(
            format!("{}/grpc", tag),
            Some(Arc::new(handler)),
            None,
        )))
    }
    #[cfg(not(feature = "inbound-grpc"))]
    Err(not_compiled(
        tag,
        "inbound",
        "transport grpc",
        "inbound-grpc",
    ))
}

#[allow(unused_variables)]
fn quic_inbound(
    ctx: &crate::adapter::registry::InboundContext<'_>,
    tls: &InboundTls,
    core: AnyInboundHandler,
) -> Result<AnyInboundHandler> {
    let tag = ctx.tag;
    #[cfg(feature = "inbound-quic")]
    {
        let handler = crate::transport::quic::inbound::DatagramHandler::new(ctx, tls, core)?;
        Ok(Arc::new(crate::adapter::inbound::Handler::new(
            tag.to_owned(),
            None,
            Some(Arc::new(handler)),
        )))
    }
    #[cfg(not(feature = "inbound-quic"))]
    Err(not_compiled(
        tag,
        "inbound",
        "transport quic",
        "inbound-quic",
    ))
}

#[allow(unused_variables)]
fn amux_inbound(
    tag: &str,
    mux: &InboundMultiplex,
    actors: Vec<AnyInboundHandler>,
    env: &RuntimeEnv,
) -> Result<AnyInboundHandler> {
    #[cfg(feature = "inbound-amux")]
    return Ok(Arc::new(crate::adapter::inbound::Handler::new(
        format!("{}/amux", tag),
        Some(Arc::new(crate::transport::amux::inbound::StreamHandler {
            actors,
            tuning: (&env.options.mux).into(),
        })),
        None,
    )));
    #[cfg(not(feature = "inbound-amux"))]
    Err(not_compiled(tag, "inbound", "multiplex", "inbound-amux"))
}

#[cfg(all(test, any(feature = "outbound-tls", feature = "outbound-reality")))]
mod tests {
    use super::OutboundTls;
    use crate::transport::tls::Fingerprint;

    fn tls(json: &str) -> OutboundTls {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn test_utls_fingerprint() {
        let chrome = Some(Fingerprint::Chrome);
        assert_eq!(
            tls(r#"{"enabled": true}"#).fingerprint("t").unwrap(),
            chrome
        );
        assert_eq!(
            tls(r#"{"enabled": true, "utls": {}}"#)
                .fingerprint("t")
                .unwrap(),
            chrome
        );
        assert_eq!(
            tls(r#"{"enabled": true, "utls": {"fingerprint": "edge"}}"#)
                .fingerprint("t")
                .unwrap(),
            chrome
        );
        for (name, fingerprint) in [
            ("firefox", Fingerprint::Firefox),
            ("safari", Fingerprint::Safari),
        ] {
            let json = format!(
                r#"{{"enabled": true, "utls": {{"fingerprint": "{}"}}}}"#,
                name
            );
            assert_eq!(tls(&json).fingerprint("t").unwrap(), Some(fingerprint));
        }
        assert_eq!(
            tls(r#"{"enabled": true, "utls": {"enabled": false}}"#)
                .fingerprint("t")
                .unwrap(),
            None
        );
        let err = tls(r#"{"enabled": true, "utls": {"fingerprint": "netscape"}}"#)
            .fingerprint("t")
            .unwrap_err()
            .to_string();
        assert!(err.contains("tls.utls.fingerprint"), "{}", err);
        assert!(
            serde_json::from_str::<OutboundTls>(r#"{"utls": {"fingerprnt": "chrome"}}"#).is_err()
        );
    }

    /// The client identity `json` configures, or the error.
    fn identity(json: serde_json::Value) -> Result<bool, String> {
        let tls: OutboundTls = serde_json::from_value(json).unwrap();
        tls.client_identity(&crate::runtime::RuntimeEnv::default())
            .map(|i| i.is_some())
            .map_err(|e| e.to_string())
    }

    /// A certificate `key` signs for itself, PEM.
    fn self_signed(key: &btls::pkey::PKey<btls::pkey::Private>) -> String {
        let pem = String::from_utf8(key.private_key_to_pem_pkcs8().unwrap()).unwrap();
        let key = rcgen::KeyPair::from_pem(&pem).unwrap();
        rcgen::CertificateParams::new(vec!["client".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap()
            .pem()
    }

    #[test]
    fn test_client_certificate_options() {
        use serde_json::json;
        let pki = crate::transport::tls::tests::client_pki();
        // The key is not printed.
        let tls: OutboundTls =
            serde_json::from_value(json!({"client_certificate": pki.cert, "client_key": pki.key}))
                .unwrap();
        let debug = format!("{:?}", tls);
        assert!(!debug.contains("PRIVATE KEY"), "{}", debug);
        assert!(debug.contains("<redacted>"), "{}", debug);
        assert_eq!(identity(json!({})), Ok(false));
        assert_eq!(
            identity(json!({"client_certificate": pki.cert, "client_key": pki.key})),
            Ok(true)
        );
        // Line by line, as sing-box lists PEM.
        let lines = |pem: &str| pem.lines().map(str::to_string).collect::<Vec<_>>();
        assert_eq!(
            identity(json!({
                "client_certificate": lines(&pki.cert),
                "client_key": lines(&pki.key)
            })),
            Ok(true)
        );

        let dir = std::env::temp_dir().join(format!("sail-client-cert-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (cert_path, key_path) = (dir.join("client.crt"), dir.join("client.key"));
        std::fs::write(&cert_path, &pki.cert).unwrap();
        std::fs::write(&key_path, &pki.key).unwrap();
        assert_eq!(
            identity(json!({
                "client_certificate_path": cert_path,
                "client_key_path": key_path
            })),
            Ok(true)
        );
        // Inline one half, the other by path.
        assert_eq!(
            identity(json!({"client_certificate": pki.cert, "client_key_path": key_path})),
            Ok(true)
        );

        let err = |json| identity(json).unwrap_err();
        assert_eq!(
            err(json!({"client_certificate": pki.cert})),
            "client_key: needed with client_certificate"
        );
        assert_eq!(
            err(json!({"client_key_path": key_path})),
            "client_certificate: needed with client_key"
        );
        assert_eq!(
            err(json!({
                "client_certificate": pki.cert,
                "client_certificate_path": cert_path,
                "client_key": pki.key
            })),
            "client_certificate: set at most one of client_certificate and \
             client_certificate_path"
        );
        // An inline key that is not PEM is not echoed.
        let e = err(json!({"client_certificate": pki.cert, "client_key": "c2VjcmV0"}));
        assert_eq!(e, "client_key: not PEM");
        let e = err(json!({
            "client_certificate": pki.cert,
            "client_key_path": dir.join("missing.key")
        }));
        assert!(e.starts_with("client_key: load key from"), "{}", e);
        let e = err(json!({
            "client_certificate": "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----",
            "client_key": pki.key
        }));
        assert!(e.starts_with("client_certificate: "), "{}", e);
        let other = crate::transport::tls::tests::client_pki();
        let e = err(json!({"client_certificate": pki.cert, "client_key": other.key}));
        assert!(e.starts_with("client_key: "), "{}", e);
        assert!(!e.contains("PRIVATE"), "{}", e);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_client_key_types() {
        use btls::pkey::{Id, PKey};
        use serde_json::json;
        let rsa = btls::rsa::Rsa::generate(2048).unwrap();
        let pkcs1 = String::from_utf8(rsa.private_key_to_pem().unwrap()).unwrap();
        assert!(pkcs1.contains("BEGIN RSA PRIVATE KEY"));
        let key = PKey::from_rsa(rsa).unwrap();
        let cert = self_signed(&key);
        assert_eq!(
            identity(json!({"client_certificate": cert, "client_key": pkcs1})),
            Ok(true)
        );
        let key = PKey::generate(Id::ED25519).unwrap();
        let cert = self_signed(&key);
        let pkcs8 = String::from_utf8(key.private_key_to_pem_pkcs8().unwrap()).unwrap();
        assert_eq!(
            identity(json!({"client_certificate": cert, "client_key": pkcs8})),
            Ok(true)
        );
    }

    /// A REALITY handshake dials with its own dial fields over the
    /// instance's defaults, and names the fields it does not take.
    #[test]
    fn a_reality_handshake_dials_its_fields_over_the_instance_defaults() {
        use super::RealityHandshake;
        use crate::net::dial::{DialEnv, RouteDefaults};
        use crate::net::{DialDefaults, InstanceDial, TcpKeepAlive};
        use std::time::Duration;

        let dial = InstanceDial::default();
        dial.defaults.store(std::sync::Arc::new(DialDefaults {
            route: RouteDefaults {
                routing_mark: Some(7),
                ..Default::default()
            },
            env: DialEnv::default(),
        }));
        let handshake =
            |json: serde_json::Value| -> RealityHandshake { serde_json::from_value(json).unwrap() };
        let dialer = handshake(serde_json::json!({
            "server": "example.com", "server_port": 443,
            "connect_timeout": "2s", "tcp_keep_alive": "40s",
        }))
        .dialer("r", &dial)
        .unwrap()
        .dialer();
        assert_eq!(dialer.spec().routing_mark, Some(7));
        assert_eq!(dialer.connect_timeout(), Duration::from_secs(2));
        assert_eq!(
            dialer.spec().tcp_keep_alive,
            Some(TcpKeepAlive {
                idle: Duration::from_secs(40),
                interval: TcpKeepAlive::DEFAULT.interval,
            })
        );
        let err = handshake(serde_json::json!({
            "server": "example.com", "server_port": 443, "detour": "proxy",
        }))
        .dialer("r", &dial)
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "[r] inbound: tls.reality.handshake: detour: sail does not implement this field yet"
        );
    }

    #[test]
    fn test_disable_sni_conflicts() {
        use serde_json::json;
        let dns = crate::app::dns::DnsClient::new(
            &crate::config::Dns::default(),
            Default::default(),
            &Default::default(),
        )
        .unwrap()
        .into_shared();
        let env = crate::runtime::RuntimeEnv::default();
        let build = |json: serde_json::Value| {
            let tls: OutboundTls = serde_json::from_value(json).unwrap();
            super::tls_outbound("t", &tls, &dns, &env)
                .map(|_| ())
                .map_err(|e| e.to_string())
        };
        let reality = json!({"enabled": true, "public_key": "x"});
        assert_eq!(
            build(json!({"enabled": true, "disable_sni": true, "reality": reality})),
            Err("[t] outbound: tls.disable_sni: not with tls.reality".into())
        );
        let pki = crate::transport::tls::tests::client_pki();
        assert_eq!(
            build(json!({
                "enabled": true, "reality": reality,
                "client_certificate": pki.cert, "client_key": pki.key
            })),
            Err("[t] outbound: tls.client_certificate: not with tls.reality".into())
        );
        #[cfg(feature = "outbound-tls")]
        {
            assert_eq!(
                build(json!({"enabled": true, "disable_sni": true, "ech": {"enabled": true}})),
                Err("[t] outbound: tls.disable_sni: not with tls.ech".into())
            );
            assert!(build(json!({"enabled": true, "disable_sni": true})).is_ok());
            assert_eq!(
                build(json!({"enabled": true, "client_certificate": pki.cert})),
                Err("[t] outbound: tls.client_key: needed with client_certificate".into())
            );
        }
    }

    #[test]
    fn test_versions_and_pins() {
        use crate::transport::tls::options::Version;
        use crate::transport::tls::TlsVersionRange;
        use serde_json::json;
        let dns = crate::app::dns::DnsClient::new(
            &crate::config::Dns::default(),
            Default::default(),
            &Default::default(),
        )
        .unwrap()
        .into_shared();
        let env = crate::runtime::RuntimeEnv::default();
        let build = |json: serde_json::Value| {
            let tls: OutboundTls = serde_json::from_value(json).unwrap();
            super::tls_outbound("t", &tls, &dns, &env)
                .map(|_| ())
                .map_err(|e| e.to_string())
        };
        let options = |json: serde_json::Value| {
            let tls: OutboundTls = serde_json::from_value(json).unwrap();
            tls.stream_options("[t] outbound")
                .map_err(|e| e.to_string())
        };
        let pin = btls::base64::encode_block(&[1; 32]);

        // Mistakes are errors, naming the field.
        assert_eq!(
            build(json!({"enabled": true, "min_version": "1.4"})),
            Err(
                "[t] outbound: tls.min_version: unknown TLS version \"1.4\", \
                 one of 1.0, 1.1, 1.2, 1.3"
                    .into()
            )
        );
        assert_eq!(
            build(json!({"enabled": true, "min_version": "1.3", "max_version": "1.2"})),
            Err("[t] outbound: tls.min_version: 1.3 is above max_version 1.2".into())
        );
        let err = build(json!({"enabled": true, "certificate_public_key_sha256": [pin, "x"]}))
            .unwrap_err();
        assert!(
            err.starts_with("[t] outbound: tls.certificate_public_key_sha256[1]: not base64"),
            "{}",
            err
        );
        let err =
            build(json!({"enabled": true, "certificate_public_key_sha256": "AAAA"})).unwrap_err();
        assert!(
            err.starts_with("[t] outbound: tls.certificate_public_key_sha256[0]: 3 bytes"),
            "{}",
            err
        );
        // A pin replaces the certificate to trust, as in sing-box.
        assert_eq!(
            build(
                json!({"enabled": true, "certificate_public_key_sha256": pin,
                "certificate_path": "ca.pem"})
            ),
            Err("[t] outbound: tls.certificate_public_key_sha256: \
                 not with certificate or certificate_path"
                .into())
        );

        // Whole certificates, hex: each entry checked, the pins exclusive of
        // the certificate to trust and of the keys pinned.
        let hex = "ab".repeat(32);
        let colons = vec!["AB"; 32].join(":");
        assert!(build(json!({"enabled": true, "certificate_sha256": [&hex, &colons]})).is_ok());
        for (bad, why) in [
            (
                "xy".repeat(32),
                "tls.certificate_sha256[1]: not the hex of a SHA-256 hash",
            ),
            (
                "abc".to_string(),
                "tls.certificate_sha256[1]: not the hex of a SHA-256 hash",
            ),
            (
                "ab".repeat(20),
                "tls.certificate_sha256[1]: 20 bytes, where a SHA-256 hash has 32",
            ),
            (
                format!(" {}", hex),
                "tls.certificate_sha256[1]: not the hex of a SHA-256 hash",
            ),
            (
                pin.clone(),
                "tls.certificate_sha256[1]: not the hex of a SHA-256 hash",
            ),
        ] {
            let err =
                build(json!({"enabled": true, "certificate_sha256": [&hex, bad]})).unwrap_err();
            assert_eq!(err, format!("[t] outbound: {}", why));
        }
        for other in [
            json!({"certificate": "PEM"}),
            json!({"certificate_path": "ca.pem"}),
        ] {
            let mut tls = json!({"enabled": true, "certificate_sha256": &hex});
            tls.as_object_mut()
                .unwrap()
                .extend(other.as_object().unwrap().clone());
            assert_eq!(
                build(tls),
                Err("[t] outbound: tls.certificate_sha256: \
                     not with certificate or certificate_path"
                    .into())
            );
        }
        assert_eq!(
            build(json!({"enabled": true, "certificate_sha256": &hex,
                "certificate_public_key_sha256": pin})),
            Err("[t] outbound: tls.certificate_sha256: \
                 not with certificate_public_key_sha256"
                .into())
        );
        let reality = json!({"enabled": true, "public_key": "x"});
        let ignored = options(json!({"enabled": true, "reality": reality,
            "certificate_sha256": &hex}))
        .unwrap();
        assert!(ignored.pins.is_none());

        // With REALITY both are ignored, as sing-box's REALITY client does.
        let reality = json!({"enabled": true, "public_key": "x"});
        let ignored = options(json!({"enabled": true, "reality": reality,
            "max_version": "1.2", "certificate_public_key_sha256": pin}))
        .unwrap();
        assert!(!ignored.versions.is_set() && ignored.pins.is_none());

        // With sing-box's uTLS, the browser's versions are offered.
        let utls = options(json!({"enabled": true, "utls": {"enabled": true},
            "min_version": "1.3", "certificate_public_key_sha256": pin}))
        .unwrap();
        assert!(!utls.versions.is_set());
        assert!(utls.pins.is_some(), "pins apply with any ClientHello");
        // Without, as with sing-box's own TLS, they are negotiated, with
        // the default fingerprint or none.
        for json in [
            json!({"enabled": true, "min_version": "1.3"}),
            json!({"enabled": true, "min_version": "1.3", "utls": {"enabled": false}}),
        ] {
            assert_eq!(
                options(json).unwrap().versions,
                TlsVersionRange {
                    min: Some(Version::Tls13),
                    max: None
                }
            );
        }
        #[cfg(feature = "outbound-tls")]
        assert!(build(json!({"enabled": true, "max_version": "1.2"})).is_ok());

        // ECH is TLS 1.3 only: sing-box fails every handshake below it.
        let ech = json!({"enabled": true, "config": "AAT+DQBB"});
        assert_eq!(
            options(json!({"enabled": true, "ech": ech, "min_version": "1.2"})).map(|_| ()),
            Err("min_version: ECH is TLS 1.3 only: 1.3, or unset, with tls.ech".into())
        );
        assert_eq!(
            options(json!({"enabled": true, "ech": ech, "max_version": "1.2"})).map(|_| ()),
            Err("max_version: ECH is TLS 1.3 only: 1.3, or unset, with tls.ech".into())
        );
        assert!(options(json!({"enabled": true, "ech": ech, "min_version": "1.3"})).is_ok());
    }
}

#[cfg(all(test, feature = "inbound-tls"))]
mod inbound_tls_tests {
    use super::{tls_inbound, InboundTls};

    /// An inbound's `tls.server_name` without REALITY is ignored, as
    /// sing-box ignores it, rather than refused.
    #[test]
    fn an_inbound_s_server_name_is_ignored_without_reality() {
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let tls: InboundTls = serde_json::from_value(serde_json::json!({
            "enabled": true,
            "server_name": "example.com",
            "certificate": cert.pem(),
            "key": key_pair.serialize_pem(),
        }))
        .unwrap();
        let env = crate::runtime::RuntimeEnv::default();
        tls_inbound("in", &tls, Vec::new(), &env, &Default::default()).unwrap();
    }
}
