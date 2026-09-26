//! The blocks a protocol can be carried over -- `tls`, `transport`,
//! `multiplex` -- its dial fields and `detour`, and how they become layers
//! around it.
//!
//! In a configuration they are fields of the protocol's own entry, as in
//! sing-box. Inside, an outbound with layers is a chain of handlers,
//! `[tls, ws, vless]`, and one with a detour is a chain of that and the
//! outbound it detours through; chains are not something a configuration
//! names.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use futures::future::AbortHandle;
use serde_derive::Deserialize;

use crate::adapter::{AnyInboundHandler, AnyOutboundHandler};
use crate::app::SyncDnsClient;
use crate::config::model::{parse_options, Options};
use crate::net::DialOptions;
use crate::runtime::RuntimeEnv;

/// Which blocks a protocol can be configured with.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Blocks {
    /// The dial fields: `bind_interface`, `inet4_bind_address`,
    /// `inet6_bind_address`, `routing_mark`, `connect_timeout`.
    pub dial: bool,
    pub detour: bool,
    pub tls: bool,
    pub transport: bool,
    pub multiplex: bool,
}

/// The fields `Blocks::dial` covers.
const DIAL_FIELDS: [&str; 5] = [
    "bind_interface",
    "inet4_bind_address",
    "inet6_bind_address",
    "routing_mark",
    "connect_timeout",
];

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
        let dial = DIAL_FIELDS.into_iter().filter(move |_| with_dial);
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
    /// The outbound to dial this one's server through.
    #[serde(default)]
    pub detour: Option<String>,
    /// The interface to send through, by name.
    #[serde(default)]
    pub bind_interface: Option<String>,
    #[serde(default)]
    pub inet4_bind_address: Option<std::net::Ipv4Addr>,
    #[serde(default)]
    pub inet6_bind_address: Option<std::net::Ipv6Addr>,
    /// `SO_MARK`, Linux only.
    #[serde(default)]
    pub routing_mark: Option<u32>,
    /// How long a TCP connect may take, e.g. `5s`.
    #[serde(default, with = "crate::config::model::duration")]
    pub connect_timeout: Option<std::time::Duration>,
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
    #[serde(default)]
    pub insecure: bool,
    #[serde(default)]
    pub alpn: Option<Listable>,
    /// An inline PEM certificate to trust.
    #[serde(default)]
    pub certificate: Option<Listable>,
    /// A PEM certificate to trust, by path.
    #[serde(default)]
    pub certificate_path: Option<String>,
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
    #[cfg(feature = "tls")]
    fn fingerprint(&self, tag: &str) -> Result<Option<crate::transport::tls::Fingerprint>> {
        use crate::transport::tls::Fingerprint;
        match &self.utls {
            None => Ok(Some(Fingerprint::Chrome)),
            Some(utls) if !utls.enabled => Ok(None),
            Some(utls) => Fingerprint::from_name(&utls.fingerprint)
                .map(Some)
                .map_err(|e| anyhow!("[{}] outbound: tls.utls.fingerprint: {}", tag, e)),
        }
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
        /// sing-box's; no effect here, where a connection carries one call
        /// and is closed when that ends.
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
        ClientOptions::new(
            protocol,
            mux.padding,
            mux.max_connections,
            mux.min_streams,
            mux.max_streams,
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

    /// The dial fields set, checked against each other and the platform.
    pub fn dial(&self, tag: &str) -> Result<DialOptions> {
        let dial = DialOptions {
            bind_interface: self.bind_interface.clone(),
            inet4_bind_address: self.inet4_bind_address,
            inet6_bind_address: self.inet6_bind_address,
            routing_mark: self.routing_mark,
            connect_timeout: self
                .connect_timeout
                .unwrap_or(crate::net::dial::DEFAULT_CONNECT_TIMEOUT),
            protect: None,
            ipv6: false,
        };
        if let Some(detour) = &self.detour {
            let set = [
                ("bind_interface", dial.bind_interface.is_some()),
                ("inet4_bind_address", dial.inet4_bind_address.is_some()),
                ("inet6_bind_address", dial.inet6_bind_address.is_some()),
                ("routing_mark", dial.routing_mark.is_some()),
                ("connect_timeout", self.connect_timeout.is_some()),
            ];
            if let Some((field, _)) = set.iter().find(|(_, set)| *set) {
                return Err(anyhow!(
                    "[{}] outbound: {}: has no effect with a detour; set it on [{}]",
                    tag,
                    field,
                    detour
                ));
            }
        }
        check_dial_platform("outbound", tag, &dial)?;
        Ok(dial)
    }
}

/// Fails for dial options this platform cannot apply.
pub fn check_dial_platform(kind: &str, tag: &str, dial: &DialOptions) -> Result<()> {
    if dial.routing_mark.is_some() && !crate::net::dial::supports_routing_mark() {
        return Err(anyhow!(
            "[{}] {}: routing_mark: only supported on Linux",
            tag,
            kind
        ));
    }
    if let Some(name) = &dial.bind_interface {
        if !crate::net::dial::supports_bind_interface() {
            return Err(anyhow!(
                "[{}] {}: bind_interface: not supported on this platform",
                tag,
                kind
            ));
        }
        if crate::net::dial::interface_exists(name) == Some(false) {
            return Err(anyhow!(
                "[{}] {}: bind_interface: there is no interface \"{}\"",
                tag,
                kind,
                name
            ));
        }
    }
    Ok(())
}

/// What layering an outbound needs from where it is built.
pub struct OutboundLayering<'a> {
    pub tag: &'a str,
    /// The protocol's own options, for the server the layers dial.
    pub options: &'a Options,
    pub dns_client: &'a SyncDnsClient,
    pub abort_handles: &'a mut Vec<AbortHandle>,
    /// The outbound `detour` names, already built.
    pub detour: Option<AnyOutboundHandler>,
    /// How the outbound dials: its dial fields over the instance's
    /// defaults, from `OutboundBlocks::dial`.
    pub dial: Arc<DialOptions>,
    pub env: &'a RuntimeEnv,
}

/// The server a protocol's options name, which the layers under it dial.
fn server(tag: &str, options: &Options) -> Result<(String, u16)> {
    let missing = |field| anyhow!("[{}] outbound: {} is needed by its layers", tag, field);
    let server = options
        .get("server")
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing("server"))?;
    let port = options
        .get("server_port")
        .and_then(|v| v.as_u64())
        .and_then(|p| u16::try_from(p).ok())
        .ok_or_else(|| missing("server_port"))?;
    Ok((server.to_string(), port))
}

/// Puts `core` inside the layers `blocks` configure.
pub fn outbound(
    core: AnyOutboundHandler,
    blocks: &OutboundBlocks,
    layering: OutboundLayering<'_>,
) -> Result<AnyOutboundHandler> {
    let tag = layering.tag;
    let dial = layering.dial;
    let mut actors: Vec<AnyOutboundHandler> = Vec::new();
    // sing-mux runs above everything else, over connections of the whole.
    let mut sing_mux = None;

    if let Some(OutboundTransport::Http(_)) = &blocks.transport {
        return Err(anyhow!(
            "[{}] outbound: transport: type http (HTTP/2) is not supported; grpc is",
            tag
        ));
    }
    if matches!(blocks.transport, Some(OutboundTransport::Grpc { .. }))
        && blocks.multiplex().is_some()
    {
        return Err(anyhow!(
            "[{}] outbound: multiplex: not supported over the grpc transport",
            tag
        ));
    }
    let quic = matches!(blocks.transport, Some(OutboundTransport::Quic {}));
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
        let (address, port) = server(tag, layering.options)?;
        actors.push(quic_outbound(
            tag,
            tls,
            address,
            port,
            layering.dns_client,
            &dial,
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
        }) = &blocks.transport
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
        }) = &blocks.transport
        {
            under_mux.push(httpupgrade_outbound(tag, host, path, headers)?);
        }
        if let Some(OutboundTransport::Grpc {
            service_name,
            idle_timeout,
            ping_timeout,
            permit_without_stream: _,
        }) = &blocks.transport
        {
            under_mux.push(grpc_outbound(
                tag,
                service_name,
                blocks.tls().is_some(),
                *idle_timeout,
                *ping_timeout,
            )?);
        }
        match blocks.multiplex() {
            None => actors.extend(under_mux),
            Some(mux) if !mux.is_amux() => {
                sing_mux = Some(sing_mux_options(tag, mux)?);
                actors.extend(under_mux);
            }
            Some(mux) => {
                let (address, port) = server(tag, layering.options)?;
                actors.push(amux_outbound(
                    tag,
                    mux,
                    address,
                    port,
                    under_mux,
                    layering.dns_client,
                    &dial,
                    layering.abort_handles,
                )?);
            }
        }
    }

    let layered = if actors.is_empty() {
        core
    } else {
        actors.push(core);
        chain_outbound(tag, actors)?
    };
    // What it asks to have dialled is dialled as it says. Through a detour,
    // that is what the detour asks for, with the detour's own options.
    let layered = crate::adapter::outbound::with_dial(layered, dial);
    let whole = match layering.detour {
        Some(detour) => chain_outbound(tag, vec![detour, layered])?,
        None => layered,
    };
    match sing_mux {
        Some(options) => sing_mux_outbound(
            tag,
            whole,
            layering.dns_client,
            options,
            layering.abort_handles,
        ),
        None => Ok(whole),
    }
}

#[allow(unused_variables)]
fn sing_mux_outbound(
    tag: &str,
    whole: AnyOutboundHandler,
    dns_client: &SyncDnsClient,
    options: SingMuxOptions,
    abort_handles: &mut Vec<AbortHandle>,
) -> Result<AnyOutboundHandler> {
    #[cfg(feature = "mux")]
    return Ok(crate::transport::mux::client::outbound(
        tag,
        whole,
        dns_client.clone(),
        options,
        abort_handles,
    ));
    #[cfg(not(feature = "mux"))]
    Err(not_compiled(tag, "outbound", "multiplex", "mux"))
}

/// Opens connections to a protocol's server through the layers its blocks
/// configure: dial fields, detour, tls, transport.
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
        let (server, port) = server(layering.tag, layering.options)?;
        let dns_client = layering.dns_client.clone();
        let handover = crate::adapter::outbound::HandlerBuilder::default()
            .tag(layering.tag.to_owned())
            .stream_handler(Arc::new(Handover { server, port }))
            .build();
        Ok(Connector {
            layers: outbound(handover, blocks, layering)?,
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
}

/// The innermost layer of a `Connector`: asks for the server to be dialled,
/// and hands over what the layers around it made of that.
struct Handover {
    server: String,
    port: u16,
}

#[async_trait::async_trait]
impl crate::adapter::OutboundStreamHandler for Handover {
    fn connect_addr(&self) -> crate::adapter::OutboundConnect {
        crate::adapter::OutboundConnect::Proxy(
            crate::session::Network::Tcp,
            self.server.clone(),
            self.port,
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
#[cfg_attr(not(any(feature = "outbound-tls", feature = "quic")), allow(dead_code))]
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
        let ech_config_list = match ech.and_then(|e| e.config.clone()) {
            Some(config) => Some(ech_config_list(tag, config)?),
            None => None,
        };
        let handler = crate::transport::tls::outbound::StreamHandler::new(
            server_name,
            tls.alpn.clone().map(Listable::into_vec).unwrap_or_default(),
            trusted_certificate(tls, env),
            tls.insecure,
            tls.fingerprint(tag)?,
            ech.is_some(),
            ech.is_some_and(|e| e.disable_dns_lookup),
            ech_config_list,
            dns_client.clone(),
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
    tls: bool,
    idle_timeout: Option<std::time::Duration>,
    ping_timeout: Option<std::time::Duration>,
) -> Result<AnyOutboundHandler> {
    #[cfg(feature = "outbound-grpc")]
    {
        let handler = crate::transport::grpc::outbound::StreamHandler::new(
            service_name,
            tls,
            idle_timeout,
            ping_timeout,
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
    dial: &Arc<DialOptions>,
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
                dial.clone(),
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
fn amux_outbound(
    tag: &str,
    mux: &OutboundMultiplex,
    address: String,
    port: u16,
    actors: Vec<AnyOutboundHandler>,
    dns_client: &SyncDnsClient,
    dial: &Arc<DialOptions>,
    abort_handles: &mut Vec<AbortHandle>,
) -> Result<AnyOutboundHandler> {
    let sing_mux_only = [
        ("max_connections", mux.max_connections.is_some()),
        ("min_streams", mux.min_streams.is_some()),
        ("max_streams", mux.max_streams.is_some()),
        ("padding", mux.padding),
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
            dial.clone(),
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
    /// The name REALITY clients must ask for; only REALITY uses it.
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
/// dial fields. `detour` is not among them: inbounds do not reach the
/// outbounds.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct RealityHandshake {
    pub server: String,
    pub server_port: u16,
    #[serde(default)]
    pub bind_interface: Option<String>,
    #[serde(default)]
    pub inet4_bind_address: Option<std::net::Ipv4Addr>,
    #[serde(default)]
    pub inet6_bind_address: Option<std::net::Ipv6Addr>,
    /// `SO_MARK`, Linux only.
    #[serde(default)]
    pub routing_mark: Option<u32>,
    /// How long the TCP connect may take, e.g. `5s`.
    #[serde(default, with = "crate::config::model::duration")]
    pub connect_timeout: Option<std::time::Duration>,
}

impl RealityHandshake {
    #[cfg_attr(not(feature = "inbound-reality"), allow(dead_code))]
    fn dial(&self, tag: &str) -> Result<DialOptions> {
        let dial = DialOptions {
            bind_interface: self.bind_interface.clone(),
            inet4_bind_address: self.inet4_bind_address,
            inet6_bind_address: self.inet6_bind_address,
            routing_mark: self.routing_mark,
            connect_timeout: self
                .connect_timeout
                .unwrap_or(crate::net::dial::DEFAULT_CONNECT_TIMEOUT),
            ..Default::default()
        };
        check_dial_platform("inbound: tls.reality.handshake", tag, &dial)?;
        Ok(dial)
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

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct InboundMultiplex {
    #[serde(default)]
    pub enabled: bool,
    /// Only `amux` for now.
    pub protocol: String,
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
    tag: &str,
    core: AnyInboundHandler,
    blocks: &InboundBlocks,
    env: &RuntimeEnv,
) -> Result<AnyInboundHandler> {
    let tls = blocks.tls.as_ref().filter(|t| t.enabled);
    let mux = blocks.multiplex.as_ref().filter(|m| m.enabled);
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
        actors.push(quic_inbound(tag, tls, env)?);
    } else {
        let mut under_mux = Vec::new();
        if let Some(tls) = tls {
            let alpn = match &tls.alpn {
                Some(alpn) => alpn.clone().into_vec(),
                None => default_inbound_alpn(blocks.transport.as_ref()),
            };
            under_mux.push(tls_inbound(tag, tls, alpn, env)?);
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
            Some(mux) => actors.push(amux_inbound(tag, mux, under_mux)?),
            None => actors.extend(under_mux),
        }
    }

    if actors.is_empty() {
        return Ok(core);
    }
    actors.push(core);
    chain_inbound(tag, actors, env)
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
) -> Result<AnyInboundHandler> {
    if let Some(reality) = tls.reality.as_ref().filter(|r| r.enabled) {
        // REALITY negotiates no ALPN, as Xray's does not by default.
        if tls.alpn.is_some() {
            return Err(anyhow!(
                "[{}] inbound: tls.alpn: not supported with tls.reality",
                tag
            ));
        }
        return reality_inbound(tag, tls, reality);
    }
    if tls.server_name.is_some() {
        return Err(anyhow!(
            "[{}] inbound: tls.server_name: only used by tls.reality",
            tag
        ));
    }
    #[cfg(feature = "inbound-tls")]
    {
        let handler = crate::transport::tls::inbound::StreamHandler::new(
            tls.certificate(tag, env)?,
            tls.key(tag, env)?,
            alpn,
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
            reality.handshake.dial(tag)?,
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
fn quic_inbound(tag: &str, tls: &InboundTls, env: &RuntimeEnv) -> Result<AnyInboundHandler> {
    #[cfg(feature = "inbound-quic")]
    {
        let handler = crate::transport::quic::inbound::DatagramHandler::new(tag, tls, env)?;
        Ok(Arc::new(crate::adapter::inbound::Handler::new(
            format!("{}/quic", tag),
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
) -> Result<AnyInboundHandler> {
    if mux.protocol != "amux" {
        return Err(anyhow!(
            "[{}] inbound: multiplex.protocol: unsupported protocol \"{}\", only amux is",
            tag,
            mux.protocol
        ));
    }
    #[cfg(feature = "inbound-amux")]
    return Ok(Arc::new(crate::adapter::inbound::Handler::new(
        format!("{}/amux", tag),
        Some(Arc::new(crate::transport::amux::inbound::StreamHandler {
            actors,
        })),
        None,
    )));
    #[cfg(not(feature = "inbound-amux"))]
    Err(not_compiled(tag, "inbound", "multiplex", "inbound-amux"))
}

#[cfg(all(test, feature = "tls"))]
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
}
