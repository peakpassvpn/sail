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
    },
    /// Its TLS parameters come from the `tls` block.
    Quic {},
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct OutboundMultiplex {
    #[serde(default)]
    pub enabled: bool,
    /// Only `amux` for now.
    pub protocol: String,
    #[serde(default = "default_max_accepts")]
    pub max_accepts: usize,
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,
    #[serde(default)]
    pub max_recv_bytes: usize,
    #[serde(default)]
    pub max_lifetime: u64,
}

fn default_path() -> String {
    "/".to_string()
}

fn default_max_accepts() -> usize {
    8
}

fn default_concurrency() -> usize {
    2
}

impl OutboundBlocks {
    pub fn parse(tag: &str, blocks: &Options) -> Result<Self> {
        parse_options("outbound", tag, blocks)
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
    if dial.bind_interface.is_some() && !crate::net::dial::supports_bind_interface() {
        return Err(anyhow!(
            "[{}] {}: bind_interface: not supported on this platform",
            tag,
            kind
        ));
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
        if let Some(OutboundTransport::Ws { path, headers }) = &blocks.transport {
            under_mux.push(ws_outbound(tag, path, headers, layering.env)?);
        }
        match blocks.multiplex() {
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
            None => actors.extend(under_mux),
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
    match layering.detour {
        Some(detour) => chain_outbound(tag, vec![detour, layered]),
        None => Ok(layered),
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
    not(any(feature = "outbound-tls", feature = "outbound-quic")),
    allow(dead_code)
)]
fn trusted_certificate(tls: &OutboundTls, env: &RuntimeEnv) -> Option<String> {
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
                crate::transport::reality::outbound::StreamHandler {
                    server_name,
                    public_key: reality.public_key.clone(),
                    short_id: reality.short_id.clone(),
                },
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
            None,
            tls.insecure,
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
    env: &RuntimeEnv,
) -> Result<AnyOutboundHandler> {
    #[cfg(feature = "outbound-ws")]
    return Ok(crate::adapter::outbound::HandlerBuilder::default()
        .tag(format!("{}/ws", tag))
        .stream_handler(Arc::new(crate::transport::ws::outbound::StreamHandler {
            path: path.to_string(),
            headers: headers.clone(),
            half_close: env.options.ws.half_close,
        }))
        .build());
    #[cfg(not(feature = "outbound-ws"))]
    Err(not_compiled(tag, "outbound", "transport ws", "outbound-ws"))
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
                address,
                port,
                tls.server_name.clone(),
                tls.alpn.clone().map(Listable::into_vec).unwrap_or_default(),
                trusted_certificate(tls, env),
                None,
                dns_client.clone(),
                dial.clone(),
                &env.options.quic,
            ),
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
    if mux.protocol != "amux" {
        return Err(anyhow!(
            "[{}] outbound: multiplex.protocol: unsupported protocol \"{}\", only amux is",
            tag,
            mux.protocol
        ));
    }
    #[cfg(feature = "outbound-amux")]
    {
        let (stream, mut handles) = crate::transport::amux::outbound::StreamHandler::new(
            address,
            port,
            actors,
            mux.max_accepts,
            mux.concurrency,
            mux.max_recv_bytes,
            mux.max_lifetime,
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
}

#[derive(Deserialize, Debug)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum InboundTransport {
    Ws {
        #[serde(default = "default_path")]
        path: String,
    },
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
}

#[cfg_attr(
    not(any(feature = "inbound-tls", feature = "inbound-quic")),
    allow(dead_code)
)]
impl InboundTls {
    fn certificate(&self, tag: &str, env: &RuntimeEnv) -> Result<String> {
        match (&self.certificate, &self.certificate_path) {
            (Some(inline), None) => Ok(inline.clone().joined()),
            (None, Some(path)) => Ok(env.data_path(path)),
            _ => Err(anyhow!(
                "[{}] inbound: tls: set exactly one of certificate and certificate_path",
                tag
            )),
        }
    }

    fn key(&self, tag: &str, env: &RuntimeEnv) -> Result<String> {
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
            if tls.alpn.is_some() {
                return Err(anyhow!(
                    "[{}] inbound: tls.alpn: only supported with the quic transport",
                    tag
                ));
            }
            under_mux.push(tls_inbound(tag, tls, env)?);
        }
        if let Some(InboundTransport::Ws { path }) = &blocks.transport {
            under_mux.push(ws_inbound(tag, path, env)?);
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

#[allow(unused_variables)]
fn tls_inbound(tag: &str, tls: &InboundTls, env: &RuntimeEnv) -> Result<AnyInboundHandler> {
    #[cfg(feature = "inbound-tls")]
    {
        let handler = crate::transport::tls::inbound::StreamHandler::new(
            tls.certificate(tag, env)?,
            tls.key(tag, env)?,
            None,
            None,
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
fn ws_inbound(tag: &str, path: &str, env: &RuntimeEnv) -> Result<AnyInboundHandler> {
    #[cfg(feature = "inbound-ws")]
    return Ok(Arc::new(crate::adapter::inbound::Handler::new(
        format!("{}/ws", tag),
        Some(Arc::new(crate::transport::ws::inbound::StreamHandler::new(
            path.to_string(),
            env.options.ws.half_close,
        ))),
        None,
    )));
    #[cfg(not(feature = "inbound-ws"))]
    Err(not_compiled(tag, "inbound", "transport ws", "inbound-ws"))
}

#[allow(unused_variables)]
fn quic_inbound(tag: &str, tls: &InboundTls, env: &RuntimeEnv) -> Result<AnyInboundHandler> {
    #[cfg(feature = "inbound-quic")]
    {
        let handler = crate::transport::quic::inbound::DatagramHandler::new(
            tls.certificate(tag, env)?,
            tls.key(tag, env)?,
            tls.alpn.clone().map(Listable::into_vec).unwrap_or_default(),
            &env.options.quic,
        )?;
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
