//! The AnyTLS outbound.
//!
//! Its sessions outlive the streams on them, so it cannot be one more
//! handler in a chain that dials anew for every stream, as the `tls` and
//! `detour` blocks would make it. It takes those blocks, and the dial
//! fields, itself, and layers them around a handler of its own that only
//! hands over the connection; the client dials through that when it needs
//! a new session. To everything else it is an outbound that dials by
//! itself (`OutboundConnect::Unknown`), like `multiplex`.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::BytesMut;
use serde_derive::Deserialize;

use crate::adapter::outbound::HandlerBuilder;
use crate::adapter::registry::{
    parse_options, Options, OutboundContext, OutboundFactory, OutboundRegistry,
};
use crate::adapter::*;
use crate::session::{Session, SocksAddrWireType};
use crate::transport::layers::{self, Blocks, OutboundBlocks, OutboundLayering};

mod client;
mod datagram;

use client::{Client, ClientOptions};

/// The shared blocks the outbound applies itself, around its connections
/// rather than around its streams.
const CONNECTION_BLOCKS: Blocks = Blocks {
    dial: true,
    detour: true,
    tls: true,
    ..Blocks::NONE
};

/// sing-box's defaults. The reference client takes anything of 5s or less
/// to mean these as well; here that is refused instead.
const DEFAULT_CHECK_INTERVAL: Duration = Duration::from_secs(30);
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const MIN_DURATION: Duration = Duration::from_secs(5);

pub(crate) fn register(registry: &mut OutboundRegistry) {
    // `composite`, for the `detour` it depends on; its blocks are taken
    // out of its options by `build`, not by the registry.
    registry.register("anytls", OutboundFactory::composite(dependencies, build));
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AnyTlsOutboundOptions {
    server: String,
    server_port: u16,
    password: String,
    #[serde(default, with = "crate::config::model::duration")]
    idle_session_check_interval: Option<Duration>,
    #[serde(default, with = "crate::config::model::duration")]
    idle_session_timeout: Option<Duration>,
    #[serde(default)]
    min_idle_session: usize,
}

fn dependencies(_tag: &str, options: &Options) -> Result<Vec<String>> {
    Ok(options
        .get("detour")
        .and_then(|d| d.as_str())
        .map(|d| vec![d.to_string()])
        .unwrap_or_default())
}

fn duration(
    tag: &str,
    field: &str,
    value: Option<Duration>,
    default: Duration,
) -> Result<Duration> {
    match value {
        None => Ok(default),
        Some(d) if d > MIN_DURATION => Ok(d),
        Some(_) => Err(anyhow!(
            "[{}] outbound: {}: must be longer than {}s",
            tag,
            field,
            MIN_DURATION.as_secs()
        )),
    }
}

fn build(ctx: &mut OutboundContext<'_>) -> Result<AnyOutboundHandler> {
    let tag = ctx.tag;
    let (protocol, blocks) = CONNECTION_BLOCKS.split(ctx.options);
    let blocks = OutboundBlocks::parse(tag, &blocks)?;
    if !blocks.tls.as_ref().is_some_and(|t| t.enabled) {
        return Err(anyhow!("[{}] outbound: tls: anytls needs it enabled", tag));
    }
    let options: AnyTlsOutboundOptions = parse_options("outbound", tag, &protocol)?;
    let client_options = ClientOptions {
        check_interval: duration(
            tag,
            "idle_session_check_interval",
            options.idle_session_check_interval,
            DEFAULT_CHECK_INTERVAL,
        )?,
        idle_timeout: duration(
            tag,
            "idle_session_timeout",
            options.idle_session_timeout,
            DEFAULT_IDLE_TIMEOUT,
        )?,
        min_idle: options.min_idle_session,
    };

    let dial = Arc::new(blocks.dial(tag)?.or(&ctx.dial));
    let detour = blocks
        .detour
        .as_ref()
        .map(|detour| ctx.handler(detour))
        .transpose()?;
    let handover = HandlerBuilder::default()
        .tag(tag.to_owned())
        .stream_handler(Arc::new(Handover {
            server: options.server.clone(),
            port: options.server_port,
        }))
        .build();
    let connector = layers::outbound(
        handover,
        &blocks,
        OutboundLayering {
            tag,
            options: &protocol,
            dns_client: ctx.dns_client,
            abort_handles: ctx.abort_handles,
            detour,
            dial,
            env: ctx.env,
        },
    )?;

    let (client, cleanup) = Client::new(
        options.server,
        options.server_port,
        &options.password,
        connector,
        ctx.dns_client.clone(),
        client_options,
    );
    ctx.abort_handles.push(cleanup);
    Ok(HandlerBuilder::default()
        .tag(tag.to_owned())
        .stream_handler(Arc::new(StreamHandler {
            client: client.clone(),
        }))
        .datagram_handler(Arc::new(datagram::Handler { client }))
        .build())
}

/// The innermost layer of a connection: asks for the server to be dialled,
/// and hands over what the layers around it made of that.
struct Handover {
    server: String,
    port: u16,
}

#[async_trait]
impl OutboundStreamHandler for Handover {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Proxy(crate::session::Network::Tcp, self.server.clone(), self.port)
    }

    async fn handle<'a>(
        &'a self,
        _sess: &'a Session,
        _lhs: Option<&mut AnyStream>,
        stream: Option<AnyStream>,
    ) -> std::io::Result<AnyStream> {
        stream.ok_or_else(|| std::io::Error::other("anytls: no connection to the server"))
    }
}

struct StreamHandler {
    client: Arc<Client>,
}

#[async_trait]
impl OutboundStreamHandler for StreamHandler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Unknown
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _lhs: Option<&mut AnyStream>,
        _stream: Option<AnyStream>,
    ) -> std::io::Result<AnyStream> {
        tracing::trace!("handling outbound stream");
        let mut first = BytesMut::new();
        sess.destination
            .write_buf(&mut first, SocksAddrWireType::PortLast);
        Ok(Box::new(self.client.open_stream(sess, &first).await?))
    }
}
