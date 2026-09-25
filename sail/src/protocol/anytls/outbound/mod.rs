//! The AnyTLS outbound.
//!
//! Its sessions outlive the streams on them, so its blocks (dial fields,
//! `detour`, `tls`) make its connections rather than wrap its handler: the
//! client dials through the `Connector` they make when it needs a new
//! session. To everything else it is an outbound that dials by itself
//! (`OutboundConnect::Unknown`), like `multiplex`.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::BytesMut;
use serde_derive::Deserialize;

use crate::adapter::outbound::HandlerBuilder;
use crate::adapter::registry::{OutboundContext, OutboundFactory, OutboundRegistry};
use crate::adapter::*;
use crate::session::{Session, SocksAddrWireType};
use crate::transport::layers::Blocks;

mod client;
mod datagram;

use client::{Client, ClientOptions};

/// The shared blocks that make its connections.
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
    registry.register(
        "anytls",
        OutboundFactory::standalone(build)
            .with_blocks(CONNECTION_BLOCKS)
            .over_connector(),
    );
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
    let connector = ctx.connector()?;
    if !connector.tls() {
        return Err(anyhow!("[{}] outbound: tls: anytls needs it enabled", tag));
    }
    let options: AnyTlsOutboundOptions = ctx.options()?;
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

    let (client, cleanup) = Client::new(
        options.server,
        options.server_port,
        &options.password,
        connector,
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
