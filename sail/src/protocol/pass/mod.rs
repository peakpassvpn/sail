//! `pass`, a sail extension, as Mihomo's PASS: an outbound that is never
//! dialled on purpose. A rule that routes to it, or to a group whose pick
//! it is at the time, is skipped, and the next rules decide; when `final`
//! comes to it through a group, the connection goes direct. A connection
//! that reaches it all the same, a selector switched to it between routing
//! and dialling, fails.

use std::io;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use serde_derive::Deserialize;

use crate::adapter::outbound::HandlerBuilder;
use crate::adapter::registry::{OutboundContext, OutboundFactory, OutboundRegistry};
use crate::adapter::*;
use crate::session::Session;

pub(crate) fn register(registry: &mut OutboundRegistry) {
    registry.register("pass", OutboundFactory::standalone(build));
}

/// A pass outbound has nothing to configure but its tag.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PassOptions {}

fn build(ctx: &mut OutboundContext<'_>) -> Result<AnyOutboundHandler> {
    let PassOptions {} = ctx.options()?;
    Ok(HandlerBuilder::default()
        .tag(ctx.tag.to_owned())
        .stream_handler(Arc::new(Handler))
        .datagram_handler(Arc::new(Handler))
        .is_pass(true)
        .build())
}

/// Why a connection dialled through a pass outbound fails.
fn passed() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionRefused, "routed to PASS")
}

struct Handler;

#[async_trait]
impl OutboundStreamHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Unknown
    }

    async fn handle<'a>(
        &'a self,
        _sess: &'a Session,
        _lhs: Option<&mut AnyStream>,
        _stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        Err(passed())
    }
}

#[async_trait]
impl OutboundDatagramHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Unknown
    }

    fn transport_type(&self) -> DatagramTransportType {
        DatagramTransportType::Unknown
    }

    async fn handle<'a>(
        &'a self,
        _sess: &'a Session,
        _transport: Option<AnyOutboundTransport>,
    ) -> io::Result<AnyOutboundDatagram> {
        Err(passed())
    }
}
