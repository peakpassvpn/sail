use std::sync::Arc;

use anyhow::Result;

use crate::adapter::inbound::Handler;
use crate::adapter::registry::{InboundContext, InboundFactory, InboundRegistry};
use crate::adapter::AnyInboundHandler;
use crate::config;

mod datagram;
mod stream;

pub use datagram::Handler as DatagramHandler;
pub use stream::Handler as StreamHandler;

pub(crate) fn register(registry: &mut InboundRegistry) {
    registry.register("socks", InboundFactory::standalone(build));
}

fn build(ctx: &InboundContext<'_>) -> Result<Option<AnyInboundHandler>> {
    let mut username = None;
    let mut password = None;
    if !ctx.settings.is_empty() {
        let settings: config::SocksInboundSettings = ctx.settings()?;
        username = if settings.username.is_empty() {
            None
        } else {
            Some(settings.username)
        };
        password = if settings.password.is_empty() {
            None
        } else {
            Some(settings.password)
        };
    }
    let stream = Arc::new(StreamHandler { username, password });
    let datagram = Arc::new(DatagramHandler);
    Ok(Some(Arc::new(Handler::new(
        ctx.tag.to_owned(),
        Some(stream),
        Some(datagram),
    ))))
}
