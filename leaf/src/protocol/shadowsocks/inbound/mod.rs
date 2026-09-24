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

use super::shadow;

pub(crate) fn register(registry: &mut InboundRegistry) {
    registry.register("shadowsocks", InboundFactory::standalone(build));
}

fn build(ctx: &InboundContext<'_>) -> Result<Option<AnyInboundHandler>> {
    let settings: config::ShadowsocksInboundSettings = ctx.settings()?;
    let stream = Arc::new(StreamHandler {
        cipher: settings.method.clone(),
        password: settings.password.clone(),
    });
    let datagram = Arc::new(DatagramHandler {
        cipher: settings.method.clone(),
        password: settings.password.clone(),
    });
    Ok(Some(Arc::new(Handler::new(
        ctx.tag.to_owned(),
        Some(stream),
        Some(datagram),
    ))))
}
