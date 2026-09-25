use std::sync::Arc;

use anyhow::Result;

use crate::adapter::inbound::Handler;
use crate::adapter::registry::{InboundContext, InboundFactory, InboundRegistry};
use crate::adapter::AnyInboundHandler;
use serde_derive::Deserialize;

mod datagram;
mod stream;

pub use datagram::Handler as DatagramHandler;
pub use stream::Handler as StreamHandler;

use super::shadow;

pub(crate) fn register(registry: &mut InboundRegistry) {
    registry.register("shadowsocks", InboundFactory::standalone(build));
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ShadowsocksInboundOptions {
    method: String,
    password: String,
}

fn build(ctx: &InboundContext<'_>) -> Result<AnyInboundHandler> {
    let options: ShadowsocksInboundOptions = ctx.options()?;
    shadow::check_method("inbound", ctx.tag, &options.method)?;
    let stream = Arc::new(StreamHandler {
        cipher: options.method.clone(),
        password: options.password.clone(),
    });
    let datagram = Arc::new(DatagramHandler {
        cipher: options.method,
        password: options.password,
    });
    Ok(Arc::new(Handler::new(
        ctx.tag.to_owned(),
        Some(stream),
        Some(datagram),
    )))
}
