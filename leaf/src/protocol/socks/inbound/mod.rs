use std::sync::Arc;

use anyhow::{anyhow, Result};

use crate::adapter::inbound::Handler;
use crate::adapter::registry::{InboundContext, InboundFactory, InboundRegistry};
use crate::adapter::AnyInboundHandler;
use serde_derive::Deserialize;

mod datagram;
mod stream;

pub use datagram::Handler as DatagramHandler;
pub use stream::Handler as StreamHandler;

pub(crate) fn register(registry: &mut InboundRegistry) {
    registry.register("socks", InboundFactory::standalone(build));
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SocksInboundOptions {
    /// Clients must authenticate as one of these; anyone may connect when
    /// there are none.
    #[serde(default)]
    users: Vec<SocksUser>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SocksUser {
    username: String,
    password: String,
}

fn build(ctx: &InboundContext<'_>) -> Result<AnyInboundHandler> {
    let options: SocksInboundOptions = ctx.options()?;
    if options.users.len() > 1 {
        return Err(anyhow!(
            "[{}] inbound: users: more than one user is not supported yet",
            ctx.tag
        ));
    }
    let (username, password) = match options.users.into_iter().next() {
        Some(user) => (Some(user.username), Some(user.password)),
        None => (None, None),
    };
    let stream = Arc::new(StreamHandler { username, password });
    let datagram = Arc::new(DatagramHandler);
    Ok(Arc::new(Handler::new(
        ctx.tag.to_owned(),
        Some(stream),
        Some(datagram),
    )))
}
