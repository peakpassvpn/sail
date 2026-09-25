//! The AnyTLS inbound.
//!
//! One TLS connection is one session, and every stream on it is a
//! connection of its own to route, so the handler hands back the session as
//! `InboundTransport::Incoming`, as `multiplex` does.
//!
//! An unauthenticated connection is closed, as `sing-anytls` does when it
//! has no fallback.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use serde_derive::Deserialize;
use sha2::{Digest, Sha256};

use crate::adapter::inbound::Handler;
use crate::adapter::registry::{parse_options, InboundContext, InboundFactory, InboundRegistry};
use crate::adapter::AnyInboundHandler;
use crate::transport::layers::{self, Blocks, InboundBlocks, Listable};

use super::padding::PaddingScheme;

mod datagram;
mod stream;

pub use stream::Handler as StreamHandler;

/// The shared block the inbound applies itself, so that it can insist on
/// it: AnyTLS is meant to look like TLS.
const CONNECTION_BLOCKS: Blocks = Blocks {
    tls: true,
    ..Blocks::NONE
};

pub(crate) fn register(registry: &mut InboundRegistry) {
    registry.register("anytls", InboundFactory::standalone(build));
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AnyTlsInboundOptions {
    users: Vec<AnyTlsUser>,
    /// The padding scheme, as lines. Unset, the default.
    #[serde(default)]
    padding_scheme: Option<Listable>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AnyTlsUser {
    /// Who the user is to routing (`auth_user`), statistics and logs.
    #[serde(default)]
    name: Option<String>,
    password: String,
}

fn build(ctx: &InboundContext<'_>) -> Result<AnyInboundHandler> {
    let tag = ctx.tag;
    let (protocol, blocks) = CONNECTION_BLOCKS.split(ctx.options);
    let blocks = InboundBlocks::parse(tag, &blocks)?;
    if !blocks.tls.as_ref().is_some_and(|t| t.enabled) {
        return Err(anyhow!("[{}] inbound: tls: anytls needs it enabled", tag));
    }
    let options: AnyTlsInboundOptions = parse_options("inbound", tag, &protocol)?;
    if options.users.is_empty() {
        return Err(anyhow!("[{}] inbound: users: needs at least one", tag));
    }
    let padding = match options.padding_scheme {
        Some(scheme) => PaddingScheme::parse_strict(&scheme.joined())
            .map_err(|e| anyhow!("[{}] inbound: padding_scheme: {}", tag, e))?,
        None => PaddingScheme::default_scheme(),
    };
    let mut users = HashMap::new();
    for user in options.users {
        let hash: [u8; 32] = Sha256::digest(user.password.as_bytes()).into();
        if users.insert(hash, user.name.map(Into::into)).is_some() {
            return Err(anyhow!(
                "[{}] inbound: users: a password is used more than once",
                tag
            ));
        }
    }
    let stream = Arc::new(StreamHandler::new(
        users,
        Arc::new(padding),
        ctx.env.options.inbound.handshake_timeout,
    ));
    let core: AnyInboundHandler = Arc::new(Handler::new(tag.to_owned(), Some(stream), None));
    layers::inbound(tag, core, &blocks, ctx.env)
}
