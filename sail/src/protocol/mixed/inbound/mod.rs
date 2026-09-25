//! HTTP and SOCKS4a/5 on one port, as sing-box's `mixed` inbound.
//!
//! The first byte tells them apart: a SOCKS request starts with its version,
//! 4 or 5, which no HTTP method does. UDP is SOCKS5's `UDP ASSOCIATE`, served
//! on the same port as the socks inbound serves it.
//!
//! sing-box's `set_system_proxy` is not taken: sail does not change the
//! host's proxy settings, and the field is an unknown one.

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use serde_derive::Deserialize;
use tokio::io::AsyncReadExt;

use crate::adapter::inbound::Handler;
use crate::adapter::registry::{InboundContext, InboundFactory, InboundRegistry};
use crate::adapter::*;
use crate::protocol::{http, socks};
use crate::session::Session;

pub(crate) fn register(registry: &mut InboundRegistry) {
    registry.register("mixed", InboundFactory::standalone(build));
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MixedInboundOptions {
    /// Clients must authenticate as one of these, by SOCKS5
    /// username/password or HTTP Basic; anyone may connect when there are
    /// none.
    #[serde(default)]
    users: Vec<MixedUser>,
}

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct MixedUser {
    username: String,
    password: String,
}

fn build(ctx: &InboundContext<'_>) -> Result<AnyInboundHandler> {
    let options: MixedInboundOptions = ctx.options()?;
    // Both protocols' rules apply, as either may carry the credentials.
    let http_users = http::inbound::users_by_name(
        ctx.tag,
        options
            .users
            .iter()
            .cloned()
            .map(|u| http::inbound::HttpUser {
                username: u.username,
                password: u.password,
            })
            .collect(),
    )?;
    let socks_users = socks::inbound::users_by_name(
        ctx.tag,
        options
            .users
            .into_iter()
            .map(|u| socks::inbound::SocksUser {
                username: u.username,
                password: u.password,
            })
            .collect(),
    )?;
    let stream = Arc::new(StreamHandler {
        http: http::inbound::StreamHandler::new(http_users),
        socks: socks::inbound::StreamHandler::new(socks_users),
    });
    let datagram = Arc::new(socks::inbound::DatagramHandler);
    Ok(Arc::new(Handler::new(
        ctx.tag.to_owned(),
        Some(stream),
        Some(datagram),
    )))
}

pub struct StreamHandler {
    http: http::inbound::StreamHandler,
    socks: socks::inbound::StreamHandler,
}

#[async_trait]
impl InboundStreamHandler for StreamHandler {
    async fn handle<'a>(
        &'a self,
        sess: Session,
        mut stream: AnyStream,
    ) -> std::io::Result<AnyInboundTransport> {
        tracing::trace!("handling inbound stream");
        let first = stream.read_u8().await?;
        match first {
            0x04 | 0x05 => self.socks.handle_version(sess, stream, first).await,
            _ => {
                self.http
                    .handle_with_prefix(sess, stream, vec![first])
                    .await
            }
        }
    }
}
