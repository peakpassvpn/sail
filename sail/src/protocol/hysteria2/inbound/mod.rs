//! The Hysteria2 inbound: an HTTP/3 server on the inbound's UDP socket
//! that turns authenticated connections into proxy connections.
//!
//! The inbound binds UDP only: it registers a datagram handler, which the
//! network listener hands the socket, and yields the streams and UDP
//! sessions it accepts as they come.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use serde_derive::Deserialize;

use crate::adapter::inbound::Handler;
use crate::adapter::registry::{InboundContext, InboundFactory, InboundRegistry};
use crate::adapter::AnyInboundHandler;
use crate::transport::{self, layers::InboundTls};

use super::proto::MBPS_TO_BPS;
use super::quic;
use super::Obfs;

mod masquerade;
mod server;

use masquerade::{Masquerade, MasqueradeOptions};
use server::{DatagramHandler, Server};

pub(crate) fn register(registry: &mut InboundRegistry) {
    registry.register("hysteria2", InboundFactory::standalone(build));
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Hysteria2InboundOptions {
    /// What the server may send at, at most, to each client.
    #[serde(default)]
    up_mbps: Option<u64>,
    /// What the server can receive at, told to clients.
    #[serde(default)]
    down_mbps: Option<u64>,
    #[serde(default)]
    obfs: Option<Obfs>,
    users: Vec<User>,
    /// Ignores the rate clients say they receive at, and has them find
    /// their own: BBR both ways.
    #[serde(default)]
    ignore_client_bandwidth: bool,
    tls: InboundTls,
    /// What anyone without a password is served.
    #[serde(default)]
    masquerade: Option<MasqueradeOptions>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct User {
    /// Who the user is to routing (`auth_user`), statistics and logs.
    #[serde(default)]
    name: Option<String>,
    password: String,
}

fn build(ctx: &InboundContext<'_>) -> Result<AnyInboundHandler> {
    let options: Hysteria2InboundOptions = ctx.options()?;
    let tag = ctx.tag;
    let err = |msg: String| anyhow!("[{}] inbound: {}", tag, msg);

    let mut users = HashMap::new();
    for user in options.users {
        if user.password.is_empty() {
            return Err(err("users: a password is empty".into()));
        }
        if users
            .insert(user.password, user.name.map(Arc::<str>::from))
            .is_some()
        {
            return Err(err("users: two users share a password".into()));
        }
    }
    if users.is_empty() {
        return Err(err("users: none".into()));
    }

    let tls = options.tls;
    if !tls.enabled {
        return Err(err("tls: hysteria2 needs tls enabled".into()));
    }
    let crypto = transport::quic::inbound_crypto(
        tag,
        &tls,
        ctx.env,
        &transport::quic::alpn_protocols(tls.alpn.as_ref(), quic::DEFAULT_ALPN),
    )?;
    let server_config =
        transport::quic::server_config(crypto).map_err(|e| err(format!("tls: {}", e)))?;

    let obfs = options
        .obfs
        .map(|o| o.salamander())
        .transpose()
        .map_err(|e| err(format!("obfs: {}", e)))?;
    let masquerade = match options.masquerade {
        Some(m) => Masquerade::new(m).map_err(|e| err(format!("masquerade: {}", e)))?,
        None => Masquerade::NotFound,
    };

    let server = Arc::new(Server {
        users,
        send_bps: options.up_mbps.unwrap_or(0) * MBPS_TO_BPS,
        recv_bps: options.down_mbps.unwrap_or(0) * MBPS_TO_BPS,
        ignore_client_bandwidth: options.ignore_client_bandwidth,
        masquerade,
        handshake_timeout: ctx.env.options.inbound.handshake_timeout,
        tuning: ctx.env.options.quic.clone(),
    });
    Ok(Arc::new(Handler::new(
        tag.to_owned(),
        None,
        Some(Arc::new(DatagramHandler::new(server_config, obfs, server))),
    )))
}
