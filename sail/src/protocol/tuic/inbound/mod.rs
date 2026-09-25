use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use serde_derive::Deserialize;

use crate::adapter::inbound::Handler;
use crate::adapter::registry::{InboundContext, InboundFactory, InboundRegistry};
use crate::adapter::AnyInboundHandler;
use crate::runtime::RuntimeEnv;
use crate::transport::layers::{InboundTls, Listable};

use super::common::{parse_uuid, CongestionControl, DEFAULT_HEARTBEAT};

mod server;

pub use server::{Server, User};

pub(crate) fn register(registry: &mut InboundRegistry) {
    // TUIC owns its QUIC connection, `tls` included, so it takes no
    // shared blocks.
    registry.register("tuic", InboundFactory::standalone(build));
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TuicInboundOptions {
    users: Vec<TuicUser>,
    #[serde(default)]
    congestion_control: CongestionControl,
    /// How long a connection may go without authenticating. 3s, as in
    /// sing-box, when not set.
    #[serde(default, with = "crate::config::model::duration")]
    auth_timeout: Option<Duration>,
    #[serde(default)]
    zero_rtt_handshake: bool,
    #[serde(default, with = "crate::config::model::duration")]
    heartbeat: Option<Duration>,
    tls: InboundTls,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TuicUser {
    /// Who the user is to routing (`auth_user`), statistics and logs.
    #[serde(default)]
    name: Option<String>,
    uuid: String,
    #[serde(default)]
    password: String,
}

const DEFAULT_AUTH_TIMEOUT: Duration = Duration::from_secs(3);

fn build(ctx: &InboundContext<'_>) -> Result<AnyInboundHandler> {
    let tag = ctx.tag;
    let options: TuicInboundOptions = ctx.options()?;
    if options.users.is_empty() {
        return Err(anyhow!("[{}] inbound: users: needs at least one user", tag));
    }
    let mut users = HashMap::new();
    for (i, user) in options.users.into_iter().enumerate() {
        let field = format!("users[{}].uuid", i);
        let uuid = parse_uuid("inbound", tag, &field, &user.uuid)?;
        let user = User {
            password: user.password.into_bytes(),
            name: user.name.map(Into::into),
        };
        if users.insert(uuid, user).is_some() {
            return Err(anyhow!(
                "[{}] inbound: {}: UUID used by more than one user",
                tag,
                field
            ));
        }
    }
    if !options.tls.enabled {
        return Err(anyhow!("[{}] inbound: tls: TUIC needs TLS enabled", tag));
    }
    let tls = &options.tls;
    let server = Server::new(
        users,
        certificate(tag, tls, ctx.env)?,
        key(tag, tls, ctx.env)?,
        tls.alpn.clone().map(Listable::into_vec),
        options.congestion_control,
        options.auth_timeout.unwrap_or(DEFAULT_AUTH_TIMEOUT),
        options.zero_rtt_handshake,
        options.heartbeat.unwrap_or(DEFAULT_HEARTBEAT),
        &ctx.env.options.quic,
    )
    .map_err(|e| anyhow!("[{}] inbound: tls: {}", tag, e))?;
    Ok(Arc::new(Handler::new(
        tag.to_owned(),
        None,
        Some(Arc::new(server)),
    )))
}

// As `InboundTls` reads them for the `tls` block, which keeps its readers
// to itself.

fn certificate(tag: &str, tls: &InboundTls, env: &RuntimeEnv) -> Result<String> {
    match (&tls.certificate, &tls.certificate_path) {
        (Some(inline), None) => Ok(inline.clone().joined()),
        (None, Some(path)) => Ok(env.data_path(path)),
        _ => Err(anyhow!(
            "[{}] inbound: tls: set exactly one of certificate and certificate_path",
            tag
        )),
    }
}

fn key(tag: &str, tls: &InboundTls, env: &RuntimeEnv) -> Result<String> {
    match (&tls.key, &tls.key_path) {
        (Some(inline), None) => Ok(inline.clone().joined()),
        (None, Some(path)) => Ok(env.data_path(path)),
        _ => Err(anyhow!(
            "[{}] inbound: tls: set exactly one of key and key_path",
            tag
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(json: &str) -> Result<TuicInboundOptions> {
        Ok(serde_json::from_str(json)?)
    }

    #[test]
    fn options_are_sing_boxs() {
        let o = parse(
            r#"{
                "users": [{"name": "a", "uuid": "b8f7a0c2-3f5e-4b0a-9c7d-1e2f3a4b5c6d", "password": "p"}],
                "congestion_control": "bbr",
                "auth_timeout": "5s",
                "zero_rtt_handshake": true,
                "heartbeat": "10s",
                "tls": {"enabled": true, "certificate_path": "c", "key_path": "k", "alpn": "h3"}
            }"#,
        )
        .unwrap();
        assert_eq!(o.congestion_control, CongestionControl::Bbr);
        assert_eq!(o.auth_timeout, Some(Duration::from_secs(5)));
        assert!(parse(r#"{"users": [], "tls": {}, "udp_relay_mode": "quic"}"#).is_err());
        assert!(parse(r#"{"users": [{"uuid": "x", "passwd": "p"}], "tls": {}}"#).is_err());
    }
}
