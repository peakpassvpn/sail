use std::sync::Arc;

use anyhow::{anyhow, Result};

use crate::adapter::inbound::Handler;
use crate::adapter::registry::{InboundContext, InboundFactory, InboundRegistry};
use crate::adapter::AnyInboundHandler;
use serde_derive::Deserialize;

mod datagram;
mod ss2022;
mod stream;

pub use datagram::Handler as DatagramHandler;
pub use stream::Handler as StreamHandler;

use super::shadow;
use super::sip022;

pub(crate) fn register(registry: &mut InboundRegistry) {
    registry.register("shadowsocks", InboundFactory::standalone(build));
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ShadowsocksInboundOptions {
    method: String,
    /// The PSK with a 2022 method; with `users`, the server's identity PSK.
    password: String,
    /// Shadowsocks 2022 users, told apart by identity headers.
    #[serde(default)]
    users: Option<Vec<ShadowsocksUser>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ShadowsocksUser {
    /// Who the user is to routing (`auth_user`), statistics and logs.
    #[serde(default)]
    name: Option<String>,
    /// The user's base64 PSK.
    password: String,
}

fn build(ctx: &InboundContext<'_>) -> Result<AnyInboundHandler> {
    let options: ShadowsocksInboundOptions = ctx.options()?;
    if sip022::is_2022(&options.method) {
        return build_2022(ctx.tag, options);
    }
    shadow::check_method("inbound", ctx.tag, &options.method)?;
    if options.users.is_some() {
        return Err(anyhow!(
            "[{}] inbound: users: only the 2022 methods have users",
            ctx.tag
        ));
    }
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

fn build_2022(tag: &str, options: ShadowsocksInboundOptions) -> Result<AnyInboundHandler> {
    let method = sip022::Method::from_name(&options.method)
        .map_err(|e| anyhow!("[{}] inbound: method: {}", tag, e))?;
    let psk = sip022::decode_psk(method, &options.password)
        .map_err(|e| anyhow!("[{}] inbound: password: {}", tag, e))?;
    let users = match options.users {
        None => None,
        Some(users) => {
            if !method.supports_eih() {
                return Err(anyhow!(
                    "[{}] inbound: users: {} has no identity headers, users need an AES method",
                    tag,
                    options.method
                ));
            }
            if users.is_empty() {
                return Err(anyhow!("[{}] inbound: users: empty", tag));
            }
            let users = users
                .into_iter()
                .enumerate()
                .map(|(i, u)| {
                    let psk = sip022::decode_psk(method, &u.password)
                        .map_err(|e| anyhow!("[{}] inbound: users[{}]: password: {}", tag, i, e))?;
                    Ok(sip022::User {
                        name: u.name.map(Into::into),
                        psk,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            Some(
                sip022::Users::new(users)
                    .map_err(|e| anyhow!("[{}] inbound: users: {}", tag, e))?,
            )
        }
    };
    let udp = sip022::udp::Server::new(method, psk.clone(), users.clone())?;
    let stream = Arc::new(ss2022::StreamHandler {
        config: Arc::new(sip022::stream::ServerConfig {
            method,
            psk,
            users,
            salts: sip022::SaltPool::new(),
        }),
    });
    let datagram = Arc::new(ss2022::DatagramHandler {
        server: Arc::new(udp),
    });
    Ok(Arc::new(Handler::new(
        tag.to_owned(),
        Some(stream),
        Some(datagram),
    )))
}
