use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use base64::prelude::*;
use serde_derive::Deserialize;

use crate::adapter::outbound::HandlerBuilder;
use crate::adapter::registry::{OutboundContext, OutboundFactory, OutboundRegistry};
use crate::adapter::AnyOutboundHandler;
use crate::transport::layers::{Blocks, Listable};

pub mod stream;

pub use stream::Handler as StreamHandler;

/// An HTTP proxy, over `CONNECT`; an HTTPS one with the `tls` block.
///
/// TCP only: HTTP proxies do not carry UDP, so the outbound has no datagram
/// handler. A UDP session routed to it fails with "no udp handler", and
/// groups and chains see it as TCP-only.
pub(crate) fn register(registry: &mut OutboundRegistry) {
    registry.register(
        "http",
        OutboundFactory::standalone(build).with_blocks(Blocks {
            dial: true,
            detour: true,
            tls: true,
            ..Blocks::NONE
        }),
    );
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpOutboundOptions {
    server: String,
    server_port: u16,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
    /// The request target instead of the destination, which then goes only
    /// in `Host`, as sing-box sends it.
    #[serde(default)]
    path: Option<String>,
    /// Sent with every `CONNECT`.
    #[serde(default)]
    headers: BTreeMap<String, Listable>,
}

/// Whether `name` is an HTTP header name (RFC 9110 token).
fn is_token(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

fn build(ctx: &mut OutboundContext<'_>) -> Result<AnyOutboundHandler> {
    let options: HttpOutboundOptions = ctx.options()?;
    let tag = ctx.tag;

    let authorization = match (options.username, options.password) {
        (Some(username), password) if !username.is_empty() => {
            // Basic credentials split at the first colon.
            if username.contains(':') {
                return Err(anyhow!(
                    "[{}] outbound: username: contains a colon, which Basic authentication cannot carry",
                    tag
                ));
            }
            let credentials = format!("{}:{}", username, password.unwrap_or_default());
            Some(format!("Basic {}", BASE64_STANDARD.encode(credentials)))
        }
        (_, Some(_)) => {
            return Err(anyhow!(
                "[{}] outbound: password: set without a username",
                tag
            ))
        }
        _ => None,
    };

    let path = match options.path {
        Some(path) if !path.starts_with('/') || path.contains(char::is_whitespace) => {
            return Err(anyhow!(
                "[{}] outbound: path: \"{}\" must start with / and hold no whitespace",
                tag,
                path
            ))
        }
        path => path,
    };

    let mut headers = Vec::new();
    for (name, values) in options.headers {
        if !is_token(&name) {
            return Err(anyhow!(
                "[{}] outbound: headers: \"{}\" is not a header name",
                tag,
                name
            ));
        }
        for value in values.into_vec() {
            // A line break would end the head, or start a header of its own.
            if value.contains(['\r', '\n']) {
                return Err(anyhow!(
                    "[{}] outbound: headers: {}: value holds a line break",
                    tag,
                    name
                ));
            }
            headers.push((name.clone(), value));
        }
    }

    let stream = Arc::new(StreamHandler {
        address: options.server,
        port: options.server_port,
        authorization,
        path,
        headers,
    });
    Ok(HandlerBuilder::default()
        .tag(ctx.tag.to_owned())
        .stream_handler(stream)
        .build())
}
