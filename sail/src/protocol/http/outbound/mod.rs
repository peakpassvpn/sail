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
    /// May be left out, with `server_port`, by an outbound with a
    /// `detour`: one over ShadowTLS, which dials its own server.
    #[serde(default)]
    server: Option<String>,
    #[serde(default)]
    server_port: Option<u16>,
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
    /// The HTTP version sing-box 1.15 asks for, 1, 2 or 3; unset (or 0),
    /// 2, or 1 with a `path` or a `Host` header. sail proxies over
    /// HTTP/1.1 whichever, as sing-box does with a server that speaks no
    /// other; the configuration's warnings say so.
    #[serde(default)]
    version: Option<u8>,
    /// `version` alone, never HTTP/1.1 in its place: warned of with 2 or
    /// 3, as `version` is. Read only so that it is taken: sail's own use
    /// of it is the warning (`Config::http_outbound_warnings`).
    #[serde(default)]
    #[allow(dead_code)]
    disable_version_fallback: bool,
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
    let (server, server_port) = ctx.server(options.server.clone(), options.server_port)?;
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

    crate::config::model::check_http_version(options.version)
        .map_err(|e| anyhow!("[{}] outbound: {}", tag, e))?;
    // As sing-box, which carries the path and the Host header over
    // HTTP/1.1 alone.
    let has_host = options
        .headers
        .keys()
        .any(|name| name.eq_ignore_ascii_case("host"));
    let has_path = options.path.as_deref().is_some_and(|p| !p.is_empty());
    if options.version.is_some_and(|v| v >= 2) && (has_path || has_host) {
        return Err(anyhow!(
            "[{}] outbound: version: {}: a path and a Host header go over HTTP/1.1 alone",
            tag,
            options.version.unwrap_or_default()
        ));
    }

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
        address: server,
        port: server_port,
        dialer: ctx.dialer.clone(),
        authorization,
        path,
        headers,
    });
    Ok(HandlerBuilder::default()
        .tag(ctx.tag.to_owned())
        .stream_handler(stream)
        .build())
}

#[cfg(test)]
mod tests {
    /// sing-box 1.15's `version` and `disable_version_fallback`: read,
    /// over HTTP/1.1 whichever, warned of where they ask for another.
    #[test]
    fn version_is_read_and_another_than_1_warned_of() {
        let check = |fields: serde_json::Value| {
            let mut json = serde_json::json!({ "outbounds": [{ "type": "http", "tag": "h",
                "server": "192.0.2.1", "server_port": 8080 }] });
            let outbound = json["outbounds"][0].as_object_mut().unwrap();
            outbound.extend(fields.as_object().unwrap().clone());
            crate::config::from_string(&json.to_string())
                .and_then(|c| {
                    crate::check_config(&c, &Default::default())?;
                    Ok(c.warnings)
                })
                .map_err(|e| format!("{:#}", e))
        };
        let none: Vec<String> = Vec::new();
        let version = |v: u8| {
            vec![format!(
                "outbounds[0].version: sail proxies over HTTP/1.1, not HTTP/{}; ignored",
                v
            )]
        };
        let fallback = |v: u8| {
            vec![format!(
                "outbounds[0].disable_version_fallback: sail proxies over HTTP/1.1, not \
                 HTTP/{}; ignored",
                v
            )]
        };
        use serde_json::json;
        assert_eq!(check(json!({})), Ok(none.clone()));
        assert_eq!(check(json!({ "version": 0 })), Ok(none.clone()));
        assert_eq!(check(json!({ "version": 1 })), Ok(none.clone()));
        assert_eq!(check(json!({ "version": 2 })), Ok(version(2)));
        assert_eq!(check(json!({ "version": 3 })), Ok(version(3)));
        let alone =
            |v: serde_json::Value| check(json!({ "version": v, "disable_version_fallback": true }));
        assert_eq!(alone(json!(1)), Ok(none.clone()));
        assert_eq!(alone(json!(2)), Ok(fallback(2)));
        assert_eq!(alone(json!(3)), Ok(fallback(3)));
        // Unset, HTTP/2; HTTP/1.1 with a path or a Host header.
        assert_eq!(alone(json!(0)), Ok(fallback(2)));
        assert_eq!(
            check(json!({ "path": "/p", "disable_version_fallback": true })),
            Ok(none.clone())
        );
        assert_eq!(
            check(json!({ "headers": { "host": "a" }, "disable_version_fallback": true })),
            Ok(none)
        );
        // As sing-box refuses them.
        assert_eq!(
            check(json!({ "version": 4 })),
            Err("[h] outbound: version: 4 is none of 1, 2 and 3".into())
        );
        assert_eq!(
            check(json!({ "version": 2, "path": "/p" })),
            Err("[h] outbound: version: 2: a path and a Host header go over HTTP/1.1 alone".into())
        );
        assert_eq!(
            check(json!({ "version": 3, "headers": { "Host": "a" } })),
            Err("[h] outbound: version: 3: a path and a Host header go over HTTP/1.1 alone".into())
        );
    }
}
