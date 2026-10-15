use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use base64::prelude::*;
use serde_derive::Deserialize;

use crate::adapter::outbound::HandlerBuilder;
use crate::adapter::registry::{OutboundContext, OutboundFactory, OutboundRegistry};
use crate::adapter::AnyOutboundHandler;
use crate::config::model::HttpVersion;
use crate::transport::layers::{Blocks, Listable};

mod h2;
pub mod stream;

pub use stream::Handler as StreamHandler;

/// The ALPN of HTTP/1.1 alone, and of HTTP/2 with HTTP/1.1 to fall back to,
/// as sing-box offers them.
const HTTP1_ALPN: &[&str] = &["http/1.1"];
const H2_ALPN: &[&str] = &["h2", "http/1.1"];

/// An HTTP proxy, over `CONNECT`; an HTTPS one with the `tls` block.
///
/// With sing-box 1.15's `version` 2 (or 3) over TLS it speaks HTTP/2, its
/// tunnels CONNECT requests on the connections it keeps (`h2`); HTTP/1.1,
/// one connection a tunnel, otherwise, and where the server picks no `h2`
/// in ALPN.
///
/// TCP only: HTTP proxies do not carry UDP, so the outbound has no datagram
/// handler. A UDP session routed to it fails with "no udp handler", and
/// groups and chains see it as TCP-only.
pub(crate) fn register(registry: &mut OutboundRegistry) {
    registry.register(
        "http",
        OutboundFactory::standalone(build)
            .with_blocks(Blocks {
                dial: true,
                detour: true,
                tls: true,
                ..Blocks::NONE
            })
            // What it speaks, offered alone: a browser fingerprint would
            // offer h2 to an HTTP/1.1 client.
            .with_alpn(|options| match HttpVersion::of(options).resolved {
                1 => HTTP1_ALPN,
                _ => H2_ALPN,
            })
            // Over TLS, HTTP/2 on connections of its own; REALITY tells no
            // ALPN to tell HTTP/2 by, and gets HTTP/1.1.
            .over_connector_when(|options, blocks| {
                blocks.has_tls() && !blocks.has_reality() && HttpVersion::of(options).resolved >= 2
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
    /// The HTTP version, sing-box 1.15's: 1, 2 or 3; unset (or 0), 1, as
    /// sing-box 1.14 speaks, until sail follows 1.15 stable. HTTP/2 needs
    /// TLS, and not REALITY's: without, HTTP/1.1. 3 is HTTP/2, which sail
    /// speaks in its place.
    #[serde(default)]
    version: Option<u8>,
    /// HTTP/2 alone, never HTTP/1.1 in its place: a server that picks no
    /// `h2` is an error.
    #[serde(default)]
    disable_version_fallback: bool,
    /// HTTP/2's, sing-box 1.15's: how long a ping may go unanswered.
    #[serde(default, with = "crate::config::model::duration")]
    idle_timeout: Option<Duration>,
    /// HTTP/2's: a ping after this long with nothing received.
    #[serde(default, with = "crate::config::model::duration")]
    keep_alive_period: Option<Duration>,
    /// HTTP/2's: a tunnel's receive window.
    #[serde(
        default,
        deserialize_with = "crate::config::model::memory_bytes::deserialize"
    )]
    stream_receive_window: Option<u64>,
    /// HTTP/2's: a connection's receive window.
    #[serde(
        default,
        deserialize_with = "crate::config::model::memory_bytes::deserialize"
    )]
    connection_receive_window: Option<u64>,
    /// HTTP/2's: the most tunnels one connection carries.
    #[serde(default)]
    max_concurrent_streams: Option<u32>,
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
    let version = HttpVersion::of(ctx.options);
    let tls = ctx.has_tls();
    let fields = crate::protocol::http::h2::Fields {
        idle_timeout: options.idle_timeout,
        keep_alive_period: options.keep_alive_period,
        stream_receive_window: options.stream_receive_window,
        connection_receive_window: options.connection_receive_window,
        max_concurrent_streams: options.max_concurrent_streams,
    };
    // As sing-box, which takes them with HTTP/2 (and 3) alone: with
    // `version` 1 they are no field of its.
    if let Some(field) = fields.first_set().filter(|_| version.asked == Some(1)) {
        return Err(anyhow!(
            "[{}] outbound: {}: HTTP/2's, not with HTTP/1.1",
            tag,
            field
        ));
    }
    if version.resolved == 3 && !tls {
        return Err(anyhow!("[{}] outbound: version: 3 requires TLS", tag));
    }
    if version.resolved == 2 && !tls && options.disable_version_fallback {
        return Err(anyhow!("[{}] outbound: HTTP/2 requires TLS", tag));
    }
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

    let http1 = StreamHandler {
        address: server,
        port: server_port,
        dialer: ctx.dialer.clone(),
        authorization,
        path,
        headers,
    };
    if version.resolved >= 2 && tls && !ctx.has_reality() {
        let at = format!("[{}] outbound", tag);
        let settings =
            crate::protocol::http::h2::Settings::new(&at, &fields, ctx.env.options.profile)?;
        let connector = ctx.tls_connector(HTTP1_ALPN[0])?;
        let handler = h2::Handler::new(
            &at,
            http1,
            connector,
            settings,
            !options.disable_version_fallback,
            (&ctx.env.options).into(),
            ctx.env.options.profile.carrier_idle_timeout(),
        )?;
        return Ok(HandlerBuilder::default()
            .tag(ctx.tag.to_owned())
            .stream_handler(Arc::new(handler))
            .build());
    }
    Ok(HandlerBuilder::default()
        .tag(ctx.tag.to_owned())
        .stream_handler(Arc::new(http1))
        .build())
}

#[cfg(test)]
mod tests {
    /// sing-box 1.15's `version` and `disable_version_fallback`, checked as
    /// sing-box checks them, and warned of where sail does otherwise:
    /// HTTP/2 asked for without TLS, and HTTP/3, for which sail speaks
    /// HTTP/2.
    #[test]
    fn version_is_checked_as_sing_box_checks_it() {
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
        let warned = |w: &str| vec![format!("outbounds[0].{}", w)];
        use serde_json::json;
        let tls = json!({ "enabled": true, "server_name": "proxy.example" });
        // Without TLS: HTTP/1.1, said only where HTTP/2 was asked for.
        assert_eq!(check(json!({})), Ok(none.clone()));
        assert_eq!(check(json!({ "version": 0 })), Ok(none.clone()));
        assert_eq!(check(json!({ "version": 1 })), Ok(none.clone()));
        assert_eq!(
            check(json!({ "version": 2 })),
            Ok(warned("version: HTTP/2 needs TLS; HTTP/1.1, as sing-box"))
        );
        let alone =
            |v: serde_json::Value| check(json!({ "version": v, "disable_version_fallback": true }));
        assert_eq!(alone(json!(1)), Ok(none.clone()));
        // Unset, HTTP/1.1 (sing-box 1.14's) whatever the fallback.
        assert_eq!(alone(json!(0)), Ok(none.clone()));
        assert_eq!(
            alone(json!(2)),
            Err("[h] outbound: HTTP/2 requires TLS".into()),
            "HTTP/2 alone needs TLS, as in sing-box"
        );
        assert_eq!(
            check(json!({ "version": 3 })),
            Err("[h] outbound: version: 3 requires TLS".into())
        );
        // HTTP/1.1 with a path or a Host header.
        assert_eq!(
            check(json!({ "path": "/p", "disable_version_fallback": true })),
            Ok(none.clone())
        );
        assert_eq!(
            check(json!({ "headers": { "host": "a" }, "disable_version_fallback": true })),
            Ok(none.clone())
        );
        // With TLS: HTTP/1.1 unset, HTTP/2 asked for, which HTTP/3 is too.
        assert_eq!(check(json!({ "tls": tls })), Ok(none.clone()));
        assert_eq!(check(json!({ "version": 2, "tls": tls })), Ok(none.clone()));
        assert_eq!(
            check(json!({ "version": 2, "tls": tls, "disable_version_fallback": true })),
            Ok(none.clone())
        );
        let http3 = "version: sail speaks HTTP/2 and HTTP/1.1, not HTTP/3; HTTP/2 used";
        assert_eq!(
            check(json!({ "version": 3, "tls": tls })),
            Ok(warned(http3))
        );
        assert_eq!(
            check(json!({ "version": 3, "tls": tls, "disable_version_fallback": true })),
            Ok([
                warned(http3),
                warned("disable_version_fallback: HTTP/2 alone, as sail speaks no HTTP/3")
            ]
            .concat())
        );
        // REALITY tells no ALPN: HTTP/1.1.
        let reality = json!({ "enabled": true, "server_name": "www.example.com",
            "reality": { "enabled": true,
                "public_key": "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0", "short_id": "" } });
        assert_eq!(
            check(json!({ "version": 2, "tls": reality })),
            Ok(warned(
                "tls.reality: HTTP/2 needs the server's ALPN, which REALITY does not tell; \
                 HTTP/1.1"
            ))
        );
        assert_eq!(check(json!({ "tls": reality })), Ok(none.clone()));
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
            check(json!({ "version": 3, "tls": tls, "headers": { "Host": "a" } })),
            Err("[h] outbound: version: 3: a path and a Host header go over HTTP/1.1 alone".into())
        );
        // HTTP/2's fields are HTTP/2's, as sing-box takes them.
        assert_eq!(
            check(json!({ "version": 1, "idle_timeout": "30s" })),
            Err("[h] outbound: idle_timeout: HTTP/2's, not with HTTP/1.1".into())
        );
        assert_eq!(check(json!({ "idle_timeout": "30s" })), Ok(none.clone()));
        assert_eq!(
            check(
                json!({ "version": 2, "tls": tls, "idle_timeout": "30s", "keep_alive_period": "10s",
                "stream_receive_window": "8MB", "connection_receive_window": 33554432,
                "max_concurrent_streams": 64 })
            ),
            Ok(none.clone())
        );
        assert_eq!(
            check(json!({ "version": 2, "tls": tls, "stream_receive_window": "4GB" })),
            Err(
                "[h] outbound: stream_receive_window: 4294967296 is not a window, 65535 to \
                 2147483647 bytes"
                    .into()
            )
        );
    }

    /// The ALPN of the ClientHello an outbound `h` with `tls`, and the
    /// version `version` says, writes first.
    #[cfg(feature = "outbound-tls")]
    async fn offered_alpn(tls: serde_json::Value, version: u8) -> Option<Vec<u8>> {
        use crate::transport::tls::hello::{ClientHello, EXT_ALPN};
        use tokio::io::AsyncReadExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let config = crate::config::Config::from_json(
            &serde_json::json!({ "outbounds": [{ "type": "http", "tag": "h",
                "server": "127.0.0.1", "server_port": port, "tls": tls,
                "version": version }] })
            .to_string(),
        )
        .unwrap();
        let dial = crate::net::DialDefaults::default();
        let dns = crate::app::dns::DnsClient::new(
            &config.dns,
            std::sync::Arc::new(dial.clone()),
            &Default::default(),
        )
        .unwrap()
        .into_shared();
        let manager = crate::app::outbound::manager::OutboundManager::new(
            &config.outbounds,
            &dial,
            &Default::default(),
            dns.clone(),
        )
        .unwrap();
        let handler = manager.get("h").unwrap();
        let sess = crate::session::Session {
            destination: crate::session::SocksAddr::Domain("example.com".into(), 443),
            ..Default::default()
        };
        let dial = async {
            let stream = crate::net::connect_stream_outbound(&sess, dns, &handler).await?;
            handler.stream()?.handle(&sess, None, stream).await
        };
        let hello = async {
            let (mut conn, _) = listener.accept().await.unwrap();
            let mut header = [0; 5];
            conn.read_exact(&mut header).await.unwrap();
            let mut record = header.to_vec();
            record.resize(5 + u16::from_be_bytes([header[3], header[4]]) as usize, 0);
            conn.read_exact(&mut record[5..]).await.unwrap();
            // Dropped, which fails the dial.
            ClientHello::from_records(&record)
        };
        let (dialled, hello) = tokio::join!(dial, hello);
        assert!(dialled.is_err());
        hello.extension(EXT_ALPN).map(<[u8]>::to_vec)
    }

    /// An HTTP proxy offers what it speaks over its TLS, with a browser's
    /// fingerprint as without, as sing-box: `http/1.1` alone for HTTP/1.1
    /// (the default), `h2` before it for HTTP/2; a `tls.alpn` set is the
    /// configuration's.
    #[cfg(feature = "outbound-tls")]
    #[tokio::test]
    async fn tls_offers_what_it_speaks_whatever_the_fingerprint() {
        use serde_json::json;
        let http1 = Some(b"\x00\x09\x08http/1.1".to_vec());
        let h2 = Some(b"\x00\x0c\x02h2\x08http/1.1".to_vec());
        for utls in [
            json!(null),
            json!({ "enabled": true, "fingerprint": "chrome" }),
            json!({ "enabled": true, "fingerprint": "firefox" }),
            json!({ "enabled": false }),
        ] {
            let mut tls = json!({ "enabled": true, "server_name": "localhost" });
            if !utls.is_null() {
                tls["utls"] = utls.clone();
            }
            assert_eq!(offered_alpn(tls.clone(), 1).await, http1, "{}", utls);
            assert_eq!(offered_alpn(tls.clone(), 0).await, http1, "{}", utls);
            assert_eq!(offered_alpn(tls.clone(), 2).await, h2, "{}", utls);
            tls["alpn"] = json!([]);
            assert_eq!(
                offered_alpn(tls.clone(), 1).await,
                http1,
                "{} alpn []",
                utls
            );
            assert_eq!(offered_alpn(tls, 2).await, h2, "{} alpn []", utls);
        }
        assert_eq!(
            offered_alpn(
                json!({ "enabled": true, "server_name": "localhost", "alpn": ["h2"] }),
                1
            )
            .await,
            Some(b"\x00\x03\x02h2".to_vec())
        );
    }
}
