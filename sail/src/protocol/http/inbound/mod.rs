use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use serde_derive::Deserialize;

use crate::adapter::inbound::Handler;
use crate::adapter::registry::{InboundContext, InboundFactory, InboundRegistry};
use crate::adapter::AnyInboundHandler;
use crate::transport::layers::Blocks;

mod h2;
mod stream;

pub use stream::Handler as StreamHandler;

/// The ALPN offered: HTTP/2's, then HTTP/1.1's, of those served.
const H2_HTTP1_ALPN: &[&str] = &["h2", "http/1.1"];
const H2_ALPN: &[&str] = &["h2"];
const HTTP1_ALPN: &[&str] = &["http/1.1"];

pub(crate) fn register(registry: &mut InboundRegistry) {
    registry.register(
        "http",
        InboundFactory::standalone(build)
            .with_blocks(Blocks {
                tls: true,
                ..Blocks::NONE
            })
            // What it serves, as sing-box offers it: h2, then http/1.1.
            .with_alpn(|options| {
                let versions = versions_of(options);
                match (versions.contains(&2), versions.contains(&1)) {
                    (true, true) => H2_HTTP1_ALPN,
                    (true, false) => H2_ALPN,
                    _ => HTTP1_ALPN,
                }
            })
            // As sing-box: HTTP/3 is over QUIC, which takes TLS.
            .checked_by(|tag, options, blocks| {
                if versions_of(options).contains(&3) && !blocks.has_tls() {
                    return Err(anyhow!("[{}] inbound: version: 3 requires TLS", tag));
                }
                Ok(())
            }),
    );
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpInboundOptions {
    /// Clients must authenticate as one of these with `Proxy-Authorization:
    /// Basic`; anyone may connect when there are none.
    #[serde(default)]
    users: Vec<HttpUser>,
    /// The realm a `407` names, which clients show when asking for
    /// credentials: a sail extension; `sail` when unset.
    #[serde(default)]
    realm: Option<String>,
    /// The clients that go in without credentials, by the IP prefixes
    /// they connect from: Mihomo's `skip-auth-prefixes`, a sail extension.
    #[serde(default)]
    skip_auth_prefixes: Vec<String>,
    /// The HTTP versions served, sing-box 1.15's: 1 and 2 when unset. HTTP/2
    /// is told by its preface, over TLS or not. 3 is warned of and not
    /// served: sail speaks no HTTP/3.
    #[serde(default)]
    version: Option<Versions>,
    /// HTTP/2's, sing-box 1.15's: how long a ping may go unanswered, and
    /// how long a connection with no tunnel is kept.
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
    /// HTTP/2's: the most tunnels a client may have open on one connection.
    #[serde(default)]
    max_concurrent_streams: Option<u32>,
}

/// A version, or a list of them.
#[derive(Deserialize)]
#[serde(untagged)]
enum Versions {
    One(u8),
    Many(Vec<u8>),
}

/// The versions `options` name, as written: 1 and 2 when unset (or empty).
fn versions_of(options: &crate::config::model::Options) -> Vec<u64> {
    let versions: Vec<u64> = match options.get("version") {
        Some(serde_json::Value::Number(n)) => n.as_u64().into_iter().collect(),
        Some(serde_json::Value::Array(list)) => list.iter().filter_map(|v| v.as_u64()).collect(),
        _ => Vec::new(),
    };
    if versions.is_empty() {
        vec![1, 2]
    } else {
        versions
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HttpUser {
    pub username: String,
    pub password: String,
}

/// The realm `realm` names, checked: it goes into a header as a quoted
/// string, so it may hold no quote, backslash or control character.
pub(crate) fn realm<'a>(tag: &str, realm: Option<&'a str>) -> Result<&'a str> {
    let realm = realm.unwrap_or(stream::DEFAULT_REALM);
    if realm.is_empty()
        || realm
            .chars()
            .any(|c| c == '"' || c == '\\' || c.is_control())
    {
        return Err(anyhow!(
            "[{}] inbound: realm: not empty, and no quote, backslash or control character",
            tag
        ));
    }
    Ok(realm)
}

/// The users by username, with their passwords.
///
/// A username may appear only once: which of two passwords would name the
/// user is otherwise ambiguous. Basic credentials split at the first colon,
/// so a username cannot hold one.
pub(crate) fn users_by_name(
    tag: &str,
    users: Vec<HttpUser>,
    registry: &crate::user::UserRegistry,
) -> Result<crate::user::Passwords> {
    let mut map = HashMap::with_capacity(users.len());
    for user in users {
        if user.username.contains(':') {
            return Err(anyhow!(
                "[{}] inbound: users: username \"{}\" contains a colon",
                tag,
                user.username
            ));
        }
        if map.contains_key(&user.username) {
            return Err(anyhow!(
                "[{}] inbound: users: username \"{}\" appears more than once",
                tag,
                user.username
            ));
        }
        let bound = registry.bind_named(Some(&user.username));
        map.insert(user.username, (user.password, bound));
    }
    Ok(map)
}

fn build(ctx: &InboundContext<'_>) -> Result<AnyInboundHandler> {
    let options: HttpInboundOptions = ctx.options()?;
    let users = users_by_name(ctx.tag, options.users, &ctx.env.users)?;
    let realm = realm(ctx.tag, options.realm.as_deref())?;
    let skip_auth = crate::user::SkipAuth::new(ctx.tag, &options.skip_auth_prefixes)?;
    let versions = match options.version {
        None => vec![1, 2],
        Some(Versions::One(v)) => vec![v],
        Some(Versions::Many(v)) if v.is_empty() => vec![1, 2],
        Some(Versions::Many(v)) => v,
    };
    if let Some(v) = versions.iter().find(|v| !(1..=3).contains(*v)) {
        return Err(anyhow!(
            "[{}] inbound: version: {} is none of 1, 2 and 3",
            ctx.tag,
            v
        ));
    }
    let (http1, http2) = (versions.contains(&1), versions.contains(&2));
    if !http1 && !http2 {
        return Err(anyhow!(
            "[{}] inbound: version: 3 alone, and sail speaks no HTTP/3",
            ctx.tag
        ));
    }
    let fields = crate::protocol::http::h2::Fields {
        idle_timeout: options.idle_timeout,
        keep_alive_period: options.keep_alive_period,
        stream_receive_window: options.stream_receive_window,
        connection_receive_window: options.connection_receive_window,
        max_concurrent_streams: options.max_concurrent_streams,
    };
    // As sing-box, which takes them with HTTP/2 (and 3) alone.
    if let Some(field) = fields
        .first_set()
        .filter(|_| !http2 && !versions.contains(&3))
    {
        return Err(anyhow!(
            "[{}] inbound: {}: HTTP/2's, not with HTTP/1.1 alone",
            ctx.tag,
            field
        ));
    }
    let h2 = match http2 {
        true => Some(h2::Server {
            settings: crate::protocol::http::h2::Settings::new(
                &format!("[{}] inbound", ctx.tag),
                &fields,
                ctx.env.options.profile,
            )?,
            stall_timeout: crate::transport::muxcore::Tuning::from(&ctx.env.options).stall_timeout,
        }),
        false => None,
    };
    let stream = Arc::new(
        StreamHandler::new(users, realm)
            .skipping_auth(skip_auth)
            .with_versions(http1, h2),
    );
    Ok(Arc::new(Handler::new(
        ctx.tag.to_owned(),
        Some(stream),
        None,
    )))
}

#[cfg(test)]
mod realm_tests {
    /// A realm goes into a quoted header value: one that could end the
    /// quote or the line is a mistake.
    #[test]
    fn a_realm_that_could_break_the_header_is_refused() {
        assert_eq!(super::realm("in", None).unwrap(), "sail");
        assert_eq!(super::realm("in", Some("Office")).unwrap(), "Office");
        for bad in ["", "a\"b", "a\\b", "a\r\nX-Injected: 1"] {
            let err = super::realm("in", Some(bad)).unwrap_err().to_string();
            assert!(
                err.starts_with("[in] inbound: realm:"),
                "{:?}: {}",
                bad,
                err
            );
        }
    }
}

#[cfg(test)]
mod version_tests {
    /// sing-box 1.15's `version`: 1 and 2 unless set; 3 warned of where
    /// another is served, an error alone; HTTP/2's fields with HTTP/2.
    #[test]
    fn version_is_read_as_sing_box_reads_it() {
        let check = |fields: serde_json::Value| {
            let mut json = serde_json::json!({ "inbounds": [{ "type": "http", "tag": "in",
                "listen": "127.0.0.1", "listen_port": 1080 }] });
            let inbound = json["inbounds"][0].as_object_mut().unwrap();
            inbound.extend(fields.as_object().unwrap().clone());
            crate::config::from_string(&json.to_string())
                .and_then(|c| {
                    crate::check_config(&c, &Default::default())?;
                    Ok(c.warnings)
                })
                .map_err(|e| format!("{:#}", e))
        };
        use serde_json::json;
        let none: Vec<String> = Vec::new();
        for version in [json!(null), json!(1), json!(2), json!([1, 2]), json!([])] {
            assert_eq!(check(json!({ "version": version })), Ok(none.clone()));
        }
        // HTTP/3 takes TLS, as in sing-box.
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let tls = json!({ "enabled": true, "certificate": cert.pem(),
            "key": key_pair.serialize_pem() });
        assert_eq!(
            check(json!({ "version": [1, 3], "tls": tls })),
            Ok(vec![
                "inbounds[0].version: sail speaks no HTTP/3; 3 is not served".to_string()
            ])
        );
        assert_eq!(
            check(json!({ "version": 3, "tls": tls })),
            Err("[in] inbound: version: 3 alone, and sail speaks no HTTP/3".into())
        );
        for version in [json!(3), json!([1, 3])] {
            assert_eq!(
                check(json!({ "version": version })),
                Err("[in] inbound: version: 3 requires TLS".into())
            );
        }
        assert_eq!(
            check(json!({ "version": [1, 4] })),
            Err("[in] inbound: version: 4 is none of 1, 2 and 3".into())
        );
        assert_eq!(
            check(json!({ "version": 1, "max_concurrent_streams": 8 })),
            Err("[in] inbound: max_concurrent_streams: HTTP/2's, not with HTTP/1.1 alone".into())
        );
        assert_eq!(
            check(json!({ "idle_timeout": "1m", "keep_alive_period": "20s",
                "stream_receive_window": "2MB", "connection_receive_window": "8MB",
                "max_concurrent_streams": 64 })),
            Ok(none)
        );
    }
}
