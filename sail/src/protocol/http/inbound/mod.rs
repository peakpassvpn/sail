use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use serde_derive::Deserialize;

use crate::adapter::inbound::Handler;
use crate::adapter::registry::{InboundContext, InboundFactory, InboundRegistry};
use crate::adapter::AnyInboundHandler;
use crate::transport::layers::Blocks;

mod stream;

pub use stream::Handler as StreamHandler;

pub(crate) fn register(registry: &mut InboundRegistry) {
    registry.register(
        "http",
        InboundFactory::standalone(build).with_blocks(Blocks {
            tls: true,
            ..Blocks::NONE
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
    let stream = Arc::new(StreamHandler::new(users, realm));
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
