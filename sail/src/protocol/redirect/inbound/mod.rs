//! The `redirect` inbound: takes TCP connections an iptables or nftables
//! REDIRECT rule diverted to it, and proxies each to where it was going.
//!
//! REDIRECT rewrites a connection's destination to the listener, and
//! conntrack remembers the original; the listener reads it back from the
//! accepted socket with `SO_ORIGINAL_DST`. That needs the socket itself,
//! so it is read in `InboundHandler::accepted`, before the stream reaches
//! the stream handler. Linux only: elsewhere it is a configuration error.

use anyhow::Result;
use serde_derive::Deserialize;

use crate::adapter::registry::{InboundContext, InboundFactory, InboundRegistry};
use crate::adapter::AnyInboundHandler;

#[cfg(target_os = "linux")]
mod linux;

pub(crate) fn register(registry: &mut InboundRegistry) {
    registry.register("redirect", InboundFactory::standalone(build));
}

/// It has nothing of its own to configure: the listen fields are common to
/// every inbound.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RedirectInboundOptions {}

fn build(ctx: &InboundContext<'_>) -> Result<AnyInboundHandler> {
    let _: RedirectInboundOptions = ctx.options()?;
    #[cfg(target_os = "linux")]
    {
        Ok(std::sync::Arc::new(linux::Handler::new(ctx.tag.to_owned())))
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(anyhow::anyhow!(
            "[{}] inbound: redirect: only supported on Linux",
            ctx.tag
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::adapter::registry::build_inbounds;
    use crate::config::Config;
    use crate::include;

    fn build(json: &str) -> anyhow::Result<()> {
        let config = Config::from_json(json)?;
        build_inbounds(
            &include::INBOUNDS,
            &config.inbounds,
            include::LISTENER_INBOUNDS,
            &crate::runtime::RuntimeEnv::default(),
            &mut HashMap::new(),
            &mut HashMap::new(),
        )
    }

    #[test]
    fn an_unknown_field_is_an_error() {
        let err = build(
            r#"{ "inbounds": [ { "type": "redirect", "listen_port": 1, "network": "tcp" } ] }"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("network"), "{}", err);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn it_builds_on_linux() {
        build(r#"{ "inbounds": [ { "type": "redirect", "listen_port": 1 } ] }"#).unwrap();
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn elsewhere_it_is_an_error() {
        let err =
            build(r#"{ "inbounds": [ { "type": "redirect", "listen_port": 1 } ] }"#).unwrap_err();
        assert_eq!(
            err.to_string(),
            "[redirect] inbound: redirect: only supported on Linux"
        );
    }
}
