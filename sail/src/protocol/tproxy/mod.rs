//! The `tproxy` inbound: takes TCP connections and UDP datagrams a TPROXY
//! rule diverted to it, and proxies them to where they were going.
//!
//! TPROXY hands a packet to a local socket without rewriting it, so the
//! destination is still on it: for TCP, it is the local address of the
//! accepted connection; for UDP, the kernel reports it with each datagram
//! (`IP_RECVORIGDSTADDR`). Replies go back from a socket bound to that
//! destination, so the client sees them come from where it sent to. Both
//! only work on sockets marked transparent, which the listener does in
//! `InboundHandler::prepare_listener`. Linux only: elsewhere it is a
//! configuration error.

use anyhow::Result;
use serde_derive::Deserialize;

use crate::adapter::registry::{InboundContext, InboundFactory, InboundRegistry};
use crate::adapter::AnyInboundHandler;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
mod sys;

pub(crate) fn register(registry: &mut InboundRegistry) {
    registry.register("tproxy", InboundFactory::standalone(build));
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TproxyInboundOptions {
    /// Only `tcp`, or only `udp`; both when unset.
    #[serde(default)]
    network: Option<TproxyNetwork>,
}

#[derive(Deserialize, Clone, Copy, PartialEq, Debug)]
#[serde(rename_all = "lowercase")]
enum TproxyNetwork {
    Tcp,
    Udp,
}

fn build(ctx: &InboundContext<'_>) -> Result<AnyInboundHandler> {
    let options: TproxyInboundOptions = ctx.options()?;
    #[cfg(target_os = "linux")]
    {
        let tcp = options.network != Some(TproxyNetwork::Udp);
        let udp = options.network != Some(TproxyNetwork::Tcp);
        Ok(std::sync::Arc::new(linux::Handler::new(
            ctx.tag.to_owned(),
            tcp,
            udp,
        )))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = options.network;
        Err(anyhow::anyhow!(
            "[{}] inbound: tproxy: only supported on Linux",
            ctx.tag
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::adapter::registry::build_inbounds;
    use crate::adapter::registry::Handlers;
    use crate::config::Config;
    use crate::include;

    fn build(json: &str) -> anyhow::Result<Handlers<crate::adapter::AnyInboundHandler>> {
        let config = Config::from_json(json)?;
        let mut handlers = HashMap::new();
        build_inbounds(
            &include::INBOUNDS,
            &config.inbounds,
            include::LISTENER_INBOUNDS,
            &crate::runtime::RuntimeEnv::default(),
            &mut handlers,
            &mut HashMap::new(),
        )?;
        Ok(handlers)
    }

    #[test]
    fn an_unknown_network_is_an_error() {
        let err = build(
            r#"{ "inbounds": [ { "type": "tproxy", "listen_port": 1, "network": "sctp" } ] }"#,
        )
        .err()
        .unwrap();
        assert!(err.to_string().contains("sctp"), "{}", err);
    }

    #[test]
    fn an_unknown_field_is_an_error() {
        let err =
            build(r#"{ "inbounds": [ { "type": "tproxy", "listen_port": 1, "sniff": true } ] }"#)
                .err()
                .unwrap();
        assert!(err.to_string().contains("sniff"), "{}", err);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn network_picks_what_it_listens_on() {
        let handlers = build(
            r#"{ "inbounds": [
                { "type": "tproxy", "tag": "both", "listen_port": 1 },
                { "type": "tproxy", "tag": "tcp", "listen_port": 2, "network": "tcp" },
                { "type": "tproxy", "tag": "udp", "listen_port": 3, "network": "udp" }
            ] }"#,
        )
        .unwrap();
        let networks = |tag: &str| {
            let h = &handlers[tag];
            (h.stream().is_ok(), h.datagram().is_ok())
        };
        assert_eq!(networks("both"), (true, true));
        assert_eq!(networks("tcp"), (true, false));
        assert_eq!(networks("udp"), (false, true));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn elsewhere_it_is_an_error() {
        let err = build(r#"{ "inbounds": [ { "type": "tproxy", "listen_port": 1 } ] }"#)
            .err()
            .unwrap();
        assert_eq!(
            err.to_string(),
            "[tproxy] inbound: tproxy: only supported on Linux"
        );
    }
}
