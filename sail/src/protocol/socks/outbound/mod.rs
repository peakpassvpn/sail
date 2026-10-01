use std::sync::Arc;

use anyhow::{anyhow, Result};

use crate::adapter::outbound::HandlerBuilder;
use crate::adapter::registry::{OutboundContext, OutboundFactory, OutboundRegistry};
use crate::adapter::AnyOutboundHandler;
use crate::transport::layers::Blocks;
use crate::transport::uot;
use serde_derive::Deserialize;

mod datagram;
mod stream;

pub use datagram::Handler as DatagramHandler;
pub use stream::Handler as StreamHandler;

pub(crate) fn register(registry: &mut OutboundRegistry) {
    registry.register(
        "socks",
        OutboundFactory::standalone(build).with_blocks(Blocks::DIALER),
    );
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SocksOutboundOptions {
    /// May be left out, with `server_port`, by an outbound with a
    /// `detour`: one over ShadowTLS, which dials its own server.
    #[serde(default)]
    server: Option<String>,
    #[serde(default)]
    server_port: Option<u16>,
    /// `5`, the default, which is all sail speaks. sing-box also takes
    /// `4` and `4a` (option/simple.go:25), which are errors here.
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
    /// UDP over its TCP, to `sp.v2.udp-over-tcp.arpa` (version 2, the
    /// default) or `sp.udp-over-tcp.arpa` (version 1), instead of UDP
    /// ASSOCIATE.
    #[serde(default)]
    udp_over_tcp: Option<uot::UdpOverTcpOptions>,
}

fn build(ctx: &mut OutboundContext<'_>) -> Result<AnyOutboundHandler> {
    let options: SocksOutboundOptions = ctx.options()?;
    // As sing-box parses it (protocol/socks/outbound.go:41, sing's
    // protocol/socks/client.go:39).
    match options.version.as_deref() {
        None | Some("") | Some("5") => {}
        Some("4") | Some("4a") => {
            return Err(anyhow!(
                "[{}] outbound: version: SOCKS4 is not supported; only 5",
                ctx.tag
            ))
        }
        Some(other) => {
            return Err(anyhow!(
                "[{}] outbound: version: unknown socks version \"{}\"",
                ctx.tag,
                other
            ))
        }
    }
    let (server, server_port) = ctx.server(options.server.clone(), options.server_port)?;
    let udp_over_tcp = match &options.udp_over_tcp {
        Some(uot) => uot.version(ctx.tag)?,
        None => None,
    };
    let stream = Arc::new(StreamHandler {
        address: server.clone(),
        port: server_port,
        username: options.username.clone(),
        password: options.password.clone(),
        dialer: ctx.dialer.clone(),
    });
    let datagram = Arc::new(DatagramHandler {
        address: server,
        port: server_port,
        username: options.username,
        password: options.password,
        dns_client: ctx.dns_client.clone(),
        dialer: ctx.dialer.clone(),
    });
    let socks = HandlerBuilder::default()
        .tag(ctx.tag.to_owned())
        .stream_handler(stream)
        .datagram_handler(datagram)
        .build();
    if let Some(version) = udp_over_tcp {
        return Ok(uot::over_stream(socks, version)?);
    }
    Ok(socks)
}

#[cfg(test)]
mod tests {
    /// SOCKS 5, given or not, is taken without a word; 4 and 4a, which
    /// sing-box also speaks, are errors.
    #[test]
    fn version_5_is_taken_and_4_refused() {
        let check = |version: serde_json::Value| {
            let json = serde_json::json!({ "outbounds": [{ "type": "socks", "tag": "s",
                "server": "192.0.2.1", "server_port": 1080, "version": version }] });
            crate::config::from_string(&json.to_string())
                .and_then(|c| {
                    crate::check_config(&c, &Default::default())?;
                    Ok(c.warnings)
                })
                .map_err(|e| format!("{:#}", e))
        };
        assert_eq!(check("5".into()), Ok(vec![]));
        assert_eq!(check(serde_json::Value::Null), Ok(vec![]));
        for version in ["4", "4a"] {
            assert_eq!(
                check(version.into()),
                Err("[s] outbound: version: SOCKS4 is not supported; only 5".into())
            );
        }
    }
}
