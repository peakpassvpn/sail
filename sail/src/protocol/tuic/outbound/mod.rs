use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use serde_derive::Deserialize;

use crate::adapter::outbound::HandlerBuilder;
use crate::adapter::registry::{OutboundContext, OutboundFactory, OutboundRegistry};
use crate::adapter::AnyOutboundHandler;
use crate::transport::layers::{Blocks, Listable, OutboundTls};

use super::common::{parse_uuid, CongestionControl, UdpRelayMode, DEFAULT_HEARTBEAT};

mod client;

pub use client::{Client, ClientOptions, DatagramHandler, StreamHandler};

pub(crate) fn register(registry: &mut OutboundRegistry) {
    // It dials its server over UDP itself, with its own `tls`: of the
    // shared blocks only the dial fields apply.
    registry.register(
        "tuic",
        OutboundFactory::standalone(build).with_blocks(Blocks::DIAL),
    );
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TuicOutboundOptions {
    server: String,
    server_port: u16,
    uuid: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    congestion_control: CongestionControl,
    #[serde(default)]
    udp_relay_mode: Option<UdpRelayMode>,
    /// sing-box's UDP over TCP (v2) in a `Connect` stream. Not supported
    /// yet.
    #[serde(default)]
    udp_over_stream: bool,
    #[serde(default)]
    zero_rtt_handshake: bool,
    #[serde(default, with = "crate::config::model::duration")]
    heartbeat: Option<Duration>,
    /// `tcp` or `udp`; both when not set.
    #[serde(default)]
    network: Option<Network>,
    tls: OutboundTls,
}

#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Network {
    Tcp,
    Udp,
}

fn build(ctx: &mut OutboundContext<'_>) -> Result<AnyOutboundHandler> {
    let tag = ctx.tag;
    let options: TuicOutboundOptions = ctx.options()?;
    let uuid = parse_uuid("outbound", tag, "uuid", &options.uuid)?;
    if options.udp_over_stream {
        if options.udp_relay_mode.is_some() {
            return Err(anyhow!(
                "[{}] outbound: udp_over_stream: cannot be set with udp_relay_mode",
                tag
            ));
        }
        return Err(anyhow!(
            "[{}] outbound: udp_over_stream: not supported yet",
            tag
        ));
    }
    let tls = &options.tls;
    if !tls.enabled {
        return Err(anyhow!("[{}] outbound: tls: TUIC needs TLS enabled", tag));
    }
    let unsupported = [
        ("ech", tls.ech.as_ref().is_some_and(|e| e.enabled)),
        ("reality", tls.reality.as_ref().is_some_and(|r| r.enabled)),
        ("utls", tls.utls.as_ref().is_some_and(|u| u.enabled)),
    ];
    if let Some((field, _)) = unsupported.iter().find(|(_, on)| *on) {
        return Err(anyhow!(
            "[{}] outbound: tls.{}: not supported with TUIC",
            tag,
            field
        ));
    }
    let certificate = match (&tls.certificate, &tls.certificate_path) {
        (Some(inline), _) => Some(inline.clone().joined()),
        (None, Some(path)) => Some(ctx.env.data_path(path)),
        (None, None) => None,
    };
    let client = Arc::new(
        Client::new(ClientOptions {
            server: options.server.clone(),
            port: options.server_port,
            server_name: tls.server_name.clone().unwrap_or(options.server),
            insecure: tls.insecure,
            certificate,
            alpn: tls.alpn.clone().map(Listable::into_vec),
            uuid,
            password: options.password.into_bytes(),
            congestion: options.congestion_control,
            udp_relay_mode: options.udp_relay_mode.unwrap_or_default(),
            zero_rtt: options.zero_rtt_handshake,
            heartbeat: options.heartbeat.unwrap_or(DEFAULT_HEARTBEAT),
            dns_client: ctx.dns_client.clone(),
            dial: ctx.dial.clone(),
            tuning: &ctx.env.options.quic,
        })
        .map_err(|e| anyhow!("[{}] outbound: tls: {}", tag, e))?,
    );
    let mut builder = HandlerBuilder::default().tag(tag.to_owned());
    if options.network != Some(Network::Udp) {
        builder = builder.stream_handler(Arc::new(StreamHandler(client.clone())));
    }
    if options.network != Some(Network::Tcp) {
        builder = builder.datagram_handler(Arc::new(DatagramHandler(client)));
    }
    Ok(builder.build())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(json: &str) -> Result<TuicOutboundOptions> {
        Ok(serde_json::from_str(json)?)
    }

    #[test]
    fn options_are_sing_boxs() {
        let o = parse(
            r#"{
                "server": "example.com",
                "server_port": 443,
                "uuid": "b8f7a0c2-3f5e-4b0a-9c7d-1e2f3a4b5c6d",
                "password": "p",
                "congestion_control": "new_reno",
                "udp_relay_mode": "quic",
                "udp_over_stream": false,
                "zero_rtt_handshake": true,
                "heartbeat": "10s",
                "network": "tcp",
                "tls": {"enabled": true, "server_name": "example.com", "alpn": ["h3"]}
            }"#,
        )
        .unwrap();
        assert_eq!(o.udp_relay_mode, Some(UdpRelayMode::Quic));
        assert_eq!(o.network, Some(Network::Tcp));
        assert_eq!(o.heartbeat, Some(Duration::from_secs(10)));
        assert!(
            parse(r#"{"server": "a", "server_port": 1, "uuid": "u", "tls": {}, "users": []}"#)
                .is_err()
        );
        assert!(parse(
            r#"{"server": "a", "server_port": 1, "uuid": "u", "tls": {}, "network": "icmp"}"#
        )
        .is_err());
    }
}
