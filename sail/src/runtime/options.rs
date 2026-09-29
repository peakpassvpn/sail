//! Tuning an instance runs with: buffer and queue sizes, internal timeouts
//! and limits. They are not part of a configuration -- what a user writes
//! does not depend on them -- but chosen by whoever starts the instance: a
//! preset for the device (`--profile`), and single values on top of it
//! (`--set relay.buffer_size=32`).

use std::str::FromStr;
use std::time::Duration;

use anyhow::{anyhow, Result};
use serde_derive::{Deserialize, Serialize};

/// Whether sail is built for a phone, for what cannot see the profile it
/// runs with: the profile says so where it can be seen.
pub const MOBILE: bool = cfg!(any(target_os = "ios", target_os = "android"));

/// A resource budget to start from.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Profile {
    /// Phones: a small memory budget, few concurrent connections.
    Mobile,
    /// The default.
    #[default]
    Desktop,
    /// Many concurrent connections; throughput over memory.
    Server,
    /// Routers and other small devices: the least memory.
    Router,
}

impl FromStr for Profile {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "mobile" => Ok(Profile::Mobile),
            "desktop" => Ok(Profile::Desktop),
            "server" => Ok(Profile::Server),
            "router" => Ok(Profile::Router),
            _ => Err(anyhow!(
                "unknown profile \"{}\", expected mobile, desktop, server or router",
                s
            )),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeOptions {
    pub relay: Relay,
    pub udp: Udp,
    pub netstack: Netstack,
    pub inbound: Inbound,
    pub quic: Quic,
    pub ws: Ws,
    pub dns: Dns,
    pub stats: Stats,
}

/// Forwarding a TCP connection.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Relay {
    /// The buffer a direction starts with, in KiB.
    pub buffer_size: usize,
    /// The largest a direction's buffer grows to, in KiB.
    pub buffer_max_size: usize,
    /// A direction with data its writer does not take for this long
    /// aborts the connection, both sides closed. Short outages stall
    /// writes for a while and TCP recovers from them: a 90 s outage has
    /// been seen to stall one for 123 s.
    #[serde(with = "duration")]
    pub write_stall_timeout: Duration,
    /// Idle after half-close: once the server closed its side, the
    /// client-to-server direction is closed after this long without a
    /// byte moving, counted from the close or the last byte. Connections
    /// that were never half-closed have no idle timeout.
    #[serde(with = "duration")]
    pub uplink_idle_timeout: Duration,
    /// Idle after half-close the other way: the server-to-client direction
    /// once the client closed its side. Data the client sent may still be
    /// on its way to the server, in buffers further on where the relay
    /// cannot see it move, while the answer waits for it.
    #[serde(with = "duration")]
    pub downlink_idle_timeout: Duration,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Udp {
    /// The buffer a datagram is read into, in KiB: 64 holds the largest
    /// UDP payload (65535 bytes), and a smaller one drops bigger datagrams.
    /// One per UDP session and one per inbound datagram, reused.
    pub datagram_buffer_size: usize,
    /// Datagrams queued towards outbounds.
    pub uplink_channel_size: usize,
    /// Datagrams queued towards a TUN.
    pub downlink_channel_size: usize,
    /// How often idle UDP sessions are looked for.
    #[serde(with = "duration")]
    pub session_check_interval: Duration,
}

/// The TUN inbound's TCP/IP stack.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Netstack {
    /// The hard memory and flow budget: `mobile`, `router`, `desktop` or
    /// `server`.
    pub budget: NetstackBudget,
    /// Packets read from or written to the device at a time.
    pub batch_size: usize,
    /// Linux: device queues, each with a runner of its own; no more than
    /// there are CPUs.
    pub max_queues: usize,
    /// Linux: GSO/GRO offload, which needs `batch_size` to hold a whole
    /// 64 KiB super-packet at the configured MTU.
    pub offload: bool,
    /// Application commands and accepted connections queued per runner.
    pub command_channel_size: usize,
    /// Datagrams queued from the stack towards NAT.
    pub udp_uplink_channel_size: usize,
}

/// A budget preset of the TUN inbound's stack.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NetstackBudget {
    Mobile,
    Router,
    Desktop,
    Server,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Inbound {
    /// How long a client has to finish its protocol's handshake.
    #[serde(with = "duration")]
    pub handshake_timeout: Duration,
    /// Streams of one multiplexed connection handshaking at once.
    pub multiplex_accept_concurrency: usize,
    /// Resets accepted TCP connections on close instead of closing them
    /// gracefully: sockets are reclaimed at once, and whatever is still
    /// queued for the peer is lost.
    pub tcp_abort_on_close: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Quic {
    pub max_concurrent_streams: u32,
    #[serde(with = "duration")]
    pub client_idle_timeout: Duration,
    #[serde(with = "duration")]
    pub client_keep_alive_interval: Duration,
    #[serde(with = "duration")]
    pub server_idle_timeout: Duration,
    /// Zero sends none.
    #[serde(with = "duration")]
    pub server_keep_alive_interval: Duration,
    /// What a Hysteria2 connection's peer may send ahead of what is read,
    /// all streams together, in KiB. At eight times a stream's 8 MiB,
    /// streams nobody reads do not hold up the rest.
    pub hysteria2_receive_window: usize,
    /// What a Hysteria2 connection keeps sent and not yet acknowledged, in
    /// KiB: the memory it may take for what it sends.
    pub hysteria2_send_window: usize,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Ws {
    /// Half-closes a WebSocket stream instead of closing it, for servers
    /// that relay after the client stops sending.
    pub half_close: bool,
}

/// Retrying DNS servers, and how a `smart_select` chooses among its
/// members.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Dns {
    /// Attempts per query to one server.
    pub max_retries: usize,
    /// How often the preferred server is chosen again.
    #[serde(with = "duration")]
    pub reselect_interval: Duration,
    /// Answers slower than this count against a server.
    #[serde(with = "duration")]
    pub slow_response: Duration,
    /// Slow or failed answers in a row before switching server.
    pub switch_threshold: usize,
    /// Servers asked at once when falling back.
    pub fallback_concurrency: usize,
    /// How long an AAAA answer is waited for after the A answer.
    #[serde(with = "duration")]
    pub dualstack_delay: Duration,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Stats {
    /// Finished connections kept for the API to list.
    pub max_recent_connections: usize,
}

impl Default for RuntimeOptions {
    fn default() -> Self {
        Self::profile(Profile::default())
    }
}

impl Default for Relay {
    fn default() -> Self {
        RuntimeOptions::default().relay
    }
}

impl Default for Udp {
    fn default() -> Self {
        RuntimeOptions::default().udp
    }
}

impl Default for Netstack {
    fn default() -> Self {
        RuntimeOptions::default().netstack
    }
}

impl Default for Inbound {
    fn default() -> Self {
        RuntimeOptions::default().inbound
    }
}

impl Default for Quic {
    fn default() -> Self {
        RuntimeOptions::default().quic
    }
}

impl Default for Ws {
    fn default() -> Self {
        RuntimeOptions::default().ws
    }
}

impl Default for Dns {
    fn default() -> Self {
        RuntimeOptions::default().dns
    }
}

impl Default for Stats {
    fn default() -> Self {
        RuntimeOptions::default().stats
    }
}

impl RuntimeOptions {
    /// The options a profile starts from.
    pub fn profile(profile: Profile) -> Self {
        let desktop = RuntimeOptions {
            relay: Relay {
                buffer_size: 16,
                buffer_max_size: 128,
                write_stall_timeout: Duration::from_secs(300),
                uplink_idle_timeout: Duration::from_secs(300),
                downlink_idle_timeout: Duration::from_secs(300),
            },
            udp: Udp {
                datagram_buffer_size: 64,
                uplink_channel_size: 256,
                downlink_channel_size: 256,
                session_check_interval: Duration::from_secs(10),
            },
            netstack: Netstack {
                budget: NetstackBudget::Desktop,
                batch_size: 32,
                max_queues: 4,
                offload: false,
                command_channel_size: 512,
                udp_uplink_channel_size: 256,
            },
            inbound: Inbound {
                handshake_timeout: Duration::from_secs(60),
                multiplex_accept_concurrency: 256,
                tcp_abort_on_close: false,
            },
            quic: Quic {
                max_concurrent_streams: 1024,
                client_idle_timeout: Duration::from_secs(15),
                client_keep_alive_interval: Duration::from_secs(3),
                server_idle_timeout: Duration::from_secs(120),
                server_keep_alive_interval: Duration::ZERO,
                hysteria2_receive_window: 64 << 10,
                hysteria2_send_window: 16 << 10,
            },
            ws: Ws { half_close: false },
            dns: Dns {
                max_retries: 4,
                reselect_interval: Duration::from_secs(30),
                slow_response: Duration::from_millis(800),
                switch_threshold: 3,
                fallback_concurrency: 1,
                dualstack_delay: Duration::from_millis(250),
            },
            stats: Stats {
                max_recent_connections: 0,
            },
        };
        match profile {
            Profile::Desktop => desktop,
            Profile::Mobile => RuntimeOptions {
                relay: Relay {
                    buffer_size: 8,
                    buffer_max_size: 64,
                    ..desktop.relay
                },
                udp: Udp {
                    uplink_channel_size: 128,
                    downlink_channel_size: 128,
                    ..desktop.udp
                },
                netstack: Netstack {
                    budget: NetstackBudget::Mobile,
                    batch_size: 1,
                    max_queues: 1,
                    offload: false,
                    command_channel_size: 256,
                    udp_uplink_channel_size: 128,
                },
                inbound: Inbound {
                    multiplex_accept_concurrency: 64,
                    ..desktop.inbound
                },
                quic: Quic {
                    max_concurrent_streams: 256,
                    hysteria2_receive_window: 32 << 10,
                    ..desktop.quic
                },
                ..desktop
            },
            Profile::Router => RuntimeOptions {
                relay: Relay {
                    buffer_size: 4,
                    buffer_max_size: 16,
                    ..desktop.relay
                },
                udp: Udp {
                    uplink_channel_size: 64,
                    downlink_channel_size: 64,
                    ..desktop.udp
                },
                netstack: Netstack {
                    budget: NetstackBudget::Router,
                    batch_size: 4,
                    max_queues: 1,
                    offload: false,
                    command_channel_size: 128,
                    udp_uplink_channel_size: 64,
                },
                inbound: Inbound {
                    multiplex_accept_concurrency: 32,
                    ..desktop.inbound
                },
                quic: Quic {
                    max_concurrent_streams: 128,
                    hysteria2_receive_window: 32 << 10,
                    ..desktop.quic
                },
                ..desktop
            },
            Profile::Server => RuntimeOptions {
                relay: Relay {
                    buffer_size: 16,
                    buffer_max_size: 256,
                    ..desktop.relay
                },
                udp: Udp {
                    uplink_channel_size: 1024,
                    ..desktop.udp
                },
                netstack: Netstack {
                    budget: NetstackBudget::Server,
                    batch_size: 64,
                    max_queues: 8,
                    offload: true,
                    command_channel_size: 1024,
                    udp_uplink_channel_size: 1024,
                },
                inbound: Inbound {
                    multiplex_accept_concurrency: 1024,
                    ..desktop.inbound
                },
                quic: Quic {
                    max_concurrent_streams: 4096,
                    ..desktop.quic
                },
                ..desktop
            },
        }
    }

    /// Sets the option at `key`, a dotted path such as `relay.buffer_size`,
    /// from its text: a number, `true` or `false`, or a duration like `10s`.
    pub fn set(&mut self, key: &str, value: &str) -> Result<()> {
        let mut tree = serde_json::to_value(&*self)?;
        let mut node = &mut tree;
        for part in key.split('.') {
            node = node
                .get_mut(part)
                .filter(|_| !part.is_empty())
                .ok_or_else(|| anyhow!("unknown runtime option \"{}\"", key))?;
        }
        if node.is_object() {
            return Err(anyhow!(
                "runtime option \"{}\" is a group; set one of its options",
                key
            ));
        }
        *node = match serde_json::from_str::<serde_json::Value>(value) {
            Ok(v @ (serde_json::Value::Number(_) | serde_json::Value::Bool(_))) => v,
            _ => serde_json::Value::String(value.to_string()),
        };
        *self = serde_json::from_value(tree)
            .map_err(|e| anyhow!("runtime option \"{}\": {}", key, e))?;
        Ok(())
    }

    /// Applies `key=value` settings in order.
    pub fn set_all<'a>(&mut self, settings: impl IntoIterator<Item = &'a str>) -> Result<()> {
        for setting in settings {
            let (key, value) = setting.split_once('=').ok_or_else(|| {
                anyhow!("invalid runtime option \"{}\", expected key=value", setting)
            })?;
            self.set(key.trim(), value.trim())?;
        }
        Ok(())
    }
}

/// Durations as text, `10s`, both ways.
mod duration {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("{}ms", d.as_millis()))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Duration, D::Error> {
        let s = String::deserialize(de)?;
        crate::config::model::parse_duration(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_setting_changes_one_option() {
        let mut options = RuntimeOptions::profile(Profile::Mobile);
        options
            .set_all([
                "relay.buffer_size=32",
                "inbound.tcp_abort_on_close=true",
                "dns.slow_response=1s",
            ])
            .unwrap();
        assert_eq!(options.relay.buffer_size, 32);
        assert!(options.inbound.tcp_abort_on_close);
        assert_eq!(options.dns.slow_response, Duration::from_secs(1));
        // The rest stays as the profile has it.
        assert_eq!(
            options.relay.buffer_max_size,
            RuntimeOptions::profile(Profile::Mobile)
                .relay
                .buffer_max_size
        );
    }

    #[test]
    fn a_bad_setting_is_an_error_that_names_it() {
        let mut options = RuntimeOptions::default();
        let err = options.set("relay.bufer_size", "1").unwrap_err();
        assert_eq!(
            err.to_string(),
            "unknown runtime option \"relay.bufer_size\""
        );
        let err = options.set("relay", "1").unwrap_err();
        assert!(err.to_string().contains("is a group"), "{}", err);
        let err = options.set("relay.buffer_size", "big").unwrap_err();
        assert!(
            err.to_string()
                .starts_with("runtime option \"relay.buffer_size\""),
            "{}",
            err
        );
        let err = options.set_all(["relay.buffer_size"]).unwrap_err();
        assert!(err.to_string().contains("expected key=value"), "{}", err);
    }

    #[test]
    fn profiles_are_named_as_on_the_command_line() {
        assert_eq!("router".parse::<Profile>().unwrap(), Profile::Router);
        assert!("laptop".parse::<Profile>().is_err());
        assert!(
            RuntimeOptions::profile(Profile::Router)
                .relay
                .buffer_max_size
                < RuntimeOptions::profile(Profile::Server)
                    .relay
                    .buffer_max_size
        );
    }
}
