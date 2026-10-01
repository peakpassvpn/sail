//! The options of a WireGuard endpoint, as sing-box names them
//! (<https://sing-box.sagernet.org/configuration/endpoint/wireguard/>), and
//! what they are checked and turned into.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_derive::Deserialize;

use crate::common::secret::Secret;

use crate::protocol::wireguard::crypto::KEY_LEN;
use crate::protocol::wireguard::PeerConfig;

/// sing-box's default: 1500 less the largest IPv6 and UDP and WireGuard
/// headers, and some room.
pub const DEFAULT_MTU: u32 = 1408;

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct WireGuardOptions {
    /// A system interface instead of the userspace stack: not supported.
    #[serde(default)]
    pub system: bool,
    /// The system interface's name, for `system` only.
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub mtu: Option<u32>,
    /// The endpoint's own addresses in the tunnel, as prefixes.
    pub address: Vec<String>,
    pub private_key: Secret<String>,
    #[serde(default)]
    pub listen_port: Option<u16>,
    pub peers: Vec<PeerOptions>,
    /// sing-box's worker count; sail has no use for it.
    #[serde(default)]
    #[allow(dead_code)]
    pub workers: Option<u32>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct PeerOptions {
    /// Where the peer is: an address or a domain. Without it, it is
    /// learnt from the peer's handshake, as a server's peers are.
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    pub public_key: String,
    #[serde(default)]
    pub pre_shared_key: Option<Secret<String>>,
    pub allowed_ips: Vec<String>,
    /// Seconds; 0 or unset is off.
    #[serde(default)]
    pub persistent_keepalive_interval: Option<u16>,
    /// Three bytes, or their base64: Cloudflare WARP's client identifier.
    #[serde(default)]
    pub reserved: Option<Reserved>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum Reserved {
    Bytes(Vec<u8>),
    Base64(String),
}

impl Reserved {
    pub fn parse(&self) -> Result<[u8; 3]> {
        let bytes = match self {
            Reserved::Bytes(b) => b.clone(),
            Reserved::Base64(s) => STANDARD
                .decode(s.trim())
                .map_err(|e| anyhow!("not base64: {}", e))?,
        };
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("{} bytes, where there must be 3", bytes.len()))
    }
}

/// A peer, checked.
#[derive(Clone, Debug)]
pub struct PeerSettings {
    /// Where the peer is, when configured: the host is resolved at start.
    pub server: Option<(String, u16)>,
    /// The device's view, without the endpoint the host resolves to.
    pub config: PeerConfig,
    /// The peer's public key in base64, which names it as the user of
    /// what comes in from it.
    pub name: Arc<str>,
}

/// An endpoint's options, checked.
#[derive(Clone, Debug)]
pub struct Settings {
    pub private_key: Secret<[u8; KEY_LEN]>,
    pub mtu: usize,
    /// The endpoint's own addresses, with their prefix lengths.
    pub address: Vec<(IpAddr, u8)>,
    pub listen_port: Option<u16>,
    pub peers: Vec<PeerSettings>,
}

fn key(field: &str, s: &str) -> Result<[u8; KEY_LEN]> {
    let bytes = STANDARD
        .decode(s.trim())
        .map_err(|e| anyhow!("{}: not base64: {}", field, e))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("{}: {} bytes, where a key has 32", field, bytes.len()))
}

/// `ip/len`, as sing-box's prefixes are written.
pub fn prefix(field: &str, s: &str) -> Result<(IpAddr, u8)> {
    let (ip, len) = s
        .split_once('/')
        .ok_or_else(|| anyhow!("{}: \"{}\" is not a prefix, as 10.0.0.2/32", field, s))?;
    let ip: IpAddr = ip
        .parse()
        .map_err(|_| anyhow!("{}: \"{}\" is not an IP address", field, ip))?;
    let len: u8 = len
        .parse()
        .map_err(|_| anyhow!("{}: \"{}\" is not a prefix length", field, len))?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    if len > max {
        bail!("{}: /{} is longer than an address of {}", field, len, ip);
    }
    Ok((ip, len))
}

impl Settings {
    /// Checks `options`; every mistake is an error, naming its field.
    pub fn parse(options: &WireGuardOptions, detour: bool) -> Result<Self> {
        if options.system {
            bail!("system: sail runs WireGuard in userspace only; it must be false");
        }
        if options.name.is_some() {
            bail!("name: names a system interface, which sail does not create");
        }
        let mtu = options.mtu.unwrap_or(DEFAULT_MTU);
        if options.address.is_empty() {
            bail!("address: the endpoint needs an address in the tunnel");
        }
        let address = options
            .address
            .iter()
            .enumerate()
            .map(|(i, a)| prefix(&format!("address[{}]", i), a))
            .collect::<Result<Vec<_>>>()?;
        for family in [true, false] {
            if address
                .iter()
                .filter(|(ip, _)| ip.is_ipv4() == family)
                .count()
                > 1
            {
                bail!(
                    "address: more than one IPv{} address",
                    if family { 4 } else { 6 }
                );
            }
        }
        // IPv6 needs 1280, IPv4 576.
        let min = if address.iter().any(|(ip, _)| ip.is_ipv6()) {
            1280
        } else {
            576
        };
        if !(min..=65_535).contains(&mtu) {
            bail!("mtu: {} is outside {} to 65535", mtu, min);
        }
        let private_key = key("private_key", &options.private_key)?;
        if detour && options.listen_port.is_some() {
            bail!("listen_port: its datagrams go through the detour, which has its own");
        }
        if options.peers.is_empty() {
            bail!("peers: there must be at least one");
        }
        let mut peers = Vec::with_capacity(options.peers.len());
        for (i, peer) in options.peers.iter().enumerate() {
            let field = |f: &str| format!("peers[{}].{}", i, f);
            let public_key = key(&field("public_key"), &peer.public_key)?;
            if peers
                .iter()
                .any(|p: &PeerSettings| p.config.public_key == public_key)
            {
                bail!("{}: another peer has it", field("public_key"));
            }
            let mut config = PeerConfig::new(public_key);
            if let Some(psk) = &peer.pre_shared_key {
                config.preshared_key = Some(key(&field("pre_shared_key"), psk)?.into());
            }
            if peer.allowed_ips.is_empty() {
                bail!(
                    "{}: nothing would be routed to the peer, or accepted from it",
                    field("allowed_ips")
                );
            }
            config.allowed_ips = peer
                .allowed_ips
                .iter()
                .enumerate()
                .map(|(j, a)| prefix(&format!("{}[{}]", field("allowed_ips"), j), a))
                .collect::<Result<Vec<_>>>()?;
            config.persistent_keepalive = peer
                .persistent_keepalive_interval
                .filter(|s| *s > 0)
                .map(|s| Duration::from_secs(s.into()));
            if let Some(reserved) = &peer.reserved {
                config.reserved = reserved
                    .parse()
                    .map_err(|e| anyhow!("{}: {}", field("reserved"), e))?;
            }
            let server = match (&peer.address, peer.port) {
                (Some(address), Some(port)) if !address.is_empty() && port != 0 => {
                    Some((address.clone(), port))
                }
                (None, None) => None,
                _ => bail!(
                    "{} and {}: set both, or neither for a peer that is not dialled",
                    field("address"),
                    field("port")
                ),
            };
            peers.push(PeerSettings {
                server,
                config,
                name: STANDARD.encode(public_key).into(),
            });
        }
        if detour && peers.iter().all(|p| p.server.is_none()) {
            bail!("detour: no peer has an address to send to through it");
        }
        Ok(Settings {
            private_key: private_key.into(),
            mtu: mtu as usize,
            address,
            listen_port: options.listen_port,
            peers,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_A: &str = "YFf6vyGG0nAu8ZlKIYO7nZbcfdd2dbmodt1XRkcCdU4=";
    const KEY_B: &str = "Z1XXLsKYkYxuiYjJIkRvtIKFepCYHTgON+GwPq7SOV4=";

    fn parse(json: serde_json::Value) -> Result<Settings> {
        let options: WireGuardOptions = serde_json::from_value(json)?;
        Settings::parse(&options, false)
    }

    #[test]
    fn keys_are_not_printed() {
        // 32 bytes of 0x55.
        const PSK: &str = "VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVU=";
        let mut json = base();
        json["peers"][0]["pre_shared_key"] = PSK.into();
        let options: WireGuardOptions = serde_json::from_value(json).unwrap();
        let settings = Settings::parse(&options, false).unwrap();
        let debug = format!("{:?} {:?}", options, settings);
        let bytes = |k: &str| {
            let k = STANDARD.decode(k).unwrap();
            format!("{:?}", k)
                .trim_matches(|c| c == '[' || c == ']')
                .to_string()
        };
        for secret in [KEY_A.to_string(), bytes(KEY_A), PSK.to_string(), bytes(PSK)] {
            assert!(!debug.contains(&secret), "{}", debug);
        }
        // The peer's public key is no secret.
        assert!(debug.contains(KEY_B), "{}", debug);
    }

    fn base() -> serde_json::Value {
        serde_json::json!({
            "address": ["10.0.0.2/32", "fd00::2/128"],
            "private_key": KEY_A,
            "peers": [{
                "address": "example.com",
                "port": 51820,
                "public_key": KEY_B,
                "allowed_ips": ["0.0.0.0/0", "::/0"],
            }],
        })
    }

    #[test]
    fn a_sing_box_endpoint_parses() {
        let mut json = base();
        json["listen_port"] = 51821.into();
        json["workers"] = 4.into();
        json["peers"][0]["pre_shared_key"] = KEY_A.into();
        json["peers"][0]["persistent_keepalive_interval"] = 25.into();
        json["peers"][0]["reserved"] = serde_json::json!([1, 2, 3]);
        let s = parse(json).unwrap();
        assert_eq!(s.mtu, 1408);
        assert_eq!(s.listen_port, Some(51821));
        assert_eq!(s.address[0], ("10.0.0.2".parse().unwrap(), 32));
        let peer = &s.peers[0];
        assert_eq!(peer.server, Some(("example.com".into(), 51820)));
        assert_eq!(peer.config.reserved, [1, 2, 3]);
        assert_eq!(
            peer.config.persistent_keepalive,
            Some(Duration::from_secs(25))
        );
        assert!(peer.config.preshared_key.is_some());
        assert_eq!(&*peer.name, KEY_B);
        assert_eq!(peer.config.allowed_ips.len(), 2);
    }

    #[test]
    fn reserved_is_three_bytes_or_their_base64() {
        for (value, expected) in [
            (serde_json::json!([0, 0, 0]), Ok([0, 0, 0])),
            (serde_json::json!([255, 1, 7]), Ok([255, 1, 7])),
            (serde_json::json!("AQID"), Ok([1, 2, 3])),
            (serde_json::json!([1, 2]), Err("2 bytes")),
            (serde_json::json!("AQIDBA=="), Err("4 bytes")),
            (serde_json::json!("!!"), Err("not base64")),
        ] {
            let mut json = base();
            json["peers"][0]["reserved"] = value.clone();
            match (parse(json), expected) {
                (Ok(s), Ok(e)) => assert_eq!(s.peers[0].config.reserved, e, "{}", value),
                (Err(err), Err(e)) => {
                    assert!(err.to_string().contains(e), "{}: {}", value, err);
                    assert!(err.to_string().contains("peers[0].reserved"), "{}", err);
                }
                (r, e) => panic!("{}: {:?}, expected {:?}", value, r.map(|_| ()), e),
            }
        }
        // 256 is not a byte.
        let mut json = base();
        json["peers"][0]["reserved"] = serde_json::json!([256, 0, 0]);
        assert!(parse(json).is_err());
    }

    #[test]
    fn mistakes_are_errors_that_name_the_field() {
        type Change = fn(&mut serde_json::Value);
        let cases: Vec<(Change, &str)> = vec![
            (|j| j["system"] = true.into(), "system"),
            (|j| j["name"] = "wg0".into(), "name"),
            (|j| j["mtu"] = 100.into(), "mtu"),
            (|j| j["mtu"] = 1000.into(), "mtu: 1000 is outside 1280"),
            (|j| j["address"] = serde_json::json!([]), "address"),
            (
                |j| j["address"] = serde_json::json!(["10.0.0.2"]),
                "address[0]",
            ),
            (
                |j| j["address"] = serde_json::json!(["10.0.0.2/33"]),
                "address[0]",
            ),
            (
                |j| j["address"] = serde_json::json!(["10.0.0.2/32", "10.0.0.3/32"]),
                "more than one IPv4",
            ),
            (|j| j["private_key"] = "short".into(), "private_key"),
            (|j| j["private_key"] = "AAAA".into(), "private_key: 3 bytes"),
            (|j| j["peers"] = serde_json::json!([]), "peers"),
            (
                |j| j["peers"][0]["public_key"] = "x".into(),
                "peers[0].public_key",
            ),
            (
                |j| j["peers"][0]["pre_shared_key"] = "x".into(),
                "peers[0].pre_shared_key",
            ),
            (
                |j| j["peers"][0]["allowed_ips"] = serde_json::json!([]),
                "peers[0].allowed_ips",
            ),
            (
                |j| j["peers"][0]["allowed_ips"] = serde_json::json!(["nope/1"]),
                "peers[0].allowed_ips[0]",
            ),
            (
                |j| {
                    j["peers"][0].as_object_mut().unwrap().remove("port");
                },
                "peers[0].port",
            ),
            (
                |j| {
                    let peer = j["peers"][0].clone();
                    j["peers"].as_array_mut().unwrap().push(peer);
                },
                "another peer",
            ),
        ];
        for (change, field) in cases {
            let mut json = base();
            change(&mut json);
            let err = parse(json.clone()).unwrap_err().to_string();
            assert!(err.contains(field), "{}: {}", json, err);
        }
    }

    #[test]
    fn unknown_fields_are_errors() {
        let mut json = base();
        json["peers"][0]["keepalive"] = 5.into();
        assert!(parse(json).unwrap_err().to_string().contains("keepalive"));
        let mut json = base();
        json["gso"] = true.into();
        assert!(parse(json).unwrap_err().to_string().contains("gso"));
    }

    #[test]
    fn a_detour_needs_a_peer_to_send_to_and_no_port_of_its_own() {
        let mut json = base();
        json["listen_port"] = 1.into();
        let options: WireGuardOptions = serde_json::from_value(json).unwrap();
        let err = Settings::parse(&options, true).unwrap_err().to_string();
        assert!(err.contains("listen_port"), "{}", err);

        let mut json = base();
        let peer = json["peers"][0].as_object_mut().unwrap();
        peer.remove("address");
        peer.remove("port");
        let options: WireGuardOptions = serde_json::from_value(json).unwrap();
        Settings::parse(&options, false).unwrap();
        let err = Settings::parse(&options, true).unwrap_err().to_string();
        assert!(err.contains("detour"), "{}", err);
    }
}
