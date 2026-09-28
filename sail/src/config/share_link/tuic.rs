//! `tuic://uuid:password@host:port?congestion_control=bbr&alpn=h3&...`:
//! TUIC v5, as dae proposed the link and mihomo reads it.
//!
//! Deviations from mihomo: a TUIC v4 link (a token and no password) is an
//! error, for sail speaks only v5; `disable_sni=1` is an error, for sail
//! always sends SNI; `allow_insecure` (and `insecure`) is read, which
//! mihomo dropped; a congestion control or UDP relay mode sail does not
//! have is an error.

use anyhow::{anyhow, Result};
use serde_json::{json, Map};

use super::url::{decode_utf8, shown, Link};
use super::v2ray::split_list;
use super::vless::check_uuid;
use super::Parsed;

pub fn parse(link: &Link) -> Result<Parsed> {
    let userinfo = link
        .userinfo
        .filter(|u| !u.is_empty())
        .ok_or_else(|| anyhow!("missing uuid:password"))?;
    let Some((uuid, password)) = userinfo.split_once(':') else {
        return Err(anyhow!(
            "a TUIC v4 link (a token, no password): only v5 is supported"
        ));
    };
    let uuid = decode_utf8(uuid, "uuid")?;
    check_uuid(&uuid)?;
    let password = decode_utf8(password, "password")?;

    let mut parsed = Parsed::new("tuic", link, link.port()?);
    parsed.insert("uuid", uuid);
    parsed.insert("password", password);
    if let Some(cc) = link.get_any(&["congestion_control", "congestion-control"]) {
        let cc = match cc.to_ascii_lowercase().as_str() {
            "bbr" => "bbr",
            "cubic" => "cubic",
            "new_reno" | "newreno" | "new-reno" => "new_reno",
            other => {
                return Err(anyhow!(
                    "congestion_control: {} is not supported, only bbr, cubic and new_reno",
                    shown(other)
                ))
            }
        };
        parsed.insert("congestion_control", cc);
    }
    if let Some(mode) = link.get_any(&["udp_relay_mode", "udp-relay-mode"]) {
        let mode = match mode.to_ascii_lowercase().as_str() {
            "native" => "native",
            "quic" => "quic",
            other => {
                return Err(anyhow!(
                    "udp_relay_mode: {} is not supported, only native and quic",
                    shown(other)
                ))
            }
        };
        parsed.insert("udp_relay_mode", mode);
    }
    if link.any_flag(&["disable_sni", "disable-sni"])? {
        return Err(anyhow!("disable_sni: sail always sends SNI"));
    }
    let mut tls = Map::new();
    tls.insert("enabled".into(), json!(true));
    if let Some(sni) = link.get_any(&["sni", "peer"]) {
        tls.insert("server_name".into(), json!(sni));
    }
    if link.any_flag(&["allow_insecure", "insecure", "allowInsecure"])? {
        tls.insert("insecure".into(), json!(true));
    }
    if let Some(alpn) = link.get("alpn") {
        tls.insert("alpn".into(), json!(split_list(alpn)));
    }
    parsed.insert("tls", tls);
    Ok(parsed)
}
