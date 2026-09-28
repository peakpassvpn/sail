//! `vless://uuid@host:port?encryption=none&security=...&type=...#name`:
//! Xray's share link standard.
//!
//! Deviations from mihomo: a transport sail does not have (HTTP/2, TCP's
//! HTTP header, XHTTP, mKCP, QUIC, gRPC's multi mode) is an error, as is
//! VLESS encryption other than `none`, a flow other than Vision and
//! `packetEncoding=packet`; mihomo passes each on. An unset `fp` stays
//! unset, which in sail is Chrome, as mihomo makes it.

use anyhow::{anyhow, Result};

use super::url::{shown, Link};
use super::v2ray::Params;
use super::Parsed;

pub fn parse(link: &Link) -> Result<Parsed> {
    let uuid = link.user()?;
    check_uuid(&uuid)?;
    match link.get("encryption") {
        None | Some("none") => {}
        Some(_) => return Err(anyhow!("encryption: VLESS encryption is not supported")),
    }
    let mut parsed = Parsed::new("vless", link, link.port()?);
    parsed.insert("uuid", uuid);
    match link.get("flow") {
        None => {}
        Some(flow) if flow.eq_ignore_ascii_case("xtls-rprx-vision") => {
            parsed.insert("flow", "xtls-rprx-vision")
        }
        Some(other) => {
            return Err(anyhow!(
                "flow: {} is not supported, only xtls-rprx-vision",
                shown(other)
            ))
        }
    }
    // XUDP unless told otherwise, as in Xray and sing-box.
    match link.get("packetEncoding") {
        None | Some("xudp") => {}
        Some("none") => parsed.insert("packet_encoding", ""),
        Some("packet") => {
            return Err(anyhow!(
                "packetEncoding: packetaddr is not supported, only xudp"
            ))
        }
        Some(other) => return Err(anyhow!("packetEncoding: unknown {}", shown(other))),
    }
    let params = Params::of_link(link)?;
    params.apply(&mut parsed.outbound, "none")?;
    if parsed.outbound.contains_key("flow")
        && (!parsed.outbound.contains_key("tls") || parsed.outbound.contains_key("transport"))
    {
        return Err(anyhow!(
            "flow: xtls-rprx-vision needs tls or reality directly under vless, with no transport"
        ));
    }
    if parsed.outbound.contains_key("flow") && parsed.outbound.get("packet_encoding").is_some() {
        return Err(anyhow!(
            "packetEncoding: xtls-rprx-vision carries UDP only as xudp"
        ));
    }
    Ok(parsed)
}

pub fn check_uuid(uuid: &str) -> Result<()> {
    uuid::Uuid::parse_str(uuid)
        .map(|_| ())
        .map_err(|_| anyhow!("uuid: not a UUID"))
}
