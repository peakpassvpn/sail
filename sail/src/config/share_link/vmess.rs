//! `vmess://`: v2rayN's base64 JSON (`v`, `ps`, `add`, `port`, `id`, `aid`,
//! `scy`, `net`, `type`, `host`, `path`, `tls`, `sni`, `alpn`, `fp`), or a
//! URL as Xray's share link standard writes VLESS's, `encryption` naming
//! the cipher.
//!
//! Deviations from mihomo: an `aid` other than 0 (legacy VMess) is an
//! error, not passed on; so are a cipher sail does not have and the
//! transports it does not (`net` h2 or http, `type` http over tcp, kcp,
//! quic, xhttp). A JSON link without `ps` is named by its host, not
//! dropped. UDP goes as XUDP, as mihomo sends it.

use anyhow::{anyhow, Result};
use serde_json::Value;

use super::url::{base64_decode, parse_bool, parse_port, shown, Link};
use super::v2ray::Params;
use super::vless::check_uuid;
use super::Parsed;

/// A v2rayN link, or `None` if `body` is not base64.
pub fn parse_v2rayn(body: &str) -> Result<Option<Parsed>> {
    let encoded = body.split('#').next().unwrap_or_default().trim();
    let Some(decoded) = base64_decode(encoded) else {
        return Ok(None);
    };
    let json: Value =
        serde_json::from_slice(&decoded).map_err(|_| anyhow!("the base64 is not v2rayN's JSON"))?;
    let Value::Object(fields) = json else {
        return Err(anyhow!("the base64 is not v2rayN's JSON object"));
    };
    // Numbers are written as numbers or as strings.
    let text = |key: &str| -> Option<String> {
        match fields.get(key) {
            Some(Value::String(s)) if !s.trim().is_empty() => Some(s.trim().to_string()),
            Some(Value::Number(n)) => Some(n.to_string()),
            Some(Value::Bool(b)) => Some(b.to_string()),
            _ => None,
        }
    };

    let host = text("add").ok_or_else(|| anyhow!("add: missing"))?;
    let port = parse_port(&text("port").ok_or_else(|| anyhow!("port: missing"))?)?;
    let uuid = text("id").ok_or_else(|| anyhow!("id: missing"))?;
    check_uuid(&uuid).map_err(|_| anyhow!("id: not a UUID"))?;
    match text("aid").as_deref() {
        None | Some("0") => {}
        Some(_) => {
            return Err(anyhow!(
                "aid: legacy VMess (alterId other than 0) is not supported"
            ))
        }
    }
    // The address as a link would hold it, for the host checks.
    let authority = if host.contains(':') && !host.starts_with('[') {
        format!("vmess://[{}]:{}", host, port)
    } else {
        format!("vmess://{}:{}", host, port)
    };
    let link = Link::parse(&authority).map_err(|e| anyhow!("add: {}", e))?;

    let network = text("net").map(|n| n.to_ascii_lowercase());
    let kind = text("type").map(|t| t.to_ascii_lowercase());
    let grpc = matches!(network.as_deref(), Some("grpc"));
    let insecure = ["allowInsecure", "insecure", "skip-cert-verify"]
        .iter()
        .filter_map(|k| text(k))
        .any(|v| parse_bool(&v) == Some(true));
    let params = Params {
        security: text("tls").map(|t| t.to_ascii_lowercase()),
        sni: text("sni"),
        fp: text("fp"),
        alpn: text("alpn"),
        insecure,
        pbk: text("pbk"),
        sid: text("sid"),
        network,
        // For gRPC, `type` is its mode.
        header_type: if grpc { None } else { kind.clone() },
        mode: if grpc { kind } else { None },
        host: text("host"),
        path: text("path"),
        ..Params::default()
    };

    let mut parsed = Parsed::new("vmess", &link, port);
    parsed.name = text("ps");
    parsed.insert("uuid", uuid);
    parsed.insert("security", security("scy", text("scy").as_deref())?);
    parsed.insert("packet_encoding", "xudp");
    params.apply(&mut parsed.outbound, "none")?;
    Ok(Some(parsed))
}

/// An Xray-style VMess link.
pub fn parse_xray(link: &Link) -> Result<Parsed> {
    let uuid = link.user()?;
    check_uuid(&uuid)?;
    let mut parsed = Parsed::new("vmess", link, link.port()?);
    parsed.insert("uuid", uuid);
    parsed.insert("security", security("encryption", link.get("encryption"))?);
    parsed.insert("packet_encoding", "xudp");
    Params::of_link(link)?.apply(&mut parsed.outbound, "none")?;
    Ok(parsed)
}

/// The cipher, as sail's VMess takes it.
fn security(field: &str, scy: Option<&str>) -> Result<String> {
    let scy = scy.unwrap_or("auto").to_ascii_lowercase();
    match scy.as_str() {
        "auto" | "aes-128-gcm" | "chacha20-poly1305" | "none" | "zero" => Ok(scy),
        "chacha20-ietf-poly1305" => Ok("chacha20-poly1305".into()),
        _ => Err(anyhow!(
            "{}: sail has no VMess cipher {}, only auto, aes-128-gcm, chacha20-poly1305, none and zero",
            field,
            shown(&scy)
        )),
    }
}
