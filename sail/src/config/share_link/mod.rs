//! Share links, and subscriptions of them, read into sing-box outbounds:
//! an importer, not a configuration format. Each outbound holds only the
//! fields sail's outbounds take, so a configuration listing them loads as
//! it is; what sail does not implement, or a link that is wrong, is an
//! error, not a field quietly left out.
//!
//! The links, as the tools that write them have it (where they disagree,
//! mihomo's `common/convert/converter.go`, the most widely used reader,
//! decides, but for the deviations noted with each scheme):
//!
//! - `ss://`: SIP002 (<https://shadowsocks.org/doc/sip002.html>), its
//!   userinfo base64 or, for the 2022 ciphers (SIP022), a percent-encoded
//!   `method:password`; and the older all-base64 form.
//! - `trojan://`: trojan-gfw's (<https://trojan-gfw.github.io/trojan/url>)
//!   with Xray's parameters.
//! - `vless://`, and `vmess://` written the same way: Xray's share link
//!   standard (<https://github.com/XTLS/Xray-core/discussions/716>).
//! - `vmess://` with base64 JSON: v2rayN's
//!   (<https://github.com/2dust/v2rayN/wiki/分享链接格式说明(ver-2)>).
//! - `hysteria2://`, `hy2://`: Hysteria's
//!   (<https://v2.hysteria.network/docs/developers/URI-Scheme/>).
//! - `tuic://`: TUIC v5's, as dae proposed it
//!   (<https://github.com/daeuniverse/dae/discussions/182>).
//! - `anytls://`: anytls-go's
//!   (<https://github.com/anytls/anytls-go/blob/main/docs/uri_scheme.md>).
//!
//! No error or warning holds a password, a UUID, a key or the link itself:
//! they may well be logged.

mod anytls;
mod hysteria2;
mod shadowsocks;
mod trojan;
mod tuic;
mod url;
mod v2ray;
mod vless;
mod vmess;

#[cfg(test)]
mod tests;

use std::collections::HashSet;

use anyhow::{anyhow, Result};
use serde_json::{Map, Value};

use url::Link;

/// An outbound read from a link, before it is tagged.
struct Parsed {
    outbound: Map<String, Value>,
    /// What the link names it, if anything.
    name: Option<String>,
    host: String,
    port: u16,
}

impl Parsed {
    /// An outbound of `protocol` to the server `link` names.
    fn new(protocol: &str, link: &Link, port: u16) -> Self {
        let mut outbound = Map::new();
        outbound.insert("type".into(), protocol.into());
        outbound.insert("tag".into(), "".into());
        outbound.insert("server".into(), link.host.clone().into());
        outbound.insert("server_port".into(), port.into());
        Parsed {
            outbound,
            name: link.fragment.clone(),
            host: link.host.clone(),
            port,
        }
    }

    fn insert(&mut self, key: &str, value: impl Into<Value>) {
        self.outbound.insert(key.into(), value.into());
    }

    fn tagged(mut self, tag: String) -> Value {
        self.outbound.insert("tag".into(), tag.into());
        Value::Object(self.outbound)
    }
}

/// Reads one share link into a sing-box outbound. Its tag is the link's
/// name (its `#fragment`, or a VMess link's `ps`), else the server's host.
pub fn parse(uri: &str) -> Result<Value> {
    let parsed = parse_one(uri.trim())?;
    let tag = parsed.name.clone().unwrap_or_else(|| parsed.host.clone());
    Ok(parsed.tagged(tag))
}

fn parse_one(uri: &str) -> Result<Parsed> {
    let Some((scheme, body)) = uri.split_once("://") else {
        return Err(anyhow!("not a share link"));
    };
    let scheme = scheme.to_ascii_lowercase();
    let parsed = match scheme.as_str() {
        // Its older form is all base64, not a URL.
        "ss" => shadowsocks::parse(uri, body),
        // v2rayN's is base64 JSON; Xray's a URL.
        "vmess" => match vmess::parse_v2rayn(body) {
            Ok(Some(parsed)) => Ok(parsed),
            Ok(None) => Link::parse(uri).and_then(|link| vmess::parse_xray(&link)),
            Err(e) => Err(e),
        },
        "trojan" | "vless" | "hysteria2" | "hy2" | "tuic" | "anytls" => {
            Link::parse(uri).and_then(|link| match scheme.as_str() {
                "trojan" => trojan::parse(&link),
                "vless" => vless::parse(&link),
                "tuic" => tuic::parse(&link),
                "anytls" => anytls::parse(&link),
                _ => hysteria2::parse(&link),
            })
        }
        _ => return Err(unsupported(&scheme)),
    };
    parsed.map_err(|e| anyhow!("{}: {}", scheme, e))
}

fn unsupported(scheme: &str) -> anyhow::Error {
    let why = match scheme {
        "ssr" => "ShadowsocksR is not supported",
        "hysteria" => "Hysteria v1 is not supported, only Hysteria2",
        "wireguard" | "wg" => {
            "a WireGuard link describes an endpoint, which is not imported; \
             write it into endpoints"
        }
        "hysteria2+realm" | "hy2+realm" => "Hysteria2 realms are not supported",
        _ => return anyhow!("unknown scheme {}", url::shown(scheme)),
    };
    anyhow!("{}: {}", scheme, why)
}

/// Reads a subscription: share links one to a line, the whole perhaps
/// base64 (standard or URL-safe, padded or not, with line breaks or
/// not). Blank lines, comments (`#` or `//`) and Shadowrocket's
/// `STATUS=` / `REMARKS=` lines are skipped. Returns an outbound for each
/// link read, and a warning for each line that is not one, by its number.
///
/// Tags are unique: a link without a name is tagged by its host, or by its
/// host and port if another has the host; a tag taken already gets " 2",
/// " 3" and so on after it.
pub fn parse_subscription(body: &str) -> (Vec<Value>, Vec<String>) {
    let body = body.trim_start_matches('\u{feff}');
    let decoded;
    let text = if body.contains("://") {
        body
    } else {
        match url::base64_decode(body.trim()).map(String::from_utf8) {
            Some(Ok(s)) => {
                decoded = s;
                decoded.trim_start_matches('\u{feff}')
            }
            _ => body,
        }
    };

    let mut outbounds = Vec::new();
    let mut warnings = Vec::new();
    let mut tags = HashSet::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with("//")
            || line.starts_with("STATUS=")
            || line.starts_with("REMARKS=")
        {
            continue;
        }
        let parsed = match parse_one(line) {
            Ok(parsed) => parsed,
            Err(e) => {
                warnings.push(format!("line {}: {}", i + 1, e));
                continue;
            }
        };
        let tag = match &parsed.name {
            Some(name) => unique(&tags, name),
            None if !tags.contains(&parsed.host) => parsed.host.clone(),
            None => {
                let host_port = if parsed.host.contains(':') {
                    format!("[{}]:{}", parsed.host, parsed.port)
                } else {
                    format!("{}:{}", parsed.host, parsed.port)
                };
                unique(&tags, &host_port)
            }
        };
        tags.insert(tag.clone());
        outbounds.push(parsed.tagged(tag));
    }
    (outbounds, warnings)
}

/// `name`, or if it is taken, `name 2`, `name 3`, ...
fn unique(taken: &HashSet<String>, name: &str) -> String {
    if !taken.contains(name) {
        return name.to_string();
    }
    (2..)
        .map(|n| format!("{} {}", name, n))
        .find(|t| !taken.contains(t))
        .expect("some number is free")
}
