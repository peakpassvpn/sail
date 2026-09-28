//! `ss://`: SIP002, `ss://userinfo@host:port/?plugin=...#name`, the
//! userinfo base64 of `method:password` or, as SIP022 has it for the 2022
//! ciphers, `method:password` percent-encoded; and the form before SIP002,
//! `ss://base64(method:password@host:port)#name`.
//!
//! Deviations from mihomo: a plugin sail does not have (v2ray-plugin and
//! the rest) is an error where mihomo leaves it out or keeps it, and a
//! cipher sail does not have is an error at once. `uot=1` is UDP over TCP
//! version 2, sing-box's default.

use anyhow::{anyhow, Result};
use serde_json::json;

use super::url::{base64_decode, decode_utf8, shown, Link};
use super::Parsed;

/// The ciphers sail's Shadowsocks has.
const METHODS: &[&str] = &[
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "chacha20-poly1305",
];

/// `uri` is the whole link, `body` what follows `ss://`.
pub fn parse(uri: &str, body: &str) -> Result<Parsed> {
    let before_fragment = body.split('#').next().unwrap_or_default();
    let before_query = before_fragment.split('?').next().unwrap_or_default();
    let (link, method, password) = if before_query.contains('@') {
        let link = Link::parse(uri)?;
        let userinfo = link.userinfo.unwrap_or_default();
        let (method, password) = credentials(userinfo)?;
        (link, method, password)
    } else {
        // The whole of it base64: `method:password@host:port`.
        let decoded = base64_decode(before_query.trim_end_matches('/'))
            .and_then(|d| String::from_utf8(d).ok())
            .ok_or_else(|| anyhow!("neither SIP002 nor base64"))?;
        let (userinfo, server) = decoded
            .rsplit_once('@')
            .ok_or_else(|| anyhow!("the base64 holds no @host:port"))?;
        let (method, password) = userinfo
            .split_once(':')
            .ok_or_else(|| anyhow!("the base64 holds no method:password"))?;
        let rest = &before_fragment[before_query.len()..];
        let fragment = &body[before_fragment.len()..];
        let rebuilt = format!("ss://{}/{}{}", server, rest, fragment);
        let link = Link::parse(&rebuilt).map_err(|_| anyhow!("the base64 holds no host:port"))?;
        return finish(&link, method.to_string(), password.to_string());
    };
    finish(&link, method, password)
}

/// The method and password of a SIP002 userinfo.
fn credentials(userinfo: &str) -> Result<(String, String)> {
    let plain = decode_utf8(userinfo, "credentials")?;
    let pair = if plain.contains(':') {
        plain
    } else {
        base64_decode(userinfo)
            .and_then(|d| String::from_utf8(d).ok())
            .ok_or_else(|| anyhow!("credentials: neither method:password nor its base64"))?
    };
    let (method, password) = pair
        .split_once(':')
        .ok_or_else(|| anyhow!("credentials: no method:password"))?;
    Ok((method.to_string(), password.to_string()))
}

fn finish(link: &Link, method: String, password: String) -> Result<Parsed> {
    let method = method.to_ascii_lowercase();
    if !METHODS.contains(&method.as_str()) {
        return Err(anyhow!(
            "method: sail has no cipher {} (it has {})",
            shown(&method),
            METHODS.join(", ")
        ));
    }
    if password.is_empty() {
        return Err(anyhow!("password: missing"));
    }
    let mut parsed = Parsed::new("shadowsocks", link, link.port()?);
    parsed.insert("method", method);
    parsed.insert("password", password);
    if let Some(plugin) = link.get("plugin") {
        let (name, opts) = plugin.split_once(';').unwrap_or((plugin, ""));
        match name.trim() {
            "obfs-local" | "simple-obfs" => {
                check_obfs(opts)?;
                parsed.insert("plugin", "obfs-local");
                if !opts.is_empty() {
                    parsed.insert("plugin_opts", opts);
                }
            }
            "" => {}
            other => {
                return Err(anyhow!(
                    "plugin: sail has no plugin {}, only obfs-local",
                    shown(other)
                ))
            }
        }
    }
    if link.flag("uot")? || link.flag("udp-over-tcp")? {
        parsed.insert("udp_over_tcp", json!(true));
    }
    Ok(parsed)
}

/// simple-obfs' options, as sail's `obfs-local` takes them.
fn check_obfs(opts: &str) -> Result<()> {
    let mut mode = None;
    for opt in opts.split(';').map(str::trim).filter(|o| !o.is_empty()) {
        match opt.split_once('=') {
            Some(("obfs", m)) => mode = Some(m),
            Some(("obfs-host" | "obfs-uri", _)) => {}
            Some((key, _)) => {
                return Err(anyhow!("plugin: obfs-local has no option {}", shown(key)))
            }
            None => return Err(anyhow!("plugin: an option is not key=value")),
        }
    }
    match mode {
        Some("http" | "tls") => Ok(()),
        Some(other) => Err(anyhow!(
            "plugin: obfs {}: expected http or tls",
            shown(other)
        )),
        None => Err(anyhow!("plugin: obfs-local needs obfs=http or obfs=tls")),
    }
}
