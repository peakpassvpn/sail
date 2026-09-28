//! The pieces of a share link, read as the link tools write them rather
//! than as RFC 3986 would have them: a standard-base64 userinfo may hold
//! `/`, Hysteria2 puts a list of ports where the port goes, and a query's
//! `+` is a space, as Go's `url.Query` reads it.

use anyhow::{anyhow, Result};

/// A share link, split up.
pub struct Link<'a> {
    /// As written: each scheme decodes it its own way.
    pub userinfo: Option<&'a str>,
    /// Without the brackets of an IPv6 address.
    pub host: String,
    /// As written; a scheme may take a list of ports.
    pub port: Option<&'a str>,
    query: Vec<(String, String)>,
    /// Percent-decoded, trimmed; `None` when missing or blank.
    pub fragment: Option<String>,
}

impl<'a> Link<'a> {
    pub fn parse(s: &'a str) -> Result<Self> {
        let (_, rest) = s.split_once("://").ok_or_else(|| anyhow!("not a link"))?;
        let (rest, fragment) = match rest.split_once('#') {
            Some((rest, fragment)) => (rest, Some(fragment)),
            None => (rest, None),
        };
        let (rest, query) = match rest.split_once('?') {
            Some((rest, query)) => (rest, query),
            None => (rest, ""),
        };
        // The userinfo runs to the last `@`: a base64 one may hold `/`.
        let (userinfo, rest) = match rest.rsplit_once('@') {
            Some((userinfo, rest)) => (Some(userinfo), rest),
            None => (None, rest),
        };
        // The path means nothing to any of the schemes.
        let authority = rest.split('/').next().unwrap_or_default();
        let (host, port) = split_host_port(authority)?;
        let fragment = fragment
            .map(|f| {
                String::from_utf8_lossy(&percent_decode(f, false))
                    .trim()
                    .to_string()
            })
            .filter(|f| !f.is_empty());
        Ok(Link {
            userinfo,
            host,
            port,
            query: parse_query(query)?,
            fragment,
        })
    }

    /// The first value of the query parameter `key`, if set and not empty.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.query
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .filter(|v| !v.is_empty())
    }

    /// The first of `keys` that is set.
    pub fn get_any(&self, keys: &[&str]) -> Option<&str> {
        keys.iter().find_map(|k| self.get(k))
    }

    /// Whether the boolean parameter `key` is on: `1` or `true`.
    pub fn flag(&self, key: &str) -> Result<bool> {
        match self.get(key) {
            None => Ok(false),
            Some(v) => parse_bool(v).ok_or_else(|| anyhow!("{}: not a boolean", key)),
        }
    }

    /// Whether any of the boolean parameters `keys` is on.
    pub fn any_flag(&self, keys: &[&str]) -> Result<bool> {
        for key in keys {
            if self.flag(key)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// The one port, required.
    pub fn port(&self) -> Result<u16> {
        match self.port {
            None => Err(anyhow!("port: missing")),
            Some(p) => parse_port(p),
        }
    }

    /// The userinfo, percent-decoded, required.
    pub fn user(&self) -> Result<String> {
        match self.userinfo {
            None | Some("") => Err(anyhow!("missing the credentials before @")),
            Some(u) => decode_utf8(u, "credentials"),
        }
    }
}

pub fn parse_bool(v: &str) -> Option<bool> {
    match v.to_ascii_lowercase().as_str() {
        "1" | "true" => Some(true),
        "0" | "false" => Some(false),
        _ => None,
    }
}

pub fn parse_port(p: &str) -> Result<u16> {
    match p.parse::<u16>() {
        Ok(port) if port != 0 => Ok(port),
        _ => Err(anyhow!("port: not a port")),
    }
}

/// A host and its port: `host`, `host:port`, `[v6]` or `[v6]:port`.
fn split_host_port(authority: &str) -> Result<(String, Option<&str>)> {
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, rest) = rest
            .split_once(']')
            .ok_or_else(|| anyhow!("host: unclosed ["))?;
        let port = match rest {
            "" => None,
            _ => Some(
                rest.strip_prefix(':')
                    .ok_or_else(|| anyhow!("host: text after ]"))?,
            ),
        };
        if host.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(anyhow!("host: not an IPv6 address in []"));
        }
        (host.to_string(), port)
    } else {
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        };
        let host = String::from_utf8(percent_decode(host, false))
            .map_err(|_| anyhow!("host: not UTF-8"))?;
        if host.contains(':') {
            return Err(anyhow!("host: an IPv6 address needs []"));
        }
        (host, port)
    };
    if host.is_empty() {
        return Err(anyhow!("host: missing"));
    }
    if host
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || "/?#@[]\\\"".contains(c))
    {
        return Err(anyhow!("host: not a host name or address"));
    }
    Ok((host, port.filter(|p| !p.is_empty())))
}

fn parse_query(query: &str) -> Result<Vec<(String, String)>> {
    let mut pairs = Vec::new();
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let k = String::from_utf8(percent_decode(k, true))
            .map_err(|_| anyhow!("a query parameter's name is not UTF-8"))?;
        let v = String::from_utf8(percent_decode(v, true))
            .map_err(|_| anyhow!("{}: not UTF-8", shown(&k)))?;
        pairs.push((k, v));
    }
    Ok(pairs)
}

/// `s` percent-decoded as UTF-8; `what` names it in the error.
pub fn decode_utf8(s: &str, what: &str) -> Result<String> {
    String::from_utf8(percent_decode(s, false)).map_err(|_| anyhow!("{}: not UTF-8", what))
}

/// `s` with its `%XX` escapes decoded, and with `plus_is_space`, its `+`
/// as a space. A `%` not followed by two hex digits stands for itself.
pub fn percent_decode(s: &str, plus_is_space: bool) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => match (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                (Some(h), Some(l)) => {
                    out.push(h << 4 | l);
                    i += 3;
                    continue;
                }
                _ => out.push(b'%'),
            },
            b'+' if plus_is_space => out.push(b' '),
            b => out.push(b),
        }
        i += 1;
    }
    out
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// `s` decoded from base64, standard or URL-safe, padded or not, with any
/// whitespace in it skipped.
pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0;
    let mut padding = 0;
    let mut count = 0;
    for b in s.bytes() {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => {
                padding += 1;
                continue;
            }
            b' ' | b'\t' | b'\r' | b'\n' => continue,
            _ => return None,
        };
        // Nothing but padding after padding.
        if padding > 0 {
            return None;
        }
        count += 1;
        acc = acc << 6 | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    // A lone sixth of a byte is no encoding; nor is padding past a group.
    if count % 4 == 1 || padding > 2 || (padding > 0 && (count + padding) % 4 != 0) {
        return None;
    }
    Some(out)
}

/// `v` quoted, for an error, when it is a plain name -- a cipher, a
/// transport, a fingerprint -- and nothing that could be a secret.
pub fn shown(v: &str) -> String {
    if !v.is_empty()
        && v.len() <= 32
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
    {
        format!("\"{}\"", v)
    } else {
        "(a value not shown)".to_string()
    }
}
