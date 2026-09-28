//! `anytls://password@host:port/?sni=...&insecure=1#name`: anytls-go's
//! link. Always TLS.
//!
//! Deviations from mihomo: the userinfo is the password, all of it, as the
//! scheme has it; mihomo takes what follows a `:` in it. `hpkp` (a pinned
//! public key hash) is an error, for sail cannot pin one, where mihomo
//! checks it.

use anyhow::{anyhow, Result};
use serde_json::{json, Map};

use super::url::Link;
use super::v2ray::{fingerprint, split_list};
use super::Parsed;

pub fn parse(link: &Link) -> Result<Parsed> {
    let password = link.user()?;
    if link.get("hpkp").is_some() {
        return Err(anyhow!("hpkp: sail cannot pin a public key's hash"));
    }
    let mut parsed = Parsed::new("anytls", link, link.port()?);
    parsed.insert("password", password);
    let mut tls = Map::new();
    tls.insert("enabled".into(), json!(true));
    if let Some(sni) = link.get_any(&["sni", "peer"]) {
        tls.insert("server_name".into(), json!(sni));
    }
    if link.any_flag(&["insecure", "allowInsecure"])? {
        tls.insert("insecure".into(), json!(true));
    }
    if let Some(alpn) = link.get("alpn") {
        tls.insert("alpn".into(), json!(split_list(alpn)));
    }
    if let Some(fp) = link.get("fp") {
        tls.insert(
            "utls".into(),
            json!({ "enabled": true, "fingerprint": fingerprint(fp)? }),
        );
    }
    parsed.insert("tls", tls);
    Ok(parsed)
}
