//! `trojan://password@host:port?security=...&type=...#name`: trojan-gfw's
//! link, with Xray's TLS, REALITY and transport parameters. TLS unless
//! `security=none`.
//!
//! Deviations from mihomo: `security` is read (mihomo always takes TLS and
//! drops REALITY), `insecure` counts as well as `allowInsecure`, and
//! `httpupgrade` is carried over; mihomo keeps only ws and grpc.

use anyhow::Result;

use super::url::Link;
use super::v2ray::Params;
use super::Parsed;

pub fn parse(link: &Link) -> Result<Parsed> {
    let password = link.user()?;
    let mut parsed = Parsed::new("trojan", link, link.port()?);
    parsed.insert("password", password);
    Params::of_link(link)?.apply(&mut parsed.outbound, "tls")?;
    Ok(parsed)
}
