//! Hysteria2: TCP and UDP proxied over QUIC, authenticated by an HTTP/3
//! request, with Brutal congestion control and optional Salamander
//! obfuscation.
//!
//! See <https://v2.hysteria.network/docs/developers/Protocol/>.

use serde_derive::Deserialize;

// Each end uses its part of what the two share.
#[cfg_attr(
    not(all(feature = "inbound-hysteria2", feature = "outbound-hysteria2")),
    allow(dead_code)
)]
mod h3;
#[cfg(feature = "outbound-hysteria2")]
mod hop;
#[cfg_attr(
    not(all(feature = "inbound-hysteria2", feature = "outbound-hysteria2")),
    allow(dead_code)
)]
mod proto;
#[cfg_attr(
    not(all(feature = "inbound-hysteria2", feature = "outbound-hysteria2")),
    allow(dead_code)
)]
mod quic;

mod congestion;
mod h3_tables;
mod salamander;

#[cfg(feature = "inbound-hysteria2")]
pub mod inbound;
#[cfg(feature = "outbound-hysteria2")]
pub mod outbound;

/// The `obfs` field: `{"type": "salamander", "password": "..."}`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Obfs {
    r#type: String,
    #[serde(default)]
    password: String,
}

impl Obfs {
    fn salamander(self) -> anyhow::Result<salamander::Salamander> {
        match self.r#type.as_str() {
            "salamander" if !self.password.is_empty() => {
                Ok(salamander::Salamander::new(&self.password))
            }
            "salamander" => Err(anyhow::anyhow!("password: missing")),
            other => Err(anyhow::anyhow!("type: unknown obfuscation \"{}\"", other)),
        }
    }
}
