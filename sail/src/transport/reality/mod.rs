//! REALITY: TLS that authenticates the client in the ClientHello session ID
//! and the server with a certificate only the client can check.

#[cfg(feature = "inbound-reality")]
pub mod inbound;
#[cfg(feature = "outbound-reality")]
pub mod outbound;
#[cfg(feature = "inbound-reality")]
mod shape;

#[cfg(feature = "outbound-reality")]
pub use outbound::Handler as StreamHandler;

use anyhow::{anyhow, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

/// The version a client reports in its session ID; servers can require a
/// range.
pub const CLIENT_VERSION: [u8; 3] = [26, 9, 8];

/// An X25519 key, hex or base64url as Xray writes it; `field` names it in
/// errors.
pub fn parse_key(field: &str, key: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(key)
        .or_else(|_| URL_SAFE_NO_PAD.decode(key))
        .map_err(|_| anyhow!("{}: neither hex nor base64url", field))?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("{}: must be 32 bytes", field))
}

/// A short ID: up to 16 hex digits, the missing ones zeros at the end, as
/// Xray reads it.
pub fn parse_short_id(short_id: &str) -> Result<[u8; 8]> {
    if short_id.len() > 16 {
        return Err(anyhow!("short_id: at most 16 hex digits"));
    }
    let mut out = [0u8; 8];
    let padded = format!("{:0<16}", short_id);
    hex::decode_to_slice(&padded, &mut out).map_err(|_| anyhow!("short_id: not hex"))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_keys() {
        let key = [7u8; 32];
        assert_eq!(parse_key("k", &hex::encode(key)).unwrap(), key);
        assert_eq!(parse_key("k", &URL_SAFE_NO_PAD.encode(key)).unwrap(), key);
        assert!(parse_key("k", "abcd").is_err());
        assert_eq!(parse_short_id("ab").unwrap(), [0xab, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(parse_short_id("").unwrap(), [0; 8]);
        assert!(parse_short_id("0123456789abcdef0").is_err());
        assert!(parse_short_id("zz").is_err());
    }
}
