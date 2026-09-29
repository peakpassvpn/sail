//! Keys and passwords for configurations, as sing-box's `generate` makes
//! them, and what sail's own fields take: random bytes, UUIDs, X25519 key
//! pairs for REALITY and WireGuard, Shadowsocks 2022 keys and the Clash
//! API's secret. The command line's `sail generate` and hosts call these.

use anyhow::{anyhow, Result};
use rand::RngCore;

/// `len` random bytes, from the operating system's generator.
pub fn random(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes
}

/// A random (version 4) UUID, as VLESS, VMess and TUIC users take.
pub fn uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// A key for the Shadowsocks 2022 `method`, base64, of the length it
/// takes: 16 bytes for `2022-blake3-aes-128-gcm`, 32 for the others.
pub fn ss2022_key(method: &str) -> Result<String> {
    let len = match method {
        "2022-blake3-aes-128-gcm" => 16,
        "2022-blake3-aes-256-gcm" | "2022-blake3-chacha20-poly1305" => 32,
        other => {
            return Err(anyhow!(
                "not a Shadowsocks 2022 method: {} (2022-blake3-aes-128-gcm, \
                 2022-blake3-aes-256-gcm or 2022-blake3-chacha20-poly1305)",
                other
            ))
        }
    };
    Ok(base64(&random(len), Alphabet::Standard))
}

/// The fewest characters a Clash API secret has, and the fewest distinct
/// ones: a secret made by [`secret`] has 43, of 64.
pub const SECRET_MIN_LEN: usize = 32;
const SECRET_MIN_DISTINCT: usize = 10;

/// A secret for the Clash API: 32 random bytes, base64url without padding,
/// which a dashboard's address may carry as it is.
pub fn secret() -> String {
    base64(&random(32), Alphabet::UrlNoPad)
}

/// Why `secret` is too weak for the Clash API, if it is: fewer than 32
/// characters, or than 10 distinct ones, as a guessed or typed one would
/// have.
pub fn weak_secret(secret: &str) -> Option<String> {
    let len = secret.chars().count();
    if len < SECRET_MIN_LEN {
        return Some(format!("{} characters, fewer than {}", len, SECRET_MIN_LEN));
    }
    let mut distinct: Vec<char> = secret.chars().collect();
    distinct.sort_unstable();
    distinct.dedup();
    if distinct.len() < SECRET_MIN_DISTINCT {
        return Some(format!(
            "{} distinct characters, fewer than {}",
            distinct.len(),
            SECRET_MIN_DISTINCT
        ));
    }
    None
}

/// An X25519 key pair: private and public keys.
#[cfg(feature = "btls-sys")]
pub fn x25519_keypair() -> ([u8; 32], [u8; 32]) {
    let mut private = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut private);
    // Clamped, as RFC 7748 and WireGuard have a private key.
    private[0] &= 248;
    private[31] &= 127;
    private[31] |= 64;
    let mut public = [0u8; 32];
    // SAFETY: both buffers are 32 bytes, as X25519 keys are.
    unsafe { btls_sys::X25519_public_from_private(public.as_mut_ptr(), private.as_ptr()) };
    (private, public)
}

/// A REALITY key pair, base64url without padding, as sing-box and Xray
/// write them: the server's private key, and the clients' public key.
#[cfg(feature = "btls-sys")]
pub fn reality_keypair() -> (String, String) {
    let (private, public) = x25519_keypair();
    (
        base64(&private, Alphabet::UrlNoPad),
        base64(&public, Alphabet::UrlNoPad),
    )
}

/// A WireGuard key pair, standard base64, as WireGuard writes them.
#[cfg(feature = "btls-sys")]
pub fn wireguard_keypair() -> (String, String) {
    let (private, public) = x25519_keypair();
    (
        base64(&private, Alphabet::Standard),
        base64(&public, Alphabet::Standard),
    )
}

/// How [`base64`] writes.
#[derive(Clone, Copy, PartialEq)]
pub enum Alphabet {
    /// `+` and `/`, padded with `=`.
    Standard,
    /// `-` and `_`, unpadded.
    UrlNoPad,
}

/// `bytes`, base64.
pub fn base64(bytes: &[u8], alphabet: Alphabet) -> String {
    let table: &[u8; 64] = match alphabet {
        Alphabet::Standard => b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
        Alphabet::UrlNoPad => b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
    };
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let mut acc = 0u32;
        for (i, b) in chunk.iter().enumerate() {
            acc |= u32::from(*b) << (16 - 8 * i);
        }
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(table[(acc >> (18 - 6 * i) & 63) as usize]));
            } else if alphabet == Alphabet::Standard {
                out.push('=');
            }
        }
    }
    out
}

/// `bytes`, lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_is_rfc_4648_s() {
        // RFC 4648 section 10.
        for (plain, standard) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(plain.as_bytes(), Alphabet::Standard), standard);
            assert_eq!(
                base64(plain.as_bytes(), Alphabet::UrlNoPad),
                standard.trim_end_matches('=')
            );
        }
        assert_eq!(base64(&[0xfb, 0xff], Alphabet::Standard), "+/8=");
        assert_eq!(base64(&[0xfb, 0xff], Alphabet::UrlNoPad), "-_8");
        assert_eq!(hex(&[0, 0xab, 0x10]), "00ab10");
    }

    #[test]
    fn keys_are_of_their_lengths() {
        assert_eq!(random(7).len(), 7);
        assert_ne!(random(16), random(16));
        assert_eq!(uuid::Uuid::parse_str(&uuid()).unwrap().get_version_num(), 4);
        assert_eq!(ss2022_key("2022-blake3-aes-128-gcm").unwrap().len(), 24);
        assert_eq!(ss2022_key("2022-blake3-aes-256-gcm").unwrap().len(), 44);
        assert!(ss2022_key("aes-256-gcm").is_err());
        let secret = secret();
        assert_eq!(secret.len(), 43);
        assert_eq!(weak_secret(&secret), None);
    }

    #[test]
    fn weak_secrets_are_told() {
        assert!(weak_secret("").is_some());
        assert!(weak_secret("123456").is_some());
        assert!(weak_secret(&"a".repeat(40)).unwrap().contains("distinct"));
        assert!(weak_secret("abababababababababababababababababab").is_some());
        assert_eq!(
            weak_secret("Tr0ub4dor&3-correct-horse-battery-staple"),
            None
        );
    }

    #[cfg(feature = "btls-sys")]
    #[test]
    fn key_pairs_agree() {
        let (private, public) = x25519_keypair();
        // The public key is the private one's, as X25519 gives it.
        let mut again = [0u8; 32];
        unsafe { btls_sys::X25519_public_from_private(again.as_mut_ptr(), private.as_ptr()) };
        assert_eq!(public, again);
        let (private, public) = reality_keypair();
        assert_eq!((private.len(), public.len()), (43, 43));
        let (private, public) = wireguard_keypair();
        assert_eq!((private.len(), public.len()), (44, 44));
    }
}
