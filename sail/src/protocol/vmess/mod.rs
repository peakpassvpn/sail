//! VMess, AEAD headers only, and XUDP, which VLESS shares.

#[cfg(any(feature = "inbound-vmess", feature = "outbound-vmess"))]
mod body;
#[cfg(any(feature = "inbound-vmess", feature = "outbound-vmess"))]
mod header;
#[cfg(any(feature = "inbound-vmess", feature = "outbound-vmess"))]
mod kdf;
pub mod xudp;

#[cfg(feature = "inbound-vmess")]
pub mod inbound;
#[cfg(feature = "outbound-vmess")]
pub mod outbound;
