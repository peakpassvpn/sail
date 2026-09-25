//! Proxy protocols. Each protocol keeps its inbound and outbound side
//! together in one directory.

#[cfg(any(feature = "inbound-anytls", feature = "outbound-anytls"))]
pub mod anytls;
#[cfg(feature = "outbound-direct")]
pub mod direct;
#[cfg(feature = "outbound-drop")]
pub mod drop;
#[cfg(feature = "inbound-hc")]
pub mod hc;
#[cfg(any(feature = "inbound-http", feature = "outbound-http"))]
pub mod http;
#[cfg(any(feature = "inbound-hysteria2", feature = "outbound-hysteria2"))]
pub mod hysteria2;
#[cfg(feature = "inbound-mixed")]
pub mod mixed;
#[cfg(feature = "outbound-mptp")]
pub mod mptp;
#[cfg(all(feature = "inbound-nf", windows))]
pub mod nf;
#[cfg(feature = "outbound-redirect")]
pub mod redirect;
#[cfg(any(feature = "inbound-shadowsocks", feature = "outbound-shadowsocks"))]
pub mod shadowsocks;
#[cfg(any(feature = "inbound-socks", feature = "outbound-socks"))]
pub mod socks;
#[cfg(any(feature = "inbound-trojan", feature = "outbound-trojan"))]
pub mod trojan;
#[cfg(any(feature = "inbound-tuic", feature = "outbound-tuic"))]
pub mod tuic;
#[cfg(feature = "inbound-tun")]
pub mod tun;
#[cfg(feature = "outbound-vless")]
pub mod vless;
#[cfg(feature = "outbound-vmess")]
pub mod vmess;

pub mod group;
