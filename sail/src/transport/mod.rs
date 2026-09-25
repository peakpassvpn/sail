//! Layers a protocol runs over: security, framing, multiplexing and
//! obfuscation.

#[cfg(any(feature = "inbound-amux", feature = "outbound-amux"))]
pub mod amux;
#[cfg(any(feature = "inbound-ws", feature = "outbound-ws"))]
pub mod httpupgrade;
#[cfg(feature = "outbound-obfs")]
pub mod obfs;
#[cfg(any(feature = "inbound-quic", feature = "outbound-quic"))]
pub mod quic;
#[cfg(feature = "outbound-reality")]
pub mod reality;
#[cfg(feature = "tls")]
pub mod tls;
#[cfg(feature = "tls")]
pub mod tls_stream;
#[cfg(any(feature = "inbound-ws", feature = "outbound-ws"))]
pub mod ws;

pub mod layers;
#[cfg(any(
    feature = "outbound-vless",
    feature = "outbound-reality",
    feature = "tls"
))]
pub mod vision;
