//! Layers a protocol runs over: security, framing, multiplexing and
//! obfuscation.

#[cfg(any(feature = "inbound-amux", feature = "outbound-amux"))]
pub mod amux;
#[cfg(feature = "outbound-obfs")]
pub mod obfs;
#[cfg(any(feature = "inbound-quic", feature = "outbound-quic"))]
pub mod quic;
#[cfg(feature = "outbound-reality")]
pub mod reality;
#[cfg(feature = "outbound-tls")]
pub mod tls;
#[cfg(any(
    feature = "outbound-reality",
    all(feature = "outbound-tls", feature = "rustls-tls")
))]
pub mod tls_stream;
#[cfg(any(feature = "inbound-ws", feature = "outbound-ws"))]
pub mod ws;
