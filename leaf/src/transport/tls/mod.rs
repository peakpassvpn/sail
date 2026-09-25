//! TLS over TCP, on BoringSSL.

pub mod client;
mod conn;
pub mod fingerprint;
#[cfg(test)]
pub(crate) mod hello;
#[cfg(feature = "inbound-tls")]
pub mod inbound;
#[cfg(feature = "outbound-tls")]
pub mod outbound;

pub use client::TlsClient;
pub use conn::BoringConnection;
pub use fingerprint::Fingerprint;

#[cfg(test)]
pub(crate) mod tests;
