//! TLS over TCP, on BoringSSL.

pub mod client;
mod conn;
#[cfg(feature = "inbound-tls")]
pub mod inbound;
#[cfg(feature = "outbound-tls")]
pub mod outbound;

pub use client::TlsClient;
pub use conn::BoringConnection;

#[cfg(test)]
mod tests;
