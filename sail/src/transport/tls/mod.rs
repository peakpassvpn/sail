//! TLS over TCP, on BoringSSL.

pub mod client;
mod conn;
pub mod fingerprint;
#[cfg(test)]
pub(crate) mod hello;
#[cfg(feature = "inbound-tls")]
pub mod inbound;
pub mod options;
#[cfg(feature = "outbound-tls")]
pub mod outbound;
pub mod roots;

pub use client::TlsClient;
pub use conn::BoringConnection;
pub use fingerprint::Fingerprint;
pub use options::{ClientOptions, PublicKeyPins, TlsVersionRange};

#[cfg(test)]
pub(crate) mod tests;
