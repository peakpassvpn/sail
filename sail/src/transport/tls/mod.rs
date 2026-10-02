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

/// Runs `f`, the body of a callback BoringSSL calls. A panic would
/// unwind through C, which aborts the process whatever the panic
/// strategy: here it fails that handshake, as `failed` says, and the
/// instance goes on.
pub(crate) fn guarded<T>(failed: impl FnOnce() -> T, f: impl FnOnce() -> T) -> T {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or_else(|_| {
        tracing::error!("tls: a callback panicked; the handshake fails");
        failed()
    })
}

pub use client::TlsClient;
pub use conn::BoringConnection;
pub use fingerprint::Fingerprint;
pub use options::{CertificatePins, ClientOptions, Pins, PublicKeyPins, TlsVersionRange};

#[cfg(test)]
pub(crate) mod tests;
