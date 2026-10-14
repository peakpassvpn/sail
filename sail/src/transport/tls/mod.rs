//! TLS over TCP, on BoringSSL.

pub mod client;
pub mod client_auth;
mod conn;
#[cfg(any(feature = "outbound-tls", feature = "quic"))]
pub(crate) mod ech;
pub mod fingerprint;
#[cfg(test)]
pub(crate) mod hello;
#[cfg(feature = "inbound-tls")]
pub mod inbound;
pub mod options;
#[cfg(feature = "outbound-tls")]
pub mod outbound;
pub mod roots;
pub mod self_signed;

use btls::ssl::SslContextBuilder;
use btls::x509::verify::X509VerifyParamRef;
use btls::x509::X509StoreContextRef;

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

/// Has the SSLs of `builder`'s context verify certificates at the
/// instance's time (`crate::clock`), where BoringSSL reads the system's
/// clock: its own verification, run here in its place, with the time set
/// first. The time is read as a chain is verified, on the task running
/// that handshake, which is the instance's; the context, made before any
/// offset is measured, holds none. Every context that verifies a peer by
/// its CAs is given this, over TCP and over QUIC.
pub(crate) fn verify_at_instance_time(builder: &mut SslContextBuilder) {
    builder.set_cert_verify_callback(|context: &mut X509StoreContextRef| {
        guarded(
            || false,
            || {
                at_instance_time(context.verify_param_mut());
                matches!(context.verify_cert(), Ok(true))
            },
        )
    });
}

/// Sets the time `param` checks validity periods at to the instance's,
/// where the instance corrects it. Where it does not, nothing is set:
/// BoringSSL reads the clock itself, as it would have.
pub(crate) fn at_instance_time(param: &mut X509VerifyParamRef) {
    let Some(now) = crate::clock::corrected_now() else {
        return;
    };
    let Ok(since) = now.duration_since(std::time::UNIX_EPOCH) else {
        return;
    };
    // As wide as the platform's time_t, whichever that is.
    if let Ok(seconds) = since.as_secs().try_into() {
        param.set_time(seconds);
    }
}

/// Runs `configure` on the context of a QUIC client configuration, as on
/// the builder of one not built yet.
#[cfg(feature = "quic")]
pub(crate) fn configure_quic<T>(
    crypto: &mut quinn_btls::ClientConfig,
    configure: impl FnOnce(&mut SslContextBuilder) -> T,
) -> T {
    configure_context(crypto.ctx_mut(), configure)
}

/// `configure_quic`, of a QUIC server configuration.
#[cfg(feature = "quic")]
pub(crate) fn configure_quic_server<T>(
    crypto: &mut quinn_btls::ServerConfig,
    configure: impl FnOnce(&mut SslContextBuilder) -> T,
) -> T {
    configure_context(crypto.ctx_mut(), configure)
}

#[cfg(feature = "quic")]
fn configure_context<T>(
    ctx: &mut btls::ssl::SslContext,
    configure: impl FnOnce(&mut SslContextBuilder) -> T,
) -> T {
    use foreign_types::ForeignType;
    let ctx = ctx.as_ptr();
    // SAFETY: the builder takes a reference of its own to the context,
    // given back when it drops. The context is not in use yet: nothing
    // configures it at the same time.
    unsafe {
        btls_sys::SSL_CTX_up_ref(ctx);
        let mut builder = SslContextBuilder::from_ptr(ctx);
        configure(&mut builder)
    }
}

pub use client::TlsClient;
pub use client_auth::{ClientAuth, ClientAuthFields, ClientAuthMode};
pub use conn::BoringConnection;
pub use fingerprint::Fingerprint;
pub use options::{CertificatePins, ClientOptions, Pins, PublicKeyPins, TlsVersionRange};

#[cfg(test)]
pub(crate) mod tests;
