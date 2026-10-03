//! QUIC: the glue everything on quinn shares, and the quic transport.

mod common;
mod detour;
mod recv_backoff;

pub use common::*;
pub use detour::DetourSocket;

#[cfg(feature = "inbound-quic")]
pub mod inbound;
#[cfg(feature = "outbound-quic")]
pub mod outbound;

/// A server's QUIC handshake, given `limit` to finish, as quic-go gives it
/// its handshake idle timeout: a client that sends an Initial and falls
/// silent is dropped then, rather than held until the idle timeout. The
/// connection's state goes with the dropped `connecting`.
pub(crate) async fn server_handshake(
    connecting: quinn::Connecting,
    limit: std::time::Duration,
) -> std::io::Result<quinn::Connection> {
    match tokio::time::timeout(limit, connecting).await {
        Ok(handshake) => handshake.map_err(std::io::Error::other),
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("quic handshake not done within {:?}", limit),
        )),
    }
}
