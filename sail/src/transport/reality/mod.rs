//! REALITY: TLS that authenticates the client in the ClientHello session ID
//! and the server with a certificate only the client can check.

pub mod outbound;

pub use outbound::Handler as StreamHandler;
