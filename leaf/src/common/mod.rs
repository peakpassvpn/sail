pub mod crypto;
pub mod dns_sniff;
pub mod io;
pub mod net;
pub mod resolver;
pub mod sniff;
#[cfg(any(
    feature = "outbound-reality",
    all(feature = "outbound-tls", feature = "rustls-tls")
))]
pub mod tls_stream;

#[cfg(target_os = "macos")]
pub mod cmd_macos;
#[cfg(target_os = "macos")]
pub use cmd_macos as cmd;

#[cfg(target_os = "linux")]
pub mod cmd_linux;
#[cfg(target_os = "linux")]
pub use cmd_linux as cmd;
