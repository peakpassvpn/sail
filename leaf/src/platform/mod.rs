//! Operating-system integration: routes, interfaces and forwarding that the
//! host needs set up around the core.

#[cfg(target_os = "macos")]
pub mod cmd_macos;
#[cfg(target_os = "macos")]
pub use cmd_macos as cmd;

#[cfg(target_os = "linux")]
pub mod cmd_linux;
#[cfg(target_os = "linux")]
pub use cmd_linux as cmd;

#[cfg(all(feature = "inbound-tun", any(target_os = "macos", target_os = "linux")))]
pub(crate) mod tun_setup;

#[cfg(all(feature = "inbound-tun", target_os = "windows"))]
pub(crate) mod windows;
