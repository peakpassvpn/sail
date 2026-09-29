#[cfg(target_os = "linux")]
pub(crate) mod auto_redirect;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) mod auto_route;
pub mod inbound;
mod packet_io;
#[cfg(target_os = "linux")]
mod prematch;
