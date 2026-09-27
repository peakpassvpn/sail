mod magic;
pub mod network_listener;
mod resource;

#[cfg(feature = "inbound-tun")]
mod tun_listener;

#[cfg(feature = "inbound-cat")]
mod cat_listener;

pub mod manager;

#[cfg(feature = "inbound-nf")]
pub use network_listener::get_network_listen_addr;
