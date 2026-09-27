//! WireGuard, implemented on BoringSSL (X25519, ChaCha20-Poly1305,
//! XChaCha20-Poly1305) and the `blake2` crate, after the whitepaper
//! (<https://www.wireguard.com/papers/wireguard.pdf>) and the behaviour of
//! Linux's drivers/net/wireguard and wireguard-go.
//!
//! [`Device`] is the sans-IO core: IP packets in and out on one side, UDP
//! datagrams on the other, time passed in. [`shell::WireGuard`] runs a
//! device over a [`shell::Transport`] with a tokio timer.

pub mod allowed_ips;
pub mod cookie;
pub mod crypto;
pub mod device;
pub mod keypair;
pub mod messages;
pub mod noise;
pub mod ratelimiter;
pub mod replay;
pub mod shell;
pub mod tai64n;
pub mod timers;

pub use device::{Device, DeviceConfig, Error, Incoming, PeerConfig, PeerId, PeerStats, Transmit};
pub use shell::{Transport, WireGuard};
