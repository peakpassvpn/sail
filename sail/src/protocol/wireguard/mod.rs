//! WireGuard, implemented on BoringSSL (X25519, ChaCha20-Poly1305,
//! XChaCha20-Poly1305) and the `blake2` crate, after the whitepaper
//! (<https://www.wireguard.com/papers/wireguard.pdf>) and the behaviour of
//! Linux's drivers/net/wireguard and wireguard-go.
//!
//! [`Device`] is the sans-IO core: IP packets in and out on one side, UDP
//! datagrams on the other, time passed in. [`shell::WireGuard`] runs a
//! device over a [`shell::Transport`] with a tokio timer.


pub mod crypto;
pub mod tai64n;
pub mod messages;
pub mod replay;
pub mod timers;
pub mod noise;
pub mod cookie;
pub mod keypair;
pub mod ratelimiter;
pub mod allowed_ips;
pub mod device;
