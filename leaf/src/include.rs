//! Which inbound and outbound protocols this build has.
//!
//! This is the one list of them. A protocol registers itself from its own
//! directory; adding one means adding its line here, under its feature.
//!
//! Transports (tls, reality, ws, quic, amux, obfs) and chains are not
//! protocols of their own: they are blocks of the protocols they carry, see
//! `transport::layers`.

use std::sync::LazyLock;

use crate::adapter::registry::{InboundRegistry, OutboundRegistry, Registry};

/// Inbound protocols served by a listener of their own rather than by a
/// handler behind a network listener.
pub(crate) const LISTENER_INBOUNDS: &[&str] = &[
    #[cfg(feature = "inbound-tun")]
    "tun",
    #[cfg(feature = "inbound-cat")]
    "cat",
];

pub(crate) static OUTBOUNDS: LazyLock<OutboundRegistry> = LazyLock::new(|| {
    #[allow(unused_mut)]
    let mut registry = Registry::new("outbound");

    #[cfg(feature = "outbound-direct")]
    crate::protocol::direct::register(&mut registry);
    #[cfg(feature = "outbound-drop")]
    crate::protocol::drop::register(&mut registry);
    #[cfg(feature = "outbound-redirect")]
    crate::protocol::redirect::register(&mut registry);
    #[cfg(feature = "outbound-socks")]
    crate::protocol::socks::outbound::register(&mut registry);
    #[cfg(feature = "outbound-shadowsocks")]
    crate::protocol::shadowsocks::outbound::register(&mut registry);
    #[cfg(feature = "outbound-trojan")]
    crate::protocol::trojan::outbound::register(&mut registry);
    #[cfg(feature = "outbound-vmess")]
    crate::protocol::vmess::outbound::register(&mut registry);
    #[cfg(feature = "outbound-vless")]
    crate::protocol::vless::outbound::register(&mut registry);
    #[cfg(feature = "outbound-mptp")]
    crate::protocol::mptp::outbound::register(&mut registry);

    #[cfg(feature = "outbound-failover")]
    crate::protocol::group::failover::register(&mut registry);
    #[cfg(feature = "outbound-select")]
    crate::protocol::group::select::register(&mut registry);
    #[cfg(feature = "outbound-static")]
    crate::protocol::group::r#static::register(&mut registry);
    #[cfg(feature = "outbound-tryall")]
    crate::protocol::group::tryall::register(&mut registry);

    #[cfg(feature = "plugin")]
    crate::app::outbound::plugin::register(&mut registry);

    registry
});

pub(crate) static INBOUNDS: LazyLock<InboundRegistry> = LazyLock::new(|| {
    #[allow(unused_mut)]
    let mut registry = Registry::new("inbound");

    #[cfg(feature = "inbound-socks")]
    crate::protocol::socks::inbound::register(&mut registry);
    #[cfg(feature = "inbound-http")]
    crate::protocol::http::inbound::register(&mut registry);
    #[cfg(feature = "inbound-shadowsocks")]
    crate::protocol::shadowsocks::inbound::register(&mut registry);
    #[cfg(feature = "inbound-trojan")]
    crate::protocol::trojan::inbound::register(&mut registry);
    #[cfg(feature = "inbound-mptp")]
    crate::protocol::mptp::inbound::register(&mut registry);
    #[cfg(feature = "inbound-hc")]
    crate::protocol::hc::inbound::register(&mut registry);
    #[cfg(all(feature = "inbound-nf", windows))]
    crate::protocol::nf::inbound::register(&mut registry);

    registry
});
