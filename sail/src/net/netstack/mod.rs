//! The userspace TCP/IP stack as the rest of sail uses it: a runtime that
//! drives `sail-netstack` over any [`sail_netstack::PacketIo`], and hands
//! out the connections and datagrams it carries. The TUN inbound runs it
//! over the device; an outbound that carries IP packets runs it over
//! [`ChannelPacketIo`].
// The stack serves the protocols that carry IP packets; built without any
// of them, as `netstack` alone, it has no user.
#![cfg_attr(
    not(feature = "inbound-tun"),
    allow(
        dead_code,
        unused_imports,
        reason = "no protocol that uses it is enabled"
    )
)]

mod channel;
mod runtime;
mod stream;
#[cfg(test)]
pub(crate) mod testing;

#[expect(unused_imports, reason = "the WireGuard outbound is its first user")]
pub(crate) use channel::ChannelPacketIo;
pub(crate) use runtime::{
    NativeRuntimeControl, NativeRuntimeGroup, NativeUdpDatagram, NativeUdpReplyHandle,
};
pub(crate) use stream::NativeTcpStream;
