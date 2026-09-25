//! Stable boundary between platform packet I/O, the stack, and sail.

mod packet;
mod types;

pub use packet::{
    ChecksumCapabilities, GsoCapabilities, Packet, PacketBatch, PacketCapabilities, PacketIo,
    PacketToken,
};
pub use types::{
    FlowDecision, FlowId, FlowKey, IpEndpoint, NetworkGeneration, ShardId, TcpFlowToken,
    TransportProtocol, UdpFlowToken,
};
