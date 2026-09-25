use std::net::{IpAddr, SocketAddr};

/// Monotonically increasing identity for a network attachment.
///
/// Tokens from an older generation must never be accepted after a network
/// reset, even when their five-tuple is reused.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NetworkGeneration(u64);

impl NetworkGeneration {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0.wrapping_add(1))
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FlowId(u64);

impl FlowId {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Stable identity of a state-owning data-plane shard.
///
/// Flow identifiers are only unique within a shard. Capability tokens carry
/// this identity so a multi-queue integration can route an operation directly
/// to its owner without a global token lookup table.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ShardId(u16);

impl ShardId {
    #[must_use]
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }

    #[must_use]
    pub(crate) const fn index(self) -> usize {
        self.0 as usize
    }
}

/// A UDP reply capability. All fields are checked by the owning shard.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct UdpFlowToken {
    flow: FlowId,
    generation: NetworkGeneration,
    shard: ShardId,
}

/// A TCP connection capability. All fields are checked by the owning shard.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TcpFlowToken {
    flow: FlowId,
    generation: NetworkGeneration,
    shard: ShardId,
}

impl TcpFlowToken {
    #[must_use]
    pub const fn new(flow: FlowId, generation: NetworkGeneration) -> Self {
        Self::new_on_shard(flow, generation, ShardId::new(0))
    }

    #[must_use]
    pub const fn new_on_shard(flow: FlowId, generation: NetworkGeneration, shard: ShardId) -> Self {
        Self {
            flow,
            generation,
            shard,
        }
    }

    #[must_use]
    pub const fn flow(self) -> FlowId {
        self.flow
    }

    #[must_use]
    pub const fn generation(self) -> NetworkGeneration {
        self.generation
    }

    #[must_use]
    pub const fn shard(self) -> ShardId {
        self.shard
    }

    #[must_use]
    pub const fn is_current(self, generation: NetworkGeneration) -> bool {
        self.generation.0 == generation.0
    }

    #[must_use]
    pub const fn is_owned_by(self, generation: NetworkGeneration, shard: ShardId) -> bool {
        self.is_current(generation) && self.shard.0 == shard.0
    }
}

impl UdpFlowToken {
    #[must_use]
    pub const fn new(flow: FlowId, generation: NetworkGeneration) -> Self {
        Self::new_on_shard(flow, generation, ShardId::new(0))
    }

    #[must_use]
    pub const fn new_on_shard(flow: FlowId, generation: NetworkGeneration, shard: ShardId) -> Self {
        Self {
            flow,
            generation,
            shard,
        }
    }

    #[must_use]
    pub const fn flow(self) -> FlowId {
        self.flow
    }

    #[must_use]
    pub const fn generation(self) -> NetworkGeneration {
        self.generation
    }

    #[must_use]
    pub const fn shard(self) -> ShardId {
        self.shard
    }

    #[must_use]
    pub const fn is_current(self, generation: NetworkGeneration) -> bool {
        self.generation.0 == generation.0
    }

    #[must_use]
    pub const fn is_owned_by(self, generation: NetworkGeneration, shard: ShardId) -> bool {
        self.is_current(generation) && self.shard.0 == shard.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TransportProtocol {
    Tcp,
    Udp,
    Icmp,
    Fragment(u8),
    Other(u8),
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct IpEndpoint {
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub protocol: TransportProtocol,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FlowKey {
    pub endpoint: IpEndpoint,
    pub generation: NetworkGeneration,
}

impl IpEndpoint {
    #[must_use]
    pub const fn address_family_matches(self) -> bool {
        matches!(
            (self.source.ip(), self.destination.ip()),
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
        )
    }
}

/// Transparent forwarding decision made at the sail integration boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowDecision {
    Accept,
    Drop,
    Reject,
}
