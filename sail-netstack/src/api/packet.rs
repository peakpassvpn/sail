use std::collections::VecDeque;
use std::future::Future;
use std::io;

use crate::buffer::{ArenaPacket, BudgetLease};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[allow(clippy::struct_excessive_bools)]
pub struct ChecksumCapabilities {
    pub ipv4: bool,
    pub tcp: bool,
    pub udp: bool,
    pub icmpv4: bool,
    pub icmpv6: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GsoCapabilities {
    pub max_segments: usize,
    pub max_segment_size: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketCapabilities {
    pub max_batch: usize,
    pub queue_count: usize,
    pub headroom: usize,
    pub vectored: bool,
    pub rx_checksum: ChecksumCapabilities,
    pub tx_checksum: ChecksumCapabilities,
    pub gso: Option<GsoCapabilities>,
}

impl PacketCapabilities {
    /// Rejects nonsensical platform declarations before the runner starts.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] when a required count is zero or
    /// a GSO declaration cannot describe a segmented packet.
    pub fn validate(self) -> io::Result<Self> {
        if self.max_batch == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "max_batch must be at least one",
            ));
        }
        if self.queue_count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "queue_count must be at least one",
            ));
        }
        if let Some(gso) = self.gso {
            if gso.max_segments < 2 || gso.max_segment_size == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid GSO capabilities",
                ));
            }
        }
        Ok(self)
    }
}

/// Identifies a platform-owned packet allocation for accounting and return.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PacketToken(u64);

impl PacketToken {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// An owned packet and its explicit return identity.
#[derive(Debug)]
pub struct Packet {
    token: PacketToken,
    storage: Box<[u8]>,
    start: usize,
    len: usize,
    lease: Option<BudgetLease>,
}

impl Packet {
    #[must_use]
    pub fn from_payload(token: PacketToken, headroom: usize, payload: &[u8]) -> Self {
        let mut storage = vec![0; headroom];
        storage.extend_from_slice(payload);
        Self {
            token,
            storage: storage.into_boxed_slice(),
            start: headroom,
            len: payload.len(),
            lease: None,
        }
    }

    #[must_use]
    pub fn from_arena(token: PacketToken, packet: ArenaPacket) -> Self {
        let (storage, start, len, lease) = packet.into_parts();
        Self {
            token,
            storage,
            start,
            len,
            lease: Some(lease),
        }
    }

    #[must_use]
    pub const fn token(&self) -> PacketToken {
        self.token
    }

    #[must_use]
    pub const fn headroom(&self) -> usize {
        self.start
    }

    #[must_use]
    pub fn is_budgeted(&self) -> bool {
        self.lease.is_some()
    }

    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.storage[self.start..self.start + self.len]
    }

    #[must_use]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.storage[self.start..self.start + self.len]
    }
}

/// Ownership-preserving batch. Successfully sent packets are removed from the
/// front; a partial send leaves the unsent suffix in this batch.
#[derive(Debug)]
pub struct PacketBatch {
    limit: usize,
    packets: VecDeque<Packet>,
}

impl PacketBatch {
    #[must_use]
    /// # Panics
    ///
    /// Panics when `limit` is zero. A platform must advertise at least one
    /// packet per batch.
    pub fn with_limit(limit: usize) -> Self {
        assert!(limit > 0, "packet batch limit must be non-zero");
        Self {
            limit,
            packets: VecDeque::with_capacity(limit),
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.packets.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    #[must_use]
    pub const fn limit(&self) -> usize {
        self.limit
    }

    /// # Errors
    ///
    /// Returns the unchanged packet when the batch is full.
    pub fn push(&mut self, packet: Packet) -> Result<(), Packet> {
        if self.packets.len() == self.limit {
            return Err(packet);
        }
        self.packets.push_back(packet);
        Ok(())
    }

    pub fn pop_front(&mut self) -> Option<Packet> {
        self.packets.pop_front()
    }

    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidData`] if the platform claims to have
    /// sent more packets than the batch contains.
    pub fn acknowledge_sent(&mut self, count: usize) -> io::Result<()> {
        if count > self.packets.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "platform reported more sent packets than supplied",
            ));
        }
        self.packets.drain(..count);
        Ok(())
    }

    #[must_use]
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &Packet> {
        self.packets.iter()
    }
}

/// Capability-negotiated packet transport.
///
/// `send` returns the number of packets accepted by the platform. The caller
/// acknowledges that prefix with [`PacketBatch::acknowledge_sent`], preserving
/// ownership of a partial-send suffix. `WouldBlock` is temporary; all other I/O
/// errors are classified by the runner, and permanent failures stop the stack.
///
/// # Cancellation
///
/// Adapters race [`crate::SingleShardRunner::step`] against timers and
/// application commands, so either future may be dropped at any await point.
/// Both must therefore be cancellation safe. `send` may await only before it
/// accepts the first packet of the batch; once any packet is accepted it must
/// return that count without awaiting again, reporting a partial send when the
/// next packet is not immediately writable. A dropped `send` has then accepted
/// nothing, and the runner's retry of the unacknowledged batch cannot put an
/// accepted packet on the wire twice. `recv` likewise must not lose packets it
/// has already taken from the platform when dropped.
pub trait PacketIo: Send + 'static {
    fn recv(&mut self, out: &mut PacketBatch) -> impl Future<Output = io::Result<usize>> + Send;
    fn send(&mut self, packets: &PacketBatch) -> impl Future<Output = io::Result<usize>> + Send;
    fn capabilities(&self) -> PacketCapabilities;
}
