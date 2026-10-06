use std::collections::VecDeque;
use std::fmt;
use std::hash::{BuildHasher, RandomState};
use std::net::SocketAddr;
use std::sync::Arc;

use crate::{
    parse_ip_packet, parse_tcp_segment, parse_udp_datagram, BudgetLease, EnqueueError, FlowId,
    FlowKey, IpEndpoint, NetworkGeneration, ResourceKind, ResourceLedger, RoundStats, Scheduler,
    SchedulerConfig, SchedulerSnapshot, ShardId, TransportProtocol, WireError, WorkClass,
};

const DIRECTORY_ENTRY_CHARGE: usize = 64;

/// Produces the stable routing key used before a packet enters shard-local
/// protocol state. All fragments of one IP datagram share a synthetic key and
/// are therefore reassembled by one owner.
///
/// # Errors
///
/// Returns [`WireError`] for malformed IP, TCP, or UDP input.
pub fn classify_packet(packet: &[u8], generation: NetworkGeneration) -> Result<FlowKey, WireError> {
    classify_packet_with_class(packet, generation).map(|(key, _)| key)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PacketClass {
    Control,
    Data,
}

pub(crate) fn classify_packet_with_class(
    packet: &[u8],
    generation: NetworkGeneration,
) -> Result<(FlowKey, PacketClass), WireError> {
    let ip = parse_ip_packet(packet, true)?;
    if let Some(fragment) = ip.fragment.filter(|fragment| !fragment.is_atomic()) {
        let identification = fragment.identification.to_be_bytes();
        return Ok((
            FlowKey {
                endpoint: IpEndpoint {
                    source: SocketAddr::new(
                        ip.source,
                        u16::from_be_bytes([identification[0], identification[1]]),
                    ),
                    destination: SocketAddr::new(
                        ip.destination,
                        u16::from_be_bytes([identification[2], identification[3]]),
                    ),
                    protocol: TransportProtocol::Fragment(ip.next_header),
                },
                generation,
            },
            PacketClass::Data,
        ));
    }
    let (endpoint, class) = match ip.next_header {
        6 => {
            // Only the ports and whether it carries data: the checksum is
            // the table's to check, once, when it takes the segment.
            let segment = parse_tcp_segment(ip, false)?;
            (
                IpEndpoint {
                    source: segment.source,
                    destination: segment.destination,
                    protocol: TransportProtocol::Tcp,
                },
                if segment.payload.is_empty() {
                    PacketClass::Control
                } else {
                    PacketClass::Data
                },
            )
        }
        17 => {
            // As a TCP segment: the table checks the checksum.
            let datagram = parse_udp_datagram(ip, false)?;
            (
                IpEndpoint {
                    source: datagram.source,
                    destination: datagram.destination,
                    protocol: TransportProtocol::Udp,
                },
                PacketClass::Data,
            )
        }
        1 | 58 => (
            IpEndpoint {
                source: SocketAddr::new(ip.source, 0),
                destination: SocketAddr::new(ip.destination, 0),
                protocol: TransportProtocol::Icmp,
            },
            PacketClass::Control,
        ),
        protocol => (
            IpEndpoint {
                source: SocketAddr::new(ip.source, 0),
                destination: SocketAddr::new(ip.destination, 0),
                protocol: TransportProtocol::Other(protocol),
            },
            PacketClass::Control,
        ),
    };
    Ok((
        FlowKey {
            endpoint,
            generation,
        },
        class,
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Route {
    Local(ShardId),
    Forward(ShardId),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ShardRouterStats {
    pub directory_entries: usize,
    pub local_cache_entries: usize,
    pub queued_packets: usize,
    pub queued_bytes: usize,
    pub pressure_cache_reclaims: u64,
    pub pressure_reclaimed_directory_entries: u64,
    pub pressure_reclaimed_local_cache_entries: u64,
    pub directory_admission_failures: u64,
    pub local_cache_hits: u64,
    pub local_cache_misses: u64,
    pub local_cache_admission_failures: u64,
    pub local_routes: u64,
    pub forwarded_routes: u64,
    pub forwarded_control_packets: u64,
    pub forwarded_waker_registrations: u64,
    pub forwarded_wakeups: u64,
    pub enqueued_packets: u64,
    pub enqueued_bytes: u64,
    pub dropped_packets: u64,
    pub drained_packets: u64,
    pub drained_bytes: u64,
}

#[derive(Debug)]
struct DirectoryEntry {
    shard: ShardId,
    _lease: BudgetLease,
}

#[derive(Debug)]
pub enum ShardRouterError {
    InvalidShardCount,
    InvalidQueueConfig,
}

impl fmt::Display for ShardRouterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidShardCount => formatter.write_str("shard count must fit a non-zero u16"),
            Self::InvalidQueueConfig => formatter.write_str("invalid cross-shard queue config"),
        }
    }
}

impl std::error::Error for ShardRouterError {}

/// Control-plane directory for first-packet assignment and queue mismatch
/// forwarding. Stable-flow packet processing remains shard-local.
#[derive(Debug)]
pub struct ShardRouter<T> {
    ledger: Arc<ResourceLedger>,
    shard_count: u16,
    hasher: RandomState,
    directory: crate::FlowMap<FlowKey, DirectoryEntry>,
    directory_order: VecDeque<FlowKey>,
    max_directory_entries: usize,
    queues: Vec<Scheduler<T>>,
    stats: ShardRouterStats,
}

impl<T> ShardRouter<T> {
    /// # Errors
    ///
    /// Returns [`ShardRouterError`] for an invalid shard count or queue
    /// configuration.
    pub fn new(
        ledger: Arc<ResourceLedger>,
        shard_count: usize,
        queue_config: SchedulerConfig,
    ) -> Result<Self, ShardRouterError> {
        let shard_count = u16::try_from(shard_count)
            .ok()
            .filter(|count| *count > 0)
            .ok_or(ShardRouterError::InvalidShardCount)?;
        queue_config
            .validate()
            .map_err(|_| ShardRouterError::InvalidQueueConfig)?;
        let queues = (0..shard_count)
            .map(|_| Scheduler::new(queue_config))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ShardRouterError::InvalidQueueConfig)?;
        Ok(Self {
            ledger,
            shard_count,
            hasher: RandomState::new(),
            directory: crate::FlowMap::default(),
            directory_order: VecDeque::new(),
            max_directory_entries: queue_config.max_active_flows,
            queues,
            stats: ShardRouterStats::default(),
        })
    }

    /// Resolves the owner and records a new flow under the metadata budget.
    ///
    /// # Errors
    ///
    /// Returns [`ShardRouterError::InvalidShardCount`] for an invalid input
    /// queue. Directory budget exhaustion falls back to the same deterministic
    /// hash without caching the entry.
    pub fn route(&mut self, input_shard: ShardId, key: FlowKey) -> Result<Route, ShardRouterError> {
        if input_shard.index() >= usize::from(self.shard_count) {
            return Err(ShardRouterError::InvalidShardCount);
        }
        let hash = self.hasher.hash_one(key);
        let index = hash % u64::from(self.shard_count);
        let hashed_target =
            ShardId::new(u16::try_from(index).map_err(|_| ShardRouterError::InvalidShardCount)?);
        let target = self
            .directory
            .get(&key)
            .map_or(hashed_target, |entry| entry.shard);
        if !self.directory.contains_key(&key) {
            if self.directory.len() == self.max_directory_entries {
                self.evict_oldest_directory_entry();
            }
            let mut lease = self
                .ledger
                .try_acquire(ResourceKind::MetadataBytes, DIRECTORY_ENTRY_CHARGE);
            if lease.is_err() && !self.directory.is_empty() {
                self.evict_oldest_directory_entry();
                lease = self
                    .ledger
                    .try_acquire(ResourceKind::MetadataBytes, DIRECTORY_ENTRY_CHARGE);
            }
            match lease {
                Ok(lease) => {
                    self.directory.insert(
                        key,
                        DirectoryEntry {
                            shard: target,
                            _lease: lease,
                        },
                    );
                    self.directory_order.push_back(key);
                }
                Err(_) => {
                    self.stats.directory_admission_failures =
                        self.stats.directory_admission_failures.saturating_add(1);
                }
            }
        }
        Ok(if target == input_shard {
            self.stats.local_routes = self.stats.local_routes.saturating_add(1);
            Route::Local(target)
        } else {
            self.stats.forwarded_routes = self.stats.forwarded_routes.saturating_add(1);
            Route::Forward(target)
        })
    }

    pub fn remove(&mut self, key: &FlowKey) -> bool {
        let removed = self.directory.remove(key).is_some();
        if removed {
            self.directory_order.retain(|queued| queued != key);
        }
        removed
    }

    pub fn reset_network(&mut self) {
        self.directory.clear();
        self.directory_order.clear();
        for queue in &mut self.queues {
            queue.clear();
        }
    }

    fn evict_oldest_directory_entry(&mut self) {
        while let Some(key) = self.directory_order.pop_front() {
            if self.directory.remove(&key).is_some() {
                break;
            }
        }
    }

    /// Enqueues a budget-owned value to a target shard's bounded byte-DRR
    /// queue. The value is returned on failure.
    ///
    /// # Errors
    ///
    /// Returns [`ShardQueueError`] for an invalid target or bounded admission
    /// failure.
    pub fn enqueue(
        &mut self,
        target: ShardId,
        key: FlowKey,
        bytes: usize,
        value: T,
    ) -> Result<(), ShardQueueError<T>> {
        let Some(queue) = self.queues.get_mut(target.index()) else {
            self.stats.dropped_packets = self.stats.dropped_packets.saturating_add(1);
            return Err(ShardQueueError::InvalidShard(value));
        };
        let flow = FlowId::new(self.hasher.hash_one(key));
        match queue.enqueue(WorkClass::Data { flow, weight: 1 }, bytes, value) {
            Ok(()) => {
                self.stats.enqueued_packets = self.stats.enqueued_packets.saturating_add(1);
                self.stats.enqueued_bytes = self
                    .stats
                    .enqueued_bytes
                    .saturating_add(u64::try_from(bytes).unwrap_or(u64::MAX));
                Ok(())
            }
            Err(error) => {
                self.stats.dropped_packets = self.stats.dropped_packets.saturating_add(1);
                Err(ShardQueueError::Admission(error))
            }
        }
    }

    /// # Panics
    ///
    /// Panics when `target` does not name a configured shard.
    pub fn drain(&mut self, target: ShardId, process: impl FnMut(WorkClass, T)) -> RoundStats {
        self.drain_limited(target, usize::MAX, usize::MAX, process)
    }

    /// Drains no more than a consumer's remaining packet and byte capacity.
    ///
    /// # Panics
    ///
    /// Panics when `target` does not name a configured shard.
    pub fn drain_limited(
        &mut self,
        target: ShardId,
        max_packets: usize,
        max_bytes: usize,
        process: impl FnMut(WorkClass, T),
    ) -> RoundStats {
        let round = self.queues[target.index()].run_round_limited(max_packets, max_bytes, process);
        self.stats.drained_packets = self
            .stats
            .drained_packets
            .saturating_add(u64::try_from(round.packets).unwrap_or(u64::MAX));
        self.stats.drained_bytes = self
            .stats
            .drained_bytes
            .saturating_add(u64::try_from(round.bytes).unwrap_or(u64::MAX));
        round
    }

    #[must_use]
    pub fn queue_snapshot(&self, target: ShardId) -> Option<SchedulerSnapshot> {
        self.queues.get(target.index()).map(Scheduler::snapshot)
    }

    #[must_use]
    pub fn directory_len(&self) -> usize {
        self.directory.len()
    }

    #[must_use]
    pub fn stats(&self) -> ShardRouterStats {
        let mut stats = self.stats;
        stats.directory_entries = self.directory.len();
        for queue in &self.queues {
            let snapshot = queue.snapshot();
            stats.queued_packets = stats.queued_packets.saturating_add(snapshot.queued_packets);
            stats.queued_bytes = stats.queued_bytes.saturating_add(snapshot.queued_bytes);
        }
        stats
    }
}

#[derive(Debug)]
pub enum ShardQueueError<T> {
    InvalidShard(T),
    Admission(EnqueueError<T>),
}

impl<T> ShardQueueError<T> {
    #[must_use]
    pub fn into_inner(self) -> T {
        match self {
            Self::InvalidShard(value) => value,
            Self::Admission(error) => error.into_inner(),
        }
    }
}
