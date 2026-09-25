use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::future::{poll_fn, Future};
use std::hash::{BuildHasher, RandomState};
use std::io;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::task::{Poll, Waker};

use crate::engine::shard::{classify_packet_with_class, PacketClass};
use crate::metrics::atomic_add_counter;
use crate::{
    classify_packet, BudgetLease, FlowId, FlowKey, NetworkGeneration, Packet, PacketBatch,
    PacketCapabilities, PacketIo, PressureLevel, ResourceKind, ResourceLedger, Scheduler,
    SchedulerConfig, ShardId, ShardRouterError, ShardRouterStats, WorkClass,
};

const DIRECTORY_STRIPES: usize = 64;
const DIRECTORY_ENTRY_CHARGE: usize = 64;
const LOCAL_ROUTE_ENTRY_CHARGE: usize = 64;
const FORWARDED_ENTRY_CHARGE: usize = 64;

#[derive(Debug)]
struct DirectoryEntry {
    owner: ShardId,
    _lease: BudgetLease,
}

#[derive(Debug, Default)]
struct DirectoryStripe {
    entries: HashMap<FlowKey, DirectoryEntry>,
    insertion_order: VecDeque<FlowKey>,
}

impl DirectoryStripe {
    fn evict_oldest(&mut self) -> bool {
        while let Some(oldest) = self.insertion_order.pop_front() {
            if self.entries.remove(&oldest).is_some() {
                return true;
            }
        }
        false
    }
}

#[derive(Debug)]
struct LocalRouteEntry {
    owner: ShardId,
    hash: u64,
    _lease: BudgetLease,
}

#[derive(Debug)]
struct LocalRouteCache {
    entries: HashMap<FlowKey, LocalRouteEntry>,
    insertion_order: VecDeque<FlowKey>,
    max_entries: usize,
}

#[derive(Debug)]
struct ForwardedPacket {
    packet: Packet,
    _packet_lease: BudgetLease,
    _metadata_lease: BudgetLease,
}

#[derive(Debug)]
struct QueueState {
    scheduler: Scheduler<ForwardedPacket>,
    waker: Option<Waker>,
}

#[derive(Debug, Default)]
struct ConcurrentCounters {
    directory_entries: AtomicUsize,
    pressure_cache_reclaims: AtomicUsize,
    pressure_reclaimed_directory_entries: AtomicUsize,
    pressure_reclaimed_local_cache_entries: AtomicUsize,
    directory_admission_failures: AtomicUsize,
    local_cache_hits: AtomicUsize,
    local_cache_misses: AtomicUsize,
    local_cache_admission_failures: AtomicUsize,
    local_routes: AtomicUsize,
    forwarded_routes: AtomicUsize,
    forwarded_control_packets: AtomicUsize,
    forwarded_waker_registrations: AtomicUsize,
    forwarded_wakeups: AtomicUsize,
    enqueued_packets: AtomicUsize,
    enqueued_bytes: AtomicUsize,
    dropped_packets: AtomicUsize,
    drained_packets: AtomicUsize,
    drained_bytes: AtomicUsize,
}

#[derive(Debug)]
struct SharedIngress {
    generation: RwLock<NetworkGeneration>,
    shard_count: u16,
    hasher: RandomState,
    ledger: Arc<ResourceLedger>,
    directory: Vec<Mutex<DirectoryStripe>>,
    max_directory_entries_per_stripe: usize,
    queues: Vec<Mutex<QueueState>>,
    local_caches: Vec<Arc<Mutex<LocalRouteCache>>>,
    cache_pressure_active: AtomicBool,
    counters: ConcurrentCounters,
}

impl SharedIngress {
    fn hashed_owner(&self, key: FlowKey) -> io::Result<(ShardId, u64)> {
        let hash = self.hasher.hash_one(key);
        let owner = ShardId::new(
            u16::try_from(hash % u64::from(self.shard_count))
                .map_err(|_| io::Error::other("shard hash exceeded u16"))?,
        );
        Ok((owner, hash))
    }

    fn owner(&self, key: FlowKey) -> io::Result<(ShardId, u64)> {
        let (owner, hash) = self.hashed_owner(key)?;
        if self.cache_pressure_active.load(Ordering::Acquire) {
            return Ok((owner, hash));
        }
        let stripe_index = usize::try_from(hash % DIRECTORY_STRIPES as u64)
            .map_err(|_| io::Error::other("directory stripe exceeded usize"))?;
        let mut stripe = self.directory[stripe_index]
            .lock()
            .map_err(|_| io::Error::other("flow directory lock poisoned"))?;
        if self.cache_pressure_active.load(Ordering::Acquire) {
            return Ok((owner, hash));
        }
        if let Some(entry) = stripe.entries.get(&key) {
            return Ok((entry.owner, hash));
        }
        // Closed flows never remove their entries, so the directory is a
        // bounded FIFO cache like the `ShardRouter` model; without the bound it
        // grew until metadata pressure cleared every routing cache.
        if stripe.entries.len() >= self.max_directory_entries_per_stripe && stripe.evict_oldest() {
            self.counters
                .directory_entries
                .fetch_sub(1, Ordering::Relaxed);
        }
        let mut lease = self
            .ledger
            .try_acquire(ResourceKind::MetadataBytes, DIRECTORY_ENTRY_CHARGE);
        if lease.is_err() && stripe.evict_oldest() {
            self.counters
                .directory_entries
                .fetch_sub(1, Ordering::Relaxed);
            lease = self
                .ledger
                .try_acquire(ResourceKind::MetadataBytes, DIRECTORY_ENTRY_CHARGE);
        }
        if let Ok(lease) = lease {
            stripe.entries.insert(
                key,
                DirectoryEntry {
                    owner,
                    _lease: lease,
                },
            );
            stripe.insertion_order.push_back(key);
            self.counters
                .directory_entries
                .fetch_add(1, Ordering::Relaxed);
        } else {
            atomic_add_counter(&self.counters.directory_admission_failures, 1);
        }
        Ok((owner, hash))
    }

    fn enqueue(
        &self,
        target: ShardId,
        hash: u64,
        packet: Packet,
        class: PacketClass,
    ) -> io::Result<()> {
        let bytes = packet.payload().len();
        let packet_kind = match class {
            PacketClass::Control => ResourceKind::ControlPacketBytes,
            PacketClass::Data => ResourceKind::PacketBytes,
        };
        let Ok(packet_lease) = self.ledger.try_acquire(packet_kind, bytes) else {
            atomic_add_counter(&self.counters.dropped_packets, 1);
            return Ok(());
        };
        let Ok(metadata_lease) = self
            .ledger
            .try_acquire(ResourceKind::MetadataBytes, FORWARDED_ENTRY_CHARGE)
        else {
            atomic_add_counter(&self.counters.dropped_packets, 1);
            return Ok(());
        };
        let forwarded = ForwardedPacket {
            packet,
            _packet_lease: packet_lease,
            _metadata_lease: metadata_lease,
        };
        let mut queue = self.queues[target.index()]
            .lock()
            .map_err(|_| io::Error::other("shard queue lock poisoned"))?;
        let work_class = match class {
            PacketClass::Control => WorkClass::Control,
            PacketClass::Data => WorkClass::Data {
                flow: FlowId::new(hash),
                weight: 1,
            },
        };
        match queue.scheduler.enqueue(work_class, bytes, forwarded) {
            Ok(()) => {
                atomic_add_counter(&self.counters.enqueued_packets, 1);
                atomic_add_counter(&self.counters.enqueued_bytes, bytes);
                if class == PacketClass::Control {
                    atomic_add_counter(&self.counters.forwarded_control_packets, 1);
                }
                let wake = queue.waker.take();
                drop(queue);
                if let Some(waker) = wake {
                    atomic_add_counter(&self.counters.forwarded_wakeups, 1);
                    waker.wake();
                }
            }
            Err(_) => {
                atomic_add_counter(&self.counters.dropped_packets, 1);
            }
        }
        Ok(())
    }

    fn drain(&self, owner: ShardId, out: &mut PacketBatch) -> io::Result<usize> {
        let capacity = out.limit().saturating_sub(out.len());
        if capacity == 0 {
            return Ok(0);
        }
        let mut queue = self.queues[owner.index()]
            .lock()
            .map_err(|_| io::Error::other("shard queue lock poisoned"))?;
        let round = queue
            .scheduler
            .run_round_limited(capacity, usize::MAX, |_, forwarded| {
                out.push(forwarded.packet)
                    .expect("limited drain must fit the destination batch");
            });
        atomic_add_counter(&self.counters.drained_packets, round.packets);
        atomic_add_counter(&self.counters.drained_bytes, round.bytes);
        Ok(round.packets)
    }

    fn poll_forwarded(&self, owner: ShardId, waker: &Waker) -> io::Result<bool> {
        let mut queue = self.queues[owner.index()]
            .lock()
            .map_err(|_| io::Error::other("shard queue lock poisoned"))?;
        if queue.scheduler.snapshot().queued_packets > 0 {
            return Ok(true);
        }
        if queue
            .waker
            .as_ref()
            .is_none_or(|registered| !registered.will_wake(waker))
        {
            queue.waker = Some(waker.clone());
            atomic_add_counter(&self.counters.forwarded_waker_registrations, 1);
        }
        Ok(false)
    }

    fn clear_waker(&self, owner: ShardId) {
        if let Ok(mut queue) = self.queues[owner.index()].lock() {
            queue.waker = None;
        }
    }

    fn observe_pressure(&self) -> io::Result<()> {
        let pressure = self.ledger.snapshot().pressure;
        if matches!(pressure, PressureLevel::Critical | PressureLevel::Exhausted) {
            if self
                .cache_pressure_active
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                self.reclaim_routing_caches()?;
            }
        } else if pressure == PressureLevel::Normal {
            self.cache_pressure_active.store(false, Ordering::Release);
        }
        Ok(())
    }

    fn reclaim_routing_caches(&self) -> io::Result<()> {
        let mut directory_entries = 0_usize;
        for stripe in &self.directory {
            let mut stripe = stripe
                .lock()
                .map_err(|_| io::Error::other("flow directory lock poisoned"))?;
            directory_entries = directory_entries.saturating_add(stripe.entries.len());
            stripe.entries.clear();
            stripe.insertion_order.clear();
        }
        let mut local_cache_entries = 0_usize;
        for cache in &self.local_caches {
            let mut cache = cache
                .lock()
                .map_err(|_| io::Error::other("local route cache lock poisoned"))?;
            local_cache_entries = local_cache_entries.saturating_add(cache.entries.len());
            cache.entries.clear();
            cache.insertion_order.clear();
        }
        self.counters.directory_entries.store(0, Ordering::Release);
        atomic_add_counter(&self.counters.pressure_cache_reclaims, 1);
        atomic_add_counter(
            &self.counters.pressure_reclaimed_directory_entries,
            directory_entries,
        );
        atomic_add_counter(
            &self.counters.pressure_reclaimed_local_cache_entries,
            local_cache_entries,
        );
        Ok(())
    }

    fn reset_network(&self, generation: NetworkGeneration) -> io::Result<()> {
        let mut current_generation = self
            .generation
            .write()
            .map_err(|_| io::Error::other("network generation lock poisoned"))?;
        for stripe in &self.directory {
            let mut stripe = stripe
                .lock()
                .map_err(|_| io::Error::other("flow directory lock poisoned"))?;
            stripe.entries.clear();
            stripe.insertion_order.clear();
        }
        for queue in &self.queues {
            queue
                .lock()
                .map_err(|_| io::Error::other("shard queue lock poisoned"))?
                .scheduler
                .clear();
        }
        for cache in &self.local_caches {
            let mut cache = cache
                .lock()
                .map_err(|_| io::Error::other("local route cache lock poisoned"))?;
            cache.entries.clear();
            cache.insertion_order.clear();
        }
        self.counters.directory_entries.store(0, Ordering::Relaxed);
        *current_generation = generation;
        Ok(())
    }

    fn stats(&self) -> io::Result<ShardRouterStats> {
        let mut queued_packets = 0_usize;
        let mut queued_bytes = 0_usize;
        for queue in &self.queues {
            let queue = queue
                .lock()
                .map_err(|_| io::Error::other("shard queue lock poisoned"))?;
            let snapshot = queue.scheduler.snapshot();
            queued_packets = queued_packets.saturating_add(snapshot.queued_packets);
            queued_bytes = queued_bytes.saturating_add(snapshot.queued_bytes);
        }
        let mut local_cache_entries = 0_usize;
        for cache in &self.local_caches {
            local_cache_entries = local_cache_entries.saturating_add(
                cache
                    .lock()
                    .map_err(|_| io::Error::other("local route cache lock poisoned"))?
                    .entries
                    .len(),
            );
        }
        Ok(ShardRouterStats {
            directory_entries: self.counters.directory_entries.load(Ordering::Relaxed),
            local_cache_entries,
            queued_packets,
            queued_bytes,
            pressure_cache_reclaims: to_u64(
                self.counters
                    .pressure_cache_reclaims
                    .load(Ordering::Relaxed),
            ),
            pressure_reclaimed_directory_entries: to_u64(
                self.counters
                    .pressure_reclaimed_directory_entries
                    .load(Ordering::Relaxed),
            ),
            pressure_reclaimed_local_cache_entries: to_u64(
                self.counters
                    .pressure_reclaimed_local_cache_entries
                    .load(Ordering::Relaxed),
            ),
            directory_admission_failures: to_u64(
                self.counters
                    .directory_admission_failures
                    .load(Ordering::Relaxed),
            ),
            local_cache_hits: to_u64(self.counters.local_cache_hits.load(Ordering::Relaxed)),
            local_cache_misses: to_u64(self.counters.local_cache_misses.load(Ordering::Relaxed)),
            local_cache_admission_failures: to_u64(
                self.counters
                    .local_cache_admission_failures
                    .load(Ordering::Relaxed),
            ),
            local_routes: to_u64(self.counters.local_routes.load(Ordering::Relaxed)),
            forwarded_routes: to_u64(self.counters.forwarded_routes.load(Ordering::Relaxed)),
            forwarded_control_packets: to_u64(
                self.counters
                    .forwarded_control_packets
                    .load(Ordering::Relaxed),
            ),
            forwarded_waker_registrations: to_u64(
                self.counters
                    .forwarded_waker_registrations
                    .load(Ordering::Relaxed),
            ),
            forwarded_wakeups: to_u64(self.counters.forwarded_wakeups.load(Ordering::Relaxed)),
            enqueued_packets: to_u64(self.counters.enqueued_packets.load(Ordering::Relaxed)),
            enqueued_bytes: to_u64(self.counters.enqueued_bytes.load(Ordering::Relaxed)),
            dropped_packets: to_u64(self.counters.dropped_packets.load(Ordering::Relaxed)),
            drained_packets: to_u64(self.counters.drained_packets.load(Ordering::Relaxed)),
            drained_bytes: to_u64(self.counters.drained_bytes.load(Ordering::Relaxed)),
        })
    }
}

fn to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

struct WakerRegistration {
    shared: Arc<SharedIngress>,
    shard: ShardId,
}

impl Drop for WakerRegistration {
    fn drop(&mut self) {
        self.shared.clear_waker(self.shard);
    }
}

/// Control-plane handle shared by all queue adapters in one shard group.
#[derive(Clone, Debug)]
pub struct ShardedPacketIoControl {
    shared: Arc<SharedIngress>,
}

impl ShardedPacketIoControl {
    /// Clears flow ownership and queued cross-shard packets, then installs the
    /// generation used to classify future input.
    ///
    /// # Errors
    ///
    /// Returns an error when a directory, queue, or generation lock is
    /// poisoned.
    pub fn reset_network(&self, generation: NetworkGeneration) -> io::Result<()> {
        self.shared.reset_network(generation)
    }

    /// Returns current queue depth and cumulative routing counters.
    ///
    /// # Errors
    ///
    /// Returns an error when a shard queue lock is poisoned.
    pub fn stats(&self) -> io::Result<ShardRouterStats> {
        self.shared.stats()
    }

    /// Predicts the owner selected by the group's stable hash without creating
    /// directory state. Platform RSS setup and tests may use this as an
    /// affinity hint; correctness still relies on bounded forwarding.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed input or a poisoned generation lock.
    pub fn preferred_owner(&self, packet: &[u8]) -> io::Result<ShardId> {
        let generation = self
            .shared
            .generation
            .read()
            .map_err(|_| io::Error::other("network generation lock poisoned"))?;
        let key = classify_packet(packet, *generation)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        self.shared.hashed_owner(key).map(|(owner, _)| owner)
    }
}

/// One platform queue wrapped with striped stable-flow routing and bounded
/// forwarding to the owner shard. A
/// [`SingleShardRunner`](crate::SingleShardRunner) owns each returned adapter.
#[derive(Debug)]
pub struct ShardedPacketIo<I> {
    inner: I,
    shard: ShardId,
    capabilities: PacketCapabilities,
    shared: Arc<SharedIngress>,
    local_cache: Arc<Mutex<LocalRouteCache>>,
}

#[derive(Debug)]
pub enum ShardedPacketIoError {
    InvalidQueueCount,
    Capabilities(io::Error),
    Router(ShardRouterError),
}

impl fmt::Display for ShardedPacketIoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidQueueCount => formatter.write_str(
                "platform queue group must be non-zero, fit u16, and contain compatible queue capabilities",
            ),
            Self::Capabilities(error) => write!(formatter, "invalid packet capabilities: {error}"),
            Self::Router(error) => write!(formatter, "invalid shard router: {error}"),
        }
    }
}

impl std::error::Error for ShardedPacketIoError {}

impl<I: PacketIo> ShardedPacketIo<I> {
    /// Wraps a complete set of platform queues and returns one adapter per
    /// shard plus their reset/stats control handle.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty/oversized group, inconsistent platform
    /// queue capabilities, or an invalid forwarding scheduler.
    pub fn group(
        queues: Vec<I>,
        ledger: Arc<ResourceLedger>,
        generation: NetworkGeneration,
        scheduler: SchedulerConfig,
    ) -> Result<(Vec<Self>, ShardedPacketIoControl), ShardedPacketIoError> {
        let queue_count = queues.len();
        let shard_count = u16::try_from(queue_count)
            .ok()
            .filter(|count| *count > 0)
            .ok_or(ShardedPacketIoError::InvalidQueueCount)?;
        let mut capabilities = Vec::with_capacity(queue_count);
        for queue in &queues {
            let capability = queue
                .capabilities()
                .validate()
                .map_err(ShardedPacketIoError::Capabilities)?;
            if capability.queue_count != 1 && capability.queue_count != queue_count {
                return Err(ShardedPacketIoError::InvalidQueueCount);
            }
            capabilities.push(PacketCapabilities {
                queue_count: 1,
                ..capability
            });
        }
        scheduler
            .validate()
            .map_err(|_| ShardedPacketIoError::Router(ShardRouterError::InvalidQueueConfig))?;
        let queues_state = (0..queue_count)
            .map(|_| {
                Scheduler::new(scheduler)
                    .map(|scheduler| {
                        Mutex::new(QueueState {
                            scheduler,
                            waker: None,
                        })
                    })
                    .map_err(|_| ShardedPacketIoError::Router(ShardRouterError::InvalidQueueConfig))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let local_caches = (0..queue_count)
            .map(|_| {
                Arc::new(Mutex::new(LocalRouteCache {
                    entries: HashMap::new(),
                    insertion_order: VecDeque::new(),
                    max_entries: scheduler.max_active_flows,
                }))
            })
            .collect::<Vec<_>>();
        let shared = Arc::new(SharedIngress {
            generation: RwLock::new(generation),
            shard_count,
            hasher: RandomState::new(),
            ledger,
            directory: (0..DIRECTORY_STRIPES)
                .map(|_| Mutex::new(DirectoryStripe::default()))
                .collect(),
            max_directory_entries_per_stripe: scheduler
                .max_active_flows
                .div_ceil(DIRECTORY_STRIPES)
                .max(1),
            queues: queues_state,
            local_caches: local_caches.clone(),
            cache_pressure_active: AtomicBool::new(false),
            counters: ConcurrentCounters::default(),
        });
        let adapters = (0..shard_count)
            .zip(queues.into_iter().zip(capabilities).zip(local_caches))
            .map(|(index, ((inner, capabilities), local_cache))| Self {
                inner,
                shard: ShardId::new(index),
                capabilities,
                shared: Arc::clone(&shared),
                local_cache,
            })
            .collect();
        Ok((
            adapters,
            ShardedPacketIoControl {
                shared: Arc::clone(&shared),
            },
        ))
    }

    #[must_use]
    pub const fn shard(&self) -> ShardId {
        self.shard
    }

    #[must_use]
    pub const fn inner_mut(&mut self) -> &mut I {
        &mut self.inner
    }

    fn route_received(
        &mut self,
        mut received: PacketBatch,
        out: &mut PacketBatch,
    ) -> io::Result<()> {
        self.shared.observe_pressure()?;
        let generation = self
            .shared
            .generation
            .read()
            .map_err(|_| io::Error::other("network generation lock poisoned"))?;
        while let Some(packet) = received.pop_front() {
            let Ok((key, class)) = classify_packet_with_class(packet.payload(), *generation) else {
                out.push(packet)
                    .expect("platform batch must fit the destination batch");
                continue;
            };
            let cached = if self.shared.cache_pressure_active.load(Ordering::Acquire) {
                None
            } else {
                self.local_cache
                    .lock()
                    .map_err(|_| io::Error::other("local route cache lock poisoned"))?
                    .entries
                    .get(&key)
                    .map(|entry| (entry.owner, entry.hash))
            };
            let (target, hash) = if let Some(route) = cached {
                atomic_add_counter(&self.shared.counters.local_cache_hits, 1);
                route
            } else {
                atomic_add_counter(&self.shared.counters.local_cache_misses, 1);
                let route = self.shared.owner(key)?;
                let mut cache = self
                    .local_cache
                    .lock()
                    .map_err(|_| io::Error::other("local route cache lock poisoned"))?;
                if !self.shared.cache_pressure_active.load(Ordering::Acquire) {
                    if cache.entries.len() >= cache.max_entries {
                        while let Some(oldest) = cache.insertion_order.pop_front() {
                            if cache.entries.remove(&oldest).is_some() {
                                break;
                            }
                        }
                    }
                    match self
                        .shared
                        .ledger
                        .try_acquire(ResourceKind::MetadataBytes, LOCAL_ROUTE_ENTRY_CHARGE)
                    {
                        Ok(lease) => {
                            cache.entries.insert(
                                key,
                                LocalRouteEntry {
                                    owner: route.0,
                                    hash: route.1,
                                    _lease: lease,
                                },
                            );
                            cache.insertion_order.push_back(key);
                        }
                        Err(_) => {
                            atomic_add_counter(
                                &self.shared.counters.local_cache_admission_failures,
                                1,
                            );
                        }
                    }
                }
                route
            };
            if target == self.shard {
                atomic_add_counter(&self.shared.counters.local_routes, 1);
                out.push(packet)
                    .expect("platform batch must fit the destination batch");
            } else {
                atomic_add_counter(&self.shared.counters.forwarded_routes, 1);
                self.shared.enqueue(target, hash, packet, class)?;
            }
        }
        Ok(())
    }
}

impl<I: PacketIo> PacketIo for ShardedPacketIo<I> {
    async fn recv(&mut self, out: &mut PacketBatch) -> io::Result<usize> {
        let forwarded = self.shared.drain(self.shard, out)?;
        if forwarded > 0 {
            return Ok(forwarded);
        }
        let mut received = PacketBatch::with_limit(self.capabilities.max_batch);
        let mut platform_recv = Box::pin(self.inner.recv(&mut received));
        let ingress = Arc::clone(&self.shared);
        let owner = self.shard;
        let _registration = WakerRegistration {
            shared: Arc::clone(&ingress),
            shard: owner,
        };
        let platform_result = poll_fn(|context| {
            match ingress.poll_forwarded(owner, context.waker()) {
                Ok(true) => return Poll::Ready(None),
                Ok(false) => {}
                Err(error) => return Poll::Ready(Some(Err(error))),
            }
            match platform_recv.as_mut().poll(context) {
                Poll::Ready(result) => Poll::Ready(Some(result)),
                Poll::Pending => Poll::Pending,
            }
        })
        .await;
        drop(platform_recv);
        let Some(platform_result) = platform_result else {
            let forwarded = self.shared.drain(self.shard, out)?;
            return if forwarded == 0 {
                Err(io::Error::from(io::ErrorKind::WouldBlock))
            } else {
                Ok(forwarded)
            };
        };
        let reported = platform_result?;
        if reported == 0 || reported != received.len() || reported > self.capabilities.max_batch {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "platform recv count does not match returned batch",
            ));
        }
        self.route_received(received, out)?;
        if out.is_empty() {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }
        Ok(out.len())
    }

    async fn send(&mut self, packets: &PacketBatch) -> io::Result<usize> {
        self.inner.send(packets).await
    }

    fn capabilities(&self) -> PacketCapabilities {
        self.capabilities
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BudgetProfile, IpEndpoint, ResourceBudget, TransportProtocol};
    use std::net::{Ipv4Addr, SocketAddr};

    #[test]
    fn directory_replaces_an_old_entry_in_the_same_stripe_under_its_own_pressure() {
        let base = BudgetProfile::Mobile.budget();
        let budget = ResourceBudget {
            metadata_bytes: DIRECTORY_ENTRY_CHARGE,
            ..base
        };
        let ledger = ResourceLedger::new(budget).unwrap();
        let shared = SharedIngress {
            generation: RwLock::new(NetworkGeneration::new(1)),
            shard_count: 1,
            hasher: RandomState::new(),
            ledger: Arc::clone(&ledger),
            directory: (0..DIRECTORY_STRIPES)
                .map(|_| Mutex::new(DirectoryStripe::default()))
                .collect(),
            // Isolate the budget-driven eviction path from the count bound.
            max_directory_entries_per_stripe: usize::MAX,
            queues: Vec::new(),
            local_caches: Vec::new(),
            cache_pressure_active: AtomicBool::new(false),
            counters: ConcurrentCounters::default(),
        };
        let mut first_by_stripe = HashMap::new();
        let mut collision = None;
        for port in 1_000..=u16::MAX {
            let key = FlowKey {
                endpoint: IpEndpoint {
                    source: SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), port)),
                    destination: SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 443)),
                    protocol: TransportProtocol::Tcp,
                },
                generation: NetworkGeneration::new(1),
            };
            let stripe =
                usize::try_from(shared.hasher.hash_one(key) % DIRECTORY_STRIPES as u64).unwrap();
            if let Some(first) = first_by_stripe.insert(stripe, key) {
                collision = Some((stripe, first, key));
                break;
            }
        }
        let (stripe_index, first, second) = collision.expect("65 keys must collide in 64 stripes");

        assert_eq!(shared.owner(first).unwrap().0, ShardId::new(0));
        assert_eq!(shared.owner(second).unwrap().0, ShardId::new(0));
        let stripe = shared.directory[stripe_index].lock().unwrap();
        assert!(!stripe.entries.contains_key(&first));
        assert!(stripe.entries.contains_key(&second));
        assert_eq!(stripe.entries.len(), 1);
        assert_eq!(stripe.insertion_order.len(), 1);
        assert_eq!(shared.counters.directory_entries.load(Ordering::Relaxed), 1);
        assert_eq!(
            shared
                .counters
                .directory_admission_failures
                .load(Ordering::Relaxed),
            0
        );
        assert_eq!(
            ledger.snapshot().used[ResourceKind::MetadataBytes as usize],
            DIRECTORY_ENTRY_CHARGE
        );
    }
}
