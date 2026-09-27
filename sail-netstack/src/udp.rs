use std::collections::{hash_map::RandomState, HashMap};
use std::fmt;
use std::hash::BuildHasher;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::metrics::increment_counter;
use crate::{
    emit_udp_packet, parse_ip_packet, parse_udp_datagram, BudgetError, BudgetLease, FlowId,
    NetworkGeneration, ResourceKind, ResourceLedger, ShardId, SlabChain, SlabClass, TimerError,
    TimerId, TimerWheel, UdpFlowToken, WireError,
};

const UDP_FLOW_METADATA_CHARGE: usize = 256;
const UDP_TIMER_MIN_TICK_MS: u64 = 10;
// Leave one tick for differing deadline/current rounding phases.
const TIMER_WHEEL_SAFE_DELTA_TICKS: u64 = (1_u64 << 32) - 2;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct UdpFlowKey {
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub generation: NetworkGeneration,
}

#[derive(Debug)]
struct UdpFlow {
    id: FlowId,
    last_seen_ms: u64,
    expiry_timer: TimerId,
    _flow_lease: BudgetLease,
    _metadata_lease: BudgetLease,
}

#[derive(Debug)]
pub struct UdpIngress {
    pub token: UdpFlowToken,
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub payload: SlabChain,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UdpTableStats {
    pub active_flows: usize,
    pub peak_active_flows: usize,
    pub created_flows: u64,
    pub expired_flows: u64,
    pub stale_replies: u64,
    pub malformed_packets: u64,
    pub invalid_address_drops: u64,
}

#[derive(Debug)]
pub enum UdpError {
    Wire(WireError),
    Budget(BudgetError),
    StaleToken,
    ClockWentBackwards,
    Timer(TimerError),
    NewFlowsDisabled,
    /// A multicast, broadcast, unspecified, or otherwise non-unicast endpoint
    /// that must not become a proxied flow (for example LLMNR or mDNS).
    InvalidAddress,
    /// `originate` found no free ephemeral port towards the remote end.
    AddressInUse,
}

impl fmt::Display for UdpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wire(error) => write!(formatter, "UDP wire error: {error}"),
            Self::Budget(error) => write!(formatter, "UDP resource error: {error}"),
            Self::StaleToken => formatter.write_str("stale or unknown UDP flow token"),
            Self::ClockWentBackwards => formatter.write_str("UDP clock moved backwards"),
            Self::Timer(error) => write!(formatter, "UDP timer error: {error}"),
            Self::NewFlowsDisabled => formatter.write_str("new UDP flows are disabled"),
            Self::InvalidAddress => formatter.write_str("UDP endpoint is not unicast"),
            Self::AddressInUse => formatter.write_str("no free UDP port towards the peer"),
        }
    }
}

impl std::error::Error for UdpError {}

impl From<WireError> for UdpError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}

impl From<BudgetError> for UdpError {
    fn from(error: BudgetError) -> Self {
        Self::Budget(error)
    }
}

impl From<TimerError> for UdpError {
    fn from(error: TimerError) -> Self {
        match error {
            TimerError::ClockWentBackwards { .. } => Self::ClockWentBackwards,
            TimerError::DeadlineOutOfRange => Self::Timer(error),
        }
    }
}

/// Shard-local UDP session table. It owns all flow state and issues generation-
/// checked reply capabilities to the sail NAT integration layer.
#[derive(Debug)]
pub struct UdpTable {
    ledger: Arc<ResourceLedger>,
    generation: NetworkGeneration,
    shard: ShardId,
    idle_timeout_ms: u64,
    payload_chunk_size: usize,
    last_now_ms: u64,
    timeout_divisor: u64,
    expiry_tick_ms: u64,
    expiry: TimerWheel<UdpFlowKey>,
    next_flow_id: u64,
    by_key: HashMap<UdpFlowKey, UdpFlow>,
    by_id: HashMap<FlowId, UdpFlowKey>,
    stats: UdpTableStats,
    hash_state: RandomState,
}

impl UdpTable {
    /// # Panics
    ///
    /// Panics when `idle_timeout_ms` or `payload_chunk_size` is zero.
    #[must_use]
    pub fn new(
        ledger: Arc<ResourceLedger>,
        generation: NetworkGeneration,
        idle_timeout_ms: u64,
        payload_chunk_size: usize,
    ) -> Self {
        Self::new_on_shard(
            ledger,
            generation,
            ShardId::default(),
            idle_timeout_ms,
            payload_chunk_size,
        )
    }

    /// Constructs a table whose capabilities are owned by `shard`.
    ///
    /// # Panics
    ///
    /// Panics when `idle_timeout_ms` or `payload_chunk_size` is zero.
    #[must_use]
    pub fn new_on_shard(
        ledger: Arc<ResourceLedger>,
        generation: NetworkGeneration,
        shard: ShardId,
        idle_timeout_ms: u64,
        payload_chunk_size: usize,
    ) -> Self {
        assert!(idle_timeout_ms > 0, "UDP idle timeout must be non-zero");
        assert!(payload_chunk_size > 0, "UDP payload chunk must be non-zero");
        let expiry_tick_ms = idle_timeout_ms
            .div_ceil(TIMER_WHEEL_SAFE_DELTA_TICKS)
            .max(UDP_TIMER_MIN_TICK_MS);
        Self {
            ledger,
            generation,
            shard,
            idle_timeout_ms,
            payload_chunk_size,
            last_now_ms: 0,
            timeout_divisor: 1,
            expiry_tick_ms,
            expiry: TimerWheel::new(expiry_tick_ms, 0),
            next_flow_id: 0,
            by_key: HashMap::new(),
            by_id: HashMap::new(),
            stats: UdpTableStats::default(),
            hash_state: RandomState::new(),
        }
    }

    /// Parses and admits a UDP packet atomically. A failed payload or flow
    /// allocation does not create a session.
    ///
    /// # Errors
    ///
    /// Returns [`UdpError`] for invalid time, wire input, checksum, or resource
    /// admission failure.
    pub fn ingest(&mut self, packet: &[u8], now_ms: u64) -> Result<UdpIngress, UdpError> {
        self.ingest_with_policy(packet, now_ms, true)
    }

    /// Equivalent to [`UdpTable::ingest`], with explicit control over new-flow
    /// admission for graceful shutdown.
    ///
    /// # Errors
    ///
    /// Returns [`UdpError::NewFlowsDisabled`] for an unknown tuple when
    /// `allow_new` is false, in addition to the normal ingest errors.
    pub fn ingest_with_policy(
        &mut self,
        packet: &[u8],
        now_ms: u64,
        allow_new: bool,
    ) -> Result<UdpIngress, UdpError> {
        self.update_time(now_ms)?;
        // Ingress is also a clock-driving operation. Expire a retired tuple
        // before looking it up so a packet arriving after the idle deadline
        // creates a fresh capability instead of reviving the old flow ID.
        self.expire_due(now_ms)?;
        let ip = match parse_ip_packet(packet, true) {
            Ok(ip) => ip,
            Err(error) => {
                increment_counter(&mut self.stats.malformed_packets);
                return Err(error.into());
            }
        };
        let datagram = match parse_udp_datagram(ip, true) {
            Ok(datagram) => datagram,
            Err(error) => {
                increment_counter(&mut self.stats.malformed_packets);
                return Err(error.into());
            }
        };
        if !crate::wire::valid_flow_source(datagram.source.ip())
            || !crate::wire::valid_flow_destination(datagram.destination.ip())
        {
            increment_counter(&mut self.stats.invalid_address_drops);
            return Err(UdpError::InvalidAddress);
        }
        let key = UdpFlowKey {
            source: datagram.source,
            destination: datagram.destination,
            generation: self.generation,
        };
        if !allow_new && !self.by_key.contains_key(&key) {
            return Err(UdpError::NewFlowsDisabled);
        }
        let mut payload = SlabChain::new(
            Arc::clone(&self.ledger),
            SlabClass::Packet,
            self.payload_chunk_size,
        );
        payload.append(datagram.payload)?;

        let id = self.touch_or_admit(key, now_ms)?;
        Ok(UdpIngress {
            token: UdpFlowToken::new_on_shard(id, self.generation, self.shard),
            source: datagram.source,
            destination: datagram.destination,
            payload,
        })
    }

    /// Sends a datagram from `local` to `remote`, opening a flow for the
    /// four-tuple or refreshing the one there is, and returns its token with
    /// the packet. Port 0 in `local` picks a free ephemeral port. The remote
    /// end's datagrams back to that port arrive through
    /// [`UdpTable::ingest`] with the same token.
    ///
    /// # Errors
    ///
    /// Returns [`UdpError::InvalidAddress`] for endpoints that cannot carry
    /// a unicast flow, a wire error for a payload that does not fit a
    /// datagram, or a budget error when a new flow cannot be charged.
    pub fn originate(
        &mut self,
        local: SocketAddr,
        remote: SocketAddr,
        payload: &[u8],
        now_ms: u64,
    ) -> Result<(UdpFlowToken, Vec<u8>), UdpError> {
        self.update_time(now_ms)?;
        self.expire_due(now_ms)?;
        // Replies arrive from `remote` to `local` and must pass the checks
        // any inbound datagram does.
        if local.is_ipv4() != remote.is_ipv4()
            || remote.port() == 0
            || !crate::wire::valid_flow_source(remote.ip())
            || !crate::wire::valid_flow_destination(local.ip())
        {
            return Err(UdpError::InvalidAddress);
        }
        let local = if local.port() == 0 {
            self.ephemeral_local(local, remote)?
        } else {
            local
        };
        let key = UdpFlowKey {
            source: remote,
            destination: local,
            generation: self.generation,
        };
        // The packet is built before the flow, from the id the flow has or
        // will get, so that an unsendable payload leaves no flow behind.
        let id = self
            .by_key
            .get(&key)
            .map_or(FlowId::new(self.next_flow_id), |flow| flow.id);
        let identification =
            u16::from_be_bytes([id.get().to_be_bytes()[6], id.get().to_be_bytes()[7]]);
        let wire = emit_udp_packet(local, remote, payload, 64, identification)?;
        let admitted = self.touch_or_admit(key, now_ms)?;
        debug_assert_eq!(admitted, id);
        Ok((
            UdpFlowToken::new_on_shard(admitted, self.generation, self.shard),
            wire,
        ))
    }

    /// A local address on `local`'s IP with a port in the IANA dynamic range
    /// (RFC 6335) that no flow to `remote` uses, from a keyed offset.
    fn ephemeral_local(
        &self,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> Result<SocketAddr, UdpError> {
        const FIRST: u16 = 49_152;
        const SPAN: u64 = 65_536 - FIRST as u64;
        let start = self
            .hash_state
            .hash_one((remote, local.ip(), self.next_flow_id));
        (0..SPAN)
            .map(|offset| {
                let port = FIRST
                    + u16::try_from(start.wrapping_add(offset) % SPAN)
                        .expect("an offset below SPAN fits a port");
                SocketAddr::new(local.ip(), port)
            })
            .find(|candidate| {
                !self.by_key.contains_key(&UdpFlowKey {
                    source: remote,
                    destination: *candidate,
                    generation: self.generation,
                })
            })
            .ok_or(UdpError::AddressInUse)
    }

    /// Refreshes the flow for `key`, or admits a new one, and returns its id.
    fn touch_or_admit(&mut self, key: UdpFlowKey, now_ms: u64) -> Result<FlowId, UdpError> {
        let deadline = self.expiry_deadline(now_ms, self.timeout_divisor);
        let expiry_timer = self.schedule_expiry(deadline, key, now_ms)?;
        let id = if let Some(flow) = self.by_key.get_mut(&key) {
            self.expiry.cancel(flow.expiry_timer);
            flow.expiry_timer = expiry_timer;
            flow.last_seen_ms = now_ms;
            flow.id
        } else {
            let flow_lease = match self.ledger.try_acquire(ResourceKind::UdpFlows, 1) {
                Ok(lease) => lease,
                Err(error) => {
                    self.expiry.cancel(expiry_timer);
                    return Err(error.into());
                }
            };
            let metadata_lease = match self
                .ledger
                .try_acquire(ResourceKind::MetadataBytes, UDP_FLOW_METADATA_CHARGE)
            {
                Ok(lease) => lease,
                Err(error) => {
                    self.expiry.cancel(expiry_timer);
                    return Err(error.into());
                }
            };
            let id = FlowId::new(self.next_flow_id);
            self.next_flow_id = self.next_flow_id.wrapping_add(1);
            self.by_key.insert(
                key,
                UdpFlow {
                    id,
                    last_seen_ms: now_ms,
                    expiry_timer,
                    _flow_lease: flow_lease,
                    _metadata_lease: metadata_lease,
                },
            );
            self.by_id.insert(id, key);
            increment_counter(&mut self.stats.created_flows);
            id
        };
        self.stats.active_flows = self.by_key.len();
        self.stats.peak_active_flows = self.stats.peak_active_flows.max(self.stats.active_flows);
        Ok(id)
    }

    /// Emits a reply toward the original client. `source` may differ from the
    /// intercepted destination when sail resolves a `FakeDNS` mapping.
    ///
    /// # Errors
    ///
    /// Returns [`UdpError::StaleToken`] after expiry/reset or a wire error for
    /// incompatible addresses and oversized payloads.
    pub fn emit_reply(
        &mut self,
        token: UdpFlowToken,
        source: SocketAddr,
        payload: &[u8],
        now_ms: u64,
    ) -> Result<Vec<u8>, UdpError> {
        self.update_time(now_ms)?;
        self.expire_due(now_ms)?;
        if !token.is_owned_by(self.generation, self.shard) {
            increment_counter(&mut self.stats.stale_replies);
            return Err(UdpError::StaleToken);
        }
        let Some(key) = self.by_id.get(&token.flow()).copied() else {
            increment_counter(&mut self.stats.stale_replies);
            return Err(UdpError::StaleToken);
        };
        let flow_bytes = token.flow().get().to_be_bytes();
        let identification = u16::from_be_bytes([flow_bytes[6], flow_bytes[7]]);
        // Validate and build the datagram before refreshing the session. An
        // invalid application reply must not keep an otherwise idle flow alive.
        let wire = emit_udp_packet(source, key.source, payload, 64, identification)?;
        let deadline = self.expiry_deadline(now_ms, self.timeout_divisor);
        let expiry_timer = self.expiry.schedule(deadline, key)?;
        let Some(flow) = self.by_key.get_mut(&key) else {
            self.expiry.cancel(expiry_timer);
            increment_counter(&mut self.stats.stale_replies);
            return Err(UdpError::StaleToken);
        };
        self.expiry.cancel(flow.expiry_timer);
        flow.expiry_timer = expiry_timer;
        flow.last_seen_ms = now_ms;
        Ok(wire)
    }

    /// Expires idle flows and releases their leases.
    ///
    /// # Errors
    ///
    /// Returns [`UdpError::ClockWentBackwards`] without mutation for a reversed
    /// clock.
    pub fn expire_idle(&mut self, now_ms: u64) -> Result<usize, UdpError> {
        self.expire_idle_under_pressure(now_ms, 1)
    }

    /// Expires idle flows with a pressure-dependent timeout divisor. A value
    /// greater than one reclaims idle state earlier without changing active
    /// flow timestamps.
    ///
    /// # Errors
    ///
    /// Returns [`UdpError::ClockWentBackwards`] without mutation for a reversed
    /// clock.
    pub fn expire_idle_under_pressure(
        &mut self,
        now_ms: u64,
        timeout_divisor: u64,
    ) -> Result<usize, UdpError> {
        self.update_time(now_ms)?;
        let timeout_divisor = timeout_divisor.max(1);
        let expired = if timeout_divisor == self.timeout_divisor {
            self.expiry.advance_to(now_ms)?
        } else {
            self.rebuild_expiry(now_ms, timeout_divisor)?
        };
        Ok(self.remove_expired(&expired))
    }

    pub fn reset_network(&mut self, generation: NetworkGeneration) {
        self.generation = generation;
        self.by_key.clear();
        self.by_id.clear();
        self.expiry = TimerWheel::new(self.expiry_tick_ms, self.last_now_ms);
        self.stats.active_flows = 0;
    }

    pub fn clear(&mut self) {
        self.by_key.clear();
        self.by_id.clear();
        self.expiry = TimerWheel::new(self.expiry_tick_ms, self.last_now_ms);
        self.stats.active_flows = 0;
    }

    #[must_use]
    pub const fn generation(&self) -> NetworkGeneration {
        self.generation
    }

    #[must_use]
    pub const fn stats(&self) -> UdpTableStats {
        self.stats
    }

    /// Returns whether an outgoing packet quote names the reverse direction
    /// of a live intercepted flow in the current network generation.
    #[must_use]
    pub fn has_quoted_reply(
        &self,
        quoted_source: SocketAddr,
        quoted_destination: SocketAddr,
    ) -> bool {
        self.by_key.contains_key(&UdpFlowKey {
            source: quoted_destination,
            destination: quoted_source,
            generation: self.generation,
        })
    }

    fn update_time(&mut self, now_ms: u64) -> Result<(), UdpError> {
        if now_ms < self.last_now_ms {
            return Err(UdpError::ClockWentBackwards);
        }
        self.last_now_ms = now_ms;
        Ok(())
    }

    fn effective_timeout(&self, timeout_divisor: u64) -> u64 {
        self.idle_timeout_ms
            .checked_div(timeout_divisor.max(1))
            .unwrap_or(self.idle_timeout_ms)
            .max(1)
    }

    fn expiry_deadline(&self, last_seen_ms: u64, timeout_divisor: u64) -> u64 {
        last_seen_ms.saturating_add(self.effective_timeout(timeout_divisor))
    }

    fn expire_due(&mut self, now_ms: u64) -> Result<usize, UdpError> {
        let expired = self.expiry.advance_to(now_ms)?;
        Ok(self.remove_expired(&expired))
    }

    fn schedule_expiry(
        &mut self,
        deadline_ms: u64,
        key: UdpFlowKey,
        now_ms: u64,
    ) -> Result<TimerId, UdpError> {
        match self.expiry.schedule(deadline_ms, key) {
            Ok(timer) => Ok(timer),
            Err(TimerError::DeadlineOutOfRange) => {
                self.expire_due(now_ms)?;
                self.expiry.schedule(deadline_ms, key).map_err(Into::into)
            }
            Err(error) => Err(error.into()),
        }
    }

    fn remove_expired(&mut self, expired: &[UdpFlowKey]) -> usize {
        let mut removed = 0_usize;
        for key in expired {
            if let Some(flow) = self.by_key.remove(key) {
                self.by_id.remove(&flow.id);
                removed += 1;
            }
        }
        self.stats.expired_flows = self
            .stats
            .expired_flows
            .saturating_add(u64::try_from(removed).unwrap_or(u64::MAX));
        self.stats.active_flows = self.by_key.len();
        removed
    }

    fn rebuild_expiry(
        &mut self,
        now_ms: u64,
        timeout_divisor: u64,
    ) -> Result<Vec<UdpFlowKey>, UdpError> {
        let effective_timeout = self.effective_timeout(timeout_divisor);
        self.expiry = TimerWheel::new(self.expiry_tick_ms, now_ms);
        let mut expired = Vec::new();
        for (key, flow) in &mut self.by_key {
            if now_ms.saturating_sub(flow.last_seen_ms) >= effective_timeout {
                expired.push(*key);
                continue;
            }
            let deadline = flow.last_seen_ms.saturating_add(effective_timeout);
            flow.expiry_timer = self.expiry.schedule(deadline, *key)?;
        }
        self.timeout_divisor = timeout_divisor;
        Ok(expired)
    }
}
