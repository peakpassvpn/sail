use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use crate::metrics::increment_counter;
use crate::wire::checksum_sum;
use crate::{
    BudgetError, BudgetLease, IpVersion, NetworkGeneration, ResourceKind, ResourceLedger,
    TimerError, TimerId, TimerWheel, WireError,
};

const PMTU_METADATA_CHARGE: usize = 128;
const PMTU_TIMER_MIN_TICK_MS: u64 = 10;
const TIMER_WHEEL_SAFE_DELTA_TICKS: u64 = (1_u64 << 32) - 2;
const IPV4_MTU_PLATEAUS: [usize; 11] = [
    65_535, 32_000, 17_914, 8_166, 4_352, 2_002, 1_492, 1_006, 508, 296, 68,
];

#[derive(Debug)]
struct PmtuEntry {
    mtu: usize,
    expires_at_ms: u64,
    expiry_timer: TimerId,
    _entry_lease: BudgetLease,
    _metadata_lease: BudgetLease,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PmtuStats {
    pub active_entries: usize,
    pub learned: u64,
    pub lowered: u64,
    pub expired: u64,
    pub evicted: u64,
    pub rejected: u64,
}

#[derive(Debug)]
pub enum PmtuError {
    Budget(BudgetError),
    ClockWentBackwards,
    Timer(TimerError),
    InvalidMtu,
    InvalidQuote(WireError),
    QuoteSourceMismatch,
}

impl fmt::Display for PmtuError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Budget(error) => write!(formatter, "PMTU resource error: {error}"),
            Self::ClockWentBackwards => formatter.write_str("PMTU clock moved backwards"),
            Self::Timer(error) => write!(formatter, "PMTU timer error: {error}"),
            Self::InvalidMtu => formatter.write_str("invalid reported path MTU"),
            Self::InvalidQuote(error) => write!(formatter, "invalid PMTU quote: {error}"),
            Self::QuoteSourceMismatch => {
                formatter.write_str("PMTU quote does not belong to the ICMP destination")
            }
        }
    }
}

impl std::error::Error for PmtuError {}

impl From<BudgetError> for PmtuError {
    fn from(error: BudgetError) -> Self {
        Self::Budget(error)
    }
}

impl From<TimerError> for PmtuError {
    fn from(error: TimerError) -> Self {
        match error {
            TimerError::ClockWentBackwards { .. } => Self::ClockWentBackwards,
            TimerError::DeadlineOutOfRange => Self::Timer(error),
        }
    }
}

#[derive(Debug)]
pub struct PmtuTable {
    ledger: Arc<ResourceLedger>,
    generation: NetworkGeneration,
    timeout_ms: u64,
    last_now_ms: u64,
    expiry_tick_ms: u64,
    expiry: TimerWheel<IpAddr>,
    entries: HashMap<IpAddr, PmtuEntry>,
    eviction_order: BTreeSet<(u64, IpAddr)>,
    stats: PmtuStats,
}

impl PmtuTable {
    /// # Panics
    ///
    /// Panics when `timeout_ms` is zero.
    #[must_use]
    pub fn new(
        ledger: Arc<ResourceLedger>,
        generation: NetworkGeneration,
        timeout_ms: u64,
    ) -> Self {
        assert!(timeout_ms > 0, "PMTU timeout must be non-zero");
        let expiry_tick_ms = timeout_ms
            .div_ceil(TIMER_WHEEL_SAFE_DELTA_TICKS)
            .max(PMTU_TIMER_MIN_TICK_MS);
        Self {
            ledger,
            generation,
            timeout_ms,
            last_now_ms: 0,
            expiry_tick_ms,
            expiry: TimerWheel::new(expiry_tick_ms, 0),
            entries: HashMap::new(),
            eviction_order: BTreeSet::new(),
            stats: PmtuStats::default(),
        }
    }

    /// Learns a decreasing PMTU from a validated ICMP quote.
    ///
    /// # Errors
    ///
    /// Rejects malformed/spoofed quotes, invalid MTUs, reversed virtual time,
    /// or resource exhaustion without creating a partial entry.
    pub fn learn_from_icmp(
        &mut self,
        icmp_destination: IpAddr,
        quoted_packet: &[u8],
        reported_mtu: u32,
        platform_mtu: usize,
        now_ms: u64,
    ) -> Result<usize, PmtuError> {
        self.expire(now_ms)?;
        let (version, quoted_source, destination) = match quoted_endpoints(quoted_packet) {
            Ok(endpoints) => endpoints,
            Err(error) => {
                increment_counter(&mut self.stats.rejected);
                return Err(error);
            }
        };
        if quoted_source != icmp_destination {
            increment_counter(&mut self.stats.rejected);
            return Err(PmtuError::QuoteSourceMismatch);
        }
        if destination.is_unspecified() || destination.is_multicast() {
            increment_counter(&mut self.stats.rejected);
            return Err(PmtuError::InvalidQuote(WireError::Malformed(
                "invalid quoted destination",
            )));
        }
        let minimum = match version {
            IpVersion::V4 => 68,
            IpVersion::V6 => 1_280,
        };
        let current_mtu = self
            .entries
            .get(&destination)
            .map_or(platform_mtu, |entry| entry.mtu.min(platform_mtu));
        let reported = if version == IpVersion::V4 && reported_mtu == 0 {
            infer_old_style_ipv4_mtu(quoted_packet, current_mtu).ok_or_else(|| {
                increment_counter(&mut self.stats.rejected);
                PmtuError::InvalidMtu
            })?
        } else {
            usize::try_from(reported_mtu).unwrap_or(usize::MAX)
        };
        if reported < minimum {
            increment_counter(&mut self.stats.rejected);
            return Err(PmtuError::InvalidMtu);
        }
        let mtu = reported.min(platform_mtu);
        let expires_at_ms = now_ms.saturating_add(self.timeout_ms);
        if let Some(entry) = self.entries.get_mut(&destination) {
            let old_expiry = entry.expires_at_ms;
            let old_timer = entry.expiry_timer;
            let expiry_timer = self.expiry.schedule(expires_at_ms, destination)?;
            self.expiry.cancel(old_timer);
            self.eviction_order.remove(&(old_expiry, destination));
            entry.expiry_timer = expiry_timer;
            if mtu < entry.mtu {
                entry.mtu = mtu;
                increment_counter(&mut self.stats.lowered);
            }
            entry.expires_at_ms = expires_at_ms;
            self.eviction_order.insert((expires_at_ms, destination));
            return Ok(entry.mtu);
        }
        let entry_lease = match self.ledger.try_acquire(ResourceKind::PmtuEntries, 1) {
            Ok(lease) => lease,
            Err(_) if self.evict_one() => self.ledger.try_acquire(ResourceKind::PmtuEntries, 1)?,
            Err(error) => return Err(error.into()),
        };
        let metadata_lease = self
            .ledger
            .try_acquire(ResourceKind::MetadataBytes, PMTU_METADATA_CHARGE)?;
        let expiry_timer = self.expiry.schedule(expires_at_ms, destination)?;
        self.entries.insert(
            destination,
            PmtuEntry {
                mtu,
                expires_at_ms,
                expiry_timer,
                _entry_lease: entry_lease,
                _metadata_lease: metadata_lease,
            },
        );
        self.eviction_order.insert((expires_at_ms, destination));
        increment_counter(&mut self.stats.learned);
        self.stats.active_entries = self.entries.len();
        Ok(mtu)
    }

    /// Returns the cached PMTU, never exceeding the current platform MTU.
    ///
    /// # Errors
    ///
    /// Returns [`PmtuError::ClockWentBackwards`] for reversed virtual time.
    pub fn effective_mtu(
        &mut self,
        destination: IpAddr,
        platform_mtu: usize,
        now_ms: u64,
    ) -> Result<usize, PmtuError> {
        self.expire(now_ms)?;
        Ok(self
            .entries
            .get(&destination)
            .map_or(platform_mtu, |entry| entry.mtu.min(platform_mtu)))
    }

    /// # Errors
    ///
    /// Returns [`PmtuError::ClockWentBackwards`] for reversed virtual time.
    pub fn expire(&mut self, now_ms: u64) -> Result<usize, PmtuError> {
        self.update_time(now_ms)?;
        let due = self.expiry.advance_to(now_ms)?;
        let mut expired = 0_usize;
        for destination in due {
            if let Some(entry) = self.entries.remove(&destination) {
                self.eviction_order
                    .remove(&(entry.expires_at_ms, destination));
                expired += 1;
            }
        }
        self.stats.expired = self
            .stats
            .expired
            .saturating_add(u64::try_from(expired).unwrap_or(u64::MAX));
        self.stats.active_entries = self.entries.len();
        Ok(expired)
    }

    pub fn reset_network(&mut self, generation: NetworkGeneration) {
        self.generation = generation;
        self.last_now_ms = 0;
        self.entries.clear();
        self.eviction_order.clear();
        self.expiry = TimerWheel::new(self.expiry_tick_ms, 0);
        self.stats.active_entries = 0;
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.eviction_order.clear();
        self.expiry = TimerWheel::new(self.expiry_tick_ms, self.last_now_ms);
        self.stats.active_entries = 0;
    }

    #[must_use]
    pub const fn generation(&self) -> NetworkGeneration {
        self.generation
    }

    #[must_use]
    pub const fn stats(&self) -> PmtuStats {
        self.stats
    }

    /// Records a syntactically valid quote that did not name a live transport
    /// flow. Callers authenticate transport ownership before learning a route.
    pub fn reject_unmatched_flow(&mut self) {
        increment_counter(&mut self.stats.rejected);
    }

    fn update_time(&mut self, now_ms: u64) -> Result<(), PmtuError> {
        if now_ms < self.last_now_ms {
            return Err(PmtuError::ClockWentBackwards);
        }
        self.last_now_ms = now_ms;
        Ok(())
    }

    fn evict_one(&mut self) -> bool {
        if let Some((expires_at_ms, destination)) = self.eviction_order.pop_first() {
            if let Some(entry) = self.entries.remove(&destination) {
                debug_assert_eq!(entry.expires_at_ms, expires_at_ms);
                self.expiry.cancel(entry.expiry_timer);
            } else {
                debug_assert!(false, "PMTU eviction index referenced a missing entry");
                return false;
            }
            increment_counter(&mut self.stats.evicted);
            self.stats.active_entries = self.entries.len();
            true
        } else {
            false
        }
    }
}

fn quoted_endpoints(packet: &[u8]) -> Result<(IpVersion, IpAddr, IpAddr), PmtuError> {
    let version = packet
        .first()
        .ok_or(PmtuError::InvalidQuote(WireError::Truncated))?
        >> 4;
    match version {
        4 if packet.len() >= 20 => {
            let header_len = usize::from(packet[0] & 0x0f) * 4;
            if header_len < 20 || header_len > packet.len() {
                return Err(PmtuError::InvalidQuote(WireError::Malformed(
                    "quoted IPv4 header length",
                )));
            }
            let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
            if total_len < header_len {
                return Err(PmtuError::InvalidQuote(WireError::Malformed(
                    "quoted IPv4 total length",
                )));
            }
            if checksum_sum(&packet[..header_len], 0) != 0xffff {
                return Err(PmtuError::InvalidQuote(WireError::Checksum));
            }
            Ok((
                IpVersion::V4,
                IpAddr::V4(Ipv4Addr::new(
                    packet[12], packet[13], packet[14], packet[15],
                )),
                IpAddr::V4(Ipv4Addr::new(
                    packet[16], packet[17], packet[18], packet[19],
                )),
            ))
        }
        6 if packet.len() >= 40 => Ok((
            IpVersion::V6,
            IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&packet[8..24]).expect("fixed IPv6 address"),
            )),
            IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&packet[24..40]).expect("fixed IPv6 address"),
            )),
        )),
        4 | 6 => Err(PmtuError::InvalidQuote(WireError::Truncated)),
        _ => Err(PmtuError::InvalidQuote(WireError::Unsupported(
            "quoted IP version",
        ))),
    }
}

fn infer_old_style_ipv4_mtu(packet: &[u8], current_mtu: usize) -> Option<usize> {
    let header_len = usize::from(packet.first()? & 0x0f) * 4;
    let mut total_len = usize::from(u16::from_be_bytes([*packet.get(2)?, *packet.get(3)?]));
    if total_len >= current_mtu {
        total_len = total_len.checked_sub(header_len)?;
    }
    IPV4_MTU_PLATEAUS
        .iter()
        .copied()
        .find(|&plateau| plateau < total_len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{emit_udp_packet, BudgetProfile, ResourceBudget};
    use std::net::{Ipv4Addr, SocketAddr};

    fn quote(source: Ipv4Addr, destination: Ipv4Addr) -> Vec<u8> {
        emit_udp_packet(
            SocketAddr::from((source, 1_000)),
            SocketAddr::from((destination, 2_000)),
            b"quoted",
            64,
            1,
        )
        .unwrap()
    }

    #[test]
    fn learns_only_decreasing_authenticated_pmtu_and_expires() {
        let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
        let mut table = PmtuTable::new(Arc::clone(&ledger), NetworkGeneration::new(3), 100);
        let source = Ipv4Addr::new(10, 0, 0, 1);
        let destination = Ipv4Addr::new(1, 1, 1, 1);
        let wire = quote(source, destination);

        assert_eq!(
            table
                .learn_from_icmp(IpAddr::V4(source), &wire[..28], 1_200, 1_500, 1)
                .unwrap(),
            1_200
        );
        assert_eq!(
            table
                .learn_from_icmp(IpAddr::V4(source), &wire[..28], 1_400, 1_500, 12)
                .unwrap(),
            1_200
        );
        assert_eq!(
            table
                .effective_mtu(IpAddr::V4(destination), 1_500, 110)
                .unwrap(),
            1_200
        );
        assert_eq!(
            table
                .effective_mtu(IpAddr::V4(destination), 1_500, 120)
                .unwrap(),
            1_500
        );
        assert_eq!(
            ledger.snapshot().used[ResourceKind::PmtuEntries as usize],
            0
        );
    }

    #[test]
    fn old_style_ipv4_zero_mtu_uses_the_next_lower_plateau() {
        let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
        let source = Ipv4Addr::new(10, 0, 0, 1);
        let destination = Ipv4Addr::new(1, 1, 1, 1);
        let wire = emit_udp_packet(
            SocketAddr::from((source, 1_000)),
            SocketAddr::from((destination, 2_000)),
            &[0; 1_472],
            64,
            1,
        )
        .unwrap();

        let mut ethernet = PmtuTable::new(Arc::clone(&ledger), NetworkGeneration::new(3), 100);
        assert_eq!(
            ethernet
                .learn_from_icmp(IpAddr::V4(source), &wire[..28], 0, 1_500, 1)
                .unwrap(),
            1_006
        );
        ethernet.clear();

        let mut jumbo = PmtuTable::new(ledger, NetworkGeneration::new(3), 100);
        assert_eq!(
            jumbo
                .learn_from_icmp(IpAddr::V4(source), &wire[..28], 0, 9_000, 1)
                .unwrap(),
            1_492
        );
    }

    #[test]
    fn rejects_spoofed_quote_and_evicts_deterministically_at_hard_limit() {
        let base = BudgetProfile::Mobile.budget();
        let budget = ResourceBudget {
            max_pmtu_entries: 1,
            ..base
        };
        let ledger = ResourceLedger::new(budget).unwrap();
        let mut table = PmtuTable::new(ledger, NetworkGeneration::default(), 100);
        let source = Ipv4Addr::new(10, 0, 0, 1);
        let first = quote(source, Ipv4Addr::new(1, 1, 1, 1));
        let second = quote(source, Ipv4Addr::new(8, 8, 8, 8));

        assert!(matches!(
            table.learn_from_icmp(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                &first[..28],
                1_200,
                1_500,
                1
            ),
            Err(PmtuError::QuoteSourceMismatch)
        ));
        table
            .learn_from_icmp(IpAddr::V4(source), &first[..28], 1_200, 1_500, 2)
            .unwrap();
        table
            .learn_from_icmp(IpAddr::V4(source), &second[..28], 1_300, 1_500, 3)
            .unwrap();
        assert_eq!(table.stats().active_entries, 1);
        assert_eq!(table.stats().evicted, 1);
        assert_eq!(
            table
                .effective_mtu(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 1_500, 3)
                .unwrap(),
            1_500
        );
    }

    #[test]
    fn refreshed_entry_moves_to_the_back_of_the_eviction_index() {
        let base = BudgetProfile::Mobile.budget();
        let budget = ResourceBudget {
            max_pmtu_entries: 2,
            ..base
        };
        let ledger = ResourceLedger::new(budget).unwrap();
        let mut table = PmtuTable::new(ledger, NetworkGeneration::default(), 100);
        let source = Ipv4Addr::new(10, 0, 0, 1);
        let first_destination = Ipv4Addr::new(1, 1, 1, 1);
        let second_destination = Ipv4Addr::new(8, 8, 8, 8);
        let third_destination = Ipv4Addr::new(9, 9, 9, 9);
        let first = quote(source, first_destination);
        let second = quote(source, second_destination);
        let third = quote(source, third_destination);

        table
            .learn_from_icmp(IpAddr::V4(source), &first[..28], 1_200, 1_500, 1)
            .unwrap();
        table
            .learn_from_icmp(IpAddr::V4(source), &second[..28], 1_300, 1_500, 2)
            .unwrap();
        table
            .learn_from_icmp(IpAddr::V4(source), &first[..28], 1_250, 1_500, 3)
            .unwrap();
        table
            .learn_from_icmp(IpAddr::V4(source), &third[..28], 1_400, 1_500, 4)
            .unwrap();

        assert_eq!(table.stats().active_entries, 2);
        assert_eq!(table.stats().evicted, 1);
        assert_eq!(
            table
                .effective_mtu(IpAddr::V4(first_destination), 1_500, 4)
                .unwrap(),
            1_200
        );
        assert_eq!(
            table
                .effective_mtu(IpAddr::V4(second_destination), 1_500, 4)
                .unwrap(),
            1_500
        );
        assert_eq!(
            table
                .effective_mtu(IpAddr::V4(third_destination), 1_500, 4)
                .unwrap(),
            1_400
        );
    }
}
