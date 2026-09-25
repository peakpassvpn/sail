use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;

use crate::metrics::increment_counter;
use crate::{
    parse_ip_packet, BudgetError, BudgetLease, FragmentInfo, IpVersion, ResourceKind,
    ResourceLedger, TimerError, TimerId, TimerWheel, WireError,
};

const ASSEMBLY_METADATA_BYTES: usize = 192;
const PIECE_METADATA_BYTES: usize = 64;
const MAX_REASSEMBLED_BYTES: usize = 65_535;
const FRAGMENT_TIMER_MIN_TICK_MS: u64 = 10;
const TIMER_WHEEL_SAFE_DELTA_TICKS: u64 = (1_u64 << 32) - 2;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct FragmentKey {
    version: IpVersion,
    source: IpAddr,
    destination: IpAddr,
    protocol: u8,
    identification: u32,
}

#[derive(Debug)]
struct Piece {
    bytes: Box<[u8]>,
    _slot: BudgetLease,
    _payload: BudgetLease,
    _metadata: BudgetLease,
}

#[derive(Debug)]
struct Assembly {
    header: Option<Vec<u8>>,
    ipv6_previous_next_header: Option<usize>,
    protocol: u8,
    pieces: BTreeMap<u32, Piece>,
    total_payload_len: Option<u32>,
    created_at_ms: u64,
    expiry_timer: TimerId,
    eviction_key: (u64, u64),
    _metadata: BudgetLease,
}

#[derive(Debug)]
struct PendingFragmentCredit {
    slot: BudgetLease,
    payload: BudgetLease,
    piece_metadata: BudgetLease,
    assembly_metadata: Option<BudgetLease>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FragmentStats {
    pub active_datagrams: usize,
    pub buffered_fragments: usize,
    pub completed_datagrams: u64,
    pub expired_datagrams: u64,
    pub evicted_datagrams: u64,
    pub overlap_drops: u64,
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct FragmentExpirations {
    pub expired_datagrams: usize,
    pub invoking_packets: Vec<Vec<u8>>,
}

#[derive(Debug)]
pub enum FragmentError {
    Wire(WireError),
    Budget(BudgetError),
    ClockWentBackwards,
    Timer(TimerError),
    Malformed(&'static str),
    Overlap,
}

impl fmt::Display for FragmentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wire(error) => write!(formatter, "fragment wire error: {error}"),
            Self::Budget(error) => write!(formatter, "fragment resource error: {error}"),
            Self::ClockWentBackwards => formatter.write_str("fragment clock moved backwards"),
            Self::Timer(error) => write!(formatter, "fragment timer error: {error}"),
            Self::Malformed(message) => write!(formatter, "malformed fragment: {message}"),
            Self::Overlap => formatter.write_str("overlapping IP fragments"),
        }
    }
}

impl std::error::Error for FragmentError {}

impl From<WireError> for FragmentError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}

impl From<BudgetError> for FragmentError {
    fn from(error: BudgetError) -> Self {
        Self::Budget(error)
    }
}

impl From<TimerError> for FragmentError {
    fn from(error: TimerError) -> Self {
        match error {
            TimerError::ClockWentBackwards { .. } => Self::ClockWentBackwards,
            TimerError::DeadlineOutOfRange => Self::Timer(error),
        }
    }
}

#[derive(Debug)]
pub struct FragmentReassembler {
    ledger: Arc<ResourceLedger>,
    timeout_ms: u64,
    now_ms: u64,
    timeout_divisor: u64,
    expiry_tick_ms: u64,
    expiry: TimerWheel<FragmentKey>,
    assemblies: HashMap<FragmentKey, Assembly>,
    eviction_index: BTreeMap<(u64, u64), FragmentKey>,
    next_eviction_serial: u64,
    stats: FragmentStats,
}

impl FragmentReassembler {
    /// # Panics
    ///
    /// Panics when `timeout_ms` is zero.
    #[must_use]
    pub fn new(ledger: Arc<ResourceLedger>, timeout_ms: u64) -> Self {
        assert!(timeout_ms > 0, "fragment timeout must be non-zero");
        let expiry_tick_ms = timeout_ms
            .div_ceil(TIMER_WHEEL_SAFE_DELTA_TICKS)
            .max(FRAGMENT_TIMER_MIN_TICK_MS);
        Self {
            ledger,
            timeout_ms,
            now_ms: 0,
            timeout_divisor: 1,
            expiry_tick_ms,
            expiry: TimerWheel::new(expiry_tick_ms, 0),
            assemblies: HashMap::new(),
            eviction_index: BTreeMap::new(),
            next_eviction_serial: 0,
            stats: FragmentStats::default(),
        }
    }

    /// Buffers one fragment and returns a complete reconstructed IP packet.
    /// Non-fragmented and IPv6 atomic-fragment packets pass through unchanged.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, overlapping, over-budget, or
    /// time-regressing input.
    pub fn ingest(&mut self, packet: &[u8], now_ms: u64) -> Result<Option<Vec<u8>>, FragmentError> {
        self.advance_current(now_ms)?;
        let ip = parse_ip_packet(packet, true)?;
        let Some(fragment) = ip.fragment else {
            return Ok(Some(packet.to_vec()));
        };
        if fragment.is_atomic() {
            return Ok(Some(packet.to_vec()));
        }
        let fragment_payload = ip.fragment_payload.unwrap_or(ip.payload);
        let end = fragment_end(fragment, fragment_payload.len())?;
        let (header, previous_next_header, protocol) = fragment_header(packet, ip.version)?;
        validate_reassembled_size(ip.version, header.len(), end)?;
        let key = FragmentKey {
            version: ip.version,
            source: ip.source,
            destination: ip.destination,
            protocol: if ip.version == IpVersion::V4 {
                protocol
            } else {
                0
            },
            identification: fragment.identification,
        };
        if self.overlaps(key, fragment.offset_bytes, end) {
            self.remove_assembly(&key);
            increment_counter(&mut self.stats.overlap_drops);
            return Err(FragmentError::Overlap);
        }
        if self.conflicts(key, protocol, fragment, end, header.len()) {
            self.remove_assembly(&key);
            return Err(FragmentError::Malformed(
                "fragment conflicts with established datagram bounds",
            ));
        }
        let credit = self.acquire_fragment_credit(key, fragment_payload.len())?;
        if !self.assemblies.contains_key(&key) {
            let metadata = credit.assembly_metadata.ok_or(FragmentError::Malformed(
                "new assembly lacked metadata credit",
            ))?;
            let deadline = now_ms.saturating_add(self.effective_timeout(self.timeout_divisor));
            let expiry_timer = self.expiry.schedule(deadline, key)?;
            let eviction_key = self.next_eviction_key(now_ms);
            self.assemblies.insert(
                key,
                Assembly {
                    header: None,
                    ipv6_previous_next_header: None,
                    protocol,
                    pieces: BTreeMap::new(),
                    total_payload_len: None,
                    created_at_ms: now_ms,
                    expiry_timer,
                    eviction_key,
                    _metadata: metadata,
                },
            );
            self.eviction_index.insert(eviction_key, key);
            self.stats.active_datagrams = self.assemblies.len();
        }
        let assembly = self
            .assemblies
            .get_mut(&key)
            .ok_or(FragmentError::Malformed("fragment assembly disappeared"))?;
        if fragment.offset_bytes == 0 {
            assembly.header = Some(header);
            assembly.ipv6_previous_next_header = previous_next_header;
        }
        if !fragment.more_fragments {
            if assembly.total_payload_len.is_some_and(|total| total != end) {
                self.remove_assembly(&key);
                return Err(FragmentError::Malformed(
                    "conflicting final fragment lengths",
                ));
            }
            assembly.total_payload_len = Some(end);
        }
        assembly.pieces.insert(
            fragment.offset_bytes,
            Piece {
                bytes: fragment_payload.into(),
                _slot: credit.slot,
                _payload: credit.payload,
                _metadata: credit.piece_metadata,
            },
        );
        self.stats.buffered_fragments = self.stats.buffered_fragments.saturating_add(1);
        if !is_complete(assembly) {
            return Ok(None);
        }
        let assembly = self
            .remove_assembly(&key)
            .ok_or(FragmentError::Malformed("complete assembly disappeared"))?;
        let packet = rebuild(assembly, key.version)?;
        increment_counter(&mut self.stats.completed_datagrams);
        Ok(Some(packet))
    }

    /// Expires incomplete datagrams.
    ///
    /// # Errors
    ///
    /// Returns [`FragmentError::ClockWentBackwards`] if time regresses.
    pub fn advance_time(&mut self, now_ms: u64) -> Result<usize, FragmentError> {
        self.advance_time_under_pressure(now_ms, 1)
    }

    /// Expires incomplete datagrams using a pressure-dependent timeout
    /// divisor. Existing assemblies retain their original creation time.
    ///
    /// # Errors
    ///
    /// Returns [`FragmentError::ClockWentBackwards`] if time regresses.
    pub fn advance_time_under_pressure(
        &mut self,
        now_ms: u64,
        timeout_divisor: u64,
    ) -> Result<usize, FragmentError> {
        self.advance_time_under_pressure_with_quotes(now_ms, timeout_divisor, 0)
            .map(|expired| expired.expired_datagrams)
    }

    /// Expires incomplete datagrams and retains a bounded number of initial
    /// fragments suitable for ICMP reassembly-timeout quotes. Assemblies that
    /// never received offset zero are counted and released without a quote.
    ///
    /// # Errors
    ///
    /// Returns [`FragmentError::ClockWentBackwards`] if time regresses.
    pub fn advance_time_under_pressure_with_quotes(
        &mut self,
        now_ms: u64,
        timeout_divisor: u64,
        max_quotes: usize,
    ) -> Result<FragmentExpirations, FragmentError> {
        self.update_time(now_ms)?;
        let timeout_divisor = timeout_divisor.max(1);
        let due = if timeout_divisor == self.timeout_divisor {
            self.expiry.advance_to(now_ms)?
        } else {
            self.rebuild_expiry(now_ms, timeout_divisor)?
        };
        let expired = self.expire_due(due, max_quotes);
        self.stats.expired_datagrams = self
            .stats
            .expired_datagrams
            .saturating_add(u64::try_from(expired.expired_datagrams).unwrap_or(u64::MAX));
        Ok(expired)
    }

    pub fn clear(&mut self) {
        self.assemblies.clear();
        self.eviction_index.clear();
        self.expiry = TimerWheel::new(self.expiry_tick_ms, self.now_ms);
        self.stats.active_datagrams = 0;
        self.stats.buffered_fragments = 0;
    }

    #[must_use]
    pub const fn stats(&self) -> FragmentStats {
        self.stats
    }

    fn overlaps(&self, key: FragmentKey, start: u32, end: u32) -> bool {
        self.assemblies.get(&key).is_some_and(|assembly| {
            assembly.pieces.iter().any(|(&offset, piece)| {
                let piece_end =
                    offset.saturating_add(u32::try_from(piece.bytes.len()).unwrap_or(u32::MAX));
                start < piece_end && offset < end
            })
        })
    }

    fn conflicts(
        &self,
        key: FragmentKey,
        protocol: u8,
        fragment: FragmentInfo,
        end: u32,
        header_len: usize,
    ) -> bool {
        self.assemblies.get(&key).is_some_and(|assembly| {
            if assembly.protocol != protocol
                || assembly.total_payload_len.is_some_and(|total| end > total)
            {
                return true;
            }
            if !fragment.more_fragments
                && assembly.pieces.iter().any(|(&offset, piece)| {
                    offset.saturating_add(u32::try_from(piece.bytes.len()).unwrap_or(u32::MAX))
                        > end
                })
            {
                return true;
            }
            let total = if fragment.more_fragments {
                assembly.total_payload_len
            } else {
                Some(end)
            };
            let final_header_len = if fragment.offset_bytes == 0 {
                Some(header_len)
            } else {
                assembly.header.as_ref().map(Vec::len)
            };
            total
                .zip(final_header_len)
                .is_some_and(|(total, header_len)| {
                    reassembled_size_exceeds(key.version, header_len, total)
                })
        })
    }

    fn update_time(&mut self, now_ms: u64) -> Result<(), FragmentError> {
        if now_ms < self.now_ms {
            return Err(FragmentError::ClockWentBackwards);
        }
        self.now_ms = now_ms;
        Ok(())
    }

    fn acquire_fragment_credit(
        &mut self,
        key: FragmentKey,
        payload_len: usize,
    ) -> Result<PendingFragmentCredit, FragmentError> {
        loop {
            let needs_assembly = !self.assemblies.contains_key(&key);
            match self.try_acquire_fragment_credit(payload_len, needs_assembly) {
                Ok(credit) => return Ok(credit),
                Err(_) if self.evict_oldest_assembly() => {
                    self.stats.evicted_datagrams = self.stats.evicted_datagrams.saturating_add(1);
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    fn try_acquire_fragment_credit(
        &self,
        payload_len: usize,
        needs_assembly: bool,
    ) -> Result<PendingFragmentCredit, BudgetError> {
        let slot = self.ledger.try_acquire(ResourceKind::Fragments, 1)?;
        let payload = self
            .ledger
            .try_acquire(ResourceKind::FragmentBytes, payload_len)?;
        let piece_metadata = self
            .ledger
            .try_acquire(ResourceKind::MetadataBytes, PIECE_METADATA_BYTES)?;
        let assembly_metadata = needs_assembly
            .then(|| {
                self.ledger
                    .try_acquire(ResourceKind::MetadataBytes, ASSEMBLY_METADATA_BYTES)
            })
            .transpose()?;
        Ok(PendingFragmentCredit {
            slot,
            payload,
            piece_metadata,
            assembly_metadata,
        })
    }

    fn evict_oldest_assembly(&mut self) -> bool {
        let Some((_, key)) = self.eviction_index.first_key_value() else {
            return false;
        };
        let key = *key;
        self.remove_assembly(&key).is_some()
    }

    fn next_eviction_key(&mut self, created_at_ms: u64) -> (u64, u64) {
        loop {
            let key = (created_at_ms, self.next_eviction_serial);
            self.next_eviction_serial = self.next_eviction_serial.wrapping_add(1);
            if !self.eviction_index.contains_key(&key) {
                return key;
            }
        }
    }

    fn effective_timeout(&self, timeout_divisor: u64) -> u64 {
        self.timeout_ms
            .checked_div(timeout_divisor.max(1))
            .unwrap_or(self.timeout_ms)
            .max(1)
    }

    fn advance_current(&mut self, now_ms: u64) -> Result<usize, FragmentError> {
        self.update_time(now_ms)?;
        let due = self.expiry.advance_to(now_ms)?;
        let expired = self.expire_due(due, 0).expired_datagrams;
        self.stats.expired_datagrams = self
            .stats
            .expired_datagrams
            .saturating_add(u64::try_from(expired).unwrap_or(u64::MAX));
        Ok(expired)
    }

    fn expire_due(&mut self, due: Vec<FragmentKey>, max_quotes: usize) -> FragmentExpirations {
        let mut expired = FragmentExpirations::default();
        for key in due {
            let Some(assembly) = self.take_assembly(&key) else {
                continue;
            };
            expired.expired_datagrams = expired.expired_datagrams.saturating_add(1);
            if expired.invoking_packets.len() < max_quotes {
                if let Some(packet) = initial_fragment_packet(&assembly, key) {
                    expired.invoking_packets.push(packet);
                }
            }
        }
        expired
    }

    fn rebuild_expiry(
        &mut self,
        now_ms: u64,
        timeout_divisor: u64,
    ) -> Result<Vec<FragmentKey>, FragmentError> {
        let effective_timeout = self.effective_timeout(timeout_divisor);
        self.expiry = TimerWheel::new(self.expiry_tick_ms, now_ms);
        let mut expired = Vec::new();
        for (key, assembly) in &mut self.assemblies {
            if now_ms.saturating_sub(assembly.created_at_ms) >= effective_timeout {
                expired.push(*key);
                continue;
            }
            let deadline = assembly.created_at_ms.saturating_add(effective_timeout);
            assembly.expiry_timer = self.expiry.schedule(deadline, *key)?;
        }
        self.timeout_divisor = timeout_divisor;
        Ok(expired)
    }

    fn remove_assembly(&mut self, key: &FragmentKey) -> Option<Assembly> {
        let assembly = self.take_assembly(key)?;
        self.expiry.cancel(assembly.expiry_timer);
        Some(assembly)
    }

    fn take_assembly(&mut self, key: &FragmentKey) -> Option<Assembly> {
        let assembly = self.assemblies.remove(key)?;
        self.eviction_index.remove(&assembly.eviction_key);
        self.stats.active_datagrams = self.assemblies.len();
        self.stats.buffered_fragments = self
            .stats
            .buffered_fragments
            .saturating_sub(assembly.pieces.len());
        Some(assembly)
    }
}

fn initial_fragment_packet(assembly: &Assembly, key: FragmentKey) -> Option<Vec<u8>> {
    let first = assembly.pieces.get(&0)?;
    let mut packet = assembly.header.clone()?;
    match key.version {
        IpVersion::V4 => packet.extend_from_slice(&first.bytes),
        IpVersion::V6 => {
            let payload_len = packet
                .len()
                .checked_sub(40)?
                .checked_add(8)?
                .checked_add(first.bytes.len())?;
            let payload_len = u16::try_from(payload_len).ok()?;
            packet[4..6].copy_from_slice(&payload_len.to_be_bytes());
            packet.push(assembly.protocol);
            packet.push(0);
            packet.extend_from_slice(&1_u16.to_be_bytes());
            packet.extend_from_slice(&key.identification.to_be_bytes());
            packet.extend_from_slice(&first.bytes);
        }
    }
    Some(packet)
}

fn fragment_header(
    packet: &[u8],
    version: IpVersion,
) -> Result<(Vec<u8>, Option<usize>, u8), FragmentError> {
    match version {
        IpVersion::V4 => {
            let header_len = usize::from(packet[0] & 0x0f) * 4;
            Ok((packet[..header_len].to_vec(), None, packet[9]))
        }
        IpVersion::V6 => ipv6_fragment_header(packet),
    }
}

fn fragment_end(fragment: FragmentInfo, payload_len: usize) -> Result<u32, FragmentError> {
    if payload_len == 0 {
        return Err(FragmentError::Malformed("empty non-atomic fragment"));
    }
    if fragment.more_fragments && !payload_len.is_multiple_of(8) {
        return Err(FragmentError::Malformed(
            "non-final fragment payload is not a multiple of eight",
        ));
    }
    let length = u32::try_from(payload_len)
        .map_err(|_| FragmentError::Malformed("fragment payload length exceeds u32"))?;
    let end = fragment
        .offset_bytes
        .checked_add(length)
        .ok_or(FragmentError::Malformed("fragment range overflow"))?;
    if usize::try_from(end).unwrap_or(usize::MAX) > MAX_REASSEMBLED_BYTES {
        return Err(FragmentError::Malformed(
            "reassembled datagram is too large",
        ));
    }
    Ok(end)
}

fn validate_reassembled_size(
    version: IpVersion,
    header_len: usize,
    payload_len: u32,
) -> Result<(), FragmentError> {
    if reassembled_size_exceeds(version, header_len, payload_len) {
        return Err(FragmentError::Malformed(
            "reassembled IP datagram is too large",
        ));
    }
    Ok(())
}

fn reassembled_size_exceeds(version: IpVersion, header_len: usize, payload_len: u32) -> bool {
    let payload_len = usize::try_from(payload_len).unwrap_or(usize::MAX);
    let field_len = match version {
        IpVersion::V4 => header_len.checked_add(payload_len),
        IpVersion::V6 => header_len
            .checked_sub(40)
            .and_then(|unfragmentable_len| unfragmentable_len.checked_add(payload_len)),
    };
    field_len.is_none_or(|length| length > usize::from(u16::MAX))
}

fn ipv6_fragment_header(packet: &[u8]) -> Result<(Vec<u8>, Option<usize>, u8), FragmentError> {
    let mut next_header = packet[6];
    let mut offset = 40_usize;
    let mut previous_next_header = 6_usize;
    for _ in 0..8 {
        if next_header == 44 {
            if offset + 8 > packet.len() {
                return Err(FragmentError::Malformed("truncated IPv6 fragment header"));
            }
            return Ok((
                packet[..offset].to_vec(),
                Some(previous_next_header),
                packet[offset],
            ));
        }
        let length = match next_header {
            0 | 43 | 60 => (usize::from(packet[offset + 1]) + 1) * 8,
            51 => (usize::from(packet[offset + 1]) + 2) * 4,
            _ => return Err(FragmentError::Malformed("IPv6 fragment header not found")),
        };
        if offset + length > packet.len() {
            return Err(FragmentError::Malformed("truncated IPv6 extension header"));
        }
        next_header = packet[offset];
        previous_next_header = offset;
        offset += length;
    }
    Err(FragmentError::Malformed(
        "IPv6 extension chain exceeds limit",
    ))
}

fn is_complete(assembly: &Assembly) -> bool {
    let (Some(total), Some(_)) = (assembly.total_payload_len, &assembly.header) else {
        return false;
    };
    let mut expected = 0_u32;
    for (&offset, piece) in &assembly.pieces {
        if offset != expected {
            return false;
        }
        expected = expected.saturating_add(u32::try_from(piece.bytes.len()).unwrap_or(u32::MAX));
    }
    expected == total
}

fn rebuild(mut assembly: Assembly, version: IpVersion) -> Result<Vec<u8>, FragmentError> {
    let mut packet = assembly
        .header
        .take()
        .ok_or(FragmentError::Malformed("missing first fragment"))?;
    for piece in assembly.pieces.into_values() {
        packet.extend_from_slice(&piece.bytes);
    }
    match version {
        IpVersion::V4 => {
            let total = u16::try_from(packet.len())
                .map_err(|_| FragmentError::Malformed("IPv4 datagram too large"))?;
            packet[2..4].copy_from_slice(&total.to_be_bytes());
            packet[6..8].copy_from_slice(&0_u16.to_be_bytes());
            packet[10..12].copy_from_slice(&0_u16.to_be_bytes());
            let checksum = ipv4_checksum(&packet[..usize::from(packet[0] & 0x0f) * 4]);
            packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        }
        IpVersion::V6 => {
            let previous = assembly
                .ipv6_previous_next_header
                .ok_or(FragmentError::Malformed(
                    "missing IPv6 fragment predecessor",
                ))?;
            packet[previous] = assembly.protocol;
            let payload_len = u16::try_from(packet.len().saturating_sub(40))
                .map_err(|_| FragmentError::Malformed("IPv6 datagram too large"))?;
            packet[4..6].copy_from_slice(&payload_len.to_be_bytes());
        }
    }
    Ok(packet)
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for chunk in header.chunks_exact(2) {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !u16::try_from(sum).unwrap_or(u16::MAX)
}
