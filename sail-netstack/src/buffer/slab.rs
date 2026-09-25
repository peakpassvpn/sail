use std::collections::VecDeque;
use std::fmt;
use std::ops::Range;
use std::sync::Arc;

use super::{BudgetError, BudgetLease, ResourceKind, ResourceLedger};

const CHUNK_METADATA_CHARGE: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlabClass {
    TcpPayload,
    Packet,
    Fragment,
}

impl SlabClass {
    const fn resource_kind(self) -> ResourceKind {
        match self {
            Self::TcpPayload => ResourceKind::TcpPayloadBytes,
            Self::Packet => ResourceKind::PacketBytes,
            Self::Fragment => ResourceKind::FragmentBytes,
        }
    }
}

struct Allocation {
    bytes: Box<[u8]>,
    _lease: BudgetLease,
    _metadata_lease: BudgetLease,
}

impl fmt::Debug for Allocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Allocation")
            .field("len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct Segment {
    allocation: Arc<Allocation>,
    range: Range<usize>,
}

impl Segment {
    fn len(&self) -> usize {
        self.range.len()
    }

    fn as_slice(&self) -> &[u8] {
        &self.allocation.bytes[self.range.clone()]
    }
}

/// Immutable payload segments backed by independently budgeted allocations.
///
/// Splitting is zero-copy: both resulting chains share the original allocation,
/// whose lease remains charged until the final segment is released.
#[derive(Debug)]
pub struct SlabChain {
    ledger: Arc<ResourceLedger>,
    class: SlabClass,
    chunk_size: usize,
    len: usize,
    segments: VecDeque<Segment>,
}

impl SlabChain {
    /// # Panics
    ///
    /// Panics when `chunk_size` is zero.
    #[must_use]
    pub fn new(ledger: Arc<ResourceLedger>, class: SlabClass, chunk_size: usize) -> Self {
        assert!(chunk_size > 0, "slab chunk size must be non-zero");
        Self {
            ledger,
            class,
            chunk_size,
            len: 0,
            segments: VecDeque::new(),
        }
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Appends all bytes or leaves the chain unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`BudgetError::Exhausted`] when all new allocations cannot be
    /// reserved within the selected pool and global byte ceiling.
    pub fn append(&mut self, bytes: &[u8]) -> Result<(), BudgetError> {
        let new_len = self
            .len
            .checked_add(bytes.len())
            .ok_or(BudgetError::Invalid("slab chain length overflows usize"))?;
        let mut pending = VecDeque::new();
        for chunk in bytes.chunks(self.chunk_size) {
            let lease = self
                .ledger
                .try_acquire(self.class.resource_kind(), chunk.len())?;
            let metadata_lease = self
                .ledger
                .try_acquire(ResourceKind::MetadataBytes, CHUNK_METADATA_CHARGE)?;
            let allocation = Arc::new(Allocation {
                bytes: chunk.into(),
                _lease: lease,
                _metadata_lease: metadata_lease,
            });
            pending.push_back(Segment {
                range: 0..allocation.bytes.len(),
                allocation,
            });
        }
        self.len = new_len;
        self.segments.append(&mut pending);
        Ok(())
    }

    /// Removes up to `amount` bytes and immediately releases wholly consumed
    /// allocations that are not shared with another chain.
    ///
    /// # Panics
    ///
    /// Panics only if an internal length/segment invariant was previously
    /// violated.
    pub fn consume(&mut self, amount: usize) -> usize {
        let mut remaining = amount.min(self.len);
        let consumed = remaining;
        while remaining > 0 {
            let front = self.segments.front_mut().expect("length tracks segments");
            let take = remaining.min(front.len());
            front.range.start += take;
            remaining -= take;
            self.len -= take;
            if front.range.is_empty() {
                self.segments.pop_front();
            }
        }
        consumed
    }

    /// Moves the suffix beginning at `at` into another zero-copy chain.
    ///
    /// # Panics
    ///
    /// Panics when `at` exceeds the chain length.
    #[must_use]
    pub fn split_off(&mut self, at: usize) -> Self {
        assert!(at <= self.len, "split index exceeds chain length");
        let mut suffix = Self::new(Arc::clone(&self.ledger), self.class, self.chunk_size);
        if at == self.len {
            return suffix;
        }
        if at == 0 {
            std::mem::swap(&mut suffix.segments, &mut self.segments);
            suffix.len = self.len;
            self.len = 0;
            return suffix;
        }

        let mut offset = 0;
        let mut split_segment = None;
        for (index, segment) in self.segments.iter().enumerate() {
            if offset + segment.len() >= at {
                split_segment = Some((index, at - offset));
                break;
            }
            offset += segment.len();
        }
        let (index, within) = split_segment.expect("split point must resolve");
        if within == self.segments[index].len() {
            suffix.segments = self.segments.split_off(index + 1);
        } else if within == 0 {
            suffix.segments = self.segments.split_off(index);
        } else {
            let segment = &mut self.segments[index];
            let suffix_range = segment.range.start + within..segment.range.end;
            segment.range.end = suffix_range.start;
            let shared = Segment {
                allocation: Arc::clone(&segment.allocation),
                range: suffix_range,
            };
            suffix.segments = self.segments.split_off(index + 1);
            suffix.segments.push_front(shared);
        }
        suffix.len = self.len - at;
        self.len = at;
        suffix
    }

    /// # Panics
    ///
    /// Panics if the chains do not share a ledger and slab class. Cross-ledger
    /// moves would invalidate resource accounting.
    pub fn append_chain(&mut self, mut other: Self) {
        assert!(Arc::ptr_eq(&self.ledger, &other.ledger));
        assert_eq!(self.class, other.class);
        self.len += other.len;
        other.len = 0;
        self.segments.append(&mut other.segments);
    }

    pub fn slices(&self) -> impl ExactSizeIterator<Item = &[u8]> {
        self.segments.iter().map(Segment::as_slice)
    }

    #[must_use]
    pub fn to_vec(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.len);
        for segment in &self.segments {
            bytes.extend_from_slice(segment.as_slice());
        }
        bytes
    }
}

/// Allocates writable packet storage while charging the packet byte pool.
#[derive(Clone, Debug)]
pub struct PacketArena {
    ledger: Arc<ResourceLedger>,
    max_packet_size: usize,
}

impl PacketArena {
    /// # Panics
    ///
    /// Panics when `max_packet_size` is zero.
    #[must_use]
    pub fn new(ledger: Arc<ResourceLedger>, max_packet_size: usize) -> Self {
        assert!(max_packet_size > 0, "maximum packet size must be non-zero");
        Self {
            ledger,
            max_packet_size,
        }
    }

    /// # Errors
    ///
    /// Returns [`BudgetError::Invalid`] for an oversized request or
    /// [`BudgetError::Exhausted`] when the packet/global pool cannot reserve it.
    pub fn allocate(
        &self,
        headroom: usize,
        payload_capacity: usize,
    ) -> Result<ArenaPacket, BudgetError> {
        self.allocate_from(ResourceKind::PacketBytes, headroom, payload_capacity)
    }

    /// Allocates packet storage from the data-independent control reserve.
    /// TCP ACK/RST/close and ICMP paths use this pool so queued payload cannot
    /// consume their last protocol-progress credit.
    ///
    /// # Errors
    ///
    /// Returns [`BudgetError::Invalid`] for an oversized request or
    /// [`BudgetError::Exhausted`] when the control/global pool cannot reserve it.
    pub fn allocate_control(
        &self,
        headroom: usize,
        payload_capacity: usize,
    ) -> Result<ArenaPacket, BudgetError> {
        self.allocate_from(ResourceKind::ControlPacketBytes, headroom, payload_capacity)
    }

    fn allocate_from(
        &self,
        kind: ResourceKind,
        headroom: usize,
        payload_capacity: usize,
    ) -> Result<ArenaPacket, BudgetError> {
        let allocation_len = headroom
            .checked_add(payload_capacity)
            .ok_or(BudgetError::Invalid(
                "packet allocation size overflows usize",
            ))?;
        if allocation_len > self.max_packet_size {
            return Err(BudgetError::Invalid("packet exceeds arena maximum"));
        }
        let lease = self.ledger.try_acquire(kind, allocation_len)?;
        Ok(ArenaPacket {
            bytes: vec![0; allocation_len].into_boxed_slice(),
            headroom,
            len: 0,
            lease,
        })
    }

    #[must_use]
    pub const fn max_packet_size(&self) -> usize {
        self.max_packet_size
    }
}

#[derive(Debug)]
pub struct ArenaPacket {
    bytes: Box<[u8]>,
    headroom: usize,
    len: usize,
    lease: BudgetLease,
}

impl ArenaPacket {
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[must_use]
    pub fn capacity(&self) -> usize {
        self.bytes.len() - self.headroom
    }

    /// # Errors
    ///
    /// Returns [`BudgetError::Invalid`] if `len` exceeds payload capacity.
    pub fn set_len(&mut self, len: usize) -> Result<(), BudgetError> {
        if len > self.capacity() {
            return Err(BudgetError::Invalid("packet length exceeds capacity"));
        }
        self.len = len;
        Ok(())
    }

    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.bytes[self.headroom..self.headroom + self.len]
    }

    #[must_use]
    pub fn payload_capacity_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[self.headroom..]
    }

    pub(crate) fn into_parts(self) -> (Box<[u8]>, usize, usize, BudgetLease) {
        (self.bytes, self.headroom, self.len, self.lease)
    }
}
