use std::array;
use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

const RESOURCE_KIND_COUNT: usize = 12;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceBudget {
    pub total_bytes: usize,
    pub metadata_bytes: usize,
    pub tcp_payload_bytes: usize,
    pub packet_bytes: usize,
    pub control_packet_bytes: usize,
    pub fragment_bytes: usize,
    pub max_tcp_flows: usize,
    pub max_syn_received: usize,
    pub max_accept_queue: usize,
    pub max_udp_flows: usize,
    pub max_fragments: usize,
    pub max_time_wait: usize,
    pub max_pmtu_entries: usize,
}

impl ResourceBudget {
    /// # Errors
    ///
    /// Returns [`BudgetError::Invalid`] when pools overflow, exceed the global
    /// byte ceiling, or dependent flow limits are inconsistent.
    pub fn validate(self) -> Result<Self, BudgetError> {
        let pools = self
            .metadata_bytes
            .checked_add(self.tcp_payload_bytes)
            .and_then(|v| v.checked_add(self.packet_bytes))
            .and_then(|v| v.checked_add(self.control_packet_bytes))
            .and_then(|v| v.checked_add(self.fragment_bytes))
            .ok_or(BudgetError::Invalid("byte pool sum overflows usize"))?;
        if self.total_bytes == 0 || pools > self.total_bytes {
            return Err(BudgetError::Invalid(
                "byte pools must fit within a non-zero total_bytes",
            ));
        }
        if self.max_tcp_flows == 0 || self.max_udp_flows == 0 {
            return Err(BudgetError::Invalid("flow limits must be non-zero"));
        }
        if self.max_syn_received > self.max_tcp_flows || self.max_accept_queue > self.max_tcp_flows
        {
            return Err(BudgetError::Invalid(
                "TCP sub-state limits must not exceed max_tcp_flows",
            ));
        }
        if self.max_fragments == 0 || self.max_time_wait == 0 || self.max_pmtu_entries == 0 {
            return Err(BudgetError::Invalid(
                "fragment, TIME-WAIT, and PMTU limits must be non-zero",
            ));
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BudgetProfile {
    Mobile,
    Router,
    Desktop,
    Server,
}

impl BudgetProfile {
    #[must_use]
    pub const fn budget(self) -> ResourceBudget {
        match self {
            Self::Mobile => ResourceBudget {
                total_bytes: 24 * 1024 * 1024,
                metadata_bytes: 4 * 1024 * 1024,
                tcp_payload_bytes: 12 * 1024 * 1024,
                packet_bytes: 6 * 1024 * 1024 - 256 * 1024,
                control_packet_bytes: 256 * 1024,
                fragment_bytes: 2 * 1024 * 1024,
                max_tcp_flows: 4_096,
                max_syn_received: 512,
                max_accept_queue: 512,
                max_udp_flows: 2_048,
                max_fragments: 256,
                max_time_wait: 8_192,
                max_pmtu_entries: 2_048,
            },
            Self::Router => ResourceBudget {
                total_bytes: 16 * 1024 * 1024,
                metadata_bytes: 3 * 1024 * 1024,
                tcp_payload_bytes: 8 * 1024 * 1024,
                packet_bytes: 4 * 1024 * 1024 - 256 * 1024,
                control_packet_bytes: 256 * 1024,
                fragment_bytes: 1024 * 1024,
                max_tcp_flows: 2_048,
                max_syn_received: 256,
                max_accept_queue: 256,
                max_udp_flows: 1_024,
                max_fragments: 128,
                max_time_wait: 4_096,
                max_pmtu_entries: 1_024,
            },
            Self::Desktop => ResourceBudget {
                total_bytes: 128 * 1024 * 1024,
                metadata_bytes: 16 * 1024 * 1024,
                tcp_payload_bytes: 72 * 1024 * 1024,
                packet_bytes: 31 * 1024 * 1024,
                control_packet_bytes: 1024 * 1024,
                fragment_bytes: 8 * 1024 * 1024,
                max_tcp_flows: 32_768,
                max_syn_received: 4_096,
                max_accept_queue: 4_096,
                max_udp_flows: 16_384,
                max_fragments: 1_024,
                max_time_wait: 65_536,
                max_pmtu_entries: 16_384,
            },
            Self::Server => ResourceBudget {
                total_bytes: 1024 * 1024 * 1024,
                metadata_bytes: 128 * 1024 * 1024,
                tcp_payload_bytes: 640 * 1024 * 1024,
                packet_bytes: 184 * 1024 * 1024,
                control_packet_bytes: 8 * 1024 * 1024,
                fragment_bytes: 64 * 1024 * 1024,
                max_tcp_flows: 262_144,
                max_syn_received: 32_768,
                max_accept_queue: 32_768,
                max_udp_flows: 131_072,
                max_fragments: 8_192,
                max_time_wait: 524_288,
                max_pmtu_entries: 131_072,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub enum ResourceKind {
    MetadataBytes = 0,
    TcpPayloadBytes = 1,
    PacketBytes = 2,
    ControlPacketBytes = 3,
    FragmentBytes = 4,
    TcpFlows = 5,
    SynReceived = 6,
    AcceptQueue = 7,
    UdpFlows = 8,
    Fragments = 9,
    TimeWait = 10,
    PmtuEntries = 11,
}

impl ResourceKind {
    #[must_use]
    const fn is_bytes(self) -> bool {
        matches!(
            self,
            Self::MetadataBytes
                | Self::TcpPayloadBytes
                | Self::PacketBytes
                | Self::ControlPacketBytes
                | Self::FragmentBytes
        )
    }

    #[must_use]
    const fn index(self) -> usize {
        self as usize
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PressureLevel {
    Normal,
    Constrained,
    Critical,
    Exhausted,
}

#[derive(Debug, Eq, PartialEq)]
pub enum BudgetError {
    Invalid(&'static str),
    Exhausted {
        kind: ResourceKind,
        requested: usize,
        available: usize,
    },
}

impl fmt::Display for BudgetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => write!(formatter, "invalid resource budget: {message}"),
            Self::Exhausted {
                kind,
                requested,
                available,
            } => write!(
                formatter,
                "resource {kind:?} exhausted: requested {requested}, available {available}"
            ),
        }
    }
}

impl std::error::Error for BudgetError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BudgetSnapshot {
    pub total_bytes: usize,
    pub used: [usize; RESOURCE_KIND_COUNT],
    pub peaks: [usize; RESOURCE_KIND_COUNT],
    pub denied: u64,
    pub pressure: PressureLevel,
}

impl BudgetSnapshot {
    #[must_use]
    pub const fn used(&self, kind: ResourceKind) -> usize {
        self.used[kind.index()]
    }

    #[must_use]
    pub const fn peak(&self, kind: ResourceKind) -> usize {
        self.peaks[kind.index()]
    }
}

/// Lock-free hard-limit ledger. Acquisitions reserve the global byte ceiling
/// before a pool ceiling, so concurrent callers can never overcommit either.
#[derive(Debug)]
pub struct ResourceLedger {
    budget: ResourceBudget,
    total_bytes: AtomicUsize,
    used: [AtomicUsize; RESOURCE_KIND_COUNT],
    peaks: [AtomicUsize; RESOURCE_KIND_COUNT],
    denied: AtomicUsize,
}

impl ResourceLedger {
    /// # Errors
    ///
    /// Returns [`BudgetError::Invalid`] when `budget` violates its invariants.
    pub fn new(budget: ResourceBudget) -> Result<Arc<Self>, BudgetError> {
        let budget = budget.validate()?;
        Ok(Arc::new(Self {
            budget,
            total_bytes: AtomicUsize::new(0),
            used: array::from_fn(|_| AtomicUsize::new(0)),
            peaks: array::from_fn(|_| AtomicUsize::new(0)),
            denied: AtomicUsize::new(0),
        }))
    }

    #[must_use]
    pub const fn budget(&self) -> ResourceBudget {
        self.budget
    }

    /// # Errors
    ///
    /// Returns [`BudgetError::Exhausted`] without changing accounting when the
    /// request would exceed either its pool or the global byte ceiling.
    pub fn try_acquire(
        self: &Arc<Self>,
        kind: ResourceKind,
        amount: usize,
    ) -> Result<BudgetLease, BudgetError> {
        if amount == 0 {
            return Ok(BudgetLease {
                ledger: Arc::clone(self),
                kind,
                amount,
            });
        }
        if kind.is_bytes() {
            self.reserve(&self.total_bytes, self.budget.total_bytes, kind, amount)?;
        }
        if let Err(error) = self.reserve(&self.used[kind.index()], self.limit(kind), kind, amount) {
            if kind.is_bytes() {
                self.total_bytes.fetch_sub(amount, Ordering::AcqRel);
            }
            return Err(error);
        }
        self.peaks[kind.index()].fetch_max(
            self.used[kind.index()].load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
        Ok(BudgetLease {
            ledger: Arc::clone(self),
            kind,
            amount,
        })
    }

    fn reserve(
        &self,
        counter: &AtomicUsize,
        limit: usize,
        kind: ResourceKind,
        amount: usize,
    ) -> Result<(), BudgetError> {
        let mut current = counter.load(Ordering::Relaxed);
        loop {
            let Some(next) = current.checked_add(amount) else {
                self.record_denial();
                return Err(BudgetError::Exhausted {
                    kind,
                    requested: amount,
                    available: limit.saturating_sub(current),
                });
            };
            if next > limit {
                self.record_denial();
                return Err(BudgetError::Exhausted {
                    kind,
                    requested: amount,
                    available: limit.saturating_sub(current),
                });
            }
            match counter.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Relaxed)
            {
                Ok(_) => return Ok(()),
                Err(observed) => current = observed,
            }
        }
    }

    fn record_denial(&self) {
        let mut denied = self.denied.load(Ordering::Relaxed);
        while denied != usize::MAX {
            match self.denied.compare_exchange_weak(
                denied,
                denied + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(observed) => denied = observed,
            }
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> BudgetSnapshot {
        let used = array::from_fn(|index| self.used[index].load(Ordering::Acquire));
        let peaks = array::from_fn(|index| self.peaks[index].load(Ordering::Relaxed));
        let total_bytes = self.total_bytes.load(Ordering::Acquire);
        BudgetSnapshot {
            total_bytes,
            used,
            peaks,
            denied: self.denied.load(Ordering::Relaxed) as u64,
            pressure: self.pressure(total_bytes, &used),
        }
    }

    fn pressure(&self, total_bytes: usize, used: &[usize; RESOURCE_KIND_COUNT]) -> PressureLevel {
        let mut max_permille = ratio_permille(total_bytes, self.budget.total_bytes);
        for kind in [
            ResourceKind::MetadataBytes,
            ResourceKind::TcpPayloadBytes,
            ResourceKind::PacketBytes,
            ResourceKind::ControlPacketBytes,
            ResourceKind::FragmentBytes,
            ResourceKind::TcpFlows,
            ResourceKind::SynReceived,
            ResourceKind::AcceptQueue,
            ResourceKind::UdpFlows,
            ResourceKind::Fragments,
            ResourceKind::TimeWait,
            ResourceKind::PmtuEntries,
        ] {
            max_permille = max_permille.max(ratio_permille(used[kind.index()], self.limit(kind)));
        }
        match max_permille {
            1_000.. => PressureLevel::Exhausted,
            850.. => PressureLevel::Critical,
            700.. => PressureLevel::Constrained,
            _ => PressureLevel::Normal,
        }
    }

    const fn limit(&self, kind: ResourceKind) -> usize {
        match kind {
            ResourceKind::MetadataBytes => self.budget.metadata_bytes,
            ResourceKind::TcpPayloadBytes => self.budget.tcp_payload_bytes,
            ResourceKind::PacketBytes => self.budget.packet_bytes,
            ResourceKind::ControlPacketBytes => self.budget.control_packet_bytes,
            ResourceKind::FragmentBytes => self.budget.fragment_bytes,
            ResourceKind::TcpFlows => self.budget.max_tcp_flows,
            ResourceKind::SynReceived => self.budget.max_syn_received,
            ResourceKind::AcceptQueue => self.budget.max_accept_queue,
            ResourceKind::UdpFlows => self.budget.max_udp_flows,
            ResourceKind::Fragments => self.budget.max_fragments,
            ResourceKind::TimeWait => self.budget.max_time_wait,
            ResourceKind::PmtuEntries => self.budget.max_pmtu_entries,
        }
    }
}

fn ratio_permille(value: usize, limit: usize) -> usize {
    if limit == 0 {
        return 1_000;
    }
    value.saturating_mul(1_000) / limit
}

#[derive(Debug)]
pub struct BudgetLease {
    ledger: Arc<ResourceLedger>,
    kind: ResourceKind,
    amount: usize,
}

impl BudgetLease {
    #[must_use]
    pub const fn kind(&self) -> ResourceKind {
        self.kind
    }

    #[must_use]
    pub const fn amount(&self) -> usize {
        self.amount
    }

    pub(crate) fn shrink_to(&mut self, amount: usize) {
        assert!(
            amount <= self.amount,
            "a budget lease cannot grow by shrinking"
        );
        let released = self.amount - amount;
        if released == 0 {
            return;
        }
        self.amount = amount;
        self.ledger.used[self.kind.index()].fetch_sub(released, Ordering::AcqRel);
        if self.kind.is_bytes() {
            self.ledger
                .total_bytes
                .fetch_sub(released, Ordering::AcqRel);
        }
    }

    pub(crate) fn split_off(&mut self, at: usize) -> Self {
        assert!(at <= self.amount, "a budget lease split must be in bounds");
        let remainder = self.amount - at;
        self.amount = at;
        Self {
            ledger: Arc::clone(&self.ledger),
            kind: self.kind,
            amount: remainder,
        }
    }
}

impl Drop for BudgetLease {
    fn drop(&mut self) {
        if self.amount == 0 {
            return;
        }
        self.ledger.used[self.kind.index()].fetch_sub(self.amount, Ordering::AcqRel);
        if self.kind.is_bytes() {
            self.ledger
                .total_bytes
                .fetch_sub(self.amount, Ordering::AcqRel);
        }
    }
}
