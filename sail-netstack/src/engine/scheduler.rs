use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::time::{Duration, Instant};

use crate::FlowId;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchedulerConfig {
    pub quantum_bytes: usize,
    pub max_packets_per_round: usize,
    pub max_bytes_per_round: usize,
    pub max_time_per_round: Duration,
    pub max_contiguous_flow_bytes: usize,
    pub max_queued_packets: usize,
    pub max_queued_bytes: usize,
    pub max_active_flows: usize,
    pub max_packets_per_flow: usize,
    pub max_control_packets: usize,
    pub max_packet_bytes: usize,
}

impl SchedulerConfig {
    /// # Errors
    ///
    /// Returns [`SchedulerConfigError`] when a limit is zero or one limit makes
    /// another impossible to honor.
    pub fn validate(self) -> Result<Self, SchedulerConfigError> {
        if self.quantum_bytes == 0
            || self.max_packets_per_round == 0
            || self.max_bytes_per_round == 0
            || self.max_time_per_round.is_zero()
            || self.max_contiguous_flow_bytes == 0
            || self.max_queued_packets == 0
            || self.max_queued_bytes == 0
            || self.max_active_flows == 0
            || self.max_packets_per_flow == 0
            || self.max_control_packets == 0
            || self.max_packet_bytes == 0
        {
            return Err(SchedulerConfigError::ZeroLimit);
        }
        if self.max_packet_bytes > self.max_bytes_per_round
            || self.max_packet_bytes > self.max_queued_bytes
            || self.max_packet_bytes > self.max_contiguous_flow_bytes
        {
            return Err(SchedulerConfigError::PacketExceedsBudget);
        }
        if self.max_control_packets > self.max_packets_per_round {
            return Err(SchedulerConfigError::ControlExceedsRound);
        }
        Ok(self)
    }
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            quantum_bytes: 16 * 1024,
            max_packets_per_round: 256,
            max_bytes_per_round: 1024 * 1024,
            max_time_per_round: Duration::from_millis(2),
            max_contiguous_flow_bytes: 64 * 1024,
            max_queued_packets: 4_096,
            max_queued_bytes: 8 * 1024 * 1024,
            max_active_flows: 2_048,
            max_packets_per_flow: 128,
            max_control_packets: 32,
            max_packet_bytes: 65_535,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchedulerConfigError {
    ZeroLimit,
    PacketExceedsBudget,
    ControlExceedsRound,
}

impl fmt::Display for SchedulerConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroLimit => formatter.write_str("scheduler limits must be non-zero"),
            Self::PacketExceedsBudget => {
                formatter.write_str("maximum packet must fit round and queue byte budgets")
            }
            Self::ControlExceedsRound => {
                formatter.write_str("control packet budget exceeds round packet budget")
            }
        }
    }
}

impl std::error::Error for SchedulerConfigError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkClass {
    Control,
    Data { flow: FlowId, weight: u16 },
}

#[derive(Debug)]
struct Item<T> {
    bytes: usize,
    value: T,
}

#[derive(Debug)]
struct FlowQueue<T> {
    weight: u16,
    deficit: usize,
    bytes: usize,
    items: VecDeque<Item<T>>,
}

#[derive(Debug)]
pub enum EnqueueError<T> {
    PacketTooLarge(T),
    QueueFull(T),
    FlowQueueFull(T),
    TooManyFlows(T),
    InvalidWeight(T),
}

impl<T> EnqueueError<T> {
    #[must_use]
    pub fn into_inner(self) -> T {
        match self {
            Self::PacketTooLarge(value)
            | Self::QueueFull(value)
            | Self::FlowQueueFull(value)
            | Self::TooManyFlows(value)
            | Self::InvalidWeight(value) => value,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SchedulerSnapshot {
    pub active_flows: usize,
    pub queued_packets: usize,
    pub queued_bytes: usize,
    pub control_packets: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RoundStats {
    pub packets: usize,
    pub bytes: usize,
    pub control_packets: usize,
    pub active_flows_visited: usize,
    pub time_budget_exhausted: bool,
}

/// Bounded weighted byte-DRR scheduler for one shard.
#[derive(Debug)]
pub struct Scheduler<T> {
    config: SchedulerConfig,
    control: VecDeque<Item<T>>,
    flows: HashMap<FlowId, FlowQueue<T>>,
    active: VecDeque<FlowId>,
    queued_packets: usize,
    queued_bytes: usize,
}

impl<T> Scheduler<T> {
    /// # Errors
    ///
    /// Returns [`SchedulerConfigError`] if `config` is inconsistent.
    pub fn new(config: SchedulerConfig) -> Result<Self, SchedulerConfigError> {
        Ok(Self {
            config: config.validate()?,
            control: VecDeque::new(),
            flows: HashMap::new(),
            active: VecDeque::new(),
            queued_packets: 0,
            queued_bytes: 0,
        })
    }

    /// Enqueues work without exceeding the global or per-flow queue limits.
    ///
    /// # Errors
    ///
    /// Returns the original value in [`EnqueueError`] when admission fails.
    pub fn enqueue(
        &mut self,
        class: WorkClass,
        bytes: usize,
        value: T,
    ) -> Result<(), EnqueueError<T>> {
        if bytes > self.config.max_packet_bytes {
            return Err(EnqueueError::PacketTooLarge(value));
        }
        if self.queued_packets == self.config.max_queued_packets
            || self.queued_bytes.saturating_add(bytes) > self.config.max_queued_bytes
        {
            return Err(EnqueueError::QueueFull(value));
        }
        match class {
            WorkClass::Control => self.control.push_back(Item { bytes, value }),
            WorkClass::Data { flow, weight } => {
                if weight == 0 {
                    return Err(EnqueueError::InvalidWeight(value));
                }
                if let Some(queue) = self.flows.get_mut(&flow) {
                    if queue.items.len() == self.config.max_packets_per_flow {
                        return Err(EnqueueError::FlowQueueFull(value));
                    }
                    queue.bytes += bytes;
                    queue.items.push_back(Item { bytes, value });
                } else {
                    if self.flows.len() == self.config.max_active_flows {
                        return Err(EnqueueError::TooManyFlows(value));
                    }
                    self.flows.insert(
                        flow,
                        FlowQueue {
                            weight,
                            deficit: 0,
                            bytes,
                            items: VecDeque::from([Item { bytes, value }]),
                        },
                    );
                    self.active.push_back(flow);
                }
            }
        }
        self.queued_packets += 1;
        self.queued_bytes += bytes;
        Ok(())
    }

    /// Runs one packet + byte + time bounded scheduling round. Control work has
    /// a reserved prefix, while data flows receive weighted byte quanta.
    ///
    /// # Panics
    ///
    /// Panics only if internal queue and accounting invariants have previously
    /// been violated, or if `process` itself panics.
    pub fn run_round(&mut self, process: impl FnMut(WorkClass, T)) -> RoundStats {
        self.run_round_limited(
            self.config.max_packets_per_round,
            self.config.max_bytes_per_round,
            process,
        )
    }

    /// Runs a round additionally capped by a consumer's remaining packet and
    /// byte capacity. The supplied limits may only tighten the configured
    /// scheduler limits.
    ///
    /// # Panics
    ///
    /// Panics only if internal queue and accounting invariants have previously
    /// been violated, or if `process` itself panics.
    pub fn run_round_limited(
        &mut self,
        max_packets: usize,
        max_bytes: usize,
        mut process: impl FnMut(WorkClass, T),
    ) -> RoundStats {
        let max_packets = max_packets.min(self.config.max_packets_per_round);
        let max_bytes = max_bytes.min(self.config.max_bytes_per_round);
        let started = Instant::now();
        let mut stats = RoundStats::default();
        while stats.control_packets < self.config.max_control_packets {
            let Some(front) = self.control.front() else {
                break;
            };
            if !Self::fits_round(&stats, front.bytes, max_packets, max_bytes) {
                break;
            }
            let item = self.control.pop_front().expect("front was present");
            self.account_dequeue(item.bytes, &mut stats);
            stats.control_packets += 1;
            process(WorkClass::Control, item.value);
            if started.elapsed() >= self.config.max_time_per_round {
                stats.time_budget_exhausted = true;
                return stats;
            }
        }

        let visits = self.active.len();
        for _ in 0..visits {
            if stats.packets == max_packets {
                break;
            }
            // Only processing may exhaust the budget. Preemption before the
            // first item would otherwise end a round with queued work, no
            // progress, and no pending wakeup to resume it.
            if stats.packets > 0 && started.elapsed() >= self.config.max_time_per_round {
                stats.time_budget_exhausted = true;
                break;
            }
            let flow = self
                .active
                .pop_front()
                .expect("visit count tracks active queue");
            let mut queue = self.flows.remove(&flow).expect("active flow must exist");
            stats.active_flows_visited += 1;
            queue.deficit = queue.deficit.saturating_add(
                self.config
                    .quantum_bytes
                    .saturating_mul(usize::from(queue.weight)),
            );
            let mut contiguous = 0_usize;
            while let Some(front) = queue.items.front() {
                if front.bytes > queue.deficit
                    || contiguous.saturating_add(front.bytes)
                        > self.config.max_contiguous_flow_bytes
                    || !Self::fits_round(&stats, front.bytes, max_packets, max_bytes)
                {
                    break;
                }
                let item = queue.items.pop_front().expect("front was present");
                queue.deficit -= item.bytes;
                queue.bytes -= item.bytes;
                contiguous += item.bytes;
                self.account_dequeue(item.bytes, &mut stats);
                process(
                    WorkClass::Data {
                        flow,
                        weight: queue.weight,
                    },
                    item.value,
                );
                if started.elapsed() >= self.config.max_time_per_round {
                    stats.time_budget_exhausted = true;
                    break;
                }
            }
            if !queue.items.is_empty() {
                self.flows.insert(flow, queue);
                self.active.push_back(flow);
            }
            if stats.time_budget_exhausted {
                break;
            }
        }
        stats
    }

    #[must_use]
    pub fn snapshot(&self) -> SchedulerSnapshot {
        SchedulerSnapshot {
            active_flows: self.flows.len(),
            queued_packets: self.queued_packets,
            queued_bytes: self.queued_bytes,
            control_packets: self.control.len(),
        }
    }

    #[must_use]
    pub const fn config(&self) -> SchedulerConfig {
        self.config
    }

    pub fn clear(&mut self) {
        self.control.clear();
        self.flows.clear();
        self.active.clear();
        self.queued_packets = 0;
        self.queued_bytes = 0;
    }

    fn fits_round(stats: &RoundStats, bytes: usize, max_packets: usize, max_bytes: usize) -> bool {
        stats.packets < max_packets && stats.bytes.saturating_add(bytes) <= max_bytes
    }

    fn account_dequeue(&mut self, bytes: usize, stats: &mut RoundStats) {
        self.queued_packets -= 1;
        self.queued_bytes -= bytes;
        stats.packets += 1;
        stats.bytes += bytes;
    }
}
