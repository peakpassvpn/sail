use std::sync::atomic::{AtomicUsize, Ordering};

use crate::{BudgetSnapshot, NetworkGeneration};

pub(crate) fn increment_counter(counter: &mut u64) {
    *counter = counter.saturating_add(1);
}

pub(crate) fn atomic_add_counter(counter: &AtomicUsize, amount: usize) {
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        let next = current.saturating_add(amount);
        match counter.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

macro_rules! saturating_sum_fields {
    ($total:expr, $shard:expr, $($field:ident),+ $(,)?) => {
        $($total.$field = $total.$field.saturating_add($shard.$field);)+
    };
}

/// Cheap-to-copy aggregate. Shard-local counters will feed this snapshot;
/// consumers never receive references to mutable protocol state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StackStats {
    pub generation: NetworkGeneration,
    pub resources: BudgetSnapshot,
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub rx_batches: u64,
    pub rx_batch_packets: u64,
    pub rx_batch_max: usize,
    pub rx_io_wakeups: u64,
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub tx_batches: u64,
    pub tx_batch_packets: u64,
    pub tx_batch_max: usize,
    pub tx_io_wakeups: u64,
    pub dropped_packets: u64,
    pub dropped_wire_packets: u64,
    pub dropped_resource_packets: u64,
    pub dropped_policy_packets: u64,
    pub dropped_rate_limited_packets: u64,
    pub dropped_output_packets: u64,
    pub dropped_other_packets: u64,
    pub partial_sends: u64,
    pub runner_failures: u64,
    pub shutdowns: u64,
    pub aborts: u64,
    pub network_resets: u64,
    /// Resets of flows a network reset or a closing runner had to drop,
    /// past the queue of resets still to send.
    pub reset_rsts_dropped: u64,
    pub mtu_changes: u64,
    pub scheduler_rounds: u64,
    pub scheduler_packets: u64,
    pub scheduler_bytes: u64,
    pub scheduler_control_packets_processed: u64,
    pub scheduler_active_flow_visits: u64,
    pub scheduler_time_budget_exhaustions: u64,
    pub scheduler_active_flows: usize,
    pub scheduler_queued_packets: usize,
    pub scheduler_queued_bytes: usize,
    pub scheduler_control_packets: usize,
    pub pressure_transitions: u64,
    pub pressure_constrained_entries: u64,
    pub pressure_critical_entries: u64,
    pub pressure_exhausted_entries: u64,
    pub pressure_rejected_new_flows: u64,
    pub icmp_echo_replies: u64,
    pub icmp_echo_rate_limited: u64,
    pub icmp_errors_sent: u64,
    pub icmp_errors_rate_limited: u64,
    pub fragment_packets_rate_limited: u64,
    pub outbound_fragments: u64,
    pub pmtu_entries: usize,
    pub pmtu_learned: u64,
    pub pmtu_lowered: u64,
    pub pmtu_expired: u64,
    pub pmtu_evicted: u64,
    pub pmtu_rejected: u64,
    pub tcp_active_flows: usize,
    pub tcp_peak_active_flows: usize,
    pub tcp_time_wait: usize,
    pub tcp_peak_time_wait: usize,
    pub tcp_syn_received: usize,
    pub tcp_peak_syn_received: usize,
    pub tcp_accept_queue: usize,
    pub tcp_peak_accept_queue: usize,
    pub tcp_buffered_bytes: usize,
    pub tcp_send_buffered_bytes: usize,
    pub tcp_created_flows: u64,
    pub tcp_closed_flows: u64,
    pub tcp_time_wait_evictions: u64,
    pub tcp_malformed_packets: u64,
    pub tcp_invalid_address_drops: u64,
    pub tcp_timestamp_missing_drops: u64,
    pub tcp_paws_rejections: u64,
    pub tcp_window_scale_clamps: u64,
    pub tcp_stale_operations: u64,
    pub tcp_zero_window_writes: u64,
    pub tcp_persist_probes: u64,
    pub tcp_keepalive_probes: u64,
    pub tcp_keepalive_timeouts: u64,
    pub tcp_nagle_buffered_writes: u64,
    pub tcp_sack_recovery_events: u64,
    pub tcp_sack_retransmitted_segments: u64,
    pub tcp_sack_rescue_segments: u64,
    pub tcp_retransmission_timeouts: u64,
    pub tcp_retransmission_failures: u64,
    pub tcp_black_hole_mtu_fallbacks: u64,
    pub tcp_syns_rate_limited: u64,
    pub tcp_defensive_acks_sent: u64,
    pub tcp_defensive_acks_rate_limited: u64,
    pub tcp_challenge_acks_sent: u64,
    pub tcp_challenge_acks_rate_limited: u64,
    pub tcp_stateless_resets_sent: u64,
    pub tcp_stateless_resets_rate_limited: u64,
    pub tcp_accept_overflow_drops: u64,
    pub tcp_accept_overflow_rejections: u64,
    pub tcp_pressure_reclaimed_syns: u64,
    pub udp_active_flows: usize,
    pub udp_peak_active_flows: usize,
    pub udp_created_flows: u64,
    pub udp_expired_flows: u64,
    pub udp_stale_replies: u64,
    pub udp_malformed_packets: u64,
    pub udp_invalid_address_drops: u64,
    pub fragment_datagrams: usize,
    pub buffered_fragments: usize,
    pub completed_reassemblies: u64,
    pub expired_reassemblies: u64,
    pub evicted_reassemblies: u64,
    pub overlapping_fragment_drops: u64,
}

impl StackStats {
    /// Aggregates shard-local protocol counters while retaining one snapshot
    /// from the resource ledger shared by those shards.
    ///
    /// Returns `None` for an empty input or when shards report different
    /// network generations. Cumulative counters, current per-shard gauges, and
    /// shard-local high-watermarks are saturating sums; the latter form a
    /// conservative capacity envelope rather than a time-coincident maximum.
    /// Observed batch maxima remain maxima.
    #[must_use]
    pub fn aggregate(
        shards: impl IntoIterator<Item = Self>,
        resources: BudgetSnapshot,
    ) -> Option<Self> {
        let mut shards = shards.into_iter();
        let mut total = shards.next()?;
        total.resources = resources;
        for shard in shards {
            if shard.generation != total.generation {
                return None;
            }
            total.add_runtime_and_ip(&shard);
            total.add_transport(&shard);
        }
        Some(total)
    }

    fn add_runtime_and_ip(&mut self, shard: &Self) {
        saturating_sum_fields!(
            self,
            shard,
            rx_packets,
            rx_bytes,
            rx_batches,
            rx_batch_packets,
            rx_io_wakeups,
            tx_packets,
            tx_bytes,
            tx_batches,
            tx_batch_packets,
            tx_io_wakeups,
            dropped_packets,
            dropped_wire_packets,
            dropped_resource_packets,
            dropped_policy_packets,
            dropped_rate_limited_packets,
            dropped_output_packets,
            dropped_other_packets,
            partial_sends,
            runner_failures,
            shutdowns,
            aborts,
            network_resets,
            reset_rsts_dropped,
            mtu_changes,
            scheduler_rounds,
            scheduler_packets,
            scheduler_bytes,
            scheduler_control_packets_processed,
            scheduler_active_flow_visits,
            scheduler_time_budget_exhaustions,
            scheduler_active_flows,
            scheduler_queued_packets,
            scheduler_queued_bytes,
            scheduler_control_packets,
            pressure_transitions,
            pressure_constrained_entries,
            pressure_critical_entries,
            pressure_exhausted_entries,
            pressure_rejected_new_flows,
            icmp_echo_replies,
            icmp_echo_rate_limited,
            icmp_errors_sent,
            icmp_errors_rate_limited,
            fragment_packets_rate_limited,
            outbound_fragments,
            pmtu_entries,
            pmtu_learned,
            pmtu_lowered,
            pmtu_expired,
            pmtu_evicted,
            pmtu_rejected,
        );
        self.rx_batch_max = self.rx_batch_max.max(shard.rx_batch_max);
        self.tx_batch_max = self.tx_batch_max.max(shard.tx_batch_max);
    }

    fn add_transport(&mut self, shard: &Self) {
        saturating_sum_fields!(
            self,
            shard,
            tcp_active_flows,
            tcp_peak_active_flows,
            tcp_time_wait,
            tcp_peak_time_wait,
            tcp_syn_received,
            tcp_peak_syn_received,
            tcp_accept_queue,
            tcp_peak_accept_queue,
            tcp_buffered_bytes,
            tcp_send_buffered_bytes,
            tcp_created_flows,
            tcp_closed_flows,
            tcp_time_wait_evictions,
            tcp_malformed_packets,
            tcp_invalid_address_drops,
            tcp_timestamp_missing_drops,
            tcp_paws_rejections,
            tcp_window_scale_clamps,
            tcp_stale_operations,
            tcp_zero_window_writes,
            tcp_persist_probes,
            tcp_keepalive_probes,
            tcp_keepalive_timeouts,
            tcp_nagle_buffered_writes,
            tcp_sack_recovery_events,
            tcp_sack_retransmitted_segments,
            tcp_sack_rescue_segments,
            tcp_retransmission_timeouts,
            tcp_retransmission_failures,
            tcp_black_hole_mtu_fallbacks,
            tcp_syns_rate_limited,
            tcp_defensive_acks_sent,
            tcp_defensive_acks_rate_limited,
            tcp_challenge_acks_sent,
            tcp_challenge_acks_rate_limited,
            tcp_stateless_resets_sent,
            tcp_stateless_resets_rate_limited,
            tcp_accept_overflow_drops,
            tcp_accept_overflow_rejections,
            tcp_pressure_reclaimed_syns,
            udp_active_flows,
            udp_peak_active_flows,
            udp_created_flows,
            udp_expired_flows,
            udp_stale_replies,
            udp_malformed_packets,
            udp_invalid_address_drops,
            fragment_datagrams,
            buffered_fragments,
            completed_reassemblies,
            expired_reassemblies,
            evicted_reassemblies,
            overlapping_fragment_drops,
        );
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::{atomic_add_counter, increment_counter};

    #[test]
    fn cumulative_counters_saturate_instead_of_wrapping() {
        let mut local = u64::MAX - 1;
        increment_counter(&mut local);
        increment_counter(&mut local);
        assert_eq!(local, u64::MAX);

        let shared = AtomicUsize::new(usize::MAX - 1);
        atomic_add_counter(&shared, 1);
        atomic_add_counter(&shared, 1);
        assert_eq!(shared.load(Ordering::Relaxed), usize::MAX);
    }
}
