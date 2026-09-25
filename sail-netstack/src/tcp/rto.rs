const MIN_RTO_MS: u64 = 1_000;
const MAX_RTO_MS: u64 = 60_000;

/// RFC 6298-style integer RTT estimator. Callers apply Karn's algorithm by not
/// sampling retransmitted segments.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(clippy::struct_field_names)]
pub struct RtoEstimator {
    smoothed_rtt_ms: Option<u64>,
    rtt_variance_ms: u64,
    rto_ms: u64,
}

impl Default for RtoEstimator {
    fn default() -> Self {
        Self {
            smoothed_rtt_ms: None,
            rtt_variance_ms: 0,
            rto_ms: MIN_RTO_MS,
        }
    }
}

impl RtoEstimator {
    pub fn record_sample(&mut self, sample_ms: u64) {
        let sample_ms = sample_ms.max(1);
        if let Some(smoothed) = self.smoothed_rtt_ms {
            let error = smoothed.abs_diff(sample_ms);
            self.rtt_variance_ms = self.rtt_variance_ms.saturating_mul(3).saturating_add(error) / 4;
            self.smoothed_rtt_ms = Some(smoothed.saturating_mul(7).saturating_add(sample_ms) / 8);
        } else {
            self.smoothed_rtt_ms = Some(sample_ms);
            self.rtt_variance_ms = sample_ms / 2;
        }
        let smoothed = self.smoothed_rtt_ms.unwrap_or(sample_ms);
        self.rto_ms = smoothed
            .saturating_add(self.rtt_variance_ms.saturating_mul(4).max(1))
            .clamp(MIN_RTO_MS, MAX_RTO_MS);
    }

    pub fn backoff(&mut self) {
        self.rto_ms = self.rto_ms.saturating_mul(2).min(MAX_RTO_MS);
    }

    #[must_use]
    pub const fn rto_ms(self) -> u64 {
        self.rto_ms
    }

    #[must_use]
    pub const fn smoothed_rtt_ms(self) -> Option<u64> {
        self.smoothed_rtt_ms
    }
}
