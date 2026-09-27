use super::SeqNumber;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NewReno {
    maximum_segment_size: usize,
    congestion_window: usize,
    slow_start_threshold: usize,
    congestion_avoidance_credit: usize,
    duplicate_acks: u8,
    recover: Option<SeqNumber>,
}

impl NewReno {
    /// # Panics
    ///
    /// Panics when `maximum_segment_size` is zero.
    #[must_use]
    pub fn new(maximum_segment_size: usize) -> Self {
        assert!(maximum_segment_size > 0, "TCP MSS must be non-zero");
        let initial_window = maximum_segment_size
            .saturating_mul(4)
            .min(maximum_segment_size.saturating_mul(2).max(4_380));
        Self {
            maximum_segment_size,
            congestion_window: initial_window,
            slow_start_threshold: usize::MAX,
            congestion_avoidance_credit: 0,
            duplicate_acks: 0,
            recover: None,
        }
    }

    #[must_use]
    pub const fn window(&self) -> usize {
        self.congestion_window
    }

    #[must_use]
    pub const fn maximum_segment_size(&self) -> usize {
        self.maximum_segment_size
    }

    #[must_use]
    pub const fn slow_start_threshold(&self) -> usize {
        self.slow_start_threshold
    }

    /// Extra send allowance granted by RFC 5681 Limited Transmit for the
    /// first two duplicate acknowledgments before fast recovery begins.
    #[must_use]
    pub fn limited_transmit_allowance(&self) -> usize {
        if self.recover.is_some() {
            return 0;
        }
        usize::from(self.duplicate_acks.min(2)).saturating_mul(self.maximum_segment_size)
    }

    pub fn on_new_ack(&mut self, acknowledged_bytes: usize, acknowledgment: SeqNumber) -> bool {
        self.duplicate_acks = 0;
        if let Some(recover) = self.recover {
            if acknowledgment.before(recover) {
                self.congestion_window = self
                    .congestion_window
                    .saturating_sub(acknowledged_bytes)
                    .saturating_add(self.maximum_segment_size)
                    .max(self.maximum_segment_size);
                return true;
            }
            self.recover = None;
            self.congestion_window = self.slow_start_threshold;
            self.congestion_avoidance_credit = 0;
            return false;
        }
        if self.congestion_window < self.slow_start_threshold {
            self.congestion_window = self
                .congestion_window
                .saturating_add(acknowledged_bytes.min(self.maximum_segment_size));
        } else {
            self.congestion_avoidance_credit = self
                .congestion_avoidance_credit
                .saturating_add(acknowledged_bytes);
            while self.congestion_avoidance_credit >= self.congestion_window {
                self.congestion_avoidance_credit -= self.congestion_window;
                self.congestion_window = self
                    .congestion_window
                    .saturating_add(self.maximum_segment_size);
            }
        }
        false
    }

    pub fn on_duplicate_ack(&mut self, flight_size: usize, send_next: SeqNumber) -> bool {
        if self.recover.is_some() {
            self.congestion_window = self
                .congestion_window
                .saturating_add(self.maximum_segment_size);
            return false;
        }
        self.duplicate_acks = self.duplicate_acks.saturating_add(1);
        if self.duplicate_acks != 3 {
            return false;
        }
        self.enter_recovery(flight_size, send_next);
        true
    }

    pub fn on_sack_loss(&mut self, flight_size: usize, send_next: SeqNumber) -> bool {
        if self.recover.is_some() {
            return false;
        }
        self.slow_start_threshold =
            (flight_size / 2).max(self.maximum_segment_size.saturating_mul(2));
        self.congestion_window = self.slow_start_threshold;
        self.congestion_avoidance_credit = 0;
        self.recover = Some(send_next);
        true
    }

    fn enter_recovery(&mut self, flight_size: usize, send_next: SeqNumber) {
        self.slow_start_threshold =
            (flight_size / 2).max(self.maximum_segment_size.saturating_mul(2));
        self.congestion_window = self
            .slow_start_threshold
            .saturating_add(self.maximum_segment_size.saturating_mul(3));
        self.congestion_avoidance_credit = 0;
        self.recover = Some(send_next);
    }

    pub fn on_timeout(&mut self, flight_size: usize) {
        self.slow_start_threshold =
            (flight_size / 2).max(self.maximum_segment_size.saturating_mul(2));
        self.congestion_window = self.maximum_segment_size;
        self.congestion_avoidance_credit = 0;
        self.duplicate_acks = 0;
        self.recover = None;
    }
}
