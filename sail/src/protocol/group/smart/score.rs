//! What the smart group knows of each member, and the score it ranks them
//! by: milliseconds, lower is better.

use std::time::Duration;

use tokio::time::Instant;

/// How fast old samples lose their weight: one this old counts half.
pub const HALF_LIFE: Duration = Duration::from_secs(5 * 60);
/// The most weight the samples so far carry together: a new sample of
/// weight 1 always moves the average by at least a sixth of the way.
const MAX_WEIGHT: f64 = 5.0;

/// The penalty of a first failure; each consecutive one doubles it.
pub const PENALTY_BASE_MS: f64 = 200.0;
/// The most a penalty grows to: six failures in a row.
pub const PENALTY_CAP_MS: f64 = PENALTY_BASE_MS * 32.0;
/// How fast a penalty wears off: it halves in this time.
pub const PENALTY_HALF_LIFE: Duration = Duration::from_secs(10 * 60);
/// A member whose penalty is above this is failed: it is tried after the
/// others. A first failure keeps it failed for one penalty half-life.
pub const FAILED_ABOVE_MS: f64 = PENALTY_BASE_MS / 2.0;

/// The weight of a probe's latency, next to that of a real connection.
pub const PROBE_WEIGHT: f64 = 0.3;
/// The weight of a first response that is not a TLS or QUIC handshake's:
/// it includes the time the server took to think.
pub const PLAIN_WEIGHT: f64 = 0.2;

/// A connection takes this much longer than the member's average to
/// connect, and it is slow: half a failure's penalty.
const SLOW_CONNECT: f64 = 1.5;
/// Connect times are compared with the average only once it is of a few
/// samples.
const SLOW_AFTER_WEIGHT: f64 = 2.0;

/// A latency is only slower than another when it is also longer by at
/// least this much, in milliseconds: below it, differences are the
/// scheduler's and the network's jitter, not the member's. It is
/// sing-box urltest's default tolerance.
pub const SLOWER_BY_AT_LEAST_MS: f64 = 50.0;

/// Whether `latency` is `times` as long as `than`, and longer by more
/// than jitter.
pub fn slower(latency: f64, than: f64, times: f64) -> bool {
    latency > than * times && latency - than > SLOWER_BY_AT_LEAST_MS
}

/// The least a TLS or QUIC handshake is given to be answered, and how
/// many of the member's average connect times it is given at most.
pub const FIRST_BYTE_TIMEOUT: Duration = Duration::from_secs(3);
const FIRST_BYTE_CONNECTS: f64 = 3.0;

/// How fast a member's recent uses are forgotten, for the member shown
/// as selected and the probes of a large group.
const USE_HALF_LIFE: Duration = Duration::from_secs(3 * 60);

/// `0.5` to the power of `elapsed` in half-lives.
fn decay(elapsed: Duration, half_life: Duration) -> f64 {
    0.5f64.powf(elapsed.as_secs_f64() / half_life.as_secs_f64())
}

/// A time-weighted moving average: each sample's weight halves every
/// `HALF_LIFE`, so that after a quiet while the next samples count most.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Ewma {
    mean: f64,
    weight: f64,
    at: Instant,
}

impl Ewma {
    pub fn new(x: f64, weight: f64, now: Instant) -> Self {
        Self {
            mean: x,
            weight: weight.min(MAX_WEIGHT),
            at: now,
        }
    }

    /// Adds `x`, which weighs `weight`, to `this`.
    pub fn add(this: &mut Option<Self>, x: f64, weight: f64, now: Instant) {
        *this = Some(match *this {
            None => Self::new(x, weight, now),
            Some(e) => {
                let old = e.weight * decay(now.saturating_duration_since(e.at), HALF_LIFE);
                Self {
                    mean: (e.mean * old + x * weight) / (old + weight),
                    weight: (old + weight).min(MAX_WEIGHT),
                    at: now,
                }
            }
        });
    }

    pub fn mean(&self) -> f64 {
        self.mean
    }

    /// The weight of the samples so far, at `now`.
    pub fn weight(&self, now: Instant) -> f64 {
        self.weight * decay(now.saturating_duration_since(self.at), HALF_LIFE)
    }
}

/// What the group knows of one member.
#[derive(Clone, Debug)]
pub struct MemberStats {
    /// The time to connect through it, until the stream is ready.
    connect: Option<Ewma>,
    /// The time to the first response: to connect and have the first
    /// bytes sent answered.
    latency: Option<Ewma>,
    penalty: f64,
    penalty_at: Instant,
    /// The failures since the last success.
    failures: u32,
    /// When a connection through it, or a probe, last succeeded.
    pub last_success: Option<Instant>,
    /// When it was last probed.
    pub last_probed: Option<Instant>,
    /// Its uses, each weighing less as it ages.
    uses: f64,
    uses_at: Instant,
    /// `policy_priority`'s factor for it.
    priority: f64,
}

impl MemberStats {
    pub fn new(priority: f64, now: Instant) -> Self {
        Self {
            connect: None,
            latency: None,
            penalty: 0.0,
            penalty_at: now,
            failures: 0,
            last_success: None,
            last_probed: None,
            uses: 0.0,
            uses_at: now,
            priority,
        }
    }

    /// Its score at `now`: its latency and penalty, times its priority;
    /// `None` while its latency is unknown.
    pub fn score(&self, now: Instant) -> Option<f64> {
        self.latency
            .map(|l| (l.mean() + self.penalty(now)) * self.priority)
    }

    /// Its average latency, without penalty or priority.
    pub fn latency(&self) -> Option<f64> {
        self.latency.map(|l| l.mean())
    }

    pub fn penalty(&self, now: Instant) -> f64 {
        self.penalty
            * decay(
                now.saturating_duration_since(self.penalty_at),
                PENALTY_HALF_LIFE,
            )
    }

    /// Whether it failed lately: its penalty has not worn off yet.
    pub fn is_failed(&self, now: Instant) -> bool {
        self.penalty(now) > FAILED_ABOVE_MS
    }

    /// A connection through it failed, or a probe.
    pub fn failed(&mut self, now: Instant) {
        self.failures = self.failures.saturating_add(1);
        let exponent = (self.failures - 1).min(5) as i32;
        let penalty = (PENALTY_BASE_MS * 2f64.powi(exponent)).min(PENALTY_CAP_MS);
        self.penalty = self.penalty(now).max(penalty);
        self.penalty_at = now;
    }

    /// A connection through it, or a probe, was answered: its penalty is
    /// gone.
    pub fn succeeded(&mut self, now: Instant) {
        self.failures = 0;
        self.penalty = 0.0;
        self.penalty_at = now;
        self.last_success = Some(now);
    }

    /// A connection through it took `took` to be ready. Returns whether
    /// that was slow for it, which costs half a failure's penalty.
    pub fn connected(&mut self, took: Duration, now: Instant) -> bool {
        let ms = took.as_secs_f64() * 1000.0;
        let slow = self.connect.is_some_and(|c| {
            c.weight(now) >= SLOW_AFTER_WEIGHT && slower(ms, c.mean(), SLOW_CONNECT)
        });
        Ewma::add(&mut self.connect, ms, 1.0, now);
        if slow {
            let penalty = (self.penalty(now) + PENALTY_BASE_MS / 2.0).min(PENALTY_CAP_MS);
            self.penalty = penalty;
            self.penalty_at = now;
        }
        slow
    }

    /// The first bytes sent through it were answered `latency` after the
    /// connection began: a sample of `weight`, and a success.
    pub fn answered(&mut self, latency: Duration, weight: f64, now: Instant) {
        Ewma::add(
            &mut self.latency,
            latency.as_secs_f64() * 1000.0,
            weight,
            now,
        );
        self.succeeded(now);
    }

    /// A probe through it took `result`, or failed.
    pub fn probed(&mut self, result: Option<Duration>, now: Instant) {
        self.last_probed = Some(now);
        match result {
            Some(latency) => self.answered(latency, PROBE_WEIGHT, now),
            None => self.failed(now),
        }
    }

    /// How long a TLS or QUIC handshake through it is given to be
    /// answered.
    pub fn first_byte_timeout(&self) -> Duration {
        let connects = self
            .connect
            .map(|c| Duration::from_secs_f64(c.mean() * FIRST_BYTE_CONNECTS / 1000.0))
            .unwrap_or_default();
        FIRST_BYTE_TIMEOUT.max(connects)
    }

    /// The network changed: its failures and connect times were of the
    /// one before, and go; its latency is kept until new samples replace
    /// it, as it ranks the members much as it did.
    pub fn network_changed(&mut self, now: Instant) {
        self.connect = None;
        self.failures = 0;
        self.penalty = 0.0;
        self.penalty_at = now;
    }

    pub fn used(&mut self, now: Instant) {
        self.uses = self.uses(now) + 1.0;
        self.uses_at = now;
    }

    /// Its recent uses: each counts half after `USE_HALF_LIFE`.
    pub fn uses(&self, now: Instant) -> f64 {
        self.uses * decay(now.saturating_duration_since(self.uses_at), USE_HALF_LIFE)
    }

    /// Whether nothing told of it for `interval`: no success, real or
    /// probed, and no probe.
    pub fn is_stale(&self, interval: Duration, now: Instant) -> bool {
        let fresh = |at: Option<Instant>| at.is_some_and(|at| now.duration_since(at) < interval);
        !fresh(self.last_success) && !fresh(self.last_probed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(v: u64) -> Duration {
        Duration::from_millis(v)
    }

    #[tokio::test(start_paused = true)]
    async fn the_average_follows_recent_samples_most() {
        let t0 = Instant::now();
        let mut e = None;
        Ewma::add(&mut e, 100.0, 1.0, t0);
        Ewma::add(&mut e, 200.0, 1.0, t0);
        assert_eq!(e.unwrap().mean(), 150.0);
        // Five minutes on the old samples weigh half as much: the new one
        // counts as much as both of them.
        Ewma::add(&mut e, 300.0, 1.0, t0 + HALF_LIFE);
        assert!((e.unwrap().mean() - 225.0).abs() < 1e-9, "{:?}", e);
        // After a long quiet the next sample is nearly all there is.
        Ewma::add(&mut e, 50.0, 1.0, t0 + HALF_LIFE * 20);
        assert!((e.unwrap().mean() - 50.0).abs() < 0.1, "{:?}", e);
    }

    #[tokio::test(start_paused = true)]
    async fn many_samples_do_not_freeze_the_average() {
        let t0 = Instant::now();
        let mut e = None;
        for _ in 0..1000 {
            Ewma::add(&mut e, 100.0, 1.0, t0);
        }
        Ewma::add(&mut e, 700.0, 1.0, t0);
        assert_eq!(e.unwrap().mean(), 200.0, "a sixth of the way");
    }

    #[tokio::test(start_paused = true)]
    async fn weights_count_as_given() {
        let t0 = Instant::now();
        let mut e = None;
        Ewma::add(&mut e, 100.0, 1.0, t0);
        Ewma::add(&mut e, 1100.0, PLAIN_WEIGHT, t0);
        let mean = e.unwrap().mean();
        assert!(
            (mean - (100.0 + 1100.0 * 0.2) / 1.2).abs() < 1e-9,
            "{}",
            mean
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_penalty_grows_decays_and_is_reset() {
        let t0 = Instant::now();
        let mut s = MemberStats::new(1.0, t0);
        s.answered(ms(100), 1.0, t0);
        assert_eq!(s.score(t0), Some(100.0));
        assert!(!s.is_failed(t0));

        s.failed(t0);
        assert_eq!(s.penalty(t0), 200.0);
        assert!(s.is_failed(t0));
        s.failed(t0);
        s.failed(t0);
        assert_eq!(s.penalty(t0), 800.0);
        assert_eq!(s.score(t0), Some(900.0));
        for _ in 0..10 {
            s.failed(t0);
        }
        assert_eq!(s.penalty(t0), PENALTY_CAP_MS);

        // It halves every ten minutes, and the member is failed until it
        // is down to half a first failure's.
        let later = t0 + PENALTY_HALF_LIFE;
        assert_eq!(s.penalty(later), PENALTY_CAP_MS / 2.0);
        let mut once = MemberStats::new(1.0, t0);
        once.failed(t0);
        assert!(once.is_failed(t0 + PENALTY_HALF_LIFE - ms(1000)));
        assert!(!once.is_failed(t0 + PENALTY_HALF_LIFE + ms(1000)));

        // A success clears it, and the count of failures.
        s.answered(ms(100), 1.0, later);
        assert_eq!(s.penalty(later), 0.0);
        s.failed(later);
        assert_eq!(s.penalty(later), PENALTY_BASE_MS);
    }

    #[tokio::test(start_paused = true)]
    async fn the_priority_scales_the_score() {
        let t0 = Instant::now();
        let mut preferred = MemberStats::new(0.5, t0);
        preferred.answered(ms(180), 1.0, t0);
        let mut other = MemberStats::new(1.0, t0);
        other.answered(ms(100), 1.0, t0);
        assert_eq!(preferred.score(t0), Some(90.0));
        assert!(preferred.score(t0) < other.score(t0));
        // The penalty is scaled too.
        preferred.failed(t0);
        assert_eq!(preferred.score(t0), Some(190.0));
    }

    #[tokio::test(start_paused = true)]
    async fn an_unknown_member_has_no_score_until_answered_or_probed() {
        let t0 = Instant::now();
        let mut s = MemberStats::new(1.0, t0);
        assert_eq!(s.score(t0), None);
        // Connecting alone tells nothing of the first response.
        s.connected(ms(40), t0);
        assert_eq!(s.score(t0), None);
        s.probed(Some(ms(300)), t0);
        assert_eq!(s.score(t0), Some(300.0));
        let mut failed = MemberStats::new(1.0, t0);
        failed.probed(None, t0);
        assert!(failed.is_failed(t0));
        assert_eq!(failed.score(t0), None);
    }

    #[tokio::test(start_paused = true)]
    async fn a_slow_connect_costs_half_a_failure() {
        let t0 = Instant::now();
        let mut s = MemberStats::new(1.0, t0);
        assert!(!s.connected(ms(100), t0));
        // Not compared before the average is of a few samples.
        assert!(!s.connected(ms(400), t0));
        s.connected(ms(100), t0);
        s.connected(ms(100), t0);
        let avg = s.connect.unwrap().mean();
        assert!(!s.connected(Duration::from_secs_f64(avg * 1.4 / 1000.0), t0));
        assert!(s.connected(ms(1000), t0));
        assert_eq!(s.penalty(t0), PENALTY_BASE_MS / 2.0);
        assert!(!s.is_failed(t0), "slow is not failed");
    }

    #[tokio::test(start_paused = true)]
    async fn a_handshake_has_three_seconds_or_three_connects() {
        let t0 = Instant::now();
        let mut s = MemberStats::new(1.0, t0);
        assert_eq!(s.first_byte_timeout(), FIRST_BYTE_TIMEOUT);
        s.connected(ms(200), t0);
        assert_eq!(s.first_byte_timeout(), FIRST_BYTE_TIMEOUT);
        let mut slow = MemberStats::new(1.0, t0);
        slow.connected(ms(2000), t0);
        assert_eq!(slow.first_byte_timeout(), ms(6000));
    }

    #[tokio::test(start_paused = true)]
    async fn staleness_and_uses() {
        let t0 = Instant::now();
        let interval = Duration::from_secs(300);
        let mut s = MemberStats::new(1.0, t0);
        assert!(s.is_stale(interval, t0));
        s.answered(ms(10), 1.0, t0);
        assert!(!s.is_stale(interval, t0 + interval / 2));
        assert!(s.is_stale(interval, t0 + interval));
        s.used(t0);
        s.used(t0);
        assert_eq!(s.uses(t0), 2.0);
        assert_eq!(s.uses(t0 + USE_HALF_LIFE), 1.0);
    }

    #[test]
    fn jitter_is_not_slowness() {
        // Twice as long, but by less than jitter: not slower.
        assert!(!slower(0.8, 0.3, 2.0));
        assert!(!slower(40.0, 15.0, 2.0));
        // Twice as long and by more than jitter: slower.
        assert!(slower(120.0, 50.0, 2.0));
        // Longer by a lot, but not twice as long: not slower.
        assert!(!slower(300.0, 200.0, 2.0));
    }
}
