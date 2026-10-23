//! Whether a client's QUIC connection still has a server behind it. A
//! server that restarted has lost the connection and cannot tell us: its
//! stateless resets are made with a new key and do not verify, so quinn
//! keeps the connection until the idle timeout, and every stream opened
//! on it meanwhile goes nowhere. A server that answers sends something
//! within a round trip of a new stream: an ACK at least.

use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How long a server may send nothing after a new stream or UDP session
/// before the connection is no longer used for new ones: four smoothed
/// round trips, and no less than this. Judgment: a server that answers
/// does so within a round trip and its ACK delay (25 ms), and a lost
/// ACK is repeated with the next; past it a server restart costs this and
/// a handshake instead of the idle timeout. A connection given up for
/// this is not closed: what is open on it stays, and ends with it.
const SILENCE_MIN: Duration = Duration::from_secs(1);
const SILENCE_RTTS: u32 = 4;

/// What had been received on a connection when it last sent what the
/// server must answer, unanswered since.
#[derive(Default)]
pub struct Silence(Mutex<Option<Probe>>);

#[derive(Clone, Copy)]
struct Probe {
    /// Datagrams received on the connection, then.
    received: u64,
    since: Instant,
}

impl Silence {
    /// Notes that `conn` has just sent what the server must answer: a new
    /// stream's request. The wait runs from the first such send that is
    /// still unanswered.
    pub fn sent(&self, conn: &quinn::Connection) {
        self.sent_at(conn.stats().udp_rx.datagrams, Instant::now());
    }

    /// Whether `conn` looks to have lost its server, as it is about to
    /// carry one more stream or UDP session: nothing has been received on
    /// it since a send that needed an answer, long enough ago.
    pub fn gone(&self, conn: &quinn::Connection) -> bool {
        self.gone_at(conn.stats().udp_rx.datagrams, conn.rtt(), Instant::now())
    }

    fn sent_at(&self, received: u64, now: Instant) {
        let mut probe = self.probe();
        if probe.is_none_or(|p| p.received != received) {
            *probe = Some(Probe {
                received,
                since: now,
            });
        }
    }

    fn gone_at(&self, received: u64, rtt: Duration, now: Instant) -> bool {
        let mut probe = self.probe();
        match *probe {
            Some(p) if p.received == received => {
                now.duration_since(p.since) >= (rtt * SILENCE_RTTS).max(SILENCE_MIN)
            }
            Some(_) => {
                *probe = None;
                false
            }
            None => false,
        }
    }

    fn probe(&self) -> std::sync::MutexGuard<'_, Option<Probe>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RTT: Duration = Duration::from_millis(20);

    #[test]
    fn a_server_that_answers_is_not_gone() {
        let silence = Silence::default();
        let t = Instant::now();
        silence.sent_at(10, t);
        assert!(!silence.gone_at(11, RTT, t + Duration::from_secs(5)));
        silence.sent_at(11, t + Duration::from_secs(5));
        assert!(!silence.gone_at(12, RTT, t + Duration::from_secs(60)));
    }

    #[test]
    fn nothing_sent_is_never_gone() {
        let silence = Silence::default();
        let t = Instant::now();
        assert!(!silence.gone_at(10, RTT, t));
        assert!(!silence.gone_at(10, RTT, t + Duration::from_secs(60)));
    }

    #[test]
    fn a_server_silent_since_a_stream_is_gone_after_the_wait() {
        let silence = Silence::default();
        let t = Instant::now();
        silence.sent_at(10, t);
        assert!(!silence.gone_at(10, RTT, t + SILENCE_MIN / 2));
        // A later send does not move the wait.
        silence.sent_at(10, t + SILENCE_MIN / 2);
        assert!(silence.gone_at(10, RTT, t + SILENCE_MIN));
        assert!(silence.gone_at(10, RTT, t + SILENCE_MIN * 2));
    }

    #[test]
    fn the_wait_grows_with_the_round_trip() {
        let silence = Silence::default();
        let rtt = Duration::from_millis(400);
        let t = Instant::now();
        silence.sent_at(10, t);
        assert!(!silence.gone_at(10, rtt, t + Duration::from_millis(1500)));
        assert!(silence.gone_at(10, rtt, t + rtt * SILENCE_RTTS));
    }

    #[test]
    fn an_answer_ends_the_wait() {
        let silence = Silence::default();
        let t = Instant::now();
        silence.sent_at(10, t);
        assert!(!silence.gone_at(11, RTT, t + SILENCE_MIN));
        // Nothing sent since the answer: nothing to wait for.
        assert!(!silence.gone_at(11, RTT, t + SILENCE_MIN * 3));
        silence.sent_at(11, t + SILENCE_MIN * 3);
        assert!(silence.gone_at(11, RTT, t + SILENCE_MIN * 4));
    }
}
