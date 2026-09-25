//! Congestion control as Hysteria2 negotiates it: Brutal at a fixed rate
//! when the sending side knows the rate it may use, BBR otherwise.
//!
//! The rate is only known once the authentication exchange is over, after
//! quinn built the connection's controller, and quinn cannot swap a
//! controller. So every connection gets a `Switch`, which runs both and
//! answers with the one its `CongestionHandle` selects.

use std::any::Any;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use quinn::congestion::{BbrConfig, Controller, ControllerFactory};
use quinn_proto::RttEstimator;

/// Selects the controller of one connection: BBR, or Brutal at a rate.
#[derive(Clone, Default)]
pub struct CongestionHandle(Arc<AtomicU64>);

impl CongestionHandle {
    /// Brutal at `bps` bytes per second; zero selects BBR.
    pub fn set_brutal(&self, bps: u64) {
        self.0.store(bps, Ordering::Relaxed);
    }

    pub fn set_bbr(&self) {
        self.0.store(0, Ordering::Relaxed);
    }

    fn brutal_rate(&self) -> Option<u64> {
        match self.0.load(Ordering::Relaxed) {
            0 => None,
            bps => Some(bps),
        }
    }

    /// A factory for the connection this handle is to control. Each
    /// connection needs a handle, and so a factory, of its own.
    pub fn factory(&self) -> Arc<dyn ControllerFactory + Send + Sync> {
        Arc::new(Factory {
            handle: self.clone(),
            bbr: Arc::new(BbrConfig::default()),
        })
    }
}

struct Factory {
    handle: CongestionHandle,
    bbr: Arc<BbrConfig>,
}

impl ControllerFactory for Factory {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(Switch {
            handle: self.handle.clone(),
            bbr: self.bbr.clone().build(now, current_mtu),
            brutal: Brutal::new(now, current_mtu),
        })
    }
}

/// Feeds both controllers, so that either is up to date when selected.
struct Switch {
    handle: CongestionHandle,
    bbr: Box<dyn Controller>,
    brutal: Brutal,
}

impl Controller for Switch {
    fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {
        self.bbr.on_sent(now, bytes, last_packet_number);
    }

    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.bbr.on_ack(now, sent, bytes, app_limited, rtt);
        self.brutal.on_ack(now, rtt);
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        self.bbr
            .on_end_acks(now, in_flight, app_limited, largest_packet_num_acked);
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        self.bbr
            .on_congestion_event(now, sent, is_persistent_congestion, lost_bytes);
        self.brutal.on_loss(now, lost_bytes);
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.bbr.on_mtu_update(new_mtu);
        self.brutal.mtu = new_mtu as u64;
    }

    fn window(&self) -> u64 {
        match self.handle.brutal_rate() {
            Some(bps) => self.brutal.window(bps),
            None => self.bbr.window(),
        }
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(Switch {
            handle: self.handle.clone(),
            bbr: self.bbr.clone_box(),
            brutal: self.brutal.clone(),
        })
    }

    fn initial_window(&self) -> u64 {
        self.bbr.initial_window()
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

/// Seconds of acknowledgement statistics kept.
const SLOTS: usize = 5;
/// Packets seen before the loss rate is believed.
const MIN_SAMPLES: u64 = 50;
/// The lowest acknowledged share compensated for: at worse loss than this,
/// sending harder would only make it worse.
const MIN_ACK_RATE: f64 = 0.8;
/// The window before an RTT is known, as the reference implementation's.
const INITIAL_WINDOW: u64 = 10240;

#[derive(Clone, Copy, Default)]
struct Slot {
    second: u64,
    acked: u64,
    lost: u64,
}

/// Brutal: sends at the rate it is given whatever the loss, raising it by
/// the share of packets lost so that that rate arrives.
///
/// The reference implementation paces at the rate and lets twice the
/// bandwidth-delay product be in flight. quinn has no pacing hook: it paces
/// at 5/4 of the window per RTT. So the window here is one bandwidth-delay
/// product, which caps the rate where Brutal's pacer would.
#[derive(Clone)]
struct Brutal {
    start: Instant,
    mtu: u64,
    rtt: Duration,
    slots: [Slot; SLOTS],
    ack_rate: f64,
}

impl Brutal {
    fn new(now: Instant, mtu: u16) -> Self {
        Self {
            start: now,
            mtu: mtu as u64,
            rtt: Duration::ZERO,
            slots: [Slot::default(); SLOTS],
            ack_rate: 1.0,
        }
    }

    fn slot(&mut self, now: Instant) -> (&mut Slot, u64) {
        let second = now.saturating_duration_since(self.start).as_secs();
        let slot = &mut self.slots[(second % SLOTS as u64) as usize];
        if slot.second != second {
            *slot = Slot {
                second,
                ..Slot::default()
            };
        }
        (slot, second)
    }

    fn on_ack(&mut self, now: Instant, rtt: &RttEstimator) {
        self.rtt = rtt.get();
        let (slot, second) = self.slot(now);
        slot.acked += 1;
        self.update_ack_rate(second);
    }

    fn on_loss(&mut self, now: Instant, lost_bytes: u64) {
        if lost_bytes == 0 {
            return;
        }
        // quinn reports lost bytes; the statistics count packets.
        let packets = lost_bytes.div_ceil(self.mtu.max(1));
        let (slot, second) = self.slot(now);
        slot.lost += packets;
        self.update_ack_rate(second);
    }

    fn update_ack_rate(&mut self, second: u64) {
        let oldest = second.saturating_sub(SLOTS as u64);
        let (acked, lost) = self
            .slots
            .iter()
            .filter(|s| s.second >= oldest && (s.acked > 0 || s.lost > 0))
            .fold((0, 0), |(a, l), s| (a + s.acked, l + s.lost));
        self.ack_rate = if acked + lost < MIN_SAMPLES {
            1.0
        } else {
            (acked as f64 / (acked + lost) as f64).max(MIN_ACK_RATE)
        };
    }

    fn window(&self, bps: u64) -> u64 {
        if self.rtt.is_zero() {
            return INITIAL_WINDOW;
        }
        let window = bps as f64 * self.rtt.as_secs_f64() / self.ack_rate;
        (window as u64).max(2 * self.mtu)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn brutal_raises_the_window_by_the_loss_rate_down_to_a_floor() {
        let start = Instant::now();
        let mut brutal = Brutal::new(start, 1200);
        assert_eq!(brutal.window(1_000_000), INITIAL_WINDOW);
        brutal.rtt = Duration::from_millis(100);
        assert_eq!(brutal.window(1_000_000), 100_000);

        // 90 acked, 10 lost: a window 1/0.9 as large.
        let now = start + Duration::from_millis(1500);
        for _ in 0..90 {
            let (slot, _) = brutal.slot(now);
            slot.acked += 1;
        }
        brutal.on_loss(now, 10 * 1200);
        assert!((brutal.ack_rate - 0.9).abs() < 1e-9);
        assert_eq!(brutal.window(1_000_000), 111_111);

        // Heavy loss is compensated only down to MIN_ACK_RATE.
        brutal.on_loss(now, 100 * 1200);
        assert_eq!(brutal.ack_rate, MIN_ACK_RATE);

        // Statistics older than the slots are forgotten.
        let later = start + Duration::from_secs(20);
        brutal.on_loss(later, 1200);
        assert_eq!(brutal.ack_rate, 1.0);
    }

    #[test]
    fn the_handle_switches_between_bbr_and_brutal() {
        let handle = CongestionHandle::default();
        let now = Instant::now();
        let mut controller = handle.factory().build(now, 1200);
        let bbr_window = controller.window();
        handle.set_brutal(10_000_000);
        assert_eq!(controller.window(), INITIAL_WINDOW);
        handle.set_bbr();
        assert_eq!(controller.window(), bbr_window);
        controller.on_mtu_update(1400);
    }
}
