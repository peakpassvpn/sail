//! The handshake rate limiter of Linux's ratelimiter.c: under load, a
//! token bucket per source, 20 handshake messages a second with a burst
//! of 5. IPv4 sources count by address, IPv6 sources by /64.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

const PACKETS_PER_SECOND: u64 = 20;
const PACKETS_BURSTABLE: u64 = 5;
const PACKET_COST: u64 = 1_000_000_000 / PACKETS_PER_SECOND;
const TOKEN_MAX: u64 = PACKET_COST * PACKETS_BURSTABLE;
/// Entries idle this long are dropped.
const IDLE: Duration = Duration::from_secs(1);
/// Bounds the table against address-spraying floods.
const MAX_ENTRIES: usize = 8192;

#[derive(Default)]
pub struct RateLimiter {
    buckets: HashMap<IpAddr, (Instant, u64)>,
    last_gc: Option<Instant>,
}

fn key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => {
            let bits = u128::from(v6) & !((1u128 << 64) - 1);
            IpAddr::V6(bits.into())
        }
    }
}

impl RateLimiter {
    pub fn allow(&mut self, ip: IpAddr, now: Instant) -> bool {
        self.gc(now);
        let k = key(ip);
        if let Some((last, tokens)) = self.buckets.get_mut(&k) {
            let elapsed = now.saturating_duration_since(*last).as_nanos() as u64;
            *last = now;
            *tokens = (*tokens + elapsed).min(TOKEN_MAX);
            if *tokens >= PACKET_COST {
                *tokens -= PACKET_COST;
                return true;
            }
            return false;
        }
        if self.buckets.len() >= MAX_ENTRIES {
            return false;
        }
        self.buckets.insert(k, (now, TOKEN_MAX - PACKET_COST));
        true
    }

    fn gc(&mut self, now: Instant) {
        if self
            .last_gc
            .is_some_and(|t| now.saturating_duration_since(t) < IDLE)
        {
            return;
        }
        self.last_gc = Some(now);
        self.buckets
            .retain(|_, (last, _)| now.saturating_duration_since(*last) < IDLE);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burst_then_rate() {
        let mut rl = RateLimiter::default();
        let t0 = Instant::now();
        let a: IpAddr = "192.0.2.1".parse().unwrap();
        let b: IpAddr = "192.0.2.2".parse().unwrap();
        for _ in 0..PACKETS_BURSTABLE {
            assert!(rl.allow(a, t0));
        }
        assert!(!rl.allow(a, t0));
        assert!(rl.allow(b, t0));
        // One packet's worth of time refills one token.
        assert!(!rl.allow(a, t0 + Duration::from_millis(49)));
        assert!(rl.allow(
            a,
            t0 + Duration::from_millis(50) + Duration::from_millis(49)
        ));
    }

    #[test]
    fn ipv6_by_slash_64() {
        let mut rl = RateLimiter::default();
        let t0 = Instant::now();
        for i in 0..PACKETS_BURSTABLE {
            let ip: IpAddr = format!("2001:db8::{}", i + 1).parse().unwrap();
            assert!(rl.allow(ip, t0));
        }
        assert!(!rl.allow("2001:db8::ffff".parse().unwrap(), t0));
        assert!(rl.allow("2001:db8:0:1::1".parse().unwrap(), t0));
    }
}
