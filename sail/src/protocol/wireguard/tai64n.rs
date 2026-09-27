//! TAI64N timestamps, the replay guard of handshake initiations.
//!
//! Twelve bytes: the seconds as a big-endian u64 offset by 2^62 + 10 (the
//! TAI-UTC difference the label format fixed at its epoch), then the
//! nanoseconds as a big-endian u32. As Linux and wireguard-go do, the
//! nanoseconds are rounded down to a multiple of 2^24, the largest power of
//! two below the 20 ms a responder allows between initiations, so that the
//! timestamp does not leak a precise clock.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const LEN: usize = 12;

const BASE: u64 = 0x4000_0000_0000_000a;
const WHITENER_MASK: u32 = 0x100_0000 - 1;

/// A TAI64N label. Byte order makes the derived ordering chronological.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Tai64n(pub [u8; LEN]);

impl Tai64n {
    /// The label of `time`, whitened.
    pub fn from_system_time(time: SystemTime) -> Self {
        let since = time.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
        Self::from_unix(since.as_secs(), since.subsec_nanos())
    }

    /// The label of a Unix time, whitened.
    pub fn from_unix(secs: u64, nanos: u32) -> Self {
        let mut out = [0u8; LEN];
        out[..8].copy_from_slice(&(BASE + secs).to_be_bytes());
        out[8..].copy_from_slice(&(nanos & !WHITENER_MASK).to_be_bytes());
        Tai64n(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout() {
        let t = Tai64n::from_unix(1, 0x0123_4567);
        assert_eq!(t.0, [0x40, 0, 0, 0, 0, 0, 0, 0x0b, 0x01, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn ordering_is_chronological() {
        let a = Tai64n::from_unix(100, 999_999_999);
        let b = Tai64n::from_unix(101, 0);
        assert!(a < b);
        // Within one 2^24 ns bucket, two labels are equal: a second
        // initiation that close is a replay to the responder.
        assert_eq!(Tai64n::from_unix(5, 1), Tai64n::from_unix(5, 16_000_000));
        assert!(Tai64n::from_unix(5, 1) < Tai64n::from_unix(5, 17_000_000));
    }
}
