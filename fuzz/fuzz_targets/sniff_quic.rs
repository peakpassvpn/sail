#![no_main]

//! Datagrams to the QUIC sniffer: as they come, which almost never pass
//! the packet protection, and as the frames of Initial packets protected
//! as a client would, which reach the frame parser and the reassembly.

use libfuzzer_sys::fuzz_target;
use sail::sniff::quic::{protect, QuicSniffer};
use sail::sniff::{is_domain_name, Sniff};

/// `data` cut into pieces, each after a byte giving its length.
fn pieces(mut data: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    while let Some((&len, rest)) = data.split_first() {
        let len = (len as usize * 8).min(rest.len());
        out.push(&rest[..len]);
        data = &rest[len..];
    }
    out
}

fn check(sniff: &Sniff) {
    if let Sniff::Found(Some(name)) = sniff {
        assert!(is_domain_name(name));
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, data)) = data.split_first() else {
        return;
    };
    let mut sniffer = QuicSniffer::new();
    if mode & 1 == 0 {
        for datagram in pieces(data) {
            check(&sniffer.feed(datagram));
        }
        return;
    }
    let version = match mode >> 1 & 3 {
        0 => 1,
        1 => 0x6b33_43cf,
        _ => 0xff00_001d,
    };
    for (i, frames) in pieces(data).into_iter().enumerate() {
        // At least a sample's worth of payload.
        let mut frames = frames.to_vec();
        frames.resize(frames.len().max(20), 0);
        let Some(packet) = protect(version, &[mode; 8], i as u32, &frames) else {
            return;
        };
        let sniff = sniffer.feed(&packet);
        check(&sniff);
        if sniff != Sniff::NeedMore {
            return;
        }
    }
});
