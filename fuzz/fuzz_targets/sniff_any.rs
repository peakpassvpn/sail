#![no_main]

//! Every sniffer at once, on a stream and on datagrams, as the dispatcher
//! runs them.

use libfuzzer_sys::fuzz_target;
use sail::sniff::{sniff_stream, DatagramSniff, Protocols, Sniffed};

fuzz_target!(|data: &[u8]| {
    let whole = sniff_stream(Protocols::ALL, data);
    if let Some(cut) = data.first().map(|b| *b as usize % (data.len() + 1)) {
        // What is decided on part of the stream stays decided.
        match sniff_stream(Protocols::ALL, &data[..cut]) {
            Sniffed::NeedMore => {}
            decided => assert_eq!(decided, whole),
        }
    }
    let mut sniff = DatagramSniff::new(Protocols::ALL);
    for datagram in data.chunks(1200) {
        if sniff.feed(datagram) != Sniffed::NeedMore {
            break;
        }
    }
});
