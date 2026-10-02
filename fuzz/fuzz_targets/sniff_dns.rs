#![no_main]

use libfuzzer_sys::fuzz_target;
use sail::sniff::dns;

mod common;

fuzz_target!(|data: &[u8]| {
    let _ = dns::query(data);
    common::check_prefixes(data, dns::stream_query);
});
