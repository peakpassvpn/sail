#![no_main]

use libfuzzer_sys::fuzz_target;
use sail::sniff::{http, is_domain_name, Sniff};

mod common;

fuzz_target!(|data: &[u8]| {
    common::check_prefixes(data, http::sniff);
    if let Sniff::Found(Some(name)) = http::sniff(data) {
        assert!(is_domain_name(&name));
    }
});
