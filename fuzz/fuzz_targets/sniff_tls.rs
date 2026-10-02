#![no_main]

use libfuzzer_sys::fuzz_target;
use sail::sniff::{is_domain_name, tls, Sniff};

mod common;

fuzz_target!(|data: &[u8]| {
    common::check_prefixes(data, tls::sniff);
    common::check_prefixes(data, tls::client_hello);
    if let Sniff::Found(Some(name)) = tls::sniff(data) {
        assert!(is_domain_name(&name));
    }
});
