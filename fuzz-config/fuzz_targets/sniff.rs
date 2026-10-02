#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = sail_config_fuzz::parse_sniff_bytes(data);
});
