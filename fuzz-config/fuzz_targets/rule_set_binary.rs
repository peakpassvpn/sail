#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = sail_config_fuzz::parse_rule_set_binary_bytes(data);
});
