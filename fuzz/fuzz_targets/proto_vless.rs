#![no_main]

//! sail::fuzzing::vless: what a peer of the protocol sends, as each end
//! parses it.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    sail::fuzzing::vless(data);
});
