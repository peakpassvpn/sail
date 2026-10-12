#![no_main]

//! sail::fuzzing::hysteria2: what a peer of the protocol sends, as each end
//! parses it.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    sail::fuzzing::hysteria2(data);
});
