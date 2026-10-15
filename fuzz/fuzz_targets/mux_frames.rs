#![no_main]

//! sail::fuzzing::mux_frames: what a sing-mux or amux peer sends, as each
//! decoder reads it.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    sail::fuzzing::mux_frames(data);
});
