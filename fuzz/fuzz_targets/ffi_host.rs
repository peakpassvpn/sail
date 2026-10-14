#![no_main]

use libfuzzer_sys::fuzz_target;

// What a host tells a running instance, read without one: the network it
// is on, and who opened a connection.
fuzz_target!(|data: &[u8]| {
    sail::fuzzing::host_json(data);
});
