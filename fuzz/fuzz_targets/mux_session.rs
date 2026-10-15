#![no_main]

//! sail::fuzzing::mux_session: a sing-mux session, server or client,
//! against a peer that sends this, on paused time.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // A session's input is a connection's worth; more only slows it down.
    if data.len() <= 64 << 10 {
        sail::fuzzing::mux_session(data);
    }
});
