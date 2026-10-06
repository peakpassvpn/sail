#![no_main]

//! sail::fuzzing::tun_vnet_header, on Linux; nothing elsewhere.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    #[cfg(target_os = "linux")]
    sail::fuzzing::tun_vnet_header(data);
    #[cfg(not(target_os = "linux"))]
    let _ = data;
});
