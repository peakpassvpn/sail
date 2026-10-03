#![no_main]

use libfuzzer_sys::fuzz_target;

// The neighbor table reads lease files that dnsmasq, odhcpd, ISC dhcpd,
// Kea and bootpd write.
fuzz_target!(|data: &[u8]| {
    sail::fuzzing::dhcp_leases(data);
});
