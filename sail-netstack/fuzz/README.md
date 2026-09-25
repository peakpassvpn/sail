# sail-netstack fuzzing

The `wire_parse` target exercises raw IPv4/IPv6 input and synthesizes valid
outer headers so mutations reach the TCP, UDP, ICMP, and ICMPv6 parsers even
before their IP checksums converge. The `fragment_reassembly` target generates
valid IPv4 and IPv6 fragment trains, then fuzzes ordering, duplication, loss,
offsets, final-fragment state, reconstruction, and budget release. The
`tcp_state` target applies arbitrary segment, application, timer, RTT, and SACK
events to a deterministic TCB while continuously checking receive-credit,
advertised-window, and send-sequence invariants.

Run it with a nightly toolchain and `cargo-fuzz`:

```sh
cargo +nightly fuzz run wire_parse
cargo +nightly fuzz run fragment_reassembly
cargo +nightly fuzz run tcp_state
```

Crashes are retained by cargo-fuzz under `fuzz/artifacts/`; minimize and add a
deterministic regression test before fixing the defect.
