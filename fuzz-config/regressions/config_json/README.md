# Known configuration parser regressions

`duration-overflow.original.json` is the 201-byte artifact found by the
2026-09-28 ASan campaign. `duration-overflow.min.json` is cargo-fuzz's minimized
76-byte reproducer. Both make the public `Config::from_json` path panic in
`config::model::parse_duration` when `Duration::from_secs_f64` receives an
unrepresentably large finite float.

The core fix uses checked float conversion and checked accumulation so the
public parser returns an ordinary invalid-duration error. The stable regression
runs by default and also checks that the public parser returns that error.

Replay the minimized input from the repository root:

```sh
fuzz-config/scripts/replay.sh config_json fuzz-config/regressions/config_json/duration-overflow.min.json
```

SHA-256:

- original: `afeaedb47b780b131840f2702389d8547947a83ef957a3529abcfec30df729cb`
- minimized: `3b31abf32b6b5559e17ed33187c7f648a36cb992f16b2b8465393eeab3658417`
