---
title: CLI reference
description: Run, validate and tune Sail from the command line.
---

The `sail-cli` crate produces the `sail` executable. With no arguments it loads `config.conf` from the current directory.

## Common commands

```sh
# Start with a JSON configuration
sail -c config.json

# Validate and exit
sail -c config.json -T

# Reload after file changes
sail -c config.json --auto-reload

# Print the build version
sail -V
```

## Connectivity test

Test one outbound by tag without starting the normal listeners:

```sh
sail -c config.json -t edge
```

Sail reports TCP and UDP independently with their elapsed time or error. The default timeout is four seconds; change it with `-d`:

```sh
sail -c config.json -t edge -d 10
```

This test is useful after DNS, credential, certificate or route changes. It tests the named outbound itself, not a complete application-to-inbound path.

## Runtime profiles

Runtime profiles tune memory budgets, queues and concurrency without changing the portable configuration file.

| Profile | Intended host |
| --- | --- |
| `mobile` | Phones and memory-sensitive app processes |
| `desktop` | Default general-purpose profile |
| `server` | High concurrency and throughput |
| `router` | Small devices with the tightest memory budget |

```sh
sail -c config.json --profile server
```

Override one setting with a repeatable `--set` option:

```sh
sail -c config.json --profile server \
  --set relay.buffer_size=32 \
  --set dns.max_retries=3
```

These settings describe the host runtime, not proxy behavior. Keep protocol, DNS and routing decisions in the configuration file.

The streams of multiplexed connections (sing-mux smux and yamux, AnyTLS, amux) take three of them:

| Setting | Default | Meaning |
| --- | --- | --- |
| `mux.stream_window_max` | `16384` (KiB); `8192` on `mobile`, `4096` on `router` | The largest a stream's receive window grows to (yamux, amux). Windows start at 256 KiB and double while a stream is read faster than its window lets data in. h2mux takes a quarter of it a stream and twice it a connection. |
| `mux.stream_buffer` | `256` (KiB) | What a stream of a protocol without windows (smux, AnyTLS) holds unread before its connection stops being read. |
| `mux.stall_timeout` | `60s` | A stream whose data nothing has read for this long is reset, alone, and logged as `event=stream_stalled`; h2mux streams too. QUIC streams (Hysteria2, TUIC) are reset after 60 s. |

The API's `/api/v1/runtime/stat/mux` counts their sessions, streams and stalled streams per protocol.

## Paths and persisted state

```sh
sail -c config.json \
  --data-dir /opt/sail/data \
  --cache-dir /var/lib/sail
```

The data directory contains files such as `geo.mmdb`, `site.dat` and relative certificate paths. It defaults to the executable's directory. The cache directory preserves state such as the active member of a selector across restarts.

## Threading

Sail uses a multi-threaded runtime by default. `--single-thread` is useful for constrained hosts, deterministic debugging or embeddings that provide their own outer concurrency. `--thread-stack-size` changes the worker stack size in bytes; keep the default unless profiling shows a concrete need.

## Option summary

| Option | Purpose |
| --- | --- |
| `-c`, `--config` | Configuration path; default `config.conf` |
| `--auto-reload` | Watch the configuration and reload changes |
| `--single-thread` | Use a current-thread runtime |
| `--thread-stack-size` | Worker thread stack size in bytes |
| `-T`, `--test` | Validate configuration and exit |
| `-t`, `--test-outbound` | Test one outbound tag |
| `-d`, `--test-outbound-timeout` | Outbound test timeout in seconds |
| `--profile` | `mobile`, `desktop`, `server` or `router` |
| `--set` | Override one runtime tuning value; repeatable |
| `-D`, `--data-dir` | Assets and relative certificate base directory |
| `--cache-dir` | Persistent runtime state directory |
| `-V`, `--version` | Print version and exit |
