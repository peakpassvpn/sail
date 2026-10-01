---
title: CLI reference
description: Run, validate and tune Sail from the command line.
---

The `sail-cli` crate produces the `sail` executable. With no arguments it loads `config.json` from the current directory.

The file extension selects the format: `.json` is sing-box JSON (comments and trailing commas allowed), `.yaml` or `.yml` is Clash/Mihomo YAML, and `.conf` is a Surge profile. Any other extension is an error. All three are read directly by the same loader; there is no conversion step.

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

Override one setting with a repeatable `--set key=value` option. The key is a dotted path, and the value is a number, `true` or `false`, or a duration such as `10s`. An unknown key or a value of the wrong type is an error.

```sh
sail -c config.json --profile server \
  --set relay.buffer_size=32 \
  --set dns.max_retries=3
```

These settings describe the host runtime, not proxy behavior. Keep protocol, DNS and routing decisions in the configuration file.

The groups are `relay` (TCP relay buffers and half-close idle timeouts), `udp`, `netstack` (the TUN stack's budget, batches, queues and TCP windows), `inbound` (handshake timeout, multiplex accept concurrency, TCP send buffer), `quic`, `ws`, `dns` (`max_retries`, `dualstack_delay`), `stats`, `lifecycle` and `mux`. A few values that differ by profile:

| Setting | `desktop` | `mobile` | `router` | `server` |
| --- | --- | --- | --- | --- |
| `relay.buffer_size` (KiB) | `16` | `8` | `4` | `16` |
| `relay.buffer_max_size` (KiB) | `128` | `64` | `16` | `256` |
| `quic.max_concurrent_streams` | `1024` | `256` | `128` | `4096` |
| `inbound.tcp_send_buffer` (KiB, `0` = system) | `0` | `0` | `256` | `0` |
| `lifecycle.drain_timeout` | `0` | `0` | `0` | `30s` |

`lifecycle.drain_timeout` is how long open TCP connections may finish after SIGTERM or Ctrl-C once no new ones are accepted; `0` stops at once, and a second signal always stops at once.

The streams of multiplexed connections (sing-mux smux and yamux, AnyTLS, amux) take three of them:

| Setting | Default | Meaning |
| --- | --- | --- |
| `mux.stream_window_max` | `16384` (KiB); `8192` on `mobile` and `router` | The largest a stream's receive window grows to (yamux, amux). Windows start at 256 KiB and double while a stream is read faster than its window lets data in. h2mux takes a quarter of it a stream and twice it a connection. |
| `mux.stream_buffer` | `256` (KiB) | What a stream of a protocol without windows (smux, AnyTLS) holds unread before its connection stops being read. |
| `mux.stall_timeout` | `60s` | A stream whose data nothing has read for this long is reset, alone, and logged as `event=stream_stalled`; h2mux streams too. QUIC streams (Hysteria2, TUIC) are reset after 60 s. |

The API's `/api/v1/runtime/stat/mux` counts their sessions, streams and stalled streams per protocol.

## Paths and persisted state

```sh
sail -c config.json \
  --data-dir /opt/sail/data \
  --cache-dir /var/lib/sail
```

The data directory contains files such as `geo.mmdb`, `site.dat` and relative certificate paths. It defaults to the executable's directory. The cache directory holds `experimental.cache_file` by default (selector choices, the Clash mode and, with `store_fakeip`, fake IPs), downloaded remote rule-sets, and the copies of a Surge profile's remote includes.

## Assets

Some rules read data files from the data directory: `geoip` and `mmdb:` external rules read `geo.mmdb`, `geosite` and `site:` read `site.dat`, `ip_asn` (Surge's `IP-ASN`) and a `smart` group's `prefer_asn` read `asn.mmdb`, and an external rule or `asn_file` may name another file. Sail does not download these when it loads a configuration; a configuration that needs one that is missing fails to load, naming the path.

```sh
# What the configuration reads, where, and whether it is there
sail -D /opt/sail/data assets config.json

# Download the missing ones, or all of them again
sail -D /opt/sail/data assets config.json --fetch
sail -D /opt/sail/data assets config.json --update

# From another URL
sail assets config.json --fetch --source geo.mmdb=https://example.com/Country.mmdb

# Download the missing ones before starting
sail -c config.json --fetch-assets
```

`sail assets` prints one line per file: its name, `present` or `missing`, its path, and the fields that read it (`route.rules[3].ip_asn`). A download replaces a file only once it reads as a MaxMind database or a site list, and never leaves half a file. The defaults:

| Asset | Source |
| --- | --- |
| `asn.mmdb` | GeoLite2-ASN, Mihomo's default: `https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/GeoLite2-ASN.mmdb` |
| `geo.mmdb` | GeoLite2-Country format: `https://github.com/Loyalsoldier/geoip/releases/latest/download/Country.mmdb` |
| `site.dat` | V2Ray site lists: `https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat` |

A file a rule names has no default: give it one with `--source name=url` (or `--asset-source name=url` when starting). A rule-set read from a file or downloaded may need `asn.mmdb` too; that is known only when it loads, and its error names the file.

The sources the CLI starts with become the host's `asset_sources`, which the runtime API updates from while sail runs:

| Endpoint | Purpose |
| --- | --- |
| `GET /api/v1/runtime/assets` | The running configuration's assets, as `sail assets` lists them, in JSON |
| `POST /api/v1/runtime/assets/{name}/update` | Downloads one, from the body's `url` or else the host's source, through the body's `detour` outbound or else the default one; puts it in place if it reads, then reloads so that the rules read it. The reply says whether the reload took. 404 for a name the configuration does not read, 400 without a URL, 502 when the download or the file fails |

## Surge includes, Sub-Store and the dashboard

```sh
# Download the URLs a Surge profile includes before reading it
sail -c profile.conf --cache-dir /var/lib/sail --fetch-includes

# Resolve sub.store URLs to your own Sub-Store backend
sail -c profile.conf --sub-store https://substore.example.com/secret-path
```

`--fetch-includes` downloads every `#!include https://...` of a Surge profile, and what those include, into the cache directory, where the profile reads them. It needs `--cache-dir` and a `.conf` file. A download that fails keeps the copy already there; with no copy, startup fails.

`--sub-store` gives the base URL (secret path included) that `sub.store`, the address Sub-Store uses inside Surge, Loon and Quantumult X, stands for in subscription and rule-set URLs.

`--ui-download-url` is the ZIP the Clash API downloads into an empty `external_ui` directory when the configuration names no URL. It defaults to metacubexd; pass an empty value to download none.

## Generating keys

`sail generate` prints a key or password and exits:

```sh
sail generate uuid                              # a random UUID for VLESS, VMess or TUIC users
sail generate rand 16 --base64                  # random bytes: raw, --base64 or --hex
sail generate reality-keypair                   # PrivateKey (server) and PublicKey (clients)
sail generate wg-keypair                        # a WireGuard key pair
sail generate ss2022 2022-blake3-aes-128-gcm    # a key of the length the method takes
sail generate secret                            # a Clash API secret (clash_api.secret)
```

`ss2022` takes `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm` or `2022-blake3-chacha20-poly1305`.

## Importing share links

`sail import` reads share links (`ss://`, `trojan://`, `vless://`, `vmess://`, `hysteria2://` or `hy2://`, `tuic://`, `anytls://`) and prints them as sing-box outbounds in JSON:

```sh
sail import 'vless://...'
sail import subscription.txt
cat subscription.txt | sail import
```

The input is one link, a subscription file (base64, or one link per line), or standard input. Each line that cannot be read is reported on stderr with its line number; the command fails only if no link is read. Tags are made unique. ShadowsocksR, Hysteria v1 and WireGuard links are not imported.

## Threading

Sail uses a multi-threaded runtime by default. `--single-thread` is useful for constrained hosts, deterministic debugging or embeddings that provide their own outer concurrency. `--thread-stack-size` changes the worker stack size in bytes (default 256 KiB in release builds, 2 MiB in debug builds); keep the default unless profiling shows a concrete need.

On Unix, the CLI raises the open-file soft limit to the hard limit at startup (on macOS, no higher than `kern.maxfilesperproc`).

## Option summary

| Option | Purpose |
| --- | --- |
| `-c`, `--config` | Configuration path; default `config.json`. Format by extension: `.json`, `.yaml`/`.yml`, `.conf` |
| `--auto-reload` | Watch the configuration and reload changes |
| `--single-thread` | Use a current-thread runtime |
| `--thread-stack-size` | Worker thread stack size in bytes |
| `-T`, `--test` | Validate configuration and exit |
| `-t`, `--test-outbound` | Test one outbound tag |
| `-d`, `--test-outbound-timeout` | Outbound test timeout in seconds; default `4` |
| `--profile` | `mobile`, `desktop`, `server` or `router` |
| `--set` | Override one runtime tuning value; repeatable |
| `-D`, `--data-dir` | Assets and relative certificate base directory |
| `--cache-dir` | Where `experimental.cache_file` is by default, remote rule-sets are cached and Surge includes are kept |
| `--sub-store` | Base URL of your own Sub-Store backend, which `sub.store` stands for |
| `--ui-download-url` | ZIP the Clash API downloads into an empty `external_ui`; default metacubexd, empty for none |
| `--fetch-includes` | Download a Surge profile's remote includes into the cache directory before starting |
| `--fetch-assets` | Download the missing assets before starting |
| `--asset-source` | `name=url`: where an asset is downloaded from; repeatable |
| `assets [config]` | List the assets (of `-c` when no config is given); `--fetch`, `--update`, `--source name=url` |
| `generate <kind>` | `rand`, `uuid`, `reality-keypair`, `wg-keypair`, `ss2022`, `secret` |
| `import [input]` | Share links to sing-box outbounds JSON |
| `-V`, `--version` | Print version and exit |
| `--help` | Print usage; also after a subcommand |
