---
title: Installation
description: Prepare a Sail build environment and choose the right build target.
---

Sail is built as a Rust workspace. The same core can become a CLI executable, a native library for an app, or a platform-specific package.

:::note
There is no stable binary release yet. Build Sail from source as described below. A release pipeline for prebuilt CLI archives is being prepared.
:::

## Prerequisites

Install the following before building:

- Rust with Cargo, installed through rustup. The repository pins its toolchain in `rust-toolchain.toml`, and rustup installs that version on the first build.
- CMake.
- A C/C++ compiler such as Clang or GCC.
- libclang, which bindgen loads to generate the BoringSSL bindings (on Debian and Ubuntu, `libclang-dev`).
- Git and a standard native build environment for your platform.

BoringSSL is the only TLS and crypto library and is built from source through `btls`. A working Rust installation alone is therefore not enough.

:::note
The first build is substantially slower than later builds because native TLS code and Rust dependencies must be compiled.
:::

## Build the command-line host

```sh
git clone https://github.com/peakpassvpn/sail.git
cd sail
cargo build -p sail-cli --release
./target/release/sail --help
```

`sail-cli` is the workspace's default member, so a plain `cargo build --release` builds the same binary. BoringSSL is linked in statically; no system OpenSSL is needed. Features such as TUN still use operating-system facilities. On Windows, the TUN inbound needs Wintun's `wintun.dll` beside `sail.exe`.

## Check the workspace

For development, use Cargo's normal workspace commands:

```sh
cargo check --workspace
cargo test --workspace
```

Feature-gated protocols and formats are registered at compile time. An error saying a protocol is unknown, or that a format needs a feature which is not compiled in, can mean either that Sail does not support it or that the selected build did not include its feature. The default build includes the sing-box, Clash and Surge configuration formats.

## Cross-compiling

`scripts/install_cross_toolchain.sh <target>` installs a cross toolchain on an x86_64 Debian or Ubuntu host, and `scripts/cross.sh <target> build --release -p sail-cli` builds with it. CI builds these targets this way:

| Target | Built |
| --- | --- |
| `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, `i686-unknown-linux-musl` | CLI |
| `armv7-unknown-linux-musleabihf`, `arm-unknown-linux-musleabi` | CLI |
| `x86_64-pc-windows-gnu` | CLI (MinGW and NASM) |
| `aarch64-linux-android`, `armv7-linux-androideabi`, `x86_64-linux-android`, `i686-linux-android` | `sail-ffi` libraries (Android NDK) |

Apple frameworks are built on macOS with `scripts/build_apple_xcframework.sh`.

### Memory allocator

The CLI built for a Linux musl target allocates with [mimalloc](https://github.com/microsoft/mimalloc): the x86_64, aarch64, i686, armv7 and arm release binaries. musl's own allocator made multiplexed transfers markedly slower. In an A/B of the same build, a mux upload went from 1336 to 2248 Mbit/s with mimalloc, and across 16 sail-to-sail cells the geometric mean against sing-box went from 0.88× to 1.10×.

The router builds (`-router` archives, which OpenWrt's packages install) keep musl's own allocator, mallocng: it holds less memory, which a router has least of. On x86_64, after a 30,000-line Clash profile, the load's peak was 59 MiB against 75 with mimalloc, and after a reload 78 against 88; with 3,000 lines, 19 against 35 and 24 against 36. The cost is the mux: on x86_64 its upload was about half as fast. How it compares on a router's own CPU has not been measured. A build from source without `--no-default-features` uses mimalloc.

Only `sail-cli` sets the allocator. The `sail` and `sail-ffi` libraries leave it to the program that links them. Builds for glibc Linux, Apple platforms, Windows and Android keep the system allocator, as do MIPS musl builds: libmimalloc's C needs 64-bit atomics that 32-bit MIPS lacks. A build with the `alloc-stats` feature uses its counting allocator instead.

## Run as a systemd service

`packaging/systemd` contains a unit for Linux servers. `install.sh` installs it below an explicit root and never enables, starts or reloads anything:

```sh
packaging/systemd/install.sh --root / --allow-system-root \
  --check-binary ./target/release/sail --service-binary /usr/bin/sail
```

It checks the configuration with `--test` first, then installs:

| File | Content |
| --- | --- |
| `/etc/systemd/system/sail.service` | The unit, with `--service-binary` (default `/usr/bin/sail`) |
| `/etc/sail/config.json` | The initial configuration (`--config`, default `config.example.json`); kept if present |
| `/etc/sail/sail.env` | `SAIL_CONFIG`, `SAIL_DATA_DIR=/etc/sail`, `SAIL_CACHE_DIR=/var/cache/sail`, `SAIL_PROFILE=server`; kept if present |

The unit runs as user and group `sail`, which must exist; `install.sh` does not create them. It has no capabilities and a restricted filesystem. `--mode tun` adds a drop-in that grants `CAP_NET_ADMIN`, `CAP_NET_RAW` and `/dev/net/tun`, for configurations with a TUN inbound or transparent proxy sockets. `systemctl reload sail` validates the configuration and then sends SIGHUP, which reloads it; a configuration that fails to load leaves the previous one running. On stop, SIGTERM lets open connections drain for up to 30 seconds with the `server` profile. `uninstall.sh --root DIR` removes only unchanged files `install.sh` recorded and never the configuration. Use `--dry-run` with either script to preview.

## Choose a host

| Target | Entry point | Typical use |
| --- | --- | --- |
| CLI | `sail-cli` | Servers, routers, desktop testing |
| Rust library | `sail` | A Rust host controlling the core directly |
| C-compatible library | `sail-ffi` | iOS, Android and other native hosts |
| User-space stack | `sail-netstack` | TUN data plane shared by supported platforms |

For an application integration, continue with [Platform integration](/sail/platform-integration/). To run the binary immediately, continue with [Getting started](/sail/getting-started/).
