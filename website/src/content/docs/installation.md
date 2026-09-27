---
title: Installation
description: Prepare a Sail build environment and choose the right build target.
---

Sail is built as a Rust workspace. The same core can become a CLI executable, a native library for an app, or a platform-specific package.

## Prerequisites

Install the following before building:

- A recent stable Rust toolchain with Cargo.
- CMake.
- A C/C++ compiler such as Clang or GCC.
- Git and a standard native build environment for your platform.

BoringSSL is the only TLS backend and is built from source. A working Rust installation alone is therefore not enough.

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

The release binary is self-contained apart from operating-system facilities used by features such as TUN.

## Check the workspace

For development, use Cargo's normal workspace commands:

```sh
cargo check --workspace
cargo test --workspace
```

Feature-gated protocols are registered at compile time. An error saying a protocol is unknown can mean either that Sail does not support it or that the selected build did not include its feature.

## Choose a host

| Target | Entry point | Typical use |
| --- | --- | --- |
| CLI | `sail-cli` | Servers, routers, desktop testing |
| Rust library | `sail` | A Rust host controlling the core directly |
| C-compatible library | `sail-ffi` | iOS, Android and other native hosts |
| User-space stack | `sail-netstack` | TUN data plane shared by supported platforms |

For an application integration, continue with [Platform integration](/sail/platform-integration/). To run the binary immediately, continue with [Getting started](/sail/getting-started/).
