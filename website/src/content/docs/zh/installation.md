---
title: 安装
description: 准备 Sail 构建环境，并选择 CLI、Rust 库或原生集成目标。
---

Sail 是一个 Rust workspace。同一套核心既可以构建为命令行程序，也可以作为 Rust 库、C 兼容库或平台包嵌入应用。

:::note
目前还没有稳定的二进制发布版，请按下文从源码构建。预编译 CLI 包的发布流程正在准备中。
:::

## 前置依赖

- 通过 rustup 安装的 Rust 与 Cargo。仓库在 `rust-toolchain.toml` 中固定了工具链版本，首次构建时 rustup 会自动安装。
- CMake
- Clang 或 GCC 等 C/C++ 编译器
- libclang：bindgen 用它生成 BoringSSL 绑定（Debian、Ubuntu 上为 `libclang-dev`）
- Git 与对应平台的原生构建环境

BoringSSL 是唯一的 TLS 与密码学库，通过 `btls` 从源码构建，因此只安装 Rust 还不够。首次构建需要编译原生 TLS 代码和 Rust 依赖，通常比后续构建更慢。

## 构建命令行程序

```sh
git clone https://github.com/peakpassvpn/sail.git
cd sail
cargo build -p sail-cli --release
./target/release/sail --help
```

`sail-cli` 是 workspace 的默认成员，直接 `cargo build --release` 也会构建同一个程序。BoringSSL 静态链接进二进制，无需系统 OpenSSL。TUN 等功能仍依赖操作系统能力；在 Windows 上，TUN 入站需要把 Wintun 的 `wintun.dll` 放在 `sail.exe` 旁边。

## 检查 workspace

```sh
cargo check --workspace
cargo test --workspace
```

协议与配置格式通过 feature 在编译时注册。“未知协议”或“某格式需要未编译的 feature”这类错误，既可能表示 Sail 尚未实现，也可能表示当前构建没有启用对应 feature。默认构建包含 sing-box、Clash 和 Surge 三种配置格式。

## 交叉编译

在 x86_64 的 Debian 或 Ubuntu 主机上，`scripts/install_cross_toolchain.sh <target>` 安装交叉工具链，`scripts/cross.sh <target> build --release -p sail-cli` 用它构建。CI 以这种方式构建以下目标：

| 目标 | 构建内容 |
| --- | --- |
| `x86_64-unknown-linux-musl`、`aarch64-unknown-linux-musl`、`i686-unknown-linux-musl` | CLI |
| `armv7-unknown-linux-musleabihf`、`arm-unknown-linux-musleabi` | CLI |
| `x86_64-pc-windows-gnu` | CLI（MinGW 与 NASM） |
| `aarch64-linux-android`、`armv7-linux-androideabi`、`x86_64-linux-android`、`i686-linux-android` | `sail-ffi` 库（Android NDK） |

Apple 平台的 framework 在 macOS 上用 `scripts/build_apple_xcframework.sh` 构建。

## 作为 systemd 服务运行

`packaging/systemd` 提供面向 Linux 服务器的 unit。`install.sh` 把文件安装到明确指定的根目录下，不会启用、启动或重载任何服务：

```sh
packaging/systemd/install.sh --root / --allow-system-root \
  --check-binary ./target/release/sail --service-binary /usr/bin/sail
```

它先用 `--test` 检查配置，然后安装：

| 文件 | 内容 |
| --- | --- |
| `/etc/systemd/system/sail.service` | unit 文件，使用 `--service-binary`（默认 `/usr/bin/sail`） |
| `/etc/sail/config.json` | 初始配置（`--config`，默认 `config.example.json`）；已存在则保留 |
| `/etc/sail/sail.env` | `SAIL_CONFIG`、`SAIL_DATA_DIR=/etc/sail`、`SAIL_CACHE_DIR=/var/cache/sail`、`SAIL_PROFILE=server`；已存在则保留 |

unit 以 `sail` 用户和组运行，需事先创建，`install.sh` 不会创建。它不带任何 capability，文件系统访问受限。`--mode tun` 额外安装一个 drop-in，授予 `CAP_NET_ADMIN`、`CAP_NET_RAW` 和 `/dev/net/tun`，供带 TUN 入站或透明代理 socket 的配置使用。`systemctl reload sail` 先验证配置，再发送 SIGHUP 重载；新配置加载失败时继续运行旧配置。停止时，SIGTERM 让已有连接收尾，`server` 配置档下最多 30 秒。`uninstall.sh --root DIR` 只删除 `install.sh` 记录且未改动的文件，从不删除配置。两个脚本都可加 `--dry-run` 预览。

## 选择宿主形态

| 目标 | 入口 | 常见用途 |
| --- | --- | --- |
| CLI | `sail-cli` | 服务器、路由器与桌面调试 |
| Rust 库 | `sail` | Rust 应用直接控制核心 |
| C 兼容库 | `sail-ffi` | iOS、Android 与其他原生宿主 |
| 用户态网络栈 | `sail-netstack` | 支持平台上的 TUN 数据面 |

应用集成请继续阅读[平台集成](/sail/zh/platform-integration/)，直接运行请前往[入门指南](/sail/zh/getting-started/)。
