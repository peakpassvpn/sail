---
title: 安装
description: 准备 Sail 构建环境，并选择 CLI、Rust 库或原生集成目标。
---

Sail 是一个 Rust workspace。同一套核心既可以构建为命令行程序，也可以作为 Rust 库、C 兼容库或平台包嵌入应用。

## 前置依赖

- 最新稳定版 Rust 与 Cargo
- CMake
- Clang 或 GCC 等 C/C++ 编译器
- Git 与对应平台的原生构建环境

BoringSSL 是当前 TLS 后端，并从源码构建，因此只安装 Rust 还不够。首次构建需要编译原生 TLS 代码和 Rust 依赖，通常比后续构建更慢。

## 构建命令行程序

```sh
git clone https://github.com/peakpassvpn/sail.git
cd sail
cargo build -p sail-cli --release
./target/release/sail --help
```

除了 TUN 等功能需要的操作系统能力外，release 二进制文件可独立运行。

## 检查 workspace

```sh
cargo check --workspace
cargo test --workspace
```

协议通过 feature 在编译时注册。“未知协议”既可能表示 Sail 尚未实现该协议，也可能表示当前构建没有启用对应 feature。

## 选择宿主形态

| 目标 | 入口 | 常见用途 |
| --- | --- | --- |
| CLI | `sail-cli` | 服务器、路由器与桌面调试 |
| Rust 库 | `sail` | Rust 应用直接控制核心 |
| C 兼容库 | `sail-ffi` | iOS、Android 与其他原生宿主 |
| 用户态网络栈 | `sail-netstack` | 支持平台上的 TUN 数据面 |

应用集成请继续阅读[平台集成](/sail/zh/platform-integration/)，直接运行请前往[入门指南](/sail/zh/getting-started/)。
