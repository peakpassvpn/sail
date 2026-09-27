---
title: 入门指南
description: 构建 Sail、启动本地 SOCKS5 代理并验证第一条连接。
---

Sail 是面向客户端、服务端和中继的可复用 Rust 代理核心。本指南会构建命令行程序，启动一个本地 SOCKS5 监听，并通过直连出站发送流量。

## 运行结构

```mermaid
flowchart LR
    A["应用<br/><small>浏览器或客户端</small>"] --> B["SOCKS5<br/><small>127.0.0.1:1080</small>"]
    B --> C["Sail 路由器"]
    C --> D["direct 出站"]

    classDef client fill:#eaf2ff,stroke:#075cff,color:#082b68,stroke-width:2px
    classDef proxy fill:#13223c,stroke:#4f8cff,color:#ffffff,stroke-width:2px
    classDef core fill:#075cff,stroke:#85aeff,color:#ffffff,stroke-width:3px
    classDef direct fill:#fff2ee,stroke:#ff6759,color:#5a1a14,stroke-width:2px
    class A client
    class B proxy
    class C core
    class D direct
    linkStyle 0,1 stroke:#075cff,stroke-width:3px
    linkStyle 2 stroke:#ff6759,stroke-width:3px
```

你需要 Rust、Cargo、CMake 和 C/C++ 编译器。BoringSSL 会随项目从源码构建。平台相关说明见[安装](/sail/zh/installation/)。

## 1. 构建 CLI

```sh
cargo build -p sail-cli --release
./target/release/sail -V
```

生成的可执行文件位于 `target/release/sail`。

## 2. 创建配置

将以下内容保存为 `config.json`：

```json
{
  "log": { "level": "info", "format": "compact" },
  "inbounds": [
    {
      "type": "socks",
      "tag": "local-socks",
      "listen": "127.0.0.1",
      "listen_port": 1080
    }
  ],
  "outbounds": [{ "type": "direct", "tag": "direct" }],
  "route": { "final": "direct" }
}
```

入站接收 SOCKS5 TCP 和 UDP 流量；未命中规则的连接都会交给 `direct` 出站。

## 3. 启动前验证

```sh
./target/release/sail -c config.json -T
```

解析和引用均有效时，Sail 输出 `ok` 后退出。未知字段、缺失的出站标签和无效规则会在启动前被发现。

## 4. 运行并验证

```sh
./target/release/sail -c config.json
```

在另一个终端中测试：

```sh
curl --socks5-hostname 127.0.0.1:1080 https://example.com
```

`--socks5-hostname` 会把域名交给 Sail 解析，使域名路由规则拥有完整信息。配置调试时可加 `--auto-reload` 自动重载。

## 下一步

- [配置模型](/sail/zh/configuration/)：顶层结构、默认值和兼容范围。
- [路由规则](/sail/zh/routing/)：域名、IP、端口、入站和进程匹配。
- [协议与兼容性](/sail/zh/protocols/)：入站、出站、传输层及主流配置生态。
- [CLI 参考](/sail/zh/cli/)：验证、连通性测试与运行时配置。
