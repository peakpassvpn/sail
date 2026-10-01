---
title: 架构
description: Sail 如何分离配置、路由、端点工厂、传输层与用户态网络栈。
---

Sail 围绕可复用核心组织，而不是一个只面向客户端的程序。客户端、服务端和中继共享同一套配置模型、路由器、协议与传输层，变化的只是宿主和启用的端点。

## 请求路径

```text
宿主 / 操作系统
      ↓
入站监听 → 会话元数据 → 路由器 → 出站处理器
                                  ↓
                          传输层与 TLS
                                  ↓
                              网络套接字
```

入站创建会话，其中包含来源、目标、网络类型、入站标签以及已认证的用户。可选的嗅探或 DNS 解析会补充会话信息。路由器选出出站标签，出站管理器再调用已经构建好的处理器图。

## Workspace

| Crate | 职责 |
| --- | --- |
| `sail` | 核心运行时、协议、传输层、DNS、路由与平台集成 |
| `sail-cli` | 命令行宿主与运行时参数解析；构建 `sail` 可执行文件 |
| `sail-ffi` | C ABI（`libsail`、`sail.h`）：实例、控制、事件、命令服务与平台回调 |
| `sail-netstack` | 用安全 Rust 编写、内存有上限的用户态 TCP/IP 协议栈 |
| `sail-plugins/shadowsocks` | 出站插件示例，为 `plugin` feature 构建成动态库 |

协议与传输模块都留在 `sail` 内，以便共用会话、适配器和网络抽象。`bindings/swift` 与 `bindings/kotlin` 为应用封装 C ABI，见[平台集成](/sail/zh/platform-integration/)。

## 核心模块

| 模块 | 内容 |
| --- | --- |
| `config` | 配置模型，以及 sing-box JSON、Clash YAML、Surge 配置和分享链接的读取 |
| `adapter` | 处理器 trait，以及入站、出站工厂的注册表 |
| `app` | 实例本身：入站与出站管理器、分发器、路由器、DNS、provider、健康检查、统计、Clash API 与管理 API |
| `protocol` | 入站、出站、策略组与端点，各占一个目录 |
| `transport` | TLS、REALITY、WebSocket、HTTP Upgrade、gRPC、QUIC、多路复用与 UDP over TCP |
| `net` | 拨号、网络状态及其变化、NAT64，以及驱动 `sail-netstack` 的运行时 |
| `platform` | 操作系统集成：路由、接口、网络检测、wintun、nftables |
| `control` | 控制和观察实例的统一入口；Clash API、FFI 与命令服务都经由它 |
| `runtime` | 运行时配置档与参数、启动设置、缓存文件 |
| `user` | 入站认证的用户，及其流量与限额 |
| `sniff`、`session` | 协议嗅探，以及连接携带的会话 |

## 配置流水线

sing-box 的 JSON 是 Sail 自己的格式，直接映射到 `config::model`。Clash/Mihomo YAML 与 Surge 配置按原样读取，再转换到同一模型。文件按扩展名选择读取方式（`.json`；`.yaml` 或 `.yml`；`.conf`），宿主传入的配置文本按内容识别格式。

```text
sing-box JSON / Clash YAML / Surge 配置 → 模型 → 结构验证
                                               → 端点依赖图
                                               → 处理器与监听器
```

sing-box 接受而 Sail 未实现的字段：若忽略它会让流量的路由或安全性与配置所写不同，则报错；否则给出警告。sing-box 也不认识的字段是错误。

模型负责标签、DNS、路由和可复用端点模块等共享概念。每个协议拥有自己的选项结构，并在构建工厂时拒绝未知字段。

## 端点注册表

入站与出站协议按名称注册工厂。注册表带来三点好处：

- 由 feature 决定构建中包含哪些协议。
- 新增协议无需在管理器中修改集中的 switch 语句。
- 工厂在构建前声明依赖和支持的共享模块。

Selector、URLTest、Fallback、负载均衡和 MPTP 等复合出站依赖其他出站标签。Sail 对依赖图排序，在开始处理流量前报告缺失引用或循环依赖。

## 传输层组合

TLS、REALITY、WebSocket、HTTP Upgrade、gRPC、QUIC、多路复用、拨号选项和 detour 都是围绕端点协议的模块。内部它们组成处理器链；配置中它们与 sing-box 一样嵌套在使用它们的出站上。detour 不是一层：它是出站的拨号器，通过指定的出站而不是套接字拨号。

对流式代理，概念顺序如下：

```text
代理协议 → 复用/传输层 → TLS 或 REALITY → detour/拨号器 → 套接字
```

有些协议以不同方式管理连接。AnyTLS 在多个逻辑流之间保持会话，Hysteria2 与 TUIC 直接运行在 QUIC 上，因此它们的工厂接受的模块不同。

## 路由器

路由器接收归一化的会话元数据，按顺序检查规则。终止动作（`route`、`reject`、`hijack-dns`、`bypass`）结束匹配。非终止动作（`route-options`、`sniff`、`resolve`）设置连接选项、嗅探应用层元数据或解析域名，然后继续匹配后续规则。

路由器只认识出站标签。成员选择、健康检查和多路径调度都留在各自的出站处理器内，使策略与传输行为分离。

## TUN 与用户态网络

TUN 入站把 IP 包送入 `sail-netstack`。协议栈负责 TCP 状态、UDP 投递、分片与重组、内存预算和调度。被接受的流重新进入与套接字入站相同的会话和路由流程。WireGuard 端点在其隧道上运行同一个协议栈。

这样各平台共用一套数据面实现，同时由宿主掌控 TUN 设备、路由安装和出站套接字保护。在桌面端与服务端由 Sail 自己安装路由；通过 FFI 打开 TUN 的宿主自行配置路由。

## 运行时与资源

运行时配置档为 mobile、desktop、server、router 宿主选择一致的初始预算。它们调整转发缓冲、UDP、netstack、入站、QUIC、WebSocket、DNS、统计、多路复用和关闭行为，不改变可移植的代理配置。

健康检查、选择器、会话和监听器等长期资源属于实例，在重载或关闭时通过显式句柄释放。选择器的选择、Clash 模式与 fake IP 只有在启用 `experimental.cache_file` 时才会持久化，文件位于 `cache_dir`（未设置时为数据目录），与配置分开。

网络变化导致原有连接无法延续时，实例会清空 DNS 缓存、关闭连接并重置 TUN 的流；见[网络变化时](/sail/zh/platform-integration/)。

## 设计边界

- 协议解析自己的字段并构建适配器处理器。
- 传输层不决定路由策略。
- 路由器不了解具体协议实现。
- 平台适配器提供能力，但不拥有代理语义。
- 配置描述行为，运行时设置描述资源预算。

正是这些边界，让同一核心可以服务本地客户端、公网服务端或中间中继。
