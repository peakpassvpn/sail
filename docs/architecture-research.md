# 平台架构调研：以 sing-box 为参照

- 状态：D1–D5 已于 2026-09-25 决定，全部采用第 5 节的建议；P0.2 在 `dev` 上的 `restructure-modules` 分支进行
- 定位：统一代理平台，客户端（iOS / Android / 桌面）、服务端和路由器共用同一个内核
- 参照：sing-box `v1.15.0-alpha.8`（`b609f95`，2026-09-24）
- 上游 leaf 基线：`5e8d947`

目标：做到 sing-box 的能力范围时，不需要推翻核心结构；新增协议、传输层、规则条件、服务或宿主时，只新增代码，不改核心文件。

---

## 1. sing-box 的结构

```
sing-box
├── adapter/        所有扩展点的接口；每类扩展点一套 adapter / manager / registry
│   ├── inbound/  outbound/  endpoint/  service/  certificate/
│   └── inbound.go outbound.go router.go dns.go lifecycle.go platform.go ssm.go ...
├── protocol/       每个协议一个目录，入站和出站放在一起（vless/inbound.go、vless/outbound.go）
│   └── group/      selector、urltest 也是普通出站
├── transport/      v2ray 传输层（ws / grpc / httpupgrade / http / quic）、simple-obfs、sip003、wireguard
├── common/         dialer、listener、tls、mux、sniff、uot、urltest、process ...
├── route/          路由器 + rule/（每种规则条件一个文件）+ 规则动作 + rule-set
├── dns/            DNS 路由器 + transport/（按 registry 注册的上游类型）
├── service/        非代理类服务：ssm-api、resolved、derp、acme、api ...
├── experimental/   clashapi、v2rayapi、cachefile、libbox（移动端绑定）
├── option/         每个协议一个 options 文件，强类型
├── include/        所有注册代码 + build tag，决定哪些能力编进二进制
├── box.go          组装：建 manager → 注册到 context → 按 options 创建组件 → 分阶段启动
└── daemon/ clients/  宿主侧：gRPC 守护进程、Apple / Android 客户端
```

协议本身的编解码不在 sing-box 仓库，而在独立的库里（sing-shadowsocks、sing-vmess、sing-quic、sing-tun、sing-mux）。`protocol/` 里只有把这些库接入平台的适配代码。

### 带来灵活性的 8 个设计

| # | 设计 | 具体做法 | 效果 |
| --- | --- | --- | --- |
| 1 | 注册表 + 强类型 options | `inbound.Register[option.VLESSInboundOptions](registry, "vless", NewInbound)`；配置解析时按 `type` 字段从注册表取 options 类型 | 新增协议 = 新目录 + options 文件 + `include/` 一行，没有中心化的 `match` |
| 2 | 统一的连接元数据 | `InboundContext` 包含入站、用户、协议、嗅探结果、DNS 结果、路由选项等 | 路由、统计、限速都只依赖这一个结构 |
| 3 | 出站就是 Dialer | `Outbound` 接口只有 `DialContext` / `ListenPacket`；`detour` 是共享拨号选项的一个字段 | 任何出站都能作为另一个出站的底层连接 |
| 4 | 共享的拨号和监听选项 | `DialerOptions`（detour、绑定接口、TFO、MPTCP、keepalive、netns ...）和 `ListenOptions` 嵌入到每个协议的 options | 各协议不重复实现 socket 逻辑 |
| 5 | TLS / 传输层 / 多路复用是协议的字段 | `VLESSOutboundOptions` 内嵌 `TLS`、`Transport`、`Multiplex`，由 `common/tls`、`transport/`、`common/mux` 统一实现 | 一个传输层写一次，所有协议都能用 |
| 6 | 路由是动作流水线 | 规则动作：route、reject、hijack-dns、sniff、resolve、route-options | 嗅探、解析、劫持都由规则控制，不写死在 dispatcher 里 |
| 7 | 生命周期与依赖 | `Start(stage)` 分 Initialize / Start / PostStart / Started 四个阶段；出站声明 `Dependencies()`，manager 按依赖顺序启动并检测环路 | 组件之间的依赖是显式的 |
| 8 | 运行时增删 | 各 manager 提供 `Create` / `Remove`；多用户入站实现 `ManagedSSMServer.UpdateUsers`，由 ssm-api 服务在不重启的情况下增删用户、统计流量 | 服务端可以在线管理用户；整份配置重载则由 daemon 重建实例 |

宿主和平台的隔离：`PlatformInterface`（接口监控、TUN fd、进程查找等）由宿主注入；移动端绑定在 `experimental/libbox`，守护进程在 `daemon/`，都不在核心路径上。

---

## 2. Sail 现状对照

| 维度 | sing-box | Sail 现状 | 影响 |
| --- | --- | --- | --- |
| 扩展方式 | 注册表 | 中心化匹配：新增一个出站要改 `config.proto`、生成的 `config.rs`、`config/common.rs`、`json`、`conf`、`app/outbound/manager.rs`（67 处 `#[cfg(feature)]`） | 协议越多，这几个文件越难维护，合并冲突越多 |
| 协议方向 | 大多数协议同时有入站和出站 | VLESS、VMess、Reality 只有出站 | 无法作为这些协议的服务端 |
| 用户 | `InboundContext.User`、`auth_user` 规则、ssm-api | 没有用户概念；SS 入站只能配一个密码，trojan 的多个密码不对应身份 | 无法按用户路由、统计、限速 |
| 连接元数据 | 统一的 `InboundContext` | `Session` 基本够用，但混入了协议私有状态（`Session.vision` 属于 VLESS） | 核心结构被具体协议污染 |
| 组合方式 | 出站即 Dialer + detour；TLS / 传输层是协议字段 | chain actor：任意 handler 叠加（`AnyStream → AnyStream`），由 `plan.rs` 统一规划 | Sail 的机制更通用，是优势；但配置不直观，与主流订阅格式对不上 |
| 拨号 / 监听 | `common/dialer`、`common/listener`，选项按出站配置 | 放在 `proxy/mod.rs`，绑定接口等参数来自全局环境变量 | 不能按出站设置，也不能按实例设置 |
| 路由 | 动作流水线，每种条件一个文件，rule-set 可远程更新 | 规则只返回 tag，线性扫描；嗅探写死在 dispatcher 里 | 加 sniff / resolve / hijack-dns 等动作都要改 dispatcher |
| 生命周期 | 分阶段启动，声明依赖，manager 可 Create / Remove | `start()` 一次性组装；重载只替换 router、dns、outbounds，入站不能动 | 服务端改端口或用户需要重启 |
| 服务 | `service/` 注册表（API、用户管理、证书 ...） | 只有 Clash 风格的 API | 管理面没有扩展点 |
| 宿主隔离 | `PlatformInterface` 注入；libbox / daemon 在核心之外 | `start()` 里直接做 TUN 路由设置、改写环境变量；`mobile/` 在核心库里 | 核心和某一种宿主绑定 |
| 配置 | 单一 JSON，每个协议的 options 是强类型 | 两种外部格式（json / conf）→ 中间模型 → protobuf 内部模型 | 每个字段要在 3–4 层模型里重复定义 |

Sail 应该保留的优势：

- chain 通用叠加 + `plan.rs` 在 I/O 之前做规划。
- 按 feature 裁剪。
- Rust 在资源占用上的可控性。

---

## 3. 目标架构（Rust 版）

### 3.1 分层

```
宿主层      sail-cli（服务端 / 桌面守护进程）  sail-ffi（iOS / Android）  路由器打包
             │  通过 Platform trait 注入平台能力，通过管理 API 控制实例
运行时层    runtime：组装、分阶段启动、按组件重载、多实例
             │
平台层      route / dns / stats / user / service / sniff
             │  只依赖 adapter 里的 trait 和 Session
扩展层      protocol/<name>（入站 + 出站）  transport/（tls、reality、ws、grpc、quic、mux ...）
             │
基础层      adapter（trait + registry + lifecycle）  session  net（dialer、listener、relay、缓冲池）
```

依赖只能自上而下。`protocol/` 之间不互相引用，只通过 `transport/` 和 `net/` 复用代码。

### 3.2 目录（先在 `sail` crate 内划清模块边界，稳定后再按需拆 crate）

```
sail/src
├── lib.rs
├── adapter/        Inbound / Outbound / Dialer / Service / DnsTransport trait，Registry，Lifecycle，Context
├── session/        Session（连接元数据：入站、用户、嗅探、路由选项）；协议私有状态改为扩展字段
├── runtime/        实例组装、分阶段启动、按组件重载、多实例管理（取代 lib.rs 里的 RuntimeManager）
├── net/            dialer、listener、socket 选项、Android protect、双向转发、缓冲池
├── route/          router、rule/（每种条件一个文件）、rule_set/、action
├── dns/            router、transport/（udp、tcp、doh、dot、fakeip、hosts ...）、cache
├── sniff/          tls、http、quic、dns
├── transport/      tls、reality、ws、grpc、httpupgrade、quic、mux（amux / smux ...）、obfs
├── protocol/       每个协议一个目录，入站和出站在一起
│   ├── shadowsocks/ trojan/ vmess/ vless/ socks/ http/ direct/ block/ redirect/ tun/ mptp/ ...
│   └── group/      select、urltest、failover、tryall、static、chain
├── user/           用户、鉴权、按用户统计与限速
├── stats/          连接与流量统计
├── service/        管理 API、Clash API、用户管理 ...
├── config/         统一配置模型 model.rs；输入格式 conf/（兼容 Surge）、clash/（兼容 Clash / Mihomo）；分享链接导入
├── platform/       Platform trait；各 OS 的路由和接口实现
└── include.rs      所有注册代码 + #[cfg(feature)]，决定编进哪些能力
```

`mobile/` 移到 `sail-ffi`；`sys.rs`、`winsys.rs`、`common/cmd_*.rs` 归入 `platform/`。

### 3.3 Rust 下的关键做法

- **注册表：显式注册，不用 `inventory` / `linkme` 这类分布式注册。**
  - 所有注册写在 `include.rs`，按 feature 开关。
  - 分布式注册依赖链接器保留构造函数；iOS 静态库和 LTO 可能把它们裁掉，出问题很难排查。
- **options：每个协议一个 serde 结构体，按 `type` 分发。**
  - 共享的 `DialOptions`、`ListenOptions`、`TlsOptions`、`TransportOptions`、`MuxOptions` 用 `#[serde(flatten)]` 嵌入。
- **组合：保留 chain 作为内部执行机制，对外提供 sing-box 式的配置字段。**
  - 对外字段是「协议 + tls + transport + multiplex + detour」，构建时编译成 chain。
  - 用户写的配置和主流订阅对齐，内部保留任意叠加的能力。
- **Context：用带类型字段的结构体持有各 manager，不用 type-map。**
  - 需要热替换的状态（路由表、出站表）用 `ArcSwap` 快照，数据路径上不加锁。
- **生命周期：`Lifecycle` trait 分阶段启动。**
  - 出站声明依赖，manager 按依赖顺序启动并检测环路。
  - 入站和出站 manager 提供 `create` / `remove`，重载只替换变化的组件。

---

## 4. 迁移路径

每一步单独合并，功能不回退，现有测试和 `bench/core-compare` 性能基线保持不变。

| 步骤 | 内容 | 前置条件 |
| --- | --- | --- |
| M1 | 建 `adapter/`（trait、registry、Context）和 `include.rs`；把现有协议逐个移到 `protocol/<name>/` 并改为注册表创建；删除 manager 里的中心化匹配 | P0.1 缓冲池合并 |
| M2 | 建 `net/`：统一拨号和监听，拨号选项按出站配置；`option/` 全局变量收敛成 `RuntimeOptions` | M1 |
| M3 | 建 `route/`：规则按条件拆分并编译为索引，引入规则动作；`sniff/` 从 dispatcher 里移出，改由动作驱动 | M1 |
| M4 | 建 `runtime/`：分阶段启动，入站和出站支持按组件增删；路由和出站表改为 `ArcSwap` 快照 | M1、M2 |
| M5 | 建 `platform/`：定义 Platform trait，宿主相关逻辑移出 `start()`；`mobile/` 移到 `sail-ffi` | M4 |
| M6 | 建 `user/`、`service/`：用户身份、按用户统计与限速、管理 API | M3、M4 |

补齐入站方向（VLESS、VMess、Reality 服务端）以及后续新增的协议，都在 M1 之后按新结构来做。

---

## 5. 待决策

| # | 问题 | 选项 | 建议 |
| --- | --- | --- | --- |
| D1 | 内部配置模型 | A. 保留 protobuf 内部模型；B. 改为每个协议一个 serde options，作为唯一配置契约 | **B**。registry 模式要求每个协议自己拥有 options 类型，protobuf 会让每个字段继续在多层模型里重复定义；FFI 直接传 JSON |
| D2 | 配置格式 | A. 只有 JSON，`.conf` 降为导入器；B. 内部只有一个配置模型，多种输入格式都转换成它 | **已定：B**。JSON 为原生格式，字段对齐 sing-box；`.conf` 保留为正式输入格式，目标是兼容 Surge 语法；Clash YAML 也作为正式输入格式 |
| D3 | 组合模型 | A. 完全改成 sing-box 的 detour 模式；B. 保留 chain 作为内部机制，对外提供 sing-box 式字段 | **已定：B**。用户配置里没有 chain 类型，也没有独立的 tls、ws、reality、amux、obfs 出站：它们变成协议上的 `tls` / `transport` / `multiplex` 块和 shadowsocks 的 `plugin`，代理串联用 `dial.detour`；mptp 保留为类型 |
| D4 | 拆 crate 的时机 | A. 一开始就拆成多个 crate；B. 先在单 crate 内划清模块边界，稳定后再拆 | **B**。优先考虑拆出的是 `net`、协议实现、`tun` / netstack，它们编译最重，也最适合单独测试和 fuzz |
| D5 | 与上游的关系 | A. 继续定期合并 upstream；B. 上游仅作参考，按需人工移植修复 | **B**。M1 之后文件位置全部改变，定期合并已经不现实 |
