# Sail 迭代计划

- 基线：eycorsican/leaf `5e8d947`（2026-09-10）
- 定位：**统一代理平台**。客户端（iOS / Android / 桌面）、服务端和路由器共用同一个内核，由不同宿主接入
- 对标：sing-box（平台能力与扩展性）、Mihomo（客户端生态）
- 配置：运行时直接读取 sing-box JSON、Clash / Mihomo YAML、Surge 配置，用户不需要转换（见「PC 配置兼容」）
- 架构调研与目标结构：[`architecture-research.md`](architecture-research.md)

## 原则

- **核心不绑定宿主**：内核只依赖抽象的平台能力（接口监控、TUN fd、socket protect、进程查找），由移动端 FFI、服务端守护进程、路由器打包各自注入；启动流程里不写任何宿主专属逻辑。
- **一套核心，多种资源预算**：移动端关注 footprint 和生命周期，路由器关注低内存，桌面端和服务端关注吞吐、并发与多核扩展；预算通过配置选择，不为不同平台维护分叉实现。
- **扩展只加不改**：新增协议、传输层、规则条件、DNS 上游或服务时，只新增模块并在注册表登记，不修改核心文件。
- **协议对称**：主流协议同时提供入站和出站，Sail 自身可以作为这些协议的服务端。
- **性能与功能同时验收**：新协议和新传输层不仅验证连通性，还要验证吞吐、CPU、并发内存和长稳表现。
- **三种配置格式，一个运行时模型**：sing-box JSON、Clash / Mihomo YAML、Surge 配置都是一等输入，运行时直接读取、可热重载；sing-box JSON 就是原生格式，不再另设 sail JSON。每种格式由一个前端按上游 schema 强类型解析，再降级到同一个内部模型，路由、出站和重载只实现一套。分享链接仍然只是导入器。破坏性变更一次性迁移，能力差异通过 capability 查询显式暴露。
- **按真实需求排优先级**：客户端协议以脱敏订阅样本统计排序，服务端能力以实际部署需求排序，不机械复制 sing-box / Mihomo 的全部功能。

## 总览

| 阶段 | 主题 | 目标 | 预估 |
| --- | --- | --- | --- |
| P0 | 性能基线与平台架构 | 消除转发缓冲区瓶颈；建立注册表、分层和生命周期，让后续扩展只加不改 | 缓冲池 1–2 周；架构重构 6–10 周 |
| P1 | 协议与传输 | 主流协议入站、出站双向可用，与 Xray / sing-box 互通 | 8–12 周 |
| P2 | DNS、路由与网络 | DNS 不污染、规则准确、IPv4 / IPv6 和网络切换可靠 | 6–10 周 |
| PC | 配置兼容 | 运行时直接读取 sing-box、Clash / Mihomo、Surge 的真实配置 | 8–12 周（依赖 P2 的 DNS 与规则集） |
| P3 | 服务端与多用户 | 多用户、按用户统计与限速、在线增删用户和入站、管理 API | 4–6 周 |
| P4 | 宿主集成与生态 | 移动端 FFI、服务端守护进程、路由器打包、Clash 面板生态 | 4–6 周 |
| P5 | 工程质量与发布 | 异常输入不崩溃，有跨平台测试、性能回归和可重复发布 | 持续进行 |

预估按 1 名熟悉 Rust 的开发者计算，仅供排期参考；协议实现之外的真机适配、互操作和长稳测试必须单独留出时间。

P1 及之后各表的「涉及位置」按 P0.2 完成后的目标结构书写（`protocol/`、`transport/`、`route/`、`dns/`、`net/`、`runtime/`、`platform/` 等），详见架构调研第 3 节。

---

## P0 性能基线与平台架构

### 结论：继续基于 leaf 代码迭代

Sail 与 sing-box 的对比已经完成。当前结果表明：

- 相同量级的缓冲区下，Sail 的单位数据 CPU 成本与 sing-box 持平或更低，Rust 的计算效率优势成立。
- Sail 默认 2KB 转发缓冲区，以较高 CPU 和较低吞吐换取并发内存。
- 将 Sail 缓冲区增大到 16KB / 32KB 后，吞吐明显提高，但每条连接两个方向的缓冲区会常驻到连接结束，高并发内存显著超过 sing-box。
- 空闲 footprint 差距很小；“Go 天然占用更多内存”不能作为选择 Sail 的主要依据。

因此继续使用 Sail，但必须先修复 `sail/src/common/io.rs` 中转发缓冲区的生命周期，让 Rust 的资源可控优势真正落到数据通路上。

现有数据来自 macOS 回环测试、只跑 1 轮，且没有经过真机 TUN。它足以支持技术选型，但不能替代后续跨环境性能验收。

### P0.1 转发缓冲池（进行中）

| 任务 | 设计要求 | 验收标准 |
| --- | --- | --- |
| 按需借用转发缓冲区 | `CopyBuffer` 只在实际读写时借用缓冲区，等待期间不为每个方向长期持有完整内存 | 2000 条空闲连接不再按“连接数 × 方向数 × 缓冲区大小”线性占用完整缓冲区 |
| 归还与复用 | EOF、超时、取消和错误路径都必须归还；限制池的总容量，避免流量峰值后内存不回落 | 压测结束后 footprint / RSS 能回落；无重复归还、泄漏或跨连接数据残留 |
| 环境资源预算 | 同一实现支持移动端/路由器的低内存预算，以及桌面端/服务端的高吞吐预算；预算通过配置或启动参数选择 | 不维护平台分叉；默认值有文档，非法配置会被拒绝 |
| 多线程扩展 | 避免全局池锁成为桌面端和服务端的竞争热点，优先线程本地或分片池 | 1/2/4/8 worker 吞吐随核心数合理扩展，无明显锁竞争退化 |
| 性能回归基线 | 保留 direct 和 Shadowsocks 场景，并增加不同连接数、活跃比例和包大小 | 每组至少 3 轮取中位数；同时报告吞吐、CPU/GB、RSS、footprint、分配次数和峰值并发内存 |
| 跨环境场景 | 移动端模拟、桌面默认、低内存路由器、服务端高并发分别测试 | 移动端不越过约 50MB 的目标预算；桌面/服务端不以 2KB 缓冲牺牲吞吐；路由器预算可收紧且不会 OOM |

优化后的结果补充到本地 benchmark 记录。真机 iOS / Android TUN、Linux 服务端和低内存设备测试在 P2/P5 持续补齐。

### P0.2 平台架构重构（P0.1 合并后开始，先于 P1 新协议开发）

现状问题：新增一个出站要改 6 处以上的中心化文件；VLESS / VMess / Reality 只有出站；没有用户概念；入站不能热更新；宿主逻辑写在 `start()` 里；约 70 个全局参数来自环境变量。完整对照见架构调研第 2 节。

架构调研第 5 节的 D1–D5 已决定，全部采用建议方案：配置改为每协议强类型 serde options，JSON 对齐 sing-box，`.conf`（兼容 Surge）和 Clash YAML 作为输入格式，chain 只作为内部机制，先单 crate 划分模块，上游只作参考。

| # | 任务 | 内容 | 验收标准 |
| --- | --- | --- | --- |
| 0.2.1 | 扩展点与注册表 | 建 `adapter/`（Inbound / Outbound / Dialer / Service / DnsTransport trait、Registry、Lifecycle、Context）和 `include.rs`；现有协议逐个迁到 `protocol/<name>/`，入站和出站放在一起；`protocol/group/` 放 select / failover / tryall / static / chain | 新增一个协议只需新目录 + options 类型 + `include.rs` 一行；manager 中不再有按协议匹配的分支；现有集成测试全部通过 |
| 0.2.2 | 单一配置契约 | 按 D1 的结论实现强类型 options，JSON 字段对齐 sing-box，共享的 Dial / Listen / TLS / Transport / Mux 选项可复用；`.conf`（兼容 Surge）和 Clash YAML 作为输入格式转换到同一模型（格式部分已由「PC 配置兼容」取代：三种格式运行时直读） | 每个字段只定义一次；配置检查能指出错误字段的完整路径 |
| 0.2.3 | 统一拨号与监听 | 建 `net/`：dialer、listener、socket 选项、Android protect、转发与缓冲池；绑定接口等选项可按出站配置；`option/` 全局变量收敛为按实例的 `RuntimeOptions` | 同一进程内两个实例可使用不同的绑定接口和资源预算；数据通路性能不低于 P0.1 基线 |
| 0.2.4 | 路由骨架 | 建 `route/`：规则按条件拆成独立模块并编译为索引（域名哈希 / 后缀、关键字自动机、CIDR 前缀树）；路由结果从 tag 改为动作；嗅探从 dispatcher 移到 `sniff/`，由动作驱动 | 大规则集下单次匹配不随规则数线性增长、不分配内存；dispatcher 中不再有写死的嗅探逻辑 |
| 0.2.5 | 运行时与生命周期 | 建 `runtime/`：分阶段启动；出站声明依赖并检测环路；入站和出站支持按组件增删；路由表和出站表改为无锁快照 | 重载期间已有连接不中断、新连接不阻塞；修改入站端口无需重启进程 |
| 0.2.6 | 宿主隔离 | 建 `platform/`：定义 Platform trait；TUN 路由设置、接口选择等宿主逻辑移出 `start()`；`mobile/` 移到 `sail-ffi`；`sys.rs`、`winsys.rs`、`cmd_*.rs` 归入 `platform/` | 核心 crate 不包含任何移动端绑定代码；CLI 与 FFI 通过同一套运行时接口启动 |
| 0.2.7 | 连接元数据 | `Session` 增加用户、入站类型、路由选项等平台字段；协议私有状态（如 VLESS Vision）移出核心结构 | 路由、统计、限速只依赖 `Session`；`session.rs` 不引用任何具体协议 |

每一步单独合并，功能不回退，性能基线不下降。

---

## P1 协议与传输

### 兼容范围

1.1 TLS 指纹伪装排在所有新协议之前，已于 2026-09-26 完成（证书热更新并入 3.4）：
- TLS、QUIC 和 AEAD 统一使用 BoringSSL（btls 的 fork `peakpassvpn/btls`），rustls、ring 和 aws-lc 已移除；
- 外层 ClientHello 可模拟 Chrome、Firefox、Safari，默认 Chrome；
- Reality 发送 X25519MLKEM768，能连上 Xray 26.9.x。

过程和结论见 [`tls-fingerprint-research.md`](tls-fingerprint-research.md)。

先建立脱敏节点语料和互操作矩阵，记录协议、传输、安全层和关键字段的覆盖率。协议按下面的支持分级排期，高优先级项**入站和出站同时交付**。

### 支持分级

对照 sing-box v1.14.2 与 Mihomo v1.19.31（2026-09）。

**出站**

| 优先级 | 项目 |
| --- | --- |
| 高 | HTTP；Shadowsocks 2022；Hysteria2；TUIC v5；AnyTLS；VLESS 补齐 XUDP / packetaddr；VMess 补齐 `auto` / `none` / `zero` 与 XUDP |
| 已完成 | WireGuard（端点，出站和入站一体，1.13）；ShadowTLS v3（1.14） |
| 中 | VLESS encryption（ML-KEM）；NaiveProxy；SSH；Mieru、Sudoku、TrustTunnel、MASQUE、ShadowQUIC（观察） |
| 低 | Snell；Tailscale、ZeroTier、EasyTier、OpenVPN、OpenConnect、Tor |
| 不支持 | ShadowsocksR；Shadowsocks 流加密；VMess legacy（alterId > 0）；Hysteria v1；gost-relay |

**入站**

| 优先级 | 项目 |
| --- | --- |
| 高 | mixed；HTTP 认证；SOCKS 多用户；Shadowsocks 2022（多用户）；VLESS + REALITY + Vision；Hysteria2；TUIC；AnyTLS；Trojan fallback；redirect / TProxy |
| 已完成 | ShadowTLS v3（1.14） |
| 中 | VMess；NaiveProxy；tunnel（端口转发）；随出站跟进的新协议 |
| 低 | Snell |
| 不支持 | ShadowsocksR；Hysteria v1；Cloudflared |

**传输层**

| 优先级 | 项目 |
| --- | --- |
| 高 | WebSocket early data；gRPC；HTTPUpgrade |
| 中 | XHTTP |
| 不支持 | HTTP/2 传输；V2Ray QUIC；mKCP、mekya、kcptun；simple-obfs（移除现有实现）；v2ray-plugin、gost-plugin |

**TLS 与多路复用**

| 优先级 | 项目 |
| --- | --- |
| 高 | REALITY 入站；smux / yamux / h2mux 与 padding；UDP over TCP |
| 已完成 | Chrome / Firefox / Safari 指纹（1.1） |
| 中 | iOS 指纹（需在真机上抓包，确认是否与 macOS Safari 相同）；TLS 分片与 record 分片；服务端 ECH；ACME；kTLS；TCP Brutal；Restls、JLS、TLSMirror（观察） |
| 不支持 | ShadowTLS v1 / v2 |

**DNS**

| 优先级 | 项目 |
| --- | --- |
| 高 | DoT；DoQ；DoH3 |
| 中 | ECS（已完成）；DHCP 上游（2026-09-30 决定暂不做：sing-box 真实模板 0/47、Clash 配置 1/100 且为 Mihomo 文档示例；需 68 端口与绑定网卡，移动端做不了；配置 `dhcp` 服务器或 `dhcp://网卡` 仍报错，有需求再做） |
| 中 | mDNS（已完成，2026-10-01）：sing-box 1.14 的 `mdns` 服务器，按 RFC 6762 §5.1 在每个开启组播的网卡上一次性查询，带 QU 位（§5.4；实测 Windows 10 的应答方只回带 QU 的查询，sing-box 不带故问不到），首个答中的网卡即返回（sing-box 等到截止时间，最长 1 秒）；非 Apple 平台上 `local` 服务器遇到 `.local` 与链路本地反向区时改问 mDNS，并先用系统 hosts 文件作答；DNS 规则的 `preferred_by`（hosts / local / mdns 各自偏好的名字，逻辑规则内同样可用） |
| 暂缓 | systemd-resolved 集成（sing-box 的 `resolved` 服务与服务器，2026-10-01 决定暂缓，不是拒绝）：需要在 Linux 桌面上接管 `org.freedesktop.resolve1` 与 127.0.0.53，只在 sail 取代 systemd-resolved 时有用，语料中无人使用；配置 `resolved` 仍报错。若要做：推荐 zbus（纯 Rust，tokio 后端，放在仅 Linux 的 feature 后），`preferred_by` 已留好“网卡下发的域名”这一来源的扩展点（`Server::prefers`） |

**策略组**

| 优先级 | 项目 |
| --- | --- |
| 高 | select 默认启用；URLTest（含 tolerance）；load-balance（一致性哈希、sticky-sessions）；smart（Surge smart、Mihomo 分支 Smart，按真实连接打分） |
| 中 | chain 中各协议的 UDP 贯通 |

### 私有协议整合

- 最终只保留一个私有协议（Noise + yamux + 路由帧头）。
- 该私有协议在 Sail 接管宿主节点数据面时实现，作为独立 feature 模块，不进入通用协议列表；路由、计费和出口 IP 选择通过扩展接口交给宿主，Sail 只负责握手、复用和帧头解析。
- 现有私有协议 amux、mptp 和私有 quic 传输，在该私有协议、通用多路复用（1.8）和 Hysteria2 / TUIC 落地后移除。

### 任务

| # | 任务 | 涉及位置 | 验收标准 |
| --- | --- | --- | --- |
| 1.1 | **已完成（2026-09-26）** TLS 指纹伪装：外层 ClientHello 模拟主流浏览器（Chrome / Safari / Firefox），技术选型与实现。证书热更新并入 3.4 | `transport/tls/` | TLS 后端为 BoringSSL（btls fork）；普通 TLS 与 Reality 出站默认使用 Chrome 指纹；每个 profile 都有抓包 fixture，JA4 和各扩展内容与目标浏览器一致，普通 TLS 和 Reality 都已验证，WS 共用同一个 TLS 出站；gRPC 待 1.7 实现后补测 |
| 1.2 | **已完成（2026-09-26）** Shadowsocks 2022（`2022-blake3-aes-128-gcm` / `2022-blake3-aes-256-gcm` / `2022-blake3-chacha20-poly1305`），TCP 和 UDP，入站支持多用户（EIH） | `protocol/shadowsocks/` | 与 sing-box / shadowsocks-rust 双向互通；覆盖重放保护、盐和 UDP 会话测试 |
| 1.3 | **已完成（2026-09-26）** VLESS / Reality / Vision 双向：`flow` 可配置，支持无 Vision、Vision、UDP，明确 XUDP / UoT 策略；补齐 VLESS 入站和 Reality 服务端（含 XUDP） | `protocol/vless/`、`transport/reality/` | 不再硬编码 flow；与 Xray / sing-box 建立入站 × 出站组合测试矩阵 |
| 1.4 | **已完成（2026-09-26）** VMess 入站（含出站 `auto` / `none` / `zero`；legacy alterId 不支持） | `protocol/vmess/` | 与 Xray / sing-box 客户端互通；AEAD 头、重放保护有测试 |
| 1.5 | **已完成（2026-09-26）** Hysteria2 入站与出站，含 Salamander 混淆、端口跳跃、带宽与拥塞控制参数（Brutal 为近似实现，quinn 无 pacing 钩子） | `protocol/hysteria2/`，评估复用现有 quinn | 与官方实现双向互通；TCP、UDP、弱网和连接迁移场景可用 |
| 1.6 | **已完成（2026-09-26）** TUIC 入站与出站（含 `udp_over_stream` 与 0-RTT） | `protocol/tuic/` | 与主流实现双向互通；TCP、UDP 和拥塞控制参数生效 |
| 1.7 | **已完成（2026-09-26）** V2Ray 传输层：HTTP、gRPC、HTTPUpgrade；补齐 WebSocket early-data；入站和出站都支持（HTTP/2 传输按分级不支持；gRPC 出站暂为一流一连接） | `transport/` | VLESS / VMess / Trojan 与 Xray、sing-box 双向互通 |
| 1.8 | **已完成（2026-09-26）** 通用多路复用：smux / yamux / h2mux，入站和出站；TCP Brutal（兼容 sing-mux，默认 h2mux；含 UoT v2；TCP Brutal 按 sing-mux 协商，设置拥塞控制仅限 Linux 且需 tcp-brutal 内核模块） ；2026-09-29 统一流核心 `transport/muxcore`：smux / yamux / AnyTLS / amux 共用一个会话实现（读循环不再等任何单条流；yamux / amux 窗口按 quic-go 规则自适应，256 KiB 起、上限随 profile 16/8/8 MiB（desktop、server / mobile / router）；无窗口协议单流积压 256 KiB 时暂停读连接；数据 60 s 无人读的流单独重置并记 `event=stream_stalled`，h2mux 与 QUIC 流同样适用；控制帧优先队列；1000 条突发流全部接受；流持有会话，出站被 reload / provider 移除时在途流跑完再释放；amux 改为自有新帧格式，与旧版不互通；`/api/v1/runtime/stat/mux` 计数） | `transport/mux/`、`transport/muxcore/` | 与 sing-box / Mihomo 互通；高并发下不会因池化叠加导致内存失控 |
| 1.9 | **已完成（2026-09-26）** 出站组：默认启用 select，补齐 URLTest、fallback、load-balance 和选择持久化（selector / urltest / fallback / load-balance；failover 并入 fallback，static 已删除）；2026-09-29 补 sail 扩展 `smart` 组（`outbound-smart` 特性，默认启用）：成员按真实连接打分——连接耗时，TLS/QUIC 的握手首包往返（其余连接的首包时间只按 0.2 权重记录、从不算失败，因含服务器处理时间），加连续失败的指数惩罚（10 分钟减半、成功清零），乘 `policy_priority` 系数；同一站点（窄规则集 ≤2000 域名且无 IP、可注册域名、/24 或 /64，`prefer_asn` 时按 ASN）固定到对它可用的成员，否则在 `tolerance`（毫秒）/`tolerance_ratio` 内随机选；连不上或 TLS/QUIC 握手超时（max(3s, 3×连接均值)）时在客户端尚未收到字节前换下一个成员重放首包（16 KiB 内，最多 3 个成员）；全部失败则不怪任何成员、只尽快探测；不因打分关闭其他连接。未做：Happy Eyeballs 竞速、TCP_INFO 丢包、站点记忆持久化 | `protocol/group/` | 手动选择、自动测速、故障切换和重启恢复都有测试 |
| 1.10 | **进行中（第 5 步）** 统一拨号器 `net::Dialer`：开出站 socket 的所有路径（出站与端点、DNS 服务器、`http_clients`、健康检查、REALITY 握手、回落目标、伪装站上游）只经它拿 TCP 连接与 UDP socket；sing-box 1.14 的全部拨号字段（`DialerOptions`）在这一处实现或明确报错。分三层：`DialFields`（配置字段，只定义一次）→ `DialSpec`（合并 `route.default_*` 与协议默认值、做平台检查，配置检查时报出全部错误）→ `Dialer`（Socket 或 Detour 两种；detour 整个替换 socket 层，hysteria2/tuic、QUIC 类 DNS 与 WireGuard 因此也能 detour）；Happy Eyeballs 与 `fallback_delay`、TCP Fast Open、MPTCP、`udp_fragment`、`reuse_addr`、`bind_address_no_port`、`protect_path`、`netns`、`network_strategy` 系列；连接超时默认 5 s，数值照抄 sing-box。分 9 步，每步单独合入。第 1 步（2026-09-30）：`net/dial/fields.rs` 的 `DialFields` 字段与 sing-box 同名，出站与端点、DNS 服务器、`http_clients`、REALITY 握手都以 flatten 读它，ShadowTLS 握手的拨号字段表也由它生成；DNS 服务器与 `http_clients` 的 `tcp_keep_alive`/`tcp_keep_alive_interval`/`disable_tcp_keep_alive` 从“忽略并警告”改为生效；其余字段的分级不变；REALITY 握手未实现的拨号字段也按同一张分级表报错或警告（原先报“未知字段”），keepalive、`detour`、`domain_resolver` 在第 3 步随 Dialer 接入。第 3 步（2026-09-30）：REALITY 握手、Trojan/VLESS/AnyTLS 回落目标与 ShadowTLS 握手服务器、hysteria2 伪装站上游改用实例默认值合并后的 `Dialer`（`route.default_interface`/`default_mark`、`auto_detect_interface`、auto_redirect 防环 mark、Android protect），域名改由 sail 的 DNS 解析（原为系统解析）；入站的拨号器跟随重载后的默认值；REALITY 握手的 keepalive 三项与 `domain_resolver`/`domain_strategy`/`skip_default_domain_resolver` 生效，`detour` 留待第 4 步；连接超时默认 8 s → 5 s（每个地址，同 sing-box `constant/timeout.go`）；`http_clients`（含规则集、provider 内联）的平台不支持字段在配置检查时报错并带完整路径（原为下载时才失败）。第 4 步（2026-10-01）：`Dialer` 加上 Detour 一种，`detour` 从“handler 链的一环”改为整个替换 socket 层：出站的 TCP 与 UDP 都交给被指定的出站（直接调用其 handler，不走路由）；域名原样交给 detour 在远端解析，设了自己的 `domain_resolver` 时先在本地解析（同 sing-box）；hysteria2、tuic、quic 传输经 `Dialer::quic_socket` 获得 detour（detour 的 UDP 适配成 quinn 的 socket，hysteria2 端口跳跃同样可用），WireGuard 端点、DNS 服务器（含 DoQ/DoH3）与 `http_clients` 的 detour 也改走它；SOCKS 出站的 UDP 中继可经 detour；`detour` 指向无任何字段的 `direct` 出站、指向不存在的出站在配置检查时报错并带路径（`download_detour` 除外，同 sing-box），环路报出完整路径；REALITY 与 ShadowTLS 握手的 `domain_resolver` 指向不存在的 DNS 服务器时在配置检查时报错；ShadowTLS 握手服务器的拨号字段生效（与 REALITY 握手同一张表）；`http_clients` 带 detour 时可设 `domain_resolver`。第 5 步（2026-10-01）：多地址 TCP 改为 Happy Eyeballs（照抄 sing `DialParallel`：`prefer_ipv6` 时 v6 先，其余含未设策略 v4 先；首选族内按 DNS 顺序串行，`fallback_delay`（默认 300 ms）后或首选族全部失败时另一族并发开始，先成功者胜，败者关闭；两族都失败时报首选族的错误；每个地址仍各受 5 s `connect_timeout`），原为逐个串行；`tcp_fast_open` 生效（Linux/Android `TCP_FASTOPEN_CONNECT`，macOS/iOS `connectx` 延迟到首次写入，首包随 SYN 发出；开启时地址逐个串行，同 sing-box；Windows 与其它平台配置检查时报错，Windows 留待第 9 步；与 `network_strategy` 同设报错）；`udp_fragment` 生效，UDP socket 默认置 DF（Linux `IP_PMTUDISC_DO`、Darwin `IP_DONTFRAG`、Windows `IP_MTU_DISCOVER`），`direct`、`hysteria2`、`tuic` 默认允许分片（同 sing-box `UDPFragmentDefault`）；`reuse_addr`（UDP socket 设 `SO_REUSEADDR`，Unix 另设 `SO_REUSEPORT`）、`bind_address_no_port`（仅 Linux，其它平台配置检查时报错）生效；Linux 绑网卡先用 `SO_BINDTOIFINDEX`，内核不支持时退回 `SO_BINDTODEVICE` 并记住。以上字段在出站与端点、DNS 服务器、`http_clients`、REALITY/ShadowTLS 握手中都从“忽略并警告”改为生效 | `net/dial/`、`transport/layers.rs`、`app/dns/`、`app/http.rs`、`config/` | 所有出站 socket 都经 `Dialer`，不再有落回 `DialOptions::default()` 的路径；字段只解析一次，各处同名字段的支持、警告与错误一致；平台不支持的字段在配置检查时报错 |
| 1.11 | **已完成（2026-09-26）** 入站防探测与回落：Trojan / VLESS fallback，鉴权失败时的行为可配置（字段对齐 sing-box `fallback` / `fallback_for_alpn`） | `protocol/trojan/`、`protocol/vless/` | 未通过鉴权的连接可回落到指定目标；主动探测下行为与主流实现一致 |
| 1.12 | **已完成（2026-09-28）** 分享链接导入：`ss://`、`trojan://`、`vless://`、`vmess://`、`hy2://`、`tuic://`（另有 `hysteria2://`、`anytls://`；`share_link::parse` / `parse_subscription` 输出 sing-box 出站，`Config::from_json` 可直接加载；订阅为 base64（标准或 URL-safe，有无填充、换行均可）或逐行文本，重名按 “name 2” 去重；CLI `sail import`，FFI `sail_import_share_links`；sail 不支持的传输（HTTP/2、XHTTP、mKCP、QUIC、gRPC multi）、VMess alterId > 0、TUIC v4、证书哈希固定、缺少的加密方式与指纹都按行报错；WireGuard 链接是端点，不导入；尚未接入运行时配置加载，Clash proxy-providers 由 C.4 调用） | `config/` | 真实节点语料可导入；错误字段有可诊断提示；敏感信息不进入日志 |
| 1.13 | **已完成（2026-09-27）** WireGuard 端点：sing-box 式 `endpoints`，同一个 tag 既是出站也是入站（服务端）；协议核心自研（BoringSSL + blake2），TCP/IP 走 sail-netstack；支持 WARP `reserved`、`detour`（WG 自身的 UDP 走其他出站）和 `.conf`（Surge `[WireGuard <name>]`，`client-id` 即 reserved） | `protocol/wireguard/`、`config/` | 与 Linux 内核 wg（出站、入站、detour、重新握手、64 并发）和 sing-box（双向，含 reserved）互通；sail↔sail TCP、UDP、IPv6 |
| 1.14 | **已完成（2026-09-30）** ShadowTLS v3 出站与入站（v1/v2 为配置错误）：出站经 btls 现有的 ClientHello 钩子（REALITY 所用）在 session ID 中签名，浏览器指纹照常生效，校验服务端对站点记录的标记后进入 HMAC 链式数据阶段；其他出站以 `detour` 经过它。入站按 sing-box 中继握手（`handshake_for_server_name`、`wildcard_sni`、`strict_mode`），认证后交给 `detour` 所指入站（sing-box 的 `inbounds.*.detour` 仅对 shadowtls 开放），未认证者整体转给握手服务器。Clash `ss` 的 `plugin: shadow-tls`、Surge 的 `shadow-tls-*` 转换为派生出站 `<名称> (shadow-tls)`（组不收录；provider / policy-path 中暂未实现）。未做：握手服务器的拨号字段与 `detour`；Mihomo 的 `shadow-tls-opts`（vmess/vless/trojan/anytls）与 listener 的 `shadow-tls` | `protocol/shadowtls/`、`config/` | 与 sing-box 1.14.2（及 1.13.12）双向互通，与参考实现 ihciah/shadow-tls 双向互通；sail↔sail 含错误密码与主动探测（探测者看到握手站点）；向量取自 sing-shadowtls v0.2.1 |

所有协议任务都必须加入统一性能场景，入站和出站分别测试，避免新增协议重新引入连接级常驻大缓冲或无上限缓存。

---

## P2 DNS、路由与网络

### DNS

| # | 任务 | 涉及位置 | 验收标准 |
| --- | --- | --- | --- |
| 2.1 | **已完成（2026-09-28）** 结构化 DNS 上游和规则：按域名、query type、入站、规则集选择服务器；支持 detour 与 IPv4/IPv6 strategy（服务器为 sing-box 对象形式，另有 sail 扩展 `race`（2026-09-29 取代 `smart_select`：同时问全部成员，取第一个成功答案，SERVFAIL/REFUSED、超时与错误算失败，同 Mihomo / Surge 对服务器列表的做法）；规则按域名、query_type、入站、用户、出站选择服务器；出站 `domain_resolver`、`route.default_domain_resolver`；启动和重载时检查递归环；按规则集选择等 2.6。2026-09-28 补 sing-box 1.14 的响应匹配：`evaluate` 先问一个服务器并保留应答（可带 tag），后续规则以 `match_response` 按应答的 `ip_cidr`/`ip_is_private`/`ip_accept_any`/规则集 IP 与 `response_rcode` 匹配，`respond` 直接返回该应答；`route-options`；规则级 `timeout`、`rewrite_ttl`、`disable_cache`；`dns.client_subnet` 与规则级 `client_subnet`/`remove_client_subnet`（EDNS Client Subnet）；应答缓存按服务器、问题和子网区分。`domain_resolver` 的 `timeout`、`disable_cache`、`rewrite_ttl`、`client_subnet`，旧字段 `domain_strategy`（出站、DNS 服务器、HTTP 客户端），DoH / DoH3 的 `headers`（`Host` 改请求的主机）。2026-09-29 补齐：`predefined` 的 `answer`/`ns`/`extra` 记录（zone 文件文本或 base64 二进制，`*.后缀.` 换成查询的名字）；`response_answer`/`response_ns`/`response_extra` 按 miekg/dns `IsDuplicate` 比较记录（不看 TTL）；逻辑规则子规则里的 `match_response`（各自匹配所指的 evaluate 应答，没有则只在取反时匹配）；规则级 `race` 与 `speculative`：evaluate 只发查询不等待，race 规则随应答到达逐个判定，最先匹配的立即决定，其后规则的动作等到前面的 race 都未匹配才生效，speculative 的查询提前发出。local 服务器的 `neighbor_domain` 警告忽略。sail 扩展 `dns.client_strategy`：只限制回给客户端的应答的地址族（hijack-dns、DNS 监听），sail 自己的解析仍按 `dns.strategy`，对应 Mihomo 的 `dns.ipv6: false`） | `dns/` | 国内外 DNS 分流正确，节点域名解析无递归环，无 DNS 泄漏 |
| 2.2 | **已完成（2026-09-29）** 内置 DNS listener 和 TUN DNS hijack（按 sing-box：`direct` 入站（`network`、`override_address`、`override_port`）加一条对它的 `hijack-dns` 规则即为 DNS 服务器，UDP、TCP 均应答，Mihomo 的 `dns.listen` 降级为此；UDP 应答超出客户端 EDNS 声明的大小（无 OPT 时 512 字节）时按 Mihomo / sing-box 截断并置 TC；Linux TUN 端到端测试覆盖 IPv4/IPv6 的 UDP、TCP 53 劫持） | `dns/`、`protocol/tun/` | UDP/TCP 53 查询均可劫持；`hijack-dns` 动作可测试 |
| 2.3 | **已完成（2026-09-26）** 加密 DNS：在现有 DoH 基础上补连接复用，并按需要增加 DoT、DoQ、DoH3；每种上游按注册表接入（DoT / DoQ / DoH3 已完成；DoH 保持一条 HTTP/2 连接或空闲 HTTP/1.1 连接复用） | `dns/transport/` | bootstrap、证书校验、代理/直连 detour 和失败回退行为明确 |
| 2.4 | **已完成（2026-09-29）** DNS 缓存可配置：容量、TTL、negative cache、独立缓存、清理和统计（按 sing-box 1.14：`dns.disable_cache`、`disable_expire`、`cache_capacity`（默认 1024 且不少于 1024）、`optimistic`（过期答案在宽限期内以 TTL 1 返回并后台刷新，默认 3 天，同一问题同时只刷新一次；与前两者冲突即报错），DNS 规则与 `domain_resolver` 的 `disable_optimistic_cache`；按最短 TTL 缓存，无记录的应答按 SOA 的 TTL 与 MINIMUM 取小（RFC 2308），两者都没有则不缓存，所有记录统一为该 TTL；缓存始终按服务器区分（`independent_cache` 警告忽略）；`experimental.cache_file.store_dns` 把答案同时写入缓存文件，重启后内存未命中时从文件取，过期的按 sing-box 的间隔清理。与 sing-box 不同：宿主通知切网或默认网卡变化时清空缓存；API `GET /api/v1/runtime/dns/cache` 报告条目、命中、过期命中与未命中，`POST /api/v1/runtime/dns/cache/flush` 清空。`dns.timeout` 默认改为 10 秒，同 sing-box。路由 `resolve` 动作的缓存选项属 2.9，未做） | `dns/`、管理 API | 命中率可观察；切网和配置重载不会返回错误网络下的陈旧结果 |
| 2.5 | **已完成（2026-09-29）** FakeIP 完整化：IPv4/IPv6 地址池、TTL、过滤、容量与持久化（sing-box 的 `fakeip` DNS 服务器：双栈地址池、TTL 600、每族最多 65536 个域名，按 DNS 规则过滤；所有入站的目标由 dispatcher / NAT 还原为域名，未知 fake IP 拒绝；热重载保留地址；`exchange` 供 hijack-dns 使用；sail 自身的解析（出站拨号等）跳过指向 fakeip 的规则，同 sing-box。2026-09-29 补重启后持久化：实现 sing-box 的 `experimental.cache_file`（`enabled`、`path`、`cache_id`、`store_fakeip`；redb 单文件，默认在宿主 cache_dir 或 data_dir 下的 `cache.db`），保存选择器的选中项（取代原 `selector.cache`）、Clash 模式与 FakeIP；未开启则什么都不保存，同 sing-box。FakeIP 每次分配连同游标在后台线程按批以单个事务写入，范围不变则重启后原样恢复并接着分配，范围变了则清空；实例停止即关闭文件，被占用时按 sing-box 等待 10 秒后报错，损坏的文件移到 `.broken` 后重建。`store_rdrc`/`rdrc_timeout`（1.14 已废弃，只服务旧式地址过滤）与 `store_dns`（2.4）警告忽略） | `dns/transport/fakeip` | 支持 A/AAAA；重启后按配置恢复或安全重建；地址回收无错误映射 |

### 路由、规则集与嗅探

| # | 任务 | 涉及位置 | 验收标准 |
| --- | --- | --- | --- |
| 2.6 | **已完成（2026-09-28）** rule-set 远程下载、定时更新、本地缓存、大小限制和原子替换（sing-box 的 inline / local / remote，`{tag}` 多标签；经 `download_detour` 下载，跟随重定向、ETag；首次下载完成前不接受连接，失败则启动失败；`cache_dir` 下原子写入，更新失败保留旧规则） | `route/rule_set/` | 更新失败继续使用旧规则；下载可指定出站；不允许任意路径写入 |
| 2.7 | **已完成（2026-09-28）** 支持 sing-box `.srs` 导入（source 与 binary 格式 v1–v5；域名保持 succinct trie 形式匹配；与 sing-box 1.13.12 的 compile / match 结果和官方 geosite-cn、geoip-cn 对照一致；路由规则和 DNS 规则的 `rule_set` 按 sing-box 的合并语义） | `config/` | 导入后转换为 Sail 内部规则，不让运行时路由器长期耦合外部格式 |
| 2.8 | **基本完成（2026-09-30；剩余见行尾）** 逻辑规则 and/or/not，以及 source IP/port、用户、入站类型、进程路径、package、uid、IP version、ASN、网络类型等常用条件（按 sing-box 1.14 的分组与合并语义：`type: logical` 的 and/or 嵌套、`invert`，`domain_regex`、`source_ip_cidr`、`source_ip_is_private`、`ip_is_private`、`source_port(_range)`、`ip_version`、`protocol`（嗅探到的协议）、`process_name`（精确名）/`process_path`/`process_path_regex` 已完成；路由规则、DNS 规则与规则集规则编译为同一个匹配器；与 sing-box 实跑对照一致；进程条件仅在 Windows NetFilter 入站可得，其他平台及 `package_name`、`user`、`user_id` 在配置检查时报错；`clash_mode`、ASN 已另行补上；2026-09-30 补网络条件：`wifi_ssid`、`wifi_bssid`（规范化为小写冒号形式）、`network_type`、`network_is_expensive`、`network_is_constrained`，及为 Surge 加的 sail 扩展 `wifi_ssid_regex`（区分大小写）、`wifi_bssid_regex`（不区分）、`network_gateway`、`network_mcc_mnc`（仅非 Wi-Fi 时匹配），路由规则与规则集（源格式与 .srs）可用，按宿主推送或 sail 检测到的网络状态逐连接匹配，未知字段不匹配；匹配逻辑为 `NetworkConditions`，DNS 规则与 `network` 组共用；另加 sail 扩展组 `network`（按分支条件选出站，首个匹配者胜，否则 `default`，已建立的连接不断开），`RuntimeManager::needs_network` 告知是否需要检测网络；DNS 规则的网络条件已由 C.5d 补上；剩余：`package_name`、`user`、`user_id` 及非 Windows 平台的进程条件，需各平台宿主提供连接归属后再做） | `route/rule/` | 每种条件一个模块；与选定的 sing-box / Mihomo 规则样例得到一致结果 |
| 2.9 | **基本完成（2026-09-30；剩余见行尾）** 路由动作补齐：route、reject、hijack-dns、sniff、resolve、bypass 和 route options（`route-options` 与 route 内联选项：`override_address`/`override_port`（UDP 回包还原为原目标）、`udp_timeout`、`udp_connect`、`udp_disable_domain_unmapping`、`tls_fragment`/`tls_record_fragment`；`reject` 的 `method: default/drop` 与 `no_drop` 防洪；`hijack-dns` 把 TCP/UDP 上的 DNS 查询交给 DNS 客户端按 DNS 规则应答（含 FakeIP）；`resolve` 的 `timeout`，解析失败或超时即断开连接（同 sing-box）；嵌套规则带动作、字段与动作不符等错误组合在配置检查时报出完整路径；resolve 的 `disable_cache`、`disable_optimistic_cache`、`rewrite_ttl`、`client_subnet` 2026-09-30 已补（未指定 server 时作为这次查询的初始选项，DNS 规则的 route-options 可再覆盖，同 sing-box）；2026-09-30 起 `resolve`/`sniff` 可带 `on_demand`（sail 扩展）：规则只“挂起”动作（连同自身选项）并继续匹配，到第一条真正需要其结果的后续规则前才执行——resolve 在需要目标地址的条件（`ip_cidr`、`ip_is_private`、`ip_asn`、`geoip`、`external` mmdb，或内容含非 no_resolve 地址规则的规则集）且目标为域名时，sniff 在 `protocol`、`http_user_agent`、`url_regex` 或目标为 IP 时的域名条件前；在此之前已决定的连接不解析、不嗅探，同 Surge/Mihomo 的懒解析；auto_redirect 预匹配只执行挂起的 resolve。路由规则与规则集规则新增 `no_resolve`（sail 扩展，对应 Surge/Clash 的 `no-resolve`，规则集文本读取时逐行填入）：其地址条件只匹配已知地址，不触发挂起的 resolve；放在无地址条件的规则上报错；`bypass` 已随 auto_redirect 完成（预匹配阶段在内核放行）；剩余 `network_strategy`（依赖 1.10 统一拨号选项与 2.12 网络生命周期）；`tls_spoof` 暂不计划，配置即报错） | `route/` | 动作可组合，错误组合在配置检查阶段失败 |
| 2.10 | **已完成（2026-09-30）** 嗅探补齐并可配置覆盖目标：HTTP、TLS、QUIC、DNS（另有 STUN、BitTorrent、DTLS；`sail/src/sniff/`，各协议有 cargo-fuzz target 与回归语料） | `sniff/` | 有长度限制、超时和模糊测试；不能由异常报文触发 panic 或无限缓存 |

### TUN 与平台网络

| # | 任务 | 涉及位置 | 验收标准 |
| --- | --- | --- | --- |
| 2.11 | **部分完成（2026-09-30）** TUN IPv4/IPv6、MTU、UDP NAT timeout、ICMP/ICMPv6 和 DNS 劫持完整性（Linux 端到端测试已通过：IPv4/IPv6 的 TCP、UDP、ICMP、NAT 超时；TUN 选项改为 sing-box 的 `tun` 字段，移动端经 `Platform::open_tun` 打开设备；DNS 劫持由 2.2 的 hijack-dns 完成；TUN 自带的 FakeDNS 已删除，改由 DNS 段 fakeip（2.5）；Linux `auto_redirect`（nftables + NFQUEUE 预匹配、内核级 bypass）已完成；iOS、Android、macOS 实测未做） | `protocol/tun/`、netstack | iOS、Android、macOS、Linux 上 TCP/UDP/IPv6 测试通过 |
| 2.12 | **进行中（2026-09-30）** 设计见 design-notes/network-lifecycle-design.md（用户已批准）。第 1 步：网络状态区分“连接无法延续的变化”（默认网卡、网关、类型、地址（IPv6 按 /64）；同网段漫游不算），每个来源（检测、宿主推送、`sail_network_changed`）都经同一个 `Network` 发布；变化时统一清 DNS 缓存与 DNS 服务器的连接、关闭进行中的连接（在各连接记录绑定网卡之前为全部关闭）、重置 TUN 的流，并记一行供测试计时的日志；Linux 与 Windows 的监视循环始终运行。第 2 步：出站、端点与 provider 成员在变化时收到 `network_changed`（默认不做事；mux、组、http 连接池由各负责人实现）。第 3 步：macOS 以路由 socket 监视变化，三个桌面系统都跟随变化。第 4 步：网络消失（已知过状态、现在为空）时 `is_down()` 为真，定时的健康检查与更新据此暂停，网络恢复即一次变化、立即重测（各负责人接入）。第 5 步：桌面以“含休眠时间的时钟”与“不含休眠时间的时钟”之差检测唤醒，睡过 5 秒即算一次变化（5 秒轮询与阈值为经验值，待 5.5 实测）。第 6 步：桌面纯 IPv6 网络按 RFC 7050 查 `ipv4only.arpa` 得到 NAT64 前缀，拨号与 UDP 收发时按 RFC 6052 改写与还原 IPv4 地址（覆盖字面地址、A 记录与 TUN 流量，不改写 DNS 答案；回环等本机地址不改写）。第 7 步：宿主推送 `captive: true` 时除被劫持的 DNS 外一律直连（内置直连出站，默认拨号选项），进入与解除以 info 记录。剩余：5.5 中实测 3 秒恢复与唤醒阈值，mux、组、provider、规则集按各自负责人接入 `network_changed` 与 `is_down()`。原计划：网络生命周期：Wi-Fi/蜂窝切换、IPv6-only/NAT64、锁屏恢复、休眠唤醒、captive portal | `platform/`、`runtime/` | 宿主通知网络变化后，旧连接按策略关闭或重建，3 秒内恢复新连接；不会复用错误接口上的 DNS 或出站连接 |
| 2.13 | Android 分应用代理 | Android 侧与 `Session` 元数据 | package/uid include/exclude 生效，并明确哪些逻辑属于 VpnService、哪些属于内核 |
| 2.14 | **部分完成（2026-09-30）** 桌面与路由器原生路由管理：Linux netlink、macOS routing socket、Windows IP Helper/WFP、`strict_route`；Linux 透明代理（TProxy / redirect）（Linux 已完成：按 sing-tun 用表 2022 与 9000–9010 的 ip 规则，不改主路由表，崩溃后可恢复，`route_address(_set)`、`route_exclude_address(_set)`、按网卡/uid、`strict_route`、resolvectl DNS；出站按网段/默认网卡绑定并随网络变化切换，`auto_route` 时隐式开启；规格见 docs/route-management-spec.md。macOS 已完成（ffa2a4cd，routing socket 分段路由，仅单元测试，真机由用户手动验证）。Windows 代码已完成、待真机验收（分支 win-214，leaf-61）：wintun 网卡由 sail 自建（GUID 由名字导出，只用 IP Helper，不调 netsh），0/0 与 ::/0 以 metric 0 走 wintun、不改原默认路由，网卡 DNS 指向 TUN 下一地址，`strict_route` 为 sing-tun 的 WFP 动态规则（非 TUN 网卡的 53 端口拦截、TUN 无 IPv6 时拦截 IPv6、放行 sail 自身），出站以 `IP_UNICAST_IF` 绑定物理网卡、默认网卡按路由与网卡 metric 之和最小选取、随路由与网卡变化通知 1 秒去抖切换；Windows 上 clippy 与只读单元测试已过，待 VM 102 空出后做真实路由测试（正常退出与强杀后的清理、空闲时线程数不增长）后合入） | `platform/`、`protocol/tun/`、`protocol/redirect/` | 开关 TUN、异常退出和重启后路由表可恢复，无流量泄漏；路由器透明代理 TCP / UDP 可用 |

---

## PC 配置兼容（运行时直读）

2026-09-27 决定：用户现有的 sing-box、Clash / Mihomo、Surge 配置不经转换直接运行，包括订阅和热重载。对照版本为 sing-box 1.14.x、Mihomo 1.19.x、Surge 5。

**结构：**
- `config/singbox/`、`config/clash/`、`config/surge/` 各为一个前端：先按上游 schema 强类型解析（字段名、默认值、别名、废弃字段与上游一致），再降级到内部模型。
- 解析和降级的错误都指向原格式里的完整路径，例如 `proxy-groups[3].use`、`[Rule] 第 12 行`。
- 格式识别：`.json` 为 sing-box，`.yaml` / `.yml` 为 Clash，`.conf` 或含 `[General]` 的文本为 Surge。CLI、FFI 和热重载共用同一个入口。
- 宿主参数（如 TUN fd）通过 API 传入，不写进配置。

**上游合法但 Sail 未实现的字段（分级处理）：**
- 上游本身也不认识的字段：报错，视为写错。
- 忽略后会改变路由或安全语义的（未实现的代理类型或规则类型、被分组引用的未实现出站等）：报错。
- 只影响体验的（Surge `[MITM]` / `[Script]` / `[URL Rewrite]`、sing-box `experimental.cache_file` 等）：启动时逐条警告后忽略，并能通过 capability 查询得到清单。

| # | 任务 | 涉及位置 | 验收标准 |
| --- | --- | --- | --- |
| C.1 | 前端框架与格式识别；现有 sing-box 风格 JSON 迁为 `singbox/` 前端，sail 独有能力改为明确命名的扩展字段；删除 leaf 遗留的类 Surge `.conf` | `config/` | 三种格式走同一个加载与重载入口；未实现字段按上面的分级处理，且有测试 |
| C.2 | 内部模型补齐三家的并集：依赖 P2 的 2.1（结构化 DNS）、2.6 / 2.7（rule-set）、2.8（逻辑规则与条件）、2.9（路由动作）和 4.8（provider） | `config/model`、`dns/`、`route/` | 三个前端都能无损降级到内部模型，不需要格式专属的运行时分支 |
| C.3 | **进行中（2026-09-30）** 字段注册表已完成：`tools/singbox-fields` 从 sing-box v1.14.2 源码列出其接受的全部 5002 个字段（`sail/src/config/singbox/fields.json`），`registry` 测试逐一构造配置、读取并构建，测得 sail 对每个字段的处理（支持 / 警告忽略 / 报错，理由写在 `upstream.rs`），生成支持表 [`compat/sing-box.md`](compat/sing-box.md)（中文版 [`compat/zh/sing-box.md`](compat/zh/sing-box.md)）；语料测试（`sail/tests/corpus`，附 sing-box 与 Mihomo 的参考结论）作为回归。缺口清单据此整理。本阶段完成：警告级字段逐一用 sing-box 1.14.2 `check` 复核，已被上游移除的 `experimental.debug.oom_killer` 改为报错，`route.geoip`/`route.geosite`、入站 `tls.insecure` 上游仍接受，保留警告；字段取零值（`""`、`false`、`0`、`[]`、`{}`）视为未设置，与 sing-box 一致；入站 `udp_timeout` 接受秒数（WireGuard 端点按 sing-box 只接受时长）；`log.level: warning`；时长接受 `d`（天）；sing-box 1.13 移除的入站旧字段（`sniff` 等）按 sing-box 原文报错并指向规则动作；REALITY 公钥、私钥与 short_id 在读取时校验（`sail -T` 即报错）。Clash 前端同批：Mihomo 按结构体读取的列表中空项跳过（`rules`、`lan-allowed-ips`、`dns`、`tun`、`sniffer` 等；代理、组、provider 中仍报错，同 Mihomo）、`interface-name` 优先于 `tun.auto-detect-interface`、代理 `network: none` 即 TCP、`global-client-fingerprint` 按 Mihomo 1.19 警告忽略。无负责方的服务（`ccm`、`derp`、`ocm`、`usbip-client`/`usbip-server`、`ssm-api`）保持报错，不在计划内；未实现的 15 个协议类型（出站 NaiveProxy、Hysteria v1、Snell、SSH、Tor、bridge，入站 NaiveProxy、Hysteria v1、Snell、Cloudflared，端点 Tailscale、OpenVPN 客户端 / 服务端、OpenConnect，服务 `hysteria-realm`）按 P1 [支持分级](#支持分级) 的出站与入站表排期。其余字段缺口（及 `resolved`、`oom-killer` 服务）归各自负责方：DNS 归 leaf-61，路由 / TLS / 传输归原 leaf-80，TUN 与平台归 leaf-e0。原计划：sing-box：`log`、`dns`（servers / rules / fakeip）、`inbounds`、`outbounds`、`endpoints`（WireGuard）、`route`（rules / rule_set / final / 自动检测接口）、`experimental`（clash_api） | `config/singbox/` | sing-box 官方文档示例与脱敏真实配置语料全部可加载；与 sing-box 同配置下路由结果一致 |
| C.4 | **进行中（2026-09-29）** C.4a 已完成：YAML（锚点、合并键，按 Mihomo 的弱类型读数值与布尔）与格式识别；端口监听、`allow-lan`、认证、`mode`（即 Clash 模式与 `GLOBAL` 组）、日志；内联 `proxies`（ss 含 obfs、vmess、vless 含 REALITY、trojan、hysteria2、tuic、anytls、socks5、http、direct、reject、dns）；`select`/`url-test`/`fallback`/`load-balance` 组；基础规则（域名、IP、端口、进程、网络、入站、用户、PASS/REJECT/REJECT-DROP；无 `no-resolve` 的 IP 规则前按 Mihomo 惰性解析，解析失败继续匹配）。未实现字段按分级报错或警告，挂锚点的顶层自定义键静默。C.4b 已完成：AND/OR/NOT（任意嵌套）、SUB-RULE（就地展开，嵌套时按 Mihomo 截断）、DOMAIN-WILDCARD；rule-providers（http/file/inline，yaml/text/MRS，domain/ipcidr/classical）作为规则集，MRS 的域名集保持 succinct 形式匹配（geosite-cn 22 万条：加载约 10ms、内存约 +5MB，展开则为 250ms、+66MB）；GEOSITE/GEOIP 改为下载 MetaCubeX meta-rules-dat 同名 MRS 规则集。C.4c-1 已完成：组成员按 key（来源 + 名称）而非位置保存，选择与健康状态在成员变化后保留。C.4c-2 已完成：sail 扩展 `outbound_providers`（remote / local / inline）与组的 `providers`/`filter`/`exclude_filter`/`exclude_type`/`empty_fallback`，按 Mihomo 语义（见 4.8）。C.4c-3 已完成：`proxy-providers`（http→remote、file→local、inline 在转换时按 filter/override 选取改写）降级为 `outbound_providers`，provider 的 `health-check` 警告忽略，但其 URL 作为引用它的组的默认测速地址（同 Mihomo），`override` 中 Mihomo 不认识的键警告忽略，`age-secret-key` 报错；组的 `use`、`include-all`/`include-all-providers`/`include-all-proxies`（按名排序、按 `filter` 选取）、`filter`、`exclude-filter`、`exclude-type`、`empty-fallback`（默认 `COMPATIBLE`，即直连）。语料 68 份 `mihomo -t` 通过的配置，填上占位订阅地址后，去掉 C.4d 各段即有 66 份可加载。C.4d-1 已完成：`dns` 降级为 sail 的 DNS 服务器与规则，顺序同 Mihomo（fake-ip → `nameserver-policy` → `fallback` 与 `fallback-filter` → `nameserver`）。服务器按原字符串打 tag（udp/tcp/tls/https/h3/quic/system；`#` 后为代理/组即 `detour`、其他名字即网卡、`RULES` 即按规则出站，参数 `ecs`、`skip-cert-verify`、`disable-qtype-*`），多个服务器为 `smart_select`（Mihomo 为竞速，答案相同、延迟行为不同），带域名的服务器由 `default-nameserver` 解析；`rcode://` 为 `predefined` 规则；fake-ip 过滤支持 blacklist/whitelist/rule 三种模式、`geosite:`/`rule-set:` 条目与 `fake-ip-ttl`，HTTPS/SVCB 回空答案；`fallback-filter` 以 evaluate + `ip_match_all`（每个地址都在本国或私有才保留主服务器答案）表达；`proxy-server-nameserver` 为 `route.default_domain_resolver`，DIRECT 走 `direct-nameserver`（`direct-nameserver-follow-policy` 时先过 policy）或 DNS 规则；`respect-rules` 按路由规则出站。为此扩展了 DNS 客户端：`predefined` 规则（仅 rcode）、`ip_match_all`、服务器的 `client_subnet` 与 `respect_rules`、出站的 `skip_default_domain_resolver`、fakeip 服务器回答 HTTPS/SVCB。`listen`、`prefer-h3`、`use-hosts`/`use-system-hosts`、`cache-algorithm: arc` 警告忽略；`proxy-server-nameserver-policy` 有条目、`dhcp://`、`name-cert-verify` 报错。语料 65 份启用 DNS 的配置中 64 份可降级并能建成 DNS 客户端、无解析环路（1 份因 `proxy-server-nameserver-policy` 报错）。后续：DNS 监听（`listen`，服务局域网客户端）；`dns.ipv6: false` 目前也让 sail 自身解析只取 IPv4。之后：C.4d-2 `hosts`，C.4d-3 `sniffer`，`tun`。原计划：Clash / Mihomo：通用字段、`proxies`、`proxy-groups`、`proxy-providers`、`rules`（含 AND / OR / NOT、SUB-RULE、RULE-SET）、`rule-providers`、`dns`（nameserver-policy、fake-ip-filter）、`hosts`、`tun`、`sniffer`、`external-controller`；依赖 4.5 / 4.6 的 Clash API | `config/clash/` | 主流机场订阅与 Mihomo 示例配置可直接运行；yacd / metacubexd 端到端可用；与 Mihomo 同配置下路由结果一致 |
| C.5 | **进行中（2026-09-30）** C.5a 已完成（`config-surge` 特性，默认开启，依赖 `config-clash`；`config/surge/`）：按 Surge 手册读 `.conf`——段落、`#`/`;`/`//` 注释（行内须前置空格）、引号与 `\"` 转义、`#!include` 本地文件（相对配置目录，按所在段落展开；从字符串读取时报错；URL 自 C.5c 起读宿主取回的副本）、`#!MANAGED-CONFIG` 警告、`#!REQUIREMENT` 与 `#!IOS-ONLY`/`#!MACOS-ONLY`/`#!TVOS-ONLY`（`SYSTEM` 为 sail 所在平台，`CORE_VERSION` 视为最新版，设备类变量不成立并警告）；`[General]`：日志、`http-listen`/`socks5-listen`（及旧键 `interface`/`port`、iOS 的 `wifi-access-*` 与 `allow-wifi-access`）、`proxy-restricted-to-lan`（默认开，非回环监听只许私有源地址）、`proxy-test-url`/`test-timeout`（组测速）、`udp-policy-not-supported-behaviour`（规则指向无 UDP 的代理或全员无 UDP 的组时，其 UDP 先按 REJECT/DIRECT 处理；成员混合的组按所选成员转发）、`ipv6`、`dns-server`/`encrypted-dns-server`（各列表一个 smart_select，加密服务器域名由普通服务器解析，`encrypted-dns-follow-outbound-mode`、`skip-cert-verification`）、`hijack-dns`；TUN 路由键警告（TUN 由宿主建立），界面与平台键静默。`[Proxy]`：direct/reject 系别名、ss（含旧 `custom`、obfs）、vmess（仅 AEAD）、trojan、http/https、socks5/socks5-tls、hysteria2（端口跳跃、salamander）、tuic-v5、anytls、wireguard（`[WireGuard 名]` 段为端点）；`interface`、`ip-version`、`underlying-proxy`、`udp-relay`、TLS（`sni=off`、证书指纹、`client-cert` 报错；shadow-tls 见 1.14）。`[Proxy Group]`：select/url-test/fallback/load-balance；smart 自 C.5b 起为 sail 的 `smart` 组（仅代理成员，`policy-priority` 原样作 `policy_priority`，因子须 >0，`tolerance`/`timeout`/`evaluate-before-use` 对应，`interval` 与 Surge 一样忽略）；成员按显式、`include-other-group`、`include-all-proxies` 顺序并经 `policy-regex-filter` 过滤，空组为 DIRECT。`[Rule]`：DOMAIN 系、DOMAIN-WILDCARD、IP-CIDR(6)、GEOIP、PROCESS-NAME、DEST-PORT/SRC-PORT/IN-PORT（含 `>=` 等）、SRC-IP、PROTOCOL（需要时先嗅探），首个无 `no-resolve` 的 IP 规则前解析（C.5c 起改为按需解析，见下），`FINAL,dns-failed` 时解析失败继续；REJECT/REJECT-DROP/REJECT-NO-DROP/REJECT-TINYGIF。`[Port Forwarding]` 为 direct 入站；MITM、重写、Map Local、HTTP/cron 脚本各段警告一次；规则/DNS 脚本报错。C.5b 已完成（2026-09-30）：RULE-SET（内置 SYSTEM/LAN 按手册清单内嵌，SYSTEM 去掉两个进程；`[Ruleset 名]` 内联集就地展开，可嵌套 8 层、成环报错；URL/相对配置目录的路径为 `surge-text` 格式规则集，直连下载，`update-interval`）与 DOMAIN-SET（`.x` 含 x 本身），同一文件兼作两者报错；规则集文件内容未知，故其前先嗅探 HTTP 并尝试解析（失败继续，其后的 IP 规则再严格解析；C.5c 起改为按需）；AND/OR/NOT（10 层）；IP-ASN（新条件 `ip_asn`，读资源目录 `asn.mmdb`，GeoLite2-ASN 或 ipinfo 格式，缺文件报错）；USER-AGENT/URL-REGEX（HTTP 嗅探记录 URL 与 UA，新条件 `http_user_agent`/`url_regex`，超长截断且不匹配、不写日志）；HOSTNAME-TYPE（`ip_version` 与域名形态）；extended-matching 先嗅探 SNI/Host（此后所有域名规则匹配嗅探到的域名，宽于 Surge）；pre-matching 的 REJECT 规则对 TCP 提前、不触发解析；IP 前缀按 Surge 抹去主机位。DNS：Firefox 探测域名 NXDOMAIN、`allow-dns-svcb` 为假时外部 HTTPS/SVCB 查询回空记录（Surge 回 NOTIMP；sail 自身的 ECH 查询不受影响）、外部 A/AAAA 查询给 fake IP（198.18.0.0/15，`ipv6` 时加 fd00:6152::/96，持久化）但 `always-real-ip`（Host List，`-` 排除、首个匹配决定）除外，劫持 Surge 自身 DNS 地址 198.18.0.2–9 与 fd00:6152::2；代理服务器域名跳过 `[Host]`；`[Host]` 逐行首个匹配：地址列表、别名（CNAME）、`server:`（同 dns-server 写法，`system`/`syslib` 为系统解析器），键为域名、通配符（`*google.com` 含 bargoogle.com）或 `DOMAIN-SET:`/`RULE-SET:` 文件；`read-etc-hosts`（默认开）读系统 hosts；`.local` 与无点名走系统解析器；`script:` 报错，`use-local-host-item-for-proxy` 在有地址映射时警告（代理仍收到域名）。与 C.5a 一同发布。语料 288 份中 52 份原样可加载（C.5a 为 10），去掉出错行后 280 份（C.5a 为 276）；主要剩余为 policy-path（132）。C.5c 已完成（2026-09-30）：`policy-path` 为 outbound provider（URL 为 remote，直连下载，`update-interval` 默认一天、负数为不更新；否则为相对配置目录的本地文件），参数相同的组共用一个；provider 读 Surge 策略行列表或完整配置的 `[Proxy]`（及 `[WireGuard 名]` 段），检测顺序为 Clash YAML、Surge、分享链接，读不出的行按 Surge 跳过并汇总警告；成员排在组自身成员之后（与 Surge 的混合顺序不同），与配置内代理同名时两者并存。成员所经各组的 `policy-regex-filter`（本组及包含它的组）合成一条须全部匹配的组级 `filter`；有 `external-policy-name-prefix` 时本组过滤放在 provider 上（先过滤后加前缀，同 Surge），同一组内各 provider 的过滤不同时各自放在 provider 上。`external-policy-name-prefix` 为 `additional-prefix`；`external-policy-modifier` 按 Mihomo 键名进 `override`（`skip-cert-verify`、`interface`→`interface-name`、`ip-version`）与 provider `detour`（`underlying-proxy`），测速参数、`tfo`、`block-quic` 警告，其余会改变路由或安全的参数报错。组级 `underlying-proxy`：各来源的代理成员派生为 `名 (via 策略)`、经该策略拨号（组与内置策略不变，覆盖成员自身的 `underlying-proxy`），policy-path 成员同样加后缀；组经自身或经包含自身的组拨号、provider 经取用它的组拨号均报错。含 provider 的组 UDP 按成员而定，无成员时回落 DIRECT（同空组）。宿主设置 `sub_store`（`sail --sub-store`、FFI 启动设置）：主机恰为 `sub.store` 的 provider 与远程规则集 URL 换成该后端（保留路径与查询），未设置时启动/重载即报错并说明，日志只出现主机名。`#!include` URL 读宿主在缓存目录 `surge-include/` 中取回的副本（`sail --fetch-includes` 用 `sail::fetch` 下载，递归，失败保留旧副本）；无副本报错并指向该选项；`#!MANAGED-CONFIG` 仍为警告（配置自身的更新属于宿主）。`sail::fetch`：运维面的下载机制（直连或经运行中实例的出站，超时与大小上限，原子写入），core 不含任何下载地址。规则改为 leaf-80 的按需解析/嗅探：首个可能需要地址的规则前挂一个 `on_demand` resolve（有 `dns-failed` 时 `ignore_failure`），首个可能需要嗅探的规则（PROTOCOL、USER-AGENT、URL-REGEX、规则集文件）前挂一个 `on_demand` sniff；`no-resolve` 为规则的 `no_resolve`（IP-CIDR(6)、IP-ASN、GEOIP、文件规则集，逻辑规则内的子规则也带上）；extended-matching 仍在其规则前显式嗅探。语料 164 份原样可加载（C.5b 为 52），去掉出错行后 280 份；其中 policy-path 为本地文件占位的 103 份、`sub.store` 的 38 份在启动时才报错（缺文件、未设 `sub_store`）。C.5d 进行中（2026-09-30）：subnet/ssid 组为 sail 的 `network` 组（条目按序、`cellular` 在前、否则 `default`；只接受 hidden/icon-url/category），SUBNET 与 CELLULAR-CARRIER 规则为网络条件（`SSID:`/`BSSID:` 含通配符时为正则，`ROUTER:`、`TYPE:`、`MCCMNC:`；无前缀的值按其形态取网关地址、BSSID 或 SSID），网络状态由宿主推送或 sail 检测；CELLULAR-RADIO、DEVICE-NAME、MAC-ADDRESS 报错并说明原因；`[SSID Setting]` 警告（是否在某网络上运行由宿主决定）；不支持的策略类型逐一说明原因（Snell v4/v5 无公开规范、TUIC v4 请用 tuic-v5、external 由宿主运行）。`sni=off` 为 `disable_sni`（QUIC 协议上报错），`client-cert` 取 `[Keystore]` 中的 p12 条目，解为内联 PEM 的 `client_certificate`/`client_key`。后续：MANAGED-CONFIG 的定时拉取与重载（运维面，`sail --managed-update`）；ssh；policy-path 中的 WireGuard 策略。 | `config/surge/` | Surge 官方手册示例与脱敏真实配置可加载；未实现段落按分级逐条警告 |
| C.6 | 兼容性语料与报告：三种格式各有脱敏真实配置语料和上游示例；每种格式生成一张字段级支持表 | `sail/tests/`、`docs/` | 语料作为回归测试；支持表由前端 schema 生成，不手写 |

---

## P3 服务端与多用户

| # | 任务 | 涉及位置 | 验收标准 |
| --- | --- | --- | --- |
| 3.1 | 用户模型：入站按用户鉴权，身份写入 `Session`；支持的协议（SS2022、Trojan、VLESS、VMess、Hysteria2、TUIC 等）统一接入 | `user/`、`protocol/*/inbound` | 同一入站可配置多个用户；路由规则可按用户匹配 |
| 3.2 | 按用户、入站、出站统计流量与连接数 | `stats/` | 统计无全局锁热点；10 万级连接下统计开销可接受；计数在重载后不丢失 |
| 3.3 | 按用户限速、限连接数、配额与到期 | `user/`、`net/` | 限速误差和对其他用户的影响有测试；超额用户可被即时断开 |
| 3.4 | 在线管理：增删用户、增删或修改入站、证书替换，无需重启。证书、用户表、规则集共用一套可热更新资源机制（见表后说明） | `runtime/`、`service/` | 变更期间其他用户的连接不中断；变更结果原子可见；证书文件替换后新连接使用新证书，无需重启 |
| 3.5 | 管理 API：用户、入站、统计和运行状态的查询与变更；鉴权与访问控制。设计参考 sing-box 的 `ssm-api` 服务（实现 [Shadowsocks Server Management API v1](https://github.com/Shadowsocks-NET/shadowsocks-specs/blob/main/2023-1-shadowsocks-server-management-api-v1.md) 的 REST 服务：按 HTTP 路径映射到开启 `managed` 的 Shadowsocks 入站，增删用户、查询流量统计），仅作参考，不实现该服务 | `service/` | 默认仅监听 loopback 或 Unix socket；接口有版本和 schema；可对接面板或编排系统 |
| 3.6 | 服务端高并发验收 | `bench/` | 10 万并发连接、多核扩展、长时间运行下内存稳定；与 sing-box 服务端同场景对比 |

**可热更新资源（3.4）**：证书、用户表和规则集都是从配置构建、运行中会变、变化时不应重建监听或中断已有连接的数据，统一处理，不为某一种单独实现。

- **资源：** 由配置构建出的类型化数据，例如某个入站的证书链与私钥、某个入站的用户表、规则集。资源保存在无锁快照中；每个连接在握手或鉴权时读取一次当前快照，因此替换不影响已有连接。
- **来源：** 以下三种来源走同一个入口：
  - 配置重载：补上 `lib.rs` 中的 TODO，监听地址不变时只替换入站内部的资源，不重新绑定端口；
  - 文件监听：证书文件和规则文件，带去抖；
  - 管理 API（3.5）：在线增删用户。
- **替换规则：** 新数据先构建并校验；失败时保留旧值并报错，成功后原子替换。
- **资源机制已实现（2026-09-28；不等于整个在线管理平台完成）：**
  - Trojan、VLESS、AnyTLS、VMess、SS/SS2022、Hysteria2、TUIC、HTTP/SOCKS/mixed 可经配置重载或宿主 `update_inbound_resources` 更新凭据；支持普通 TLS、REALITY、QUIC、AMUX 等合法协议组合，不重新绑定端口。协议重放缓存、QUIC endpoint、已有 TCP/UDP 会话及 SOCKS 关联容量跨代保留。
  - 证书、用户表、规则集统一使用 `HotResource<T>`。`auto-reload` 通过父目录监听与 250ms 去抖处理配置、证书/私钥及本地规则文件，支持原子替换；所有候选先校验，失败保留旧资源。
  - 原子发布以单个入站为单位。任意监听结构迁移、扩展入站依赖图和 3.5 的 HTTP 管理平台不在本次资源实现中；现有 add/remove API 继续提供显式入站生命周期管理。具体协议语义、边界与测试见 [入站资源热更新](inbound-resource-reload.md)。

---

## P4 宿主集成与生态

| # | 任务 | 涉及位置 | 验收标准 |
| --- | --- | --- | --- |
| 4.1 | 移动端 FFI：流量统计、连接列表与关闭、日志回调、节点测速、切换节点、网络变化、运行状态、capability 查询 | `sail-ffi` | App 不经过 HTTP API 即可控制内核；回调线程、内存所有权、取消与错误消息有明确契约 |
| 4.2 | FFI 健壮性 | `sail-ffi` | 多实例、重复启动/停止、回调重入和 App 异常退出不会死锁或泄漏；Swift/Kotlin 封装有集成测试 |
| 4.3 | **部分完成（2026-09-29）** 服务端守护进程 | 已有非 root systemd unit、独立 TUN capability drop-in、安全安装/卸载、配置预检、便携自测与 Linux 验收脚本；真实 systemd PID 1 生命周期尚未验收，当前只支持 SIGTERM 停止而无连接排空或 `ExecReload` | 在一次性 Linux systemd 环境完成验收；优雅退出时等待连接排空；提供明确重载命令/信号且失败时保持旧配置运行 |
| 4.4 | 路由器打包：OpenWrt 等发行版、低内存预算预设、按需裁剪 feature（待评估，均需先在测试机实测：① 内核按内存自动设的 TCP 缓冲上限（512 MB 约 4 MiB、256 MB 约 2 MiB）把单条 TCP 连接在 100 ms 往返下限在约 100–200 Mbit/s，与 mux 窗口无关；可选由 sail 以 root 只给上游代理连接设更大的接收缓冲（SO_RCVBUFFORCE），或由安装包调大 sysctl，或建议路由器优先用 Hysteria2 / TUIC（实测不受此限）；② router profile 下 Hysteria2 每流窗口固定 8 MiB，4 条卡住的流即占满 32 MiB 连接窗口、整条连接冻结至多 60 s，可改为 4 MiB，代价是 250 ms 往返下单流约 130 Mbit/s；实测数据未入库） | `scripts/`、发布流程 | 在目标低内存设备上长时间运行不 OOM；包体积有记录 |
| 4.5 | **基本完成（2026-09-30）** Clash API 基础兼容：`/version`、`/configs`、`/proxies`、节点切换和 delay（第 1 步已完成：返回格式按 Mihomo，配置为顶层 `clash_api`（sing-box 的 `experimental.clash_api` 同样读取，两处都写即报错）；`/version`、`/configs`（修改只接受 `mode` 与 `log-level`，模式按 sing-box 从规则收集，切换时清空 DNS 缓存并存入 cache_file）、`/proxies` 与 `/group`（列出、选择、单个与整组测延迟，延迟历史保留 10 条，另给 sing-box 式的 `GLOBAL`）、`/traffic`、`/memory`、`/logs`（WebSocket 或逐行 JSON）、`/dns/query`、`/cache/fakeip/flush`、`/cache/dns/flush`、`/ui` 静态面板。第 2 步已完成：见 4.6。第 3 步已完成：`/providers/proxies`（列出、单个成员、更新、健康检查与单个成员测延迟，provider 的成员按名字出现在 `/proxies` 中，供取用它们的组查到）与 `/providers/rules`（规则集按 Mihomo 的规则 provider 列出，含类型、行为、格式、条目数、更新时间；远程规则集可手动更新）。第 4 步已完成：`external_ui` 为空时自动下载面板 ZIP（经 `external_ui_download_detour` 或默认出站，去掉 GitHub 归档的顶层目录后整体替换），核心不内置下载地址，未配置时由宿主给出（sail-cli 默认 metacubexd，`--ui-download-url` 可改或置空），`POST /upgrade/ui` 重新下载；`PUT /configs` 从配置文件重载，拒绝 path/payload。metacubexd 与 Yacd-meta 均可自动下载并提供；面板用到的 REST 与 WebSocket 接口已按面板的调用顺序逐一核对。剩余：接入浏览器后做真实面板的界面操作验收。不做：`/upgrade`（升级内核属宿主，按核心与 CLI 的分层）；暂不做：`/restart`、`/debug`） | `service/clash_api/` | yacd、metacubexd 可读取配置、展示并切换节点 |
| 4.6 | **基本完成（2026-09-30）** `/connections`（快照，或 WebSocket 按 `?interval=` 毫秒推送，默认 1000）列出进行中的连接，`chains` 按 Mihomo 从实际走的成员到规则选中的出站，`rule` 为 sing-box 式的“条件 => 动作”；`DELETE /connections` 与 `/connections/:id` 关闭连接（在统计包装层让读写以 ConnectionAborted 失败，UDP 同样）；`/rules` 按 sing-box 返回 type/payload/proxy。`/providers/proxies` 见 4.5 第 3 步。连接的 `rulePayload` 暂为空串（规则的条件文字已在 `rule` 中）。剩余：真实面板的界面操作验收（同 4.5）。原计划：Clash API 实时与管理接口：WebSocket `/traffic`、`/logs`、`/connections`，连接关闭、`/rules`、`/providers/proxies` | `service/clash_api/` | 用真实面板做端到端测试，而不只验证单个 URL |
| 4.7 | **已完成（2026-09-30）** API 安全与状态（secret 必须设置且为强 key，至少 32 个字符、10 种不同字符，否则 Clash API 不启动并给出警告，其余照常运行；`sail generate secret` 生成；认证用 `Authorization: Bearer`，WebSocket 可用 `?token=`；CORS 按 `access_control_allow_origin`，默认任意来源，另有 `access_control_allow_private_network`；节点选择与模式存入 cache_file） | `service/`、selector、FakeIP | 默认仅监听 loopback；支持 secret/CORS；节点选择等必要状态可持久化 |
| 4.8 | **进行中（2026-09-29）** provider 管理。已完成运行时（`outbound-provider` 特性，sail 扩展 `outbound_providers`）：remote 按远程规则集的方式下载（`http_client`/`download_detour`、缓存与 ETag、失败 5 分钟后重试，默认每天更新），local 读文件并可按 `update_interval` 重读，inline 直接写 sing-box 出站；内容按 Mihomo 读取（Clash YAML 的 `proxies` 或分享链接），支持 `filter`/`exclude_filter`/`exclude_type`/`override`/`detour`（即 dialer-proxy）。组的 `providers` 成员接在自身 `outbounds` 之后，`filter` 只过滤 provider 成员（多过滤器按 Mihomo 两遍排序），`exclude_filter`/`exclude_type`（按 Mihomo 类型名）对全部成员生效，全空时用 `empty_fallback`，没有则连接报错。更新失败保留旧成员；未变且无 detour 的成员沿用原 handler（QUIC/mux 连接池不断），被替换的成员在无人持有后停止其任务；reload 时配置未变的 provider 连同成员与下载状态一并保留。urltest 在成员变化时保留仍健康的当前选择，新成员尽快测速；load-balance 一致性哈希改为按成员 key 的 rendezvous 哈希，移除一个成员只移动它自己的会话；selector 的 `default` 与重启前的选择可指向 provider 成员，成员出现后生效。待做：Clash 前端（C.4c-3）、宿主/API 侧的手动更新与状态查询、健康检查由组负责（Mihomo 的 provider `health-check` 不进模型） | 配置与宿主层 | 订阅下载、更新、健康检查、过滤和原子切换可由宿主控制 |
| 4.9 | **已完成（2026-09-30）** 资源文件管理（分层：core 只提供机制，不含任何下载地址）：`sail::assets::required` 列出配置读取的 `asn.mmdb`、`geo.mmdb`、`site.dat` 及规则指定的文件（路由/DNS 规则的 `geoip`、`geosite`、`external`、`ip_asn`，内联规则集，`smart` 组的 `prefer_asn`/`asn_file`），按路径去重并给出读取字段；与加载共用文件选择与路径解析（顺带修正相对数据目录下 `geoip` 路径被拼接两次）；缺文件报错给出路径与获取方式；下载经 `sail::fetch`，按 MaxMind 数据库或站点列表校验通过才原子替换。宿主设置 `asset_sources`（StartSettings 同名字段）。sail-cli：`sail assets <config>` 列表，`--fetch`/`--update`/`--source name=url`，启动前 `--fetch-assets`，`--asset-source`；默认来源在 CLI：asn.mmdb 同 Mihomo（MetaCubeX GeoLite2-ASN），geo.mmdb 为 Loyalsoldier Country.mmdb（GeoLite2-Country 格式），site.dat 为 Loyalsoldier geosite.dat。运行时 API：`GET /api/v1/runtime/assets`、`POST /api/v1/runtime/assets/{name}/update`（`url`/`detour` 可选，替换后重载生效）。FFI：`sail_required_assets`。未做：从文件读取或下载的规则集内容所需的 `asn.mmdb` 无法静态得知，仍由加载时报错指出；定时自动更新 | `sail/src/assets.rs`、`sail-cli`、`app/api`、`sail-ffi` | 缺文件时报错可操作；CLI 与 API 下载后规则按新文件匹配；坏文件不替换旧文件 |

---

## P5 工程质量、性能与发布（持续进行）

| # | 任务 | 现状 | 目标 |
| --- | --- | --- | --- |
| 5.1 | **已完成（2026-09-26；2026-09-29 补回归）** 清理 `.unwrap()` / panic | 非测试代码 216 处降到 60 处，剩余均为写明理由的不变量；FFI 入口全部 `catch_unwind`；fuzz 发现的 duration 浮点转换/累加溢出已改为 checked 错误并启用回归 | 数据通路、配置、DNS、协议解析、入站鉴权和 FFI 不因外部输入退出进程；显式处理 `panic!` / `unimplemented!` |
| 5.2 | **部分完成（2026-09-26）** 补测试 | 协议双向互操作（对 sing-box 1.13.12 / Xray）、Reality、多用户、回落、DNS 上游已有自动测试；测试全部使用系统分配的端口和独立临时目录，可并行运行；路由、TUN、网络生命周期仍缺 | DNS、路由、TUN、Reality、协议双向互操作、多用户和网络生命周期都有自动测试 |
| 5.3 | **已完成基线（2026-09-29）** 模糊测试 | 独立的 cargo-fuzz workspace（保存在仓库外，不公开）有配置、订阅、source/binary 规则集、DNS、嗅探、TUIC/XUDP 入站解析共 8 个 cargo-fuzz target；有界语料、稳定回归、ASan campaign/replay；运行日志与证据不进仓库 | 持续延长 campaign、扩充真实且脱敏的协议语料；新 crash 先最小化并固化为默认回归 |
| 5.4 | 性能回归 CI | 目前为手动 benchmark | 移动端、桌面、服务端、路由器四种预算都有可比较基线；吞吐、CPU、内存或分配次数超阈值即告警 |
| 5.5 | **部分完成（2026-10-01）** 长稳与弱网测试：`scripts/netem`（两个 netns + netem，netgen 发送带校验的流量；延迟、突发与随机丢包、乱序、限速、断网与断链、服务端重启、2000 并发与短连接、双向半关闭）。第一阶段（直连 / SS2022 / Trojan，sail 两档与 sing-box 对照）：零损坏，断网恢复 ≤1.1s，2000 并发全部存活；发现并修复监听遇 EMFILE 永久停止、CLI 不提升文件描述符上限；sing-box 1.13 不保留半关闭（sail 之间两向均通过）。第二阶段（REALITY、Hysteria2、TUIC、多路复用、TUN 路径、sail 作服务端）与 24 小时运行待做 | `scripts/netem` | 零损坏、不崩溃；断网恢复 3 秒内（2.12 验收）；2000 并发全部建立并存活；半关闭两向完整送达；吞吐取 3 次中位数，不低于 sing-box 的 0.8 倍，限速链路不低于链路速率的 90%；回显延迟 p50 不高于 sing-box 10%、p99 不超过其 1.5 倍；每个场景后文件描述符回到空闲基线；24 小时内第 2 至 24 小时内存增长低于 10%；并发内存峰值不超过 sing-box；短连接零失败、p99 不超过 sing-box 的 2 倍 |
| 5.6 | **部分完成（2026-09-29）** 安全 | 已有依赖来源、RustSec、许可证门禁和只读 CI；根锁文件纳入版本控制，3 个漏洞和直接 `lru` unsound 路径已升级，audit 无漏洞；第一方统一 Apache-2.0，`webpki-root-certs/CDLA` 与 `tun/WTFPL` 采用精确例外并随发布提供全文；`quinn-btls -> lru 0.16.4` 和 `paste` 警告仍未闭环；已知风险：quinn 0.11 的 endpoint 在 UDP 接收遇到 ConnectionReset 以外的错误时整个失效（实际只有 ENOMEM 能触发），修法是包一层带退避的 AsyncUdpSocket，或改在我们的 quinn-btls fork 里 | 推进 fork/TUN 上游依赖；补入站抗探测和资源耗尽防护、订阅和规则下载限流/大小限制/超时/路径约束、日志脱敏 |
| 5.7 | 配置参考文档 | 只有 README 和 MPTP 文档 | 原生格式（sing-box JSON 及 sail 扩展字段）有逐字段文档、示例和 schema，由 options 类型生成；Clash 与 Surge 用 C.6 生成的支持表；变更采用一次性迁移，不保留并行版本 |
| 5.8 | 跨平台发布 | 已有部分 Apple/Android 构建脚本 | 自动产出 XCFramework、AAR、桌面、服务端和路由器二进制；记录符号、包体积、依赖和可重复构建信息 |
| 5.9 | **已完成（2026-10-01）** 处理 TODO / FIXME | 代码中已无 TODO/FIXME。已修：SOCKS5 拒绝请求时按 RFC 1928 回复（不支持的命令回 0x07），保留字节照 sing-box 忽略；Shadowsocks UDP 一次分配封包；TLS 协商 ALPN 的行为用测试固定（同 sing-box）。照 sing-box：Trojan UDP 包长度后的 CRLF 跳过不检查。转负责人：假 DNS 查询名校验、重载时重建假 DNS（DNS）；NetFilter 函数指针跨线程串行、`TCP_INFO` 过期、UDP 转发的入站 tag 取自配置（Windows）；Shadowsocks 插件首包合并需扩展插件接口（暂无负责人）；amux 待移除，不修 | 逐项处理，或转成带优先级的 issue |
| 5.10 | 与上游的关系 | 已同步到 `5e8d947` | 按 D5 的结论执行；P0.2 之后文件结构与上游不再对应，上游修复按需人工移植并跑回归矩阵 |
| 5.11 | **已完成（2026-09-26）** 代码规范门禁 | CI 此前只跑默认 feature 的测试 | CI 检查 `cargo fmt --check`、全仓库 `clippy -D warnings`（macOS 与 Linux），以及一组最小 feature 组合的无警告编译 |
| 5.12 | 定期检查浏览器指纹（**由用户手动执行**，约每月一次，或在浏览器发布大版本时） | 各 profile 只对应一个浏览器版本：chrome 154（桌面与 Android 相同）、firefox 156、safari 26.3（iOS 26 相同）、android（OkHttp 4.12 + Android 17 Conscrypt） | 每个 profile 都与该浏览器最新正式版的 ClientHello 一致；抓包与 fixture 不同时更新 profile 和 fixture，旧 fixture 删除（见下方说明） |

**5.12 检查方法：**
1. **抓包。** 运行 `scripts/capture-client-hello.py <port> <前缀>`，它只保存每个连接的首个 ClientHello，让浏览器用全新 profile 访问 `https://localhost:<port>/`，每个浏览器抓 2–3 次。
   - Chrome：用官方 stable dmg，把 app 复制出 dmg 后加 `--headless=new --use-mock-keychain` 运行。**不要**用 Chrome for Testing，它会多发实验性扩展 `0x12e0`。
   - Firefox：挂载官方 dmg 后 headless 运行，`user.js` 里设置 `network.proxy.type` 为 0。
   - Safari：`open -g -a Safari <url>`；也可以跑一个 ephemeral URLSession，两者的 ClientHello 相同。
   - Android：需要 x86 或 x86_64 的 Android 模拟器（M1 Mac 上的模拟器拿不到 HVF，可以在 PVE 上开启嵌套 KVM 的 VM 里跑）。OkHttp 用 `app_process` 运行一个 dex 化的小程序；Chrome 用 APKMirror 上 x86 的独立包。
2. **比较。** 把抓包放进 `sail/tests/fixtures/tls/`，运行 `cargo test -p sail --lib transport::tls`。对比测试会逐项报出差异：JA4、密码套件、扩展集合与顺序、groups、签名算法、key share，以及其余每个扩展的内容。
3. **更新。** 有差异时修改 `sail/src/transport/tls/fingerprint.rs` 中对应的 profile，替换 fixture，并更新 fixture README 和 `docs/tls-fingerprint-research.md` 的记录。浏览器新增了 BoringSSL 不支持的扩展时，需要在 btls fork 的 `fingerprint.patch` 里补上。

## 不作为近期目标

- 不为了数字上的功能齐全而复制 sing-box / Mihomo 的全部协议；范围以 P1「支持分级」为准。
- 不长期维护多套配置、FFI 或缓存格式。
- 不实现 Surge 的 MITM、Script、URL Rewrite 等体验类功能；这些配置按 PC 的分级规则警告后忽略。
- 不用单一 microbenchmark 代表真机、路由器或服务端的最终表现。

## 优先级说明

- P0.1 决定 Sail 能否在所有环境下同时获得合理吞吐和资源占用。
- P0.2 决定后续所有扩展是只加不改，还是每次都要修改核心；必须先于 P1 的新协议开发。
- P1 决定协议能不能双向连通，Sail 能不能同时作为客户端和服务端。
- P2 决定流量是否被正确、稳定且无泄漏地转发。
- PC 决定用户能否不做转换，直接用现有的 sing-box、Clash / Mihomo、Surge 配置和订阅。
- P3 决定 Sail 能否作为可运营的服务端。
- P4 决定各类宿主和现有生态能否可靠控制内核。
- P5 贯穿所有阶段；每项新功能合并前必须带互操作、异常路径和适当的性能测试。
