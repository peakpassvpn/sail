# Sail 迭代计划

- 基线：eycorsican/leaf `5e8d947`（2026-09-10）
- 定位：**统一代理平台**。客户端（iOS / Android / 桌面）、服务端和路由器共用同一个内核，由不同宿主接入
- 对标：sing-box（平台能力与扩展性）、Mihomo（客户端生态）
- 架构调研与目标结构：[`architecture-research.md`](architecture-research.md)

## 原则

- **核心不绑定宿主**：内核只依赖抽象的平台能力（接口监控、TUN fd、socket protect、进程查找），由移动端 FFI、服务端守护进程、路由器打包各自注入；启动流程里不写任何宿主专属逻辑。
- **一套核心，多种资源预算**：移动端关注 footprint 和生命周期，路由器关注低内存，桌面端和服务端关注吞吐、并发与多核扩展；预算通过配置选择，不为不同平台维护分叉实现。
- **扩展只加不改**：新增协议、传输层、规则条件、DNS 上游或服务时，只新增模块并在注册表登记，不修改核心文件。
- **协议对称**：主流协议同时提供入站和出站，Sail 自身可以作为这些协议的服务端。
- **性能与功能同时验收**：新协议和新传输层不仅验证连通性，还要验证吞吐、CPU、并发内存和长稳表现。
- **单一配置与接口契约**：每个组件的 options 只有一个强类型定义；其他格式（`.conf`、Clash、分享链接）一律作为导入器。破坏性变更一次性迁移，能力差异通过 capability 查询显式暴露。
- **按真实需求排优先级**：客户端协议以脱敏订阅样本统计排序，服务端能力以实际部署需求排序，不机械复制 sing-box / Mihomo 的全部功能。

## 总览

| 阶段 | 主题 | 目标 | 预估 |
| --- | --- | --- | --- |
| P0 | 性能基线与平台架构 | 消除转发缓冲区瓶颈；建立注册表、分层和生命周期，让后续扩展只加不改 | 缓冲池 1–2 周；架构重构 6–10 周 |
| P1 | 协议与传输 | 主流协议入站、出站双向可用，与 Xray / sing-box 互通 | 8–12 周 |
| P2 | DNS、路由与网络 | DNS 不污染、规则准确、IPv4 / IPv6 和网络切换可靠 | 6–10 周 |
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
| 0.2.2 | 单一配置契约 | 按 D1 的结论实现强类型 options，JSON 字段对齐 sing-box，共享的 Dial / Listen / TLS / Transport / Mux 选项可复用；`.conf`（兼容 Surge）和 Clash YAML 作为输入格式转换到同一模型 | 每个字段只定义一次；配置检查能指出错误字段的完整路径 |
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
| 高 | HTTP；Shadowsocks 2022；Hysteria2；TUIC v5；AnyTLS；WireGuard；VLESS 补齐 XUDP / packetaddr；VMess 补齐 `auto` / `none` / `zero` 与 XUDP |
| 中 | ShadowTLS v3；VLESS encryption（ML-KEM）；NaiveProxy；SSH；Mieru、Sudoku、TrustTunnel、MASQUE、ShadowQUIC（观察） |
| 低 | Snell；Tailscale、ZeroTier、EasyTier、OpenVPN、OpenConnect、Tor |
| 不支持 | ShadowsocksR；Shadowsocks 流加密；VMess legacy（alterId > 0）；Hysteria v1；gost-relay |

**入站**

| 优先级 | 项目 |
| --- | --- |
| 高 | mixed；HTTP 认证；SOCKS 多用户；Shadowsocks 2022（多用户）；VLESS + REALITY + Vision；Hysteria2；TUIC；AnyTLS；Trojan fallback；redirect / TProxy |
| 中 | VMess；ShadowTLS v3；NaiveProxy；tunnel（端口转发）；随出站跟进的新协议 |
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
| 中 | DHCP 上游；ECS |
| 不支持 | mDNS；systemd-resolved 集成 |

**策略组**

| 优先级 | 项目 |
| --- | --- |
| 高 | select 默认启用；URLTest（含 tolerance）；load-balance（一致性哈希、sticky-sessions） |
| 中 | chain 中各协议的 UDP 贯通 |

### 私有协议整合

- 最终只保留一个私有协议：ppvpn-peer（Noise_NNpsk0 + yamux + 路由帧头）。
- ppvpn-peer 在 Sail 接管 ppvpn node 数据面时实现，作为独立 feature 模块，不进入通用协议列表；路由、计费和出口 IP 选择通过扩展接口交给宿主，Sail 只负责握手、复用和帧头解析。
- 现有私有协议 amux、mptp 和私有 quic 传输，在 ppvpn-peer、通用多路复用（1.8）和 Hysteria2 / TUIC 落地后移除。

### 任务

| # | 任务 | 涉及位置 | 验收标准 |
| --- | --- | --- | --- |
| 1.1 | **已完成（2026-09-26）** TLS 指纹伪装：外层 ClientHello 模拟主流浏览器（Chrome / Safari / Firefox），技术选型与实现。证书热更新并入 3.4 | `transport/tls/` | TLS 后端为 BoringSSL（btls fork）；普通 TLS 与 Reality 出站默认使用 Chrome 指纹；每个 profile 都有抓包 fixture，JA4 和各扩展内容与目标浏览器一致，普通 TLS 和 Reality 都已验证，WS 共用同一个 TLS 出站；gRPC 待 1.7 实现后补测 |
| 1.2 | **已完成（2026-09-26）** Shadowsocks 2022（`2022-blake3-aes-128-gcm` / `2022-blake3-aes-256-gcm` / `2022-blake3-chacha20-poly1305`），TCP 和 UDP，入站支持多用户（EIH） | `protocol/shadowsocks/` | 与 sing-box / shadowsocks-rust 双向互通；覆盖重放保护、盐和 UDP 会话测试 |
| 1.3 | **已完成（2026-09-26）** VLESS / Reality / Vision 双向：`flow` 可配置，支持无 Vision、Vision、UDP，明确 XUDP / UoT 策略；补齐 VLESS 入站和 Reality 服务端（含 XUDP） | `protocol/vless/`、`transport/reality/` | 不再硬编码 flow；与 Xray / sing-box 建立入站 × 出站组合测试矩阵 |
| 1.4 | **已完成（2026-09-26）** VMess 入站（含出站 `auto` / `none` / `zero`；legacy alterId 不支持） | `protocol/vmess/` | 与 Xray / sing-box 客户端互通；AEAD 头、重放保护有测试 |
| 1.5 | **已完成（2026-09-26）** Hysteria2 入站与出站，含 Salamander 混淆、端口跳跃、带宽与拥塞控制参数（Brutal 为近似实现，quinn 无 pacing 钩子） | `protocol/hysteria2/`，评估复用现有 quinn | 与官方实现双向互通；TCP、UDP、弱网和连接迁移场景可用 |
| 1.6 | **已完成（2026-09-26）** TUIC 入站与出站（`udp_over_stream` 未实现） | `protocol/tuic/` | 与主流实现双向互通；TCP、UDP 和拥塞控制参数生效 |
| 1.7 | **已完成（2026-09-26）** V2Ray 传输层：HTTP、gRPC、HTTPUpgrade；补齐 WebSocket early-data；入站和出站都支持（HTTP/2 传输按分级不支持；gRPC 出站暂为一流一连接） | `transport/` | VLESS / VMess / Trojan 与 Xray、sing-box 双向互通 |
| 1.8 | **已完成（2026-09-26）** 通用多路复用：smux / yamux / h2mux，入站和出站；按需求决定是否实现 TCP Brutal（兼容 sing-mux，默认 h2mux；含 UoT v2；TCP Brutal 未做） | `transport/mux/` | 与 sing-box / Mihomo 互通；高并发下不会因池化叠加导致内存失控 |
| 1.9 | **已完成（2026-09-26）** 出站组：默认启用 select，补齐 URLTest、fallback、load-balance 和选择持久化（selector / urltest / load-balance；failover 待整合） | `protocol/group/` | 手动选择、自动测速、故障切换和重启恢复都有测试 |
| 1.10 | 统一拨号选项：IP 策略、接口绑定、detour、连接/空闲超时、TCP Fast Open、MPTCP、UDP over TCP | `net/`、共享 Dial options | 各协议共享同一实现，按出站配置，不重复实现 socket 与网络选择逻辑 |
| 1.11 | **已完成（2026-09-26）** 入站防探测与回落：Trojan / VLESS fallback，鉴权失败时的行为可配置（字段对齐 sing-box `fallback` / `fallback_for_alpn`） | `protocol/trojan/`、`protocol/vless/` | 未通过鉴权的连接可回落到指定目标；主动探测下行为与主流实现一致 |
| 1.12 | 分享链接导入：`ss://`、`trojan://`、`vless://`、`vmess://`、`hy2://`、`tuic://` | `config/` | 真实节点语料可导入；错误字段有可诊断提示；敏感信息不进入日志 |

所有协议任务都必须加入统一性能场景，入站和出站分别测试，避免新增协议重新引入连接级常驻大缓冲或无上限缓存。

---

## P2 DNS、路由与网络

### DNS

| # | 任务 | 涉及位置 | 验收标准 |
| --- | --- | --- | --- |
| 2.1 | 结构化 DNS 上游和规则：按域名、query type、入站、规则集选择服务器；支持 detour 与 IPv4/IPv6 strategy | `dns/` | 国内外 DNS 分流正确，节点域名解析无递归环，无 DNS 泄漏 |
| 2.2 | 内置 DNS listener 和 TUN DNS hijack | `dns/`、`protocol/tun/` | UDP/TCP 53 查询均可劫持；`hijack-dns` 动作可测试 |
| 2.3 | **部分完成（2026-09-26）** 加密 DNS：在现有 DoH 基础上补连接复用，并按需要增加 DoT、DoQ、DoH3；每种上游按注册表接入（DoT / DoQ / DoH3 已完成；DoH 连接复用未做） | `dns/transport/` | bootstrap、证书校验、代理/直连 detour 和失败回退行为明确 |
| 2.4 | DNS 缓存可配置：容量、TTL、negative cache、独立缓存、清理和统计 | `dns/`、管理 API | 命中率可观察；切网和配置重载不会返回错误网络下的陈旧结果 |
| 2.5 | FakeIP 完整化：IPv4/IPv6 地址池、TTL、过滤、容量与持久化 | `dns/transport/fakeip` | 支持 A/AAAA；重启后按配置恢复或安全重建；地址回收无错误映射 |

### 路由、规则集与嗅探

| # | 任务 | 涉及位置 | 验收标准 |
| --- | --- | --- | --- |
| 2.6 | rule-set 远程下载、定时更新、本地缓存、大小限制和原子替换 | `route/rule_set/` | 更新失败继续使用旧规则；下载可指定出站；不允许任意路径写入 |
| 2.7 | 支持 sing-box `.srs` 导入 | `config/` | 导入后转换为 Sail 内部规则，不让运行时路由器长期耦合外部格式 |
| 2.8 | 逻辑规则 and/or/not，以及 source IP/port、用户、入站类型、进程路径、package、uid、IP version、ASN、网络类型等常用条件 | `route/rule/` | 每种条件一个模块；与选定的 sing-box / Mihomo 规则样例得到一致结果 |
| 2.9 | 路由动作补齐：route、reject、hijack-dns、sniff、resolve、bypass 和 route options | `route/` | 动作可组合，错误组合在配置检查阶段失败 |
| 2.10 | 嗅探补齐并可配置覆盖目标：HTTP、TLS、QUIC、DNS | `sniff/` | 有长度限制、超时和模糊测试；不能由异常报文触发 panic 或无限缓存 |

### TUN 与平台网络

| # | 任务 | 涉及位置 | 验收标准 |
| --- | --- | --- | --- |
| 2.11 | TUN IPv4/IPv6、MTU、UDP NAT timeout、ICMP/ICMPv6 和 DNS 劫持完整性 | `protocol/tun/`、netstack | iOS、Android、macOS、Linux 上 TCP/UDP/IPv6 测试通过 |
| 2.12 | 网络生命周期：Wi-Fi/蜂窝切换、IPv6-only/NAT64、锁屏恢复、休眠唤醒、captive portal | `platform/`、`runtime/` | 宿主通知网络变化后，旧连接按策略关闭或重建，3 秒内恢复新连接；不会复用错误接口上的 DNS 或出站连接 |
| 2.13 | Android 分应用代理 | Android 侧与 `Session` 元数据 | package/uid include/exclude 生效，并明确哪些逻辑属于 VpnService、哪些属于内核 |
| 2.14 | **部分完成（2026-09-26）** 桌面与路由器原生路由管理：Linux netlink、macOS routing socket、`strict_route`；Linux 透明代理（TProxy / redirect）（Linux TProxy / redirect 已完成；原生路由管理未做） | `platform/`、`protocol/redirect/` | 开关 TUN、异常退出和重启后路由表可恢复，无流量泄漏；路由器透明代理 TCP / UDP 可用 |

---

## P3 服务端与多用户

| # | 任务 | 涉及位置 | 验收标准 |
| --- | --- | --- | --- |
| 3.1 | 用户模型：入站按用户鉴权，身份写入 `Session`；支持的协议（SS2022、Trojan、VLESS、VMess、Hysteria2、TUIC 等）统一接入 | `user/`、`protocol/*/inbound` | 同一入站可配置多个用户；路由规则可按用户匹配 |
| 3.2 | 按用户、入站、出站统计流量与连接数 | `stats/` | 统计无全局锁热点；10 万级连接下统计开销可接受；计数在重载后不丢失 |
| 3.3 | 按用户限速、限连接数、配额与到期 | `user/`、`net/` | 限速误差和对其他用户的影响有测试；超额用户可被即时断开 |
| 3.4 | 在线管理：增删用户、增删或修改入站、证书替换，无需重启。证书、用户表、规则集共用一套可热更新资源机制（见表后说明） | `runtime/`、`service/` | 变更期间其他用户的连接不中断；变更结果原子可见；证书文件替换后新连接使用新证书，无需重启 |
| 3.5 | 管理 API：用户、入站、统计和运行状态的查询与变更；鉴权与访问控制 | `service/` | 默认仅监听 loopback 或 Unix socket；接口有版本和 schema；可对接面板或编排系统 |
| 3.6 | 服务端高并发验收 | `bench/` | 10 万并发连接、多核扩展、长时间运行下内存稳定；与 sing-box 服务端同场景对比 |

**可热更新资源（3.4）**：证书、用户表和规则集都是从配置构建、运行中会变、变化时不应重建监听或中断已有连接的数据，统一处理，不为某一种单独实现。

- **资源：** 由配置构建出的类型化数据，例如某个入站的证书链与私钥、某个入站的用户表、规则集。资源保存在无锁快照中；每个连接在握手或鉴权时读取一次当前快照，因此替换不影响已有连接。
- **来源：** 以下三种来源走同一个入口：
  - 配置重载：补上 `lib.rs` 中的 TODO，监听地址不变时只替换入站内部的资源，不重新绑定端口；
  - 文件监听：证书文件和规则文件，带去抖；
  - 管理 API（3.5）：在线增删用户。
- **替换规则：** 新数据先构建并校验；失败时保留旧值并报错，成功后原子替换。
- **现状（2026-09-26）：**
  - 配置重载只覆盖 DNS、出站和路由；
  - 要替换入站证书，只能通过 API 删除后重新添加入站，端口会被重新绑定，中间有短暂时间拒绝新连接；
  - btls 的 TLS 入站 Handler 只持有一个 `SslAcceptor`，届时改为从快照读取即可。

---

## P4 宿主集成与生态

| # | 任务 | 涉及位置 | 验收标准 |
| --- | --- | --- | --- |
| 4.1 | 移动端 FFI：流量统计、连接列表与关闭、日志回调、节点测速、切换节点、网络变化、运行状态、capability 查询 | `sail-ffi` | App 不经过 HTTP API 即可控制内核；回调线程、内存所有权、取消与错误消息有明确契约 |
| 4.2 | FFI 健壮性 | `sail-ffi` | 多实例、重复启动/停止、回调重入和 App 异常退出不会死锁或泄漏；Swift/Kotlin 封装有集成测试 |
| 4.3 | 服务端守护进程：systemd 集成、信号处理（重载 / 优雅退出）、日志轮转、配置检查命令 | `sail-cli` | 优雅退出时等待连接排空；重载失败保持旧配置运行 |
| 4.4 | 路由器打包：OpenWrt 等发行版、低内存预算预设、按需裁剪 feature | `scripts/`、发布流程 | 在目标低内存设备上长时间运行不 OOM；包体积有记录 |
| 4.5 | Clash API 基础兼容：`/version`、`/configs`、`/proxies`、节点切换和 delay | `service/clash_api/` | yacd、metacubexd 可读取配置、展示并切换节点 |
| 4.6 | Clash API 实时与管理接口：WebSocket `/traffic`、`/logs`、`/connections`，连接关闭、`/rules`、`/providers/proxies` | `service/clash_api/` | 用真实面板做端到端测试，而不只验证单个 URL |
| 4.7 | API 安全与状态 | `service/`、selector、FakeIP | 默认仅监听 loopback；支持 secret/CORS；节点选择等必要状态可持久化 |
| 4.8 | provider 管理 | 配置与宿主层 | 订阅下载、更新、健康检查、过滤和原子切换可由宿主控制 |

---

## P5 工程质量、性能与发布（持续进行）

| # | 任务 | 现状 | 目标 |
| --- | --- | --- | --- |
| 5.1 | 清理 `.unwrap()` / panic | 非测试代码约 328 处 `.unwrap()`，release 为 `panic = "abort"` | 数据通路、配置、DNS、协议解析、入站鉴权和 FFI 不因外部输入退出进程；显式处理 `panic!` / `unimplemented!` |
| 5.2 | 补测试 | `sail/tests` 主要覆盖链式代理和 Trojan | DNS、路由、TUN、Reality、协议双向互操作、多用户和网络生命周期都有自动测试 |
| 5.3 | 模糊测试 | 无 | 对协议解析（入站方向优先，直接暴露给公网）、DNS 报文、嗅探、订阅和规则集导入做 cargo-fuzz |
| 5.4 | 性能回归 CI | 目前为手动 benchmark | 移动端、桌面、服务端、路由器四种预算都有可比较基线；吞吐、CPU、内存或分配次数超阈值即告警 |
| 5.5 | 长稳与弱网测试 | 无 | 24 小时运行，以及延迟、丢包、乱序、断网重连、高并发和半关闭场景通过 |
| 5.6 | 安全 | 无统一检查 | 依赖漏洞/许可证检查；入站抗探测和资源耗尽防护；订阅和规则下载有限流、大小限制、超时、路径约束；日志脱敏 |
| 5.7 | 配置参考文档 | 只有 README 和 MPTP 文档 | 单一配置契约有逐字段文档、示例和 schema，由 options 类型生成；变更采用一次性迁移，不保留并行版本 |
| 5.8 | 跨平台发布 | 已有部分 Apple/Android 构建脚本 | 自动产出 XCFramework、AAR、桌面、服务端和路由器二进制；记录符号、包体积、依赖和可重复构建信息 |
| 5.9 | 处理 TODO / FIXME | 49 处 | 逐项处理，或转成带优先级的 issue |
| 5.10 | 与上游的关系 | 已同步到 `5e8d947` | 按 D5 的结论执行；P0.2 之后文件结构与上游不再对应，上游修复按需人工移植并跑回归矩阵 |

## 不作为近期目标

- 不为了数字上的功能齐全而复制 sing-box / Mihomo 的全部协议；范围以 P1「支持分级」为准。
- 不长期维护多套配置、FFI 或缓存格式。
- 不承诺完全兼容任意 Clash 配置；Clash 只作为导入格式，优先支持实际需要的订阅、规则和 API 子集。
- 不用单一 microbenchmark 代表真机、路由器或服务端的最终表现。

## 优先级说明

- P0.1 决定 Sail 能否在所有环境下同时获得合理吞吐和资源占用。
- P0.2 决定后续所有扩展是只加不改，还是每次都要修改核心；必须先于 P1 的新协议开发。
- P1 决定协议能不能双向连通，Sail 能不能同时作为客户端和服务端。
- P2 决定流量是否被正确、稳定且无泄漏地转发。
- P3 决定 Sail 能否作为可运营的服务端。
- P4 决定各类宿主和现有生态能否可靠控制内核。
- P5 贯穿所有阶段；每项新功能合并前必须带互操作、异常路径和适当的性能测试。
