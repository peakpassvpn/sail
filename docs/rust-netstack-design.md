# sail Rust 用户态网络栈设计

> 状态：设计草案  
> 目标：为 sail 提供一套 Rust 原生、资源可控、跨移动端/桌面端/服务器/路由器的用户态 TCP/IP 数据面。

## 1. 结论

sail 应实现独立的 `sail-netstack`，而不是长期维护 smoltcp fork，也不把 gVisor、MIPS 或 sing-tun 包装成另一个可配置后端。

这里的“独立实现”指重新设计并实现：

- flow table、分片与调度模型；
- TCP 连接容器、监听与透明转发语义；
- 接收窗口、缓冲区和全局资源预算；
- timer wheel、背压和生命周期；
- 面向不同平台的批量 packet I/O。

可选择性复用 smoltcp 的 0BSD 组件：

- wire parser/emitter、地址和报文类型；
- checksum、TCP sequence number、TCP option 等基础算法；
- 可从状态机中隔离出来的 RTT/RTO 或拥塞控制算法；
- 协议边界测试与测试向量。

不得把 smoltcp 的 `Interface`、`SocketSet`、固定 socket buffer 或 `Device` 轮询模型带入公开 API。sail 只提供一个网络栈实现，不向用户暴露“新旧栈版本”选项；迁移期的回退开关仅用于编译、CI 和灰度。

## 2. 为什么不是继续改 smoltcp

smoltcp 的设计对嵌入式、无堆或固定内存设备是合理的：所有权清晰、协议代码紧凑、固定缓冲区行为可预测。问题不是代码质量，而是它优化的执行环境和 sail 不同。

对代理数据面而言，以下结构性约束需要被反转：

- 固定 RX/TX buffer 把内存绑定在连接生命周期，而不是活跃流量；
- `SocketSet` 的包到 socket 匹配和统一 poll 模型难以扩展到大量并发与多队列；
- 单 `Interface` 驱动不自然地映射到多核、多个 TUN queue 和批处理；
- listener/socket 语义不等于透明代理的“截获任意目的地址后上送 flow”；
- 同步 `Device` 抽象无法表达异步唤醒、批量收发、headroom、checksum/GSO 能力；
- receive window 与预分配容量紧耦合，无法在严格预算下按需增长。

若在这些位置持续修改，最后会得到一个难以同步上游、又受原架构约束的 fork。更合理的边界是：借用 smoltcp 的 wire 层和纯算法，重写资源所有权与执行架构。

## 3. 外部项目的参考价值

### 3.1 sing-tun：数据面架构的主要参照

sing-tun 的自研栈对 sail 很有参考价值，重点不是 Go 代码本身，而是数据面组织方式：

- 每个 engine/shard 独占 flow map、timer、packet store 和大部分连接状态；
- 常规报文只查本地 flow table，只有错投队列、新建和销毁才碰全局目录；
- 单轮处理同时受 packet 数、byte 数和时间预算约束，避免大流或控制报文饿死其他流；
- slab/chunk 按需组成 payload chain，空闲与内存压力下回收；
- packet I/O 显式建模 batch、burst、headroom、checksum/offload 和 writable wakeup；
- 网络重置、关闭和未完成 engine 都有明确处理。

sail 应独立实现这些思想：

1. shard-owned fast path；
2. 本地 O(1) flow lookup；
3. 有界跨 shard 队列；
4. packet + byte + time 三重预算；
5. 按需 slab chain 和压力回收；
6. 能力驱动的平台 I/O。

参考：

- [sing-tun engine](https://github.com/SagerNet/sing-tun/blob/dev/stack_go_engine.go)
- [sing-tun ring/buffer](https://github.com/SagerNet/sing-tun/blob/dev/stack_go_ring.go)
- [sing-tun platform I/O](https://github.com/SagerNet/sing-tun/blob/dev/stack_go_io.go)

sing-tun 使用 GPLv3。sail 只参考可观察的架构和行为，不复制代码或结构化翻译实现。

### 3.2 mihomo/MIPS：API、调度和验证的主要参照

mihomo 使用的 MIPS 对 sail 的价值主要在产品接口和完整性：

- `Forwarder` 用 Accept/Drop/Reject 表达透明转发决策；
- packet endpoint 使用批量 `Read/Write` 并明确 buffer 所有权；
- byte-based DRR 与 flow-aware admission 避免按包公平造成大包占优；
- buffer 动态增长但有明确上限；
- close 必须解除所有阻塞读写；
- 提供统计、MTU 场景和与 gVisor 的互操作测试。

sail 应吸收这些行为和测试方法，但不照搬 Go 的 goroutine/actor 组织方式。Rust 中连接状态应由 shard 独占，在热路径用普通可变借用推进，跨 shard 才使用消息。

参考：[MetaCubeX/mipstack](https://github.com/MetaCubeX/mipstack)

MIPS 使用 MPL-2.0。首选独立实现并用黑盒互操作测试验证；若未来确实移植具体文件，必须单独做许可证和文件级边界评审。

### 3.3 smoltcp：wire 层和协议算法来源

smoltcp 的 0BSD 许可和清晰协议实现使其适合做底层构件来源。初期可以直接依赖或抽取必要模块；最终是否保留依赖由二进制体积、维护成本和 fuzz 结果决定。

### 3.4 参考关系

```text
smoltcp                     sing-tun                    MIPS
wire/checksum/纯算法         shard/预算/内存/I/O          API/公平性/互操作
          \                    |                    /
           +---------------- sail-netstack --------+
                              |
                   sail Dispatcher / NAT / FakeDNS
```

## 4. 产品范围

首个可替换版本必须支持：

- IPv4 与 IPv6；
- TCP 透明接入；
- UDP session 化转发；
- ICMP 必要错误报文；
- IPv4/IPv6 fragmentation 与 PMTU；
- macOS/iOS、Linux、Android 和常见路由器环境；
- 单线程低内存模式与多队列多核模式；
- 多实例、网络切换、MTU 更新和确定性关闭；
- sail 现有 Dispatcher、NatManager、FakeDNS 和 outbound 协议。

第一阶段不实现：

- 通用路由器内核、raw socket 完整兼容层；
- SCTP、DCCP 等非代理所需传输协议；
- 任意应用直接创建用户态 socket 的 POSIX API；
- 为配置兼容而保留多个永久 TCP/IP 后端。

## 5. crate 与模块边界

```text
sail-netstack/
  src/
    api/            对 sail 稳定的 packet/flow/control API
    engine/         runner、shard、scheduler、flow directory
    tcp/            状态机、拥塞控制、重传、scoreboard
    udp/            flow table、超时与背压
    ip/             IPv4/IPv6、分片、PMTU、ICMP
    wire/           smoltcp 适配或独立 wire 层
    buffer/         slab、chain、packet arena、资源预算
    timer/          分层 timer wheel
    platform/       通用 packet I/O 能力描述
    metrics/        快照、事件与低开销计数器
  tests/
    model/
    interop/
    impairment/
    lifecycle/
```

网络栈 crate 不依赖 sail 的代理协议、规则或 outbound。sail 通过小而稳定的 API 消费 TCP flow 和 UDP datagram。

## 6. 对外 API

### 6.1 Packet I/O

```rust
pub struct PacketCapabilities {
    pub max_batch: usize,
    pub queue_count: usize,
    pub headroom: usize,
    pub vectored: bool,
    pub rx_checksum: ChecksumCapabilities,
    pub tx_checksum: ChecksumCapabilities,
    pub gso: Option<GsoCapabilities>,
}

pub trait PacketIo: Send + 'static {
    async fn recv(&mut self, out: &mut PacketBatch) -> io::Result<usize>;
    async fn send(&mut self, packets: &mut PacketBatch) -> io::Result<usize>;
    fn capabilities(&self) -> PacketCapabilities;
}
```

约束：

- `max_batch = 1` 是合法且经过完整测试的移动端路径；
- platform 层负责移除 TUN PI/header 等平台 framing；
- batch 中 packet buffer 的归还时机必须由类型或 token 明确表达；
- partial send、暂时不可写和永久错误不得折叠为同一种结果；
- offload 只能由 capability 协商启用，核心不能猜测。

### 6.2 Stack parts

```rust
pub struct StackParts {
    pub runner: StackRunner,
    pub tcp: TcpAcceptor,
    pub udp: UdpEndpoint,
    pub control: StackControl,
}
```

- `StackRunner` 驱动所有 shard，可绑定单线程 runtime 或多线程 runtime；
- `TcpAcceptor` 只产出握手完成且已计入资源预算的连接；
- `UdpEndpoint` 上送 datagram 时携带带 generation 的 `UdpFlowToken`，避免五元组复用误投；
- `StackControl` 提供 `shutdown`、`abort`、`reset_network`、`update_mtu` 和 `stats_snapshot`；
- runner 异常必须传播给 sail，不允许后台任务静默死亡。

## 7. 执行与并发模型

### 7.1 Shard ownership

每个 shard 独占：

- TCP/UDP flow table；
- TCP control block 和 timer；
- 本地 packet/slab cache；
- accept queue 与发送队列；
- 本地计数器。

flow 通过稳定哈希映射到 shard。稳定流的包在本地 O(1) 查找并推进，不加全局锁。全局 flow directory 只用于：

- 首包分配；
- 输入队列与目标 shard 不一致时转发；
- flow 创建、销毁和网络重置。

跨 shard 队列必须有界；满时按报文类别和流公平策略丢弃，不能无限堆积。

### 7.2 不使用“一连接一协议任务”

协议状态由 shard event loop 批量推进，避免高并发下 task、waker、channel 和 allocator 开销。握手完成后交给 sail 的代理转发任务仍可是一连接一任务，因为那是应用层阻塞 I/O 边界，不应与协议状态机混在一起。

### 7.3 调度公平性

每轮至少同时限制：

- 最大 packet 数；
- 最大 byte 数；
- 最大连续运行时间；
- 单 flow 最大连续 byte 数。

活动 flow 采用 weighted byte DRR。ACK、RST、ICMP、重传 timer 等控制工作保留独立预算，既不能被大流饿死，也不能无限抢占 payload。

shard 数在启动时确定，默认值由平台、队列数、CPU 和内存预算共同决定。iOS Network Extension 默认单 shard；桌面/服务器默认不超过可用 TUN queue 和物理核心的较小值。第一阶段不做运行时 shard 迁移。

## 8. 内存和资源模型

### 8.1 全局预算

```rust
pub struct ResourceBudget {
    pub total_bytes: usize,
    pub metadata_bytes: usize,
    pub tcp_payload_bytes: usize,
    pub packet_bytes: usize,
    pub fragment_bytes: usize,
    pub max_tcp_flows: usize,
    pub max_syn_received: usize,
    pub max_accept_queue: usize,
    pub max_udp_flows: usize,
    pub max_fragments: usize,
    pub max_time_wait: usize,
}
```

预算是硬约束，不是监控阈值。全局 allocator 按批次把额度租给 shard；热路径从 shard 本地额度分配，低水位才与全局协调，从而避免每个 packet 做原子操作。

### 8.2 动态 buffer

- packet 和 TCP payload 使用不同大小级别的 slab；
- TCP send/receive queue 是 chunk chain，不要求连续内存；
- 空闲连接只保留 TCB、最小控制状态和少量 metadata；
- 活跃连接按实际在途数据借用 chunk，ACK 或应用消费后立即归还；
- TUN buffer 到 TCP receive queue 的首次实现允许一次显式 copy，后续以 profile 决定是否引入 buffer ownership 转移；不能以“零拷贝”名义让生命周期失控。

### 8.3 接收窗口信用

TCP receive window 必须以已预留的 buffer credit 为依据，不能先向对端承诺窗口再尝试分配。

不变量：

```text
advertised_right_edge <= recv_next + reserved_receive_capacity
```

已经公布的窗口右边界不能后退。资源压力下：

1. 停止扩大窗口；
2. 应用消费后才重新发放 credit；
3. 必要时公布零窗口并启动 persist 处理；
4. 遵守 silly-window-syndrome avoidance；
5. 不因瞬时分配失败破坏 TCP 语义。

### 8.4 压力等级

- Normal：正常增长，保留吞吐余量；
- Constrained：停止投机预取，缩短闲置 UDP 和 fragment 生命周期；
- Critical：不接收新 flow，优先回收未建立连接、过期 fragment 和空闲 cache；
- Exhausted：对新 flow 执行协议正确的 reject/drop，已有 flow 保留控制报文和关闭额度。

所有压力转换、拒绝和回收都必须可观测。

## 9. TCP 设计

### 9.1 状态机边界

TCP core 是确定性状态机：

```text
(TCB, Segment, Time, AppEvent) -> Actions
```

`Actions` 通过受预算约束的 sink 输出 ACK、payload、timer 更新、应用唤醒和关闭事件。纯状态推进层不得自行 spawn、阻塞或访问全局 allocator。

### 9.2 协议基线

首个生产版本至少覆盖：

- RFC 9293：TCP 基础语义；
- RFC 6298：RTO；
- RFC 5681 + RFC 6582：拥塞控制和 NewReno 恢复；
- RFC 2018 + RFC 6675：SACK 与 loss recovery；
- RFC 7323：window scaling、timestamps、RTTM/PAWS；
- RFC 5961：challenge ACK 与 reset 防护；
- RFC 6528：ISN；
- delayed ACK、Nagle、persist、keepalive、TIME-WAIT；
- SYN flood、accept queue overflow 和异常 segment 的确定策略。

ECN、CUBIC、RACK/TLP 等必须分别设计和验证，不能以“高级 TCP”统称后默认开启。首个稳定拥塞控制使用 NewReno；CUBIC 以后作为内部策略演进，不形成用户可见的“栈版本”。

### 9.3 建连和关闭

- SYN_RECEIVED、已建立未 accept、应用已接管三类连接分别计数和限额；
- accept queue 满时采用可配置于平台构建的 drop/reject 策略，但产品配置不暴露实现版本；
- TIME-WAIT 使用独立紧凑表和预算，不能保留完整 TCB；
- RST、half-close、simultaneous close、应用取消和网络切换都要有模型测试；
- 应用 drop stream 后必须确定性通知 shard 回收资源。

## 10. UDP、ICMP、分片与 MTU

### UDP

- flow key 至少包含地址族、协议、源/目的地址端口和网络 generation；
- 上送 token 包含 generation，过期 reply 被拒绝；
- idle timeout 使用 timer wheel；
- 队列按 flow 公平准入，压力下优先丢弃造成积压的 flow，而不是让单一大流占满；
- reply path 支持批量提交和显式 partial send。

### ICMP

- 支持 destination unreachable、packet too big、time exceeded 和必要 echo 行为；
- 错误报文引用原始 packet 的范围经过长度检查；
- 对 ICMP error、RST 和 challenge ACK 分别限速；
- 永远不对不应响应的 ICMP error 再生成 error。

### Fragmentation

- reassembly key、字节数、fragment 数和超时均受硬预算控制；
- IPv6 overlapping fragment 丢弃整个 datagram；
- IPv6 atomic fragment 按 RFC 6946 处理；
- 重组完成前不创建 TCP/UDP flow；
- 资源不足时采用确定性淘汰并计数。

### MTU/PMTU

- platform MTU、route PMTU 和 peer MSS 分层保存；
- MTU 变化立即影响新报文分段，不破坏已有未确认数据；
- IPv4 DF、IPv6 Packet Too Big、MSS clamp 和 black-hole 场景进入系统测试矩阵。

## 11. 生命周期和系统集成

状态：

```text
Created -> Running -> Draining -> Closed
                    \-> Aborting -> Closed
Running -> Failed
```

- `shutdown(deadline)` 停止接收新 flow，允许既有连接在期限内排空；
- `abort()` 解除所有 packet、accept、TCP 和 UDP 等待；
- packet I/O 永久错误进入 `Failed` 并上报；
- `reset_network(generation)` 使旧 UDP token、route 和 PMTU 失效；
- `update_mtu` 是运行时控制事件；
- 多个 stack instance 不能共享隐式全局状态。

sail 集成仍保留现有边界：

```text
TUN PacketIo
    -> sail-netstack
       -> TcpAcceptor -> Dispatcher -> outbound
       -> UdpEndpoint -> NatManager/Dispatcher -> outbound
       -> FakeDNS/路由元数据由 sail 层处理
```

## 12. 安全性

- wire parser 对长度、offset、option 和 checksum 采用 fail-closed；
- 所有 counter、sequence 和 timer 运算使用显式 wrapping/checked 语义；
- 不接受由 packet 输入直接决定的无界分配；
- hash table 使用抗碰撞哈希或受控随机种子；
- SYN、RST、ACK、ICMP、fragment 分别限速；
- unsafe 仅允许出现在经审计的 buffer/platform 小模块，并有 Miri、fuzz 或等价边界测试；
- parser fuzz corpus 包含截断、重叠、异常 option、最大 extension chain 和 checksum 差异。

## 13. 可观测性

最低指标：

- 当前/峰值 TCP、UDP、SYN_RECV、accept queue、TIME-WAIT；
- packet/slab/fragment 使用字节与高水位；
- 按原因 drop/reject/reset；
- retransmit、RTO、SACK recovery、zero-window、persist；
- shard queue 深度、跨 shard 转发、调度超预算；
- packet batch 大小、partial send、I/O wakeup；
- 网络 reset、MTU change、runner failure；
- per-shard CPU work units 和公平性采样。

热路径只写本地计数器；snapshot 时聚合。调试 trace 采用有界 ring，默认关闭。

## 14. 验证策略

### 单元、模型和 fuzz

- TCP 状态迁移与 sequence/window 不变量；
- timer wheel 与时钟回拨/大步推进；
- buffer credit 与总预算守恒；
- slab chain split/merge/reclaim；
- parser/emitter round trip 与差分 fuzz；
- close/reset/cancel 后无等待者遗留。

推荐用 loom 或等价工具验证控制面、跨 shard 队列和关闭协议；协议核心本身尽量保持单线程所有权，减少并发状态空间。

### 黑盒互操作

- Linux、macOS/iOS 路径和另一套成熟用户态栈；
- gVisor 风格 TCP/UDP endpoint 互操作；
- NewReno/SACK/window scaling/timestamp/zero-window/half-close；
- IPv4/IPv6、不同 MTU、fragment、PMTU；
- reorder、loss、duplicate、delay、bandwidth cap 和 abrupt peer reset。

MIPS 的测试维度可作为覆盖清单，sing-tun 的输入输出行为可用于差分测试，但预期值必须来自协议和独立黑盒观察。

### 长稳与故障注入

- 百万级短连接；
- 24 小时 mixed traffic；
- 慢消费者、零窗口、UDP flood、SYN flood、fragment flood；
- 内存从 Normal 压到 Exhausted 再恢复；
- TUN 阻塞、partial write、永久错误、网络切换和关闭竞态；
- 每轮结束验证 flow、timer、slab、task 和 file descriptor 回到基线。

## 15. 性能验收

所有环境同时记录：

- throughput、PPS、connections/s；
- CPU time/GB 与 cycles/packet；
- p50/p99 latency；
- 空闲与高并发 footprint/RSS；
- 每连接 metadata、活跃 payload、峰值 slab；
- 1/2/4/8 shard 扩展率；
- 大流与小流并存时的公平性；
- 丢包/乱序时 goodput 与重传。

平台矩阵：

- iOS 风格单线程、严格 footprint；
- Android/低端路由器单核与小预算；
- macOS/Windows 桌面端中等并发；
- Linux server 多队列、多核与高连接数。

替换条件不是“功能能跑”，而是：

1. 协议与生命周期测试全部通过；
2. 资源预算在压力下从不失守；
3. 单线程不回退于优化后的现有实现；
4. 多核 server 场景得到可解释的 shard scaling；
5. 至少在 CPU/GB、峰值内存或尾延迟中的两个维度形成显著收益。

## 16. AI 并行开发计划

时间按具备 AI agent、四条并行工作流估算，不用传统人月线性相加：

### N0：契约与基线，2–3 天

- 固化 API、不变量、资源预算和 benchmark schema；
- 保存当前栈功能、性能和故障基线；
- 建立 RFC 覆盖矩阵与交叉模块接口。

### N1：可运行骨架，第 1 周

- PacketIo、runner、shard、flow directory；
- slab/packet arena、timer wheel、预算器；
- IPv4/IPv6 wire 接入，UDP 最小闭环；
- 单 shard 与多 shard benchmark。

### N2：TCP 原型，第 2–3 周

- handshake、stream I/O、ACK/RTO、关闭；
- receive credit 与动态 buffer；
- sail Dispatcher 集成；
- 基础 Linux/macOS 互操作。

### N3：协议完整性，第 3–5 周

- SACK/NewReno/window scaling/timestamps/persist；
- ICMP、fragment、PMTU；
- 压力策略、网络 reset、多实例；
- impairment 与差分测试扩展。

### N4：强化，第 5–7 周

- fuzz、模型测试、故障注入和长稳；
- iOS、路由器与 server profile 调优；
- batch/offload、多队列和公平性优化；
- 安全与许可证审计。

### N5：灰度候选，第 7–8 周

- 内部构建灰度与回归；
- 删除阻塞发布的问题；
- 达标后切换默认实现并准备移除旧适配层。

并行所有权建议：

1. TCP/RFC owner；
2. buffer/resource/timer owner；
3. IP/UDP/ICMP/fragment owner；
4. platform I/O/runtime/benchmark/interop owner。

agent 可以并行生成实现和测试，但模块接口、不变量、测试 oracle 与合并决策必须有唯一 owner。对同一核心状态机的并行改写应避免，否则会把节省的编码时间转成整合风险。

## 17. 迁移策略

1. 先把现有 TUN 入口收敛到统一 PacketIo 和 flow API；
2. 新栈以内部 build feature 接入 CI 和 benchmark；
3. FakeDNS、NatManager、Dispatcher 不随网络栈重写；
4. 对真实流量做离线 replay 和可选 shadow decode，不双发真实连接；
5. 达到验收门槛后一次性切换产品默认；
6. 回退开关仅保留一个发布窗口，且不进入用户配置；
7. 稳定后删除旧 smoltcp/tun2socks adapter、兼容代码和回退开关。

这避免形成“legacy/new/v2”长期并存。网络栈工作也不应冻结 sail 的其他 P0：CopyBuffer、TUN 批处理和现有资源泄漏修复可以独立推进，并为新栈提供基线。

## 18. 首批实现任务

按依赖顺序：

1. 新建 `sail-netstack` crate，只提交 API、不变量文档和测试 scaffold；
2. 实现 ResourceBudget、slab chain、packet arena，并做随机操作守恒测试；
3. 实现 timer wheel 和虚拟时钟；
4. 实现单 shard runner、PacketIo mock、UDP loop；
5. 加入 shard routing、有界跨 shard 队列和 byte DRR；
6. 接入 smoltcp wire/checksum，隔离在 `wire` 模块；
7. 实现 TCP 状态机最小闭环及 reference model；
8. 接 sail Dispatcher，跑现有 core-compare；
9. 加入 SACK、NewReno、window scaling、timestamps；
10. 完成 ICMP、fragment、PMTU 和全平台适配。

每项合并必须带对应测试和至少一个资源/性能观测点。

## 19. 最终方向

采用“重新设计执行与资源架构，选择性复用成熟协议零件”的路线：

- 不 fork smoltcp 的整体架构；
- 不移植 sing-tun 或 MIPS 源码；
- 用 sing-tun 校准数据面组织；
- 用 MIPS 校准透明转发 API、公平性和验证矩阵；
- 用 smoltcp 降低 wire 层和基础算法的初始风险；
- 对用户只呈现一个持续演进的 sail 网络栈，不制造版本碎片。
