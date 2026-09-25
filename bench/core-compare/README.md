# leaf vs sing-box 内核对比

在本机用同一条链路分别跑 leaf 和 sing-box，比较内存、吞吐、CPU 和延迟。

```
loadgen --SOCKS5--> 被测客户端 (:1081) --直连或 SS aes-128-gcm--> sing-box SS 服务端 (:8388) --> sink (:9000)
```

## 运行

```sh
(cd loadgen && go build -o loadgen .)
configs/gen-tls.sh                           # 生成自签名证书、REALITY 密钥和引用它们的配置（不入库）
cargo build -p leaf-cli --release            # 在仓库根目录执行
# iOS 模式需要按 libbox 方式编译的 sing-box：
#   在 sing-box 源码目录执行 go build -tags with_low_memory,with_quic,with_utls,with_clash_api -o <此目录>/bin/sing-box-lowmem ./cmd/sing-box
./run.py --group desktop      # 两边都用默认配置
./run.py --group ios          # 模拟 iOS Network Extension 里的运行方式
```

每组约 2–3 分钟；`--rounds N` 可多跑几轮取中位数。原始数据写入 `results-<group>.json`。

只测吞吐时用 `throughput.sh`：启动给定的客户端，重复 N 次 8 条流 × 64MB 的传输，输出吞吐和每 GB CPU 的中位数。服务端和 sink 需要先手动启动：

```sh
./loadgen/loadgen sink &
sing-box run -c configs/server-singbox.json &        # SS 服务端
sing-box run -c configs/server-singbox-tls.json &    # Trojan / VLESS 服务端（TLS，自签名证书）
./throughput.sh "leaf trojan" down 5 -- ../../target/release/leaf -c configs/client-leaf-trojan.json
```

统计系统调用次数和每次字节数用 `syscount/`：`clang -O2 -dynamiclib -o syscount/syscount.dylib syscount/syscount.c` 编译后，`syscount/measure.sh "leaf trojan" up -- ../../target/release/leaf -c configs/client-leaf-trojan.json`。它通过 `DYLD_INSERT_LIBRARIES` 拦截 socket 收发调用，不需要 root。libc 的 `send`/`recv` 内部会再调用 `sendto`/`recvfrom`，两者会各计一次，看其中一个即可。

- **footprint** 是 macOS `footprint` 命令给出的 phys_footprint，iOS 按这个指标决定是否杀掉 Network Extension（上限约 50MB）。
- **iOS 模式**：sing-box 按 libbox 的方式运行（`with_low_memory` 编译标签，缓冲区 16KB；GOGC=10、GOMEMLIMIT=45MiB，见 `experimental/libbox/memory.go`）；leaf 用单线程模式运行。

## P0.2 重构后的性能回归（2026-09-25，`dev`）

对比 P0.2 重构前的 `11c74ad`（base）和重构后的 `dev`（new），各用自己版本的配置格式。`./run.py --group regression --base-leaf <base 的 leaf> --base-configs <base 的配置目录>` 跑直连和 SS，多线程和单线程，2 轮取中位数；Trojan / VLESS / REALITY 用 `throughput.sh` 交替跑 base 和 new，各 2 轮 × 5 次。

**发现并修复的退化：** 第一次测时，2000 并发连接的 footprint 在四个场景都高出 3–4MB（每条连接约 1.5KB）。`heap -s` 对比：每条连接的任务分配从 6KB 档变成 7KB 档（2000 个），另有每条连接约 7 个 16 字节分配。原因：
- 每条连接的任务 future 从 5968 字节涨到 6544 字节，加上分配器开销，跨过了 6KB 的大小档。主要来自 `Session` 变大（新增 `inbound_type`、`user`），它在各层 future 里有多份。
- `inbound_type` 是 `String`，每次克隆 `Session` 都分配一次。

修复：`inbound_type` 改为注册表里协议名的 `&'static str`；`user` 改为 `Arc<str>`；三个嗅探域名合并为一个 `sniffed: Option<(SniffedFrom, String)>`（只保留优先级最高的来源，路由也只用它）；路由阶段（嗅探、解析、选路）放进单独装箱的 future，选完即释放。任务 future 降到 5872 字节，比重构前还小。

修复后（中位数）：

| 指标 | base 直连 | new 直连 | base 直连 1T | new 直连 1T | base SS | new SS | base SS 1T | new SS 1T |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 空闲 footprint (MB) | 6.5 | 6.6 | 6.3 | 6.3 | 6.5 | 6.6 | 6.3 | 6.3 |
| 下行 CPU (秒/GB) | 0.33 | 0.32 | 0.22 | 0.22 | 0.59 | 0.57 | 0.43 | 0.41 |
| 上行 CPU (秒/GB) | 0.32 | 0.31 | 0.21 | 0.21 | 0.49 | 0.49 | 0.44 | 0.43 |
| 新建连接 p50 (ms) | 0.286 | 0.224 | 0.199 | 0.199 | 0.349 | 0.379 | 0.387 | 0.354 |
| 2000 并发 footprint (MB) | 30 | 30 | 25 | 25 | 35 | 34 | 29 | 29.5 |
| 负载结束 3s 后 footprint (MB) | 30 | 30 | 25 | 26 | 35 | 34.5 | 30 | 30.5 |

TLS 类出站每 GB CPU（秒，两轮各 5 次中位数，base / new）：

| 链路 | 下行 多线程 | 下行 单线程 | 上行 多线程 | 上行 单线程 |
| --- | --- | --- | --- | --- |
| Trojan | 0.56–0.60 / 0.56–0.60 | 0.47–0.48 / 0.47–0.50 | 0.45–0.50 / 0.48 | 0.43–0.47 / 0.43 |
| VLESS | 0.61–0.65 / 0.58–0.60 | 0.47–0.48 / 0.47–0.48 | 0.50–0.52 / 0.50–0.52 | 0.43 / 0.43 |
| REALITY | 0.63 / 0.61–0.63 | 0.50–0.52 / 0.50 | 0.52–0.54 / 0.52–0.54 | 0.45 / 0.45 |

结论：CPU、延迟和内存都不低于重构前；吞吐两边都在 1100–3600MB/s 间大幅波动，不作比较。

## Vision 上行填充（2026-09-25，分支 `pooled-relay-buffer`）

`leaf/src/protocol/vless/stream.rs` 原先在请求头里声明 `xtls-rprx-vision`，写方向却直接透传。服务端遇到没有 UUID 前缀的数据会当作未填充数据接收，所以功能上能用，但 Vision 要隐藏的内层 TLS 握手长度特征完全暴露。

按 sing-vmess 的 `VisionConn` 移植了客户端写路径：
- 连接前 8 个包（上下行合计）做 TLS 探测：ClientHello / ServerHello，识别出 TLS 1.2 或 1.3 后停止。
- 帧格式 `[UUID，仅第一帧][命令][内容长度 2B][填充长度 2B][内容][填充]`；TLS 且内容不足 900 字节时填充到 900–1399 字节，否则随机 0–255 字节；每帧内容最多 8171 字节，切分点优先放在最后一个 TLS 应用数据记录开头。
- 遇到内层 TLS 应用数据（`17 03 03`），或非 TLS 1.2+ 且探测包用完，发 PaddingEnd 并停止填充。上行不发 PaddingDirect（不做上行直连），这是协议允许的做法。
- 填充帧生成后即确认接收调用方数据，未写完的部分在下次写入 / flush / shutdown 时先写出。

验证：
- 单元测试：帧格式、切分、TLS 探测，以及写入模拟的内层 TLS / 非 TLS 流量后用 Vision 解析器还原（88 个库测试全部通过）。
- 对 sing-box 服务端（Reality）：HTTPS 上传（内层 TLS，走"应用数据结束填充"）、HTTP 明文上传（走"探测包用完结束填充"）、HTTPS 下载、小请求，多线程和单线程各 2 次，sha256 全部一致。上行每 GB CPU 不变（0.56 秒）。

## Vision 直连：普通 TLS 出站与上行（2026-09-25，分支 `pooled-relay-buffer`）

**修复前：VLESS + Vision 跑在普通 TLS 出站上时，内层是 TLS 1.3 的连接全部失败**（HTTPS 上传、下载、小请求都失败）。服务端把下行切到直连后发原始数据，但普通 TLS 出站（tokio-rustls）不支持切换到原始读取，把原始数据当 TLS 记录解密，报 `cannot decrypt peer's message`。

改动：
- 新增 `leaf/src/transport/tls_stream.rs`：通用客户端 TLS 流 `ClientTlsStream`，通过 `TlsConnection` trait 同时适配 rustls 和 REALITY 用的 rustls 分支。Reality 流的读写逻辑移到这里；Reality 和普通 TLS 出站（rustls 后端）都改用它，不再用 tokio-rustls。
- `VisionState`（`leaf/src/session.rs`）增加"未启用"默认状态，只有 VLESS 出站在发请求前把它设为"未定"；Trojan 等不受按记录读的影响。另有"下层可切原始读写""上行已切直连"两个标志。
- 记录跟踪器始终跟踪读过的字节，Vision 在 TLS 握手之后才启用时边界仍然对齐。只有 Vision 未定时按记录读并经过 64KB 缓冲区；其他时候 rustls 直接读传输层（少一次拷贝）。
- **上行直连**：VLESS 从 ServerHello 识别内层 TLS 1.3 和密码套件（排除 TLS_AES_128_CCM_8，与 sing-box 一致），在内层应用数据处发 PaddingDirect；该帧完整交给 TLS 层后置位，TLS 流把已排队的 TLS 记录全部写出后切换为原始写。切换后 flush / shutdown 直接作用于传输层，不再发 close_notify。
- trait 实现最初写成 `<$conn>::method(self)`，因为这些方法实际定义在 Deref 目标上，解析到了 trait 自身导致无限递归（编译器警告发现）；改为显式 Deref，并加了单元测试。

验证（sing-box 服务端，trace 日志）：
- VLESS+TLS、Reality、Trojan 三种出站，多线程 / 单线程各 2 轮：HTTPS 上传、HTTP 明文上传、HTTPS 下载、小请求 sha256 / 状态码全部正确；loadgen 上下行和 500 条并发无失败；服务端无错误。
- VLESS 与 Reality 各 11 次上行直连切换（服务端 `XtlsRead readV`）；少数下载 / 小请求连接只有 Continue：curl 把 ChangeCipherSpec、Finished 和请求合在一次写入（以 `14 03 03` 开头），之后再无上行数据，与 sing-box / Xray 的判断一致。
- 库测试 92 个、集成测试全部通过。

性能（下行每 GB CPU，5 次中位数，同一轮）：

| 链路 | 换之前（tokio-rustls） | 通用流（全部经 64KB 缓冲区） | 通用流（仅按记录读时用缓冲区） |
| --- | --- | --- | --- |
| Trojan 单线程 | 0.50 | 0.52 | 0.48 |
| VLESS 单线程 | 0.48 | 0.52 | 0.48 |
| Reality 单线程 | 0.54 | 0.54 | 0.52 |
| Reality 多线程 | 0.71 | 0.73 | 0.69 |

Trojan / VLESS 多线程三者都在 0.67–0.69；上行持平。Trojan 2000 条连接 footprint 44MB → 45MB，空闲 6.4MB 不变。

**仍不支持：** openssl 后端的 TLS 出站不能切直连（非移动端默认后端）；Vision 跑在 WebSocket 等非 TLS 直连传输上不支持（服务端也不支持）。

## Reality 修复（2026-09-24，分支 `pooled-relay-buffer`）

`leaf/src/transport/reality/stream.rs` 修复前的实测：下行 0.84MB/s（sing-box 约 1200MB/s），上行传输几 MB 后断开（`broken pipe`）。

| 问题 | 原因 | 修复 |
| --- | --- | --- |
| 上行断开 | rustls 发送缓冲满时 `writer().write()` 返回 0，`poll_write` 把 0 原样返回，转发层当作 WriteZero 断开；也从不返回 Pending，没有反压 | 先把已排队的数据发完再写入；传输层阻塞时返回 Pending，已写入部分时返回已写字节数 |
| `pump_write` 可能空转 | `write_tls` 返回 `Ok(0)` 时 `while wants_write()` 不退出 | 报 `WriteZero` |
| 下行极慢 | 为了在 Vision 切换到直连后不越过 TLS 记录边界，每次只从 socket 读 1 字节 | 自己按记录读：先读 5 字节头，再一次读完记录体，然后从内存整条交给 rustls；每条记录 2 次系统调用（rustls 直接读传输层时按 4KB 步长扩缓冲，一条记录要 5–6 次） |
| 握手阶段可能读过记录边界 | 握手时不限读取长度，之后的逐字节读取可能从记录中间开始 | 握手也走按记录读取 |
| 没有向量写 | `TlsBridge` 只实现了 `write` | 实现 `write_vectored` |
| `poll_shutdown` 过早关闭 | close_notify 未发出就关闭下层 | 发完再关闭 |

验证：
- 用 loadgen 测上下行、单连接 256MB、500 条并发连接，全部成功。
- 通过代理用 HTTPS 下载 64MB 随机文件（本地 TLS 1.3 服务），3 次都触发了 Vision 直连切换（新增 debug 日志 `vision switched to direct copy`），sha256 一致。
- `record_len` 单元测试；库测试 82 个、TLS/Trojan/SS/链式代理集成测试全部通过。

### 下行第二轮：Vision 结束后批量读

第一轮修复后下行每 GB 仍要 1.12 秒（多线程）。采样（单线程）：`sendto` 33%、`recvfrom` 21%、AES-GCM（ring）19%、`memmove` 15%。按记录边界读导致 `poll_read` 每次只交出一条记录（约 16KB）的明文，转发层也就每 16KB 写一次。

但只有 Vision 还没有结论时才需要按记录读：切到直连后读原始数据，不经过 rustls；正常结束（padding end）后不可能再切换。改动：

- `Session` 里的 `vision_read_raw: Arc<AtomicBool>` 改为三态 `VisionState`（未定 / 直连 / 已结束，`leaf/src/session.rs`），VLESS 在 Vision 正常结束时标记为已结束。
- Reality 维护一个 64KB 密文缓冲区（从转发缓冲池借用，读返回 Pending 时归还）。Vision 未定时按 `RecordTracker` 读到记录末尾，交出一条记录的明文就返回；结束后一次读最多 64KB，在同一次 `poll_read` 里连续解出多条记录填满调用方缓冲区。
- 收到 close_notify 后 `read_tls` 返回 0 时丢弃剩余数据，不再当错误。

每 GB 下行：`recvfrom` 12.3 万次（平均 7.9KB）→ 1.7 万次（57.6KB）；写给客户端的 `sendto` 6.2 万次（15.9KB）→ 1.7 万次（57.2KB）。

每 GB CPU（秒，两轮交替，各 5 次中位数）：

| 方向 | sing-box | leaf 第一轮 多线程 | leaf 第二轮 多线程 | leaf 第一轮 单线程 | leaf 第二轮 单线程 |
| --- | --- | --- | --- | --- | --- |
| 下行 | 0.88–0.91 | 1.15–1.17 | 0.67–0.71 | 0.88–0.89 | 0.58–0.60 |
| 上行 | 0.86 | 0.54 | 0.54 | 0.45 | — |

验证：多线程、单线程各 3 次 HTTPS 下载都触发了直连切换，sha256 一致；上下行、单连接 256MB、500 条并发正常；库测试 83 个及全部集成测试通过。

内存（单线程，先跑一次批量下行，再保持 2000 条连接）：leaf 第一轮 87MB、第二轮 80MB，sing-box（lowmem、GOGC=10、GOMEMLIMIT=45MiB）116MB；空闲均约 6.4–6.9MB。2000 条 Reality 连接两边都超过 iOS 约 50MB 的上限，主要是每条 TLS 连接自身的状态。

## 合并写（2026-09-24）

用 `syscount/` 统计每 GB 数据的写调用（上行，写往服务端一侧）：

| 链路 | leaf | sing-box |
| --- | --- | --- |
| SS | writev 1.6 万次，平均 62KB | write 6.2 万次，平均 16KB |
| Trojan / VLESS | writev 1.6 万次，平均 62KB | write 6.2 万次，平均 16KB |

leaf 已经把约 4 条 TLS 记录（或 SS 块）合并成一次 writev；sing-box 每条 16KB 记录单独写一次。62KB 的上限来自 rustls 默认 64KB 发送缓冲和 SS 的 `MAX_WRITE`。

**试过但没有收益、已撤回：** 把 rustls 发送缓冲上限提到 `LINK_BUFFER_MAX_SIZE` + 16KB、SS `MAX_WRITE` 提到 128KB。每次 writev 升到约 107KB，每 GB 写调用降到约 1 万次，但 EAGAIN 比例从 2%–3% 升到 11%–12%（macOS TCP 发送缓冲约 128KB），两轮交替 A/B 的每 GB CPU 差异在噪声内，吞吐不变；而反压时每条连接缓存的待发数据会从 64KB 升到约 144KB，不划算。

下行方向 TLS 每次 `recvfrom` 约 15.5KB（rustls 一次读一条记录），合并成 64KB 预读同样没有收益（见下节）。

**没有实现向量写的包装层：** Reality 的 `TlsBridge` 原先只实现了 `write`（已修复，见上节）；其余（amux、ws、obfs、vmess、quic 等）上层每次只写一块，影响不大。

## Trojan / VLESS 优化（2026-09-24，分支 `pooled-relay-buffer`）

两处改动：

1. **流量统计和嗅探包装层转发向量写**（`leaf/src/app/stat_manager.rs`、`leaf/src/sniff/stream.rs`）：原来只实现了 `poll_write`，rustls 想用一次 writev 发出多条 TLS 记录，经过这里被拆成每条记录一次 `sendto`。所有经过 TLS 的上行都受影响。
2. **VLESS 读路径**（`leaf/src/protocol/vless/stream.rs`）：Vision 阶段结束后直接从底层流读入调用方的缓冲区。原来每次读都经过 8KB 临时缓冲区、解析器和两次拷贝，还会反复检查 UUID 前缀。

每 GB CPU（秒，5 次中位数；leaf 改动前后在同一轮内对比，sing-box 取自同一天较早的基线轮）：

| 场景 | sing-box | leaf 改动前 多线程 | leaf 改动后 多线程 | leaf 改动后 单线程 |
| --- | --- | --- | --- | --- |
| Trojan 下行 | 0.88 | 0.61 | 0.61 | 0.54 |
| Trojan 上行 | 0.86 | 0.84 | 0.54 | 0.45 |
| VLESS 下行 | 0.82 | 1.06 | 0.60 | 0.52 |
| VLESS 上行 | 0.84 | 0.88 | 0.54 | 0.45 |

吞吐两边都在约 1000–1500MB/s，波动大，不作比较。

**试过但没有收益、已撤回：** 在 TLS 下面加 64KB 预读层，把 rustls 的多次读取合并成一次系统调用（实测 rustls 每次 `recvfrom` 平均约 15.5KB，即一条记录；它按 4KB 步长扩大读缓冲，最多到一条记录的大小）。单线程两轮交替 A/B 测试，每 GB CPU 都是 0.47 秒，没有差别。

**没做：** VLESS 写方向没有 Vision 填充（请求头却声明了 `xtls-rprx-vision`），属于协议正确性问题，另行处理。

## 吞吐优化后的结果（2026-09-24，分支 `pooled-relay-buffer`）

在缓冲池之上又做了两处改动：

1. **自适应转发缓冲区**（`leaf/src/net/relay.rs`）：从 `LINK_BUFFER_SIZE`（16KB）起步，一次读满就翻倍，最大到 `LINK_BUFFER_MAX_SIZE`（默认 128KB）；读到的数据不到 1/4 就减半。每线程缓冲池按字节上限 1MB 缓存。
2. **Shadowsocks 流读写合并**（`leaf/src/protocol/shadowsocks/shadow.rs`）：读取时一次预读最多 64KB 并连续解出多个块，不再每个块两次系统调用（其中一次只读 18 字节长度头）；写入时一次加密最多 64KB（多个块）后用一次系统调用写出。空闲时释放读写缓冲区。

`sample` 显示 leaf 的 CPU 几乎全部花在 `sendto` / `recvfrom` / `kevent` 系统调用上，所以两处改动都以减少每 GB 的系统调用次数为目标。

每 GB CPU（秒，5 次中位数，只测吞吐）：

| 场景 | sing-box | leaf 改动前（固定 16KB） | leaf 改动后 多线程 | leaf 改动后 单线程 |
| --- | --- | --- | --- | --- |
| 直连 下行 / 上行 | 0.34 / 0.37 | 0.63 / 0.61 | 0.30 / 0.28 | 0.24 / 0.24 |
| SS 下行 / 上行 | 1.04 / 0.80 | 1.06 / 0.99（自适应后） | 0.56 / 0.50 | 0.45 / 0.47 |

- 直连吞吐中位数 leaf 约 2200–2300MB/s，sing-box 约 2000–2100MB/s。
- SS 吞吐两边都在约 1000MB/s，上限应在共用的 sing-box 服务端，所以这里只比较 CPU。
- iOS 模式下 2000 条并发连接的 footprint 仍为 30MB（sing-box 42MB），负载结束后回落不变。

## 缓冲池改造后的结果（2026-09-24，分支 `pooled-relay-buffer`，1 轮）

`CopyBuffer` 改为只在读写时从线程本地池借用缓冲区，读端暂无数据时立即归还；默认 `LINK_BUFFER_SIZE` 从 2KB 改为 16KB。

### iOS 模式（Shadowsocks）

| 指标 | leaf 单线程（新默认 16KB） | leaf 单线程 2KB | sing-box lowmem |
| --- | --- | --- | --- |
| 空闲 footprint (MB) | 6.3 | 6.3 | 6.3 |
| 下行 / 上行吞吐 (MB/s) | 932 / 848 | 348 / 233 | 881 / 991 |
| 下行 / 上行 CPU (秒/GB) | 0.73 / 0.91 | 1.96 / 2.79 | 1.06 / 0.73 |
| 2000 并发连接 footprint (MB) | 29 | 28 | 43 |

### 桌面默认配置

| 指标 | leaf 直连 | sing-box 直连 | leaf SS（16KB） | leaf SS 32KB | leaf SS 2KB | sing-box SS |
| --- | --- | --- | --- | --- | --- | --- |
| 下行 / 上行吞吐 (MB/s) | 1835 / 1651 | 2018 / 2557 | 698 / 743 | 1268 / 879 | 407 / 282 | 1162 / 1275 |
| 下行 / 上行 CPU (秒/GB) | 0.63 / 0.67 | 0.45 / 0.39 | 0.97 / 1.17 | 0.99 / 0.97 | 3.02 / 3.37 | 1.02 / 0.78 |
| 2000 并发连接 footprint (MB) | 24 | 47 | 30 | 30 | 28 | 49 |

- 并发内存不再随缓冲区大小增长：16KB 从 91MB 降到 29MB，32KB 从 155MB 降到 30MB，和 2KB 基本一样，比 sing-box 低约 1/3。
- 吞吐和 CPU 效率回到大缓冲区的水平：iOS 模式下 leaf 单线程下行吞吐与 sing-box 相当，每 GB CPU 少约 30%。
- 上表中 leaf SS 16KB 多线程的 698MB/s 是单次噪声：只测吞吐、每个配置重复 5 次后，改造前后、16KB / 32KB、单线程 / 多线程的下行吞吐都在约 1000–1400MB/s，同一配置单次波动约 ±15%。改造前后吞吐和每 GB CPU 没有可测差异。
- 多线程没有提高 SS 吞吐，只让每 GB CPU 从约 0.7 秒升到约 1.1 秒，瓶颈可能在共用的 sing-box 服务端或 loadgen；这套测试里每 GB CPU 比吞吐更可靠。
- 桌面直连场景 sing-box 当时仍快约 10%–35%，每 GB CPU 也更低；已由上文的自适应缓冲区解决。

## 改造前的结果（2026-09-24，Apple M1 Max，leaf `5e8d947`，sing-box 1.13.12，1 轮）

### iOS 模式（Shadowsocks）

| 指标 | leaf 单线程（默认 2KB 缓冲区） | leaf 单线程 16KB 缓冲区 | sing-box lowmem |
| --- | --- | --- | --- |
| 空闲 footprint (MB) | 6.3 | 6.3 | 6.4 |
| 空闲 RSS (MB) | 12.2 | 12.2 | 20.6 |
| 下行 / 上行吞吐 (MB/s) | 511 / 341 | 990 / 844 | 1526 / 1285 |
| 下行 / 上行 CPU (秒/GB) | 1.73 / 2.44 | 0.75 / 0.95 | 1.14 / 0.84 |
| 2000 并发连接 footprint (MB) | 36 | 91 | 42 |

### 桌面默认配置

| 指标 | leaf 直连 | sing-box 直连 | leaf SS | leaf SS 32KB 缓冲区 | sing-box SS |
| --- | --- | --- | --- | --- | --- |
| 空闲 footprint (MB) | 6.5 | 8.0 | 6.5 | 6.5 | 8.0 |
| 下行 / 上行吞吐 (MB/s) | 447 / 318 | 2034 / 2719 | 314 / 296 | 1277 / 1020 | 842 / 917 |
| 下行 / 上行 CPU (秒/GB) | 2.74 / 3.04 | 0.35 / 0.32 | 3.02 / 2.91 | 1.01 / 0.95 | 1.01 / 0.73 |
| 2000 并发连接 footprint (MB) | 32 | 47 | 36 | 155 | 49 |

新建连接和已建连接的延迟两边都在亚毫秒级（p50），p99 受机器上其它程序干扰波动较大，不作比较。

## 改造前的结论

1. **缓冲区大小相同时，leaf 的单位 CPU 效率与 sing-box 持平或更好**（SS 下行 1.01 vs 1.01 秒/GB；iOS 模式下行 0.75 vs 1.14）。
2. **leaf 默认用 2KB 转发缓冲区**（`LINK_BUFFER_SIZE`，`leaf/src/option/mod.rs`），以 3 倍的 CPU 开销和 1/3 的吞吐量换取低内存。
3. **缓冲区调大后，leaf 并发内存反而高于 sing-box**（16KB 时 91MB vs 42MB）。原因是 `CopyBuffer::new_with_capacity`（`leaf/src/net/relay.rs`）在每个连接建立时就为两个方向各分配一块完整缓冲区，并持有到连接结束，空闲连接也不释放；sing-box 只在读写时从缓冲池借用。
4. **空闲 footprint 差距很小**（6.3 vs 6.4MB）；RSS 的差距主要来自 Go 运行时的映射，不计入 footprint。

也就是说，Rust 的优势（无 GC、内存可预测）在改造前的 leaf 中没有充分体现，瓶颈在转发缓冲区的实现。改造后的结果见上文。

## 局限

- 在 macOS 上通过回环地址测试，不是 iOS 真机，也没有经过 TUN。
- 只跑了 1 轮；测试时机器上还有其它代理程序在运行。
- sing-box lowmem 用 go1.25.5 编译，Homebrew 版用 go1.26.3。
- 两边功能集不同（sing-box 编译进了更多协议），没有比较二进制体积。
