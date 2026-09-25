# P1.1 TLS 指纹伪装调研

调研日期：2026-09-25。目标对应 roadmap P1.1：外层 ClientHello 模拟主流浏览器，普通 TLS 与 Reality 出站默认使用浏览器指纹，并且服务端证书替换无需重启。

## 0. 结论先行

1. **现有 Reality 出站已经连不上新版 Xray 服务端。** Xray-core v26.9.8（REALITY 库 2026-09-08 的更新）开始拒绝不带 X25519MLKEM768 key share、或把它放在 X25519 之后的 ClientHello。Leaf 的 Reality 走 reality-rustls + ring provider，只发纯 X25519，所以会被拒绝。sing-box 目前也因同样原因失败（SagerNet/sing-box#4520）。这是 1.1 里最先要解决的问题。
2. **rustls 上游不会提供 ClientHello 定制。** 相关 issue（#1421、#1932、#2498）都以 duplicate 或 not planned 关闭。任何方案都得 fork 某个 TLS 库。
3. **已定：全部 TLS 和密码实现统一到 btls（BoringSSL）。**
   - 覆盖客户端 TLS、Reality、TLS 入站、QUIC（quinn 的加密层换成 quinn-btls）和 Shadowsocks / VMess 的 AEAD。
   - 去掉 rustls、ring、aws-lc、reality-rustls 和 openssl，进程里只有一套 BoringSSL。
   - btls 维护很活跃（2026-09 仍在频繁提交，版本 0.5.x），已经带有 Firefox 和 Safari 所需的 BoringSSL 补丁：ffdhe、旧式密码套件、扩展顺序、record_size_limit、delegated_credentials、zstd 证书压缩等。Chrome 本身就是 BoringSSL，可以做到原生一致。
   - 上游缺的功能或遇到的问题，由我们 fork 修复并提交 PR。
   - 设计见 §3.4。
4. 主要代价：
   - Reality 需要在 BoringSSL 上加一个 C 补丁，因为 btls 没有相应的钩子；
   - Vision 需要基于 BoringSSL 重写流；
   - 构建需要 cmake 和 clang；
   - quinn-btls 很新，只有 0.1.0。

## 1. 现状

| 项目 | 现状 | 问题 |
| --- | --- | --- |
| 普通 TLS 出站 | `transport/tls/outbound/stream.rs`，rustls 0.23.45（默认 aws-lc provider）；另有 `openssl-tls` 后端 | ClientHello 就是 rustls 默认的：没有 GREASE，密码套件、groups 和 sigalgs 与任何浏览器都不同，也没有 compress_certificate、ALPS、padding 等扩展。JA4 可以直接识别为 rustls |
| Reality 出站 | `transport/reality/`，依赖 reality-rs 加 reality-rustls（基于 rustls 0.23.36 的 fork，补丁 48 行：`reality_callback` 在 hello 序列化后改写 session_id） | 固定用 ring provider，没有 ML-KEM，只发 X25519，不能连 Xray ≥ 26.9.8。ALPN 写死 `h2,http/1.1`，证书校验回落用 webpki-roots |
| QUIC | quinn 使用 `rustls` 包，另外还依赖旧版 `rustls-pemfile-old` / `webpki-roots-old` | 与 TLS 出站使用不同的 rustls 配置路径 |
| TLS 入站 | `transport/tls/inbound/stream.rs`，tokio-rustls `TlsAcceptor`，启动时加载一次证书 | 更换证书需要重建入站 |
| 配置 | `transport/layers.rs` 中的 `OutboundTls` 有 `server_name / insecure / alpn / certificate / ech / reality`；`InboundTls` 有 `certificate / key / alpn` | 没有指纹字段 |

进程里现在有两份 rustls：upstream 0.23.45 和 reality-rustls 0.23.36。`TlsConnection` trait 通过宏为两者各实现一次。

## 2. 外部情况

### 2.1 各实现怎么做

| 实现 | 方案 | Reality |
| --- | --- | --- |
| Xray-core | uTLS（Go crypto/tls 的 fork），`fingerprint` 默认 chrome | 从 uTLS 的 hello 状态中取出 X25519 私钥，改写 SessionId 后重新序列化 |
| sing-box | metacubex/utls，`tls.utls.{enabled,fingerprint}`，默认不启用 | 同上；目前因为 chrome 指纹缺少 MLKEM，连不上 Xray 26.9.8+ |
| mihomo | metacubex/utls，`client-fingerprint` | 同上，issue #3193 在跟进 |
| meow-rs（Rust 版 mihomo） | 全部改用 vendored BoringSSL，运行时不用 rustls，提供 Chrome / Firefox / Safari / iOS / Android / Edge profile | README 没有提到 Reality |
| wreq / btls（0x676e67） | BoringSSL 硬 fork 加 Rust 绑定，可调扩展顺序、ALPS、证书压缩等 | 无 |
| craftls | rustls fork，提供 `with_fingerprint(CHROME_108)` | 无；停在 rustls 0.22，已不维护 |
| shoes（cfal） | Reality 使用自写的 TLS 1.3 消息（`reality_tls13_messages.rs`） | 有，自写握手 |

### 2.2 Xray REALITY 服务端的新约束

- 检查条件为 `group == X25519MLKEM768 && len == mlkem.EncapsulationKeySize768 + 32`。服务端取 hybrid share 的**末尾 32 字节**（X25519 部分）与自己的私钥做 ECDH，得到 AuthKey。没有单独的 X25519 share 时就用这一份。
- 26.9.8 起，hybrid share 缺失或排在 X25519 之后的 hello 会被拒绝，关闭 MLKEM 的 opt-in 选项也随之失效。
- 附带问题：hybrid share 有 1216 字节，ClientHello 会跨两个 TCP 段，某些移动网络会丢弃这类首包（LxBox#142）。浏览器本身也这么发，所以只能接受。

也就是说，Reality 的 ECDH 仍然只用 X25519。客户端只需要把 hybrid share 里 X25519 部分的私钥交给 `apply_reality`。

### 2.3 rustls 0.23.45 已有的能力

| 能力 | 状态 |
| --- | --- |
| X25519MLKEM768 | aws-lc-rs provider 自带（`crypto/aws_lc_rs/pq/hybrid.rs`）；ring 没有 |
| 扩展随机排序 | 已有 `order_seed`，与 Chrome 110+ 的做法一致 |
| 证书压缩 RFC 8879 | 有 `brotli` / `zlib` feature |
| ECH 与 ECH GREASE | 有 `EchMode::Grease`，需要 HPKE（aws-lc） |
| GREASE（密码套件、扩展、groups、versions） | 没有 |
| 指定密码套件、groups、sigalgs 的列表和顺序 | 只能从 provider 支持的范围中选，不能声明它实现不了的值 |
| padding、ALPS、SCT 请求、status_request、delegated_credentials、record_size_limit | 没有，或不按浏览器的形式发送 |
| 自定义扩展顺序 | 没有 |

## 3. 方案比较

### 3.1 三个方案

- **A. rustls fork（`sail-rustls`）。** 把 Reality 补丁 rebase 到 0.23.45，再加入按 `ClientHelloSpec` 生成 hello 的能力。用 `[patch.crates-io]` 替换全进程的 rustls，quinn、tokio-rustls 和入站都使用同一份。
- **B. BoringSSL（btls 或 boring2）。** Chrome 本身就用 BoringSSL，模拟 Chrome 可以做到字节一致；Firefox 和 Safari 需要靠 btls 暴露的开关拼出来。
- **C. 自写 TLS 1.3 客户端。** 参考 shoes，完全控制握手。

| 维度 | A. rustls fork | B. BoringSSL | C. 自写握手 |
| --- | --- | --- | --- |
| Chrome 的 ClientHello | 由 spec 逐字节生成，可以做到一致 | 原生一致 | 可以做到一致 |
| Firefox / Safari | 由 spec 生成，与 Chrome 难度相同 | 依赖 btls 开关；NSS 或 Apple 特有的扩展不一定能拼出来 | 可以做到 |
| 服务端选中 hello 里宣称、但 rustls 未实现的算法（TLS 1.2 CBC、3DES、ffdhe 等） | 握手失败。TLS 1.3 服务端只会在 AES-GCM 和 ChaCha20 里选，rustls 都支持，实际风险很低 | 都支持 | 需要自己实现 |
| Reality | rebase 现有的 48 行补丁，再为 hybrid group 加上 `extract_reality_key` | 要改 BoringSSL 的 C 代码：取临时私钥，在序列化后改写 session_id | 自己实现 |
| Vision 直拷贝 | 现有 `ClientTlsStream` 不变 | 需要基于内存 BIO 重写流 | 自己实现 |
| QUIC（Hysteria2 / TUIC） | quinn 自动使用同一个 fork，以后给 QUIC 加指纹几乎没有额外成本 | quinn 不能用；需要 quiche 或 tquic，整套 QUIC 都要换 | 不涉及 |
| 构建 | 纯 Rust；aws-lc 已经是默认依赖 | 多一套 BoringSSL 的 C/C++ 构建（cmake），iOS、Android、路由器的交叉编译都需要重新验证 | 纯 Rust |
| 体积 | 基本不变 | 与 aws-lc 并存时增加 1–2 MB；要去掉 aws-lc 则牵连 AEAD 和 quinn | 小 |
| 安全面 | 握手核心仍是 rustls | BoringSSL | 自写密码协议，风险最高 |
| 维护 | 跟随 rustls 小版本 rebase；补丁集中在 hello 生成、EE 解析和 kx | 跟随 btls 或 boring2；上游只有一位维护者 | 全部自己维护 |
| 预估 | 3–4 周 | 4–6 周，另加交叉编译 CI | 8 周以上 |

### 3.2 最初建议选 A（已改为 B，见 §3.4）

主要原因：

- Reality 和普通 TLS 本来就需要 fork rustls。合并成一个 fork，反而比现在的两份 rustls 更少。
- Vision、QUIC 和入站能保持现有结构，P0.2 的收益不会被推翻。
- 指纹的保真度由 spec 决定，与 TLS 库无关。实际限制只在「宣称了但实现不了的算法」，在 TLS 1.3 下基本不会触发。

### 3.3 方案 A 的设计要点

**fork 的改动（尽量集中在少数文件）：**

1. `ClientConfig` 增加 `client_hello_spec: Option<Arc<ClientHelloSpec>>`。spec 描述以下内容：
   - 密码套件列表，可含 GREASE 和 rustls 未实现的值；
   - 扩展顺序，以及是否按 Chrome 的方式随机排列；
   - supported_groups、key_share 的 groups 和顺序；
   - signature_algorithms、supported_versions，以及每一处 GREASE；
   - padding（BoringSSL 的规则）、compress_certificate 的算法列表、ALPS 的码点（Chrome 131 起从 17513 改为 17613）；
   - 不透明扩展，例如 SCT、status_request、delegated_credentials、record_size_limit、session_ticket 和 ech GREASE 的占位。
2. 接收侧：对 hello 里请求过的扩展，服务端的响应要能接受或忽略，例如 OCSP、SCT 和 EncryptedExtensions 中的 ALPS。如果服务端协商了 ALPS，客户端必须发送 Client EncryptedExtensions（Chrome 会这样做，uTLS 也实现了），否则会被 BoringSSL 服务端（如部分 CDN）判为异常。
3. `ActiveKeyExchange::extract_reality_key`：为 aws-lc 的 X25519MLKEM768 hybrid 实现，返回其中 X25519 部分的共享密钥。Reality 的 provider 改用 aws-lc，不再使用 ring。
4. Reality 的 `RealityCallback` 保持不变，仍在 hello 序列化后改写 session_id。它与 spec 是正交的。

**leaf 侧：**

- 在 `transport/tls/fingerprint/` 下每个 profile 一个文件（`chrome.rs`、`firefox.rs`、`safari.rs`），把 spec 写成常量，并注明对应的浏览器版本和抓包来源。
- `OutboundTls` 增加 `utls` 块，字段名对齐 sing-box（见 T2）。Reality 只接受带 X25519MLKEM768 的 profile，配成其他 profile 视为配置错误。
- 删除 reality-rustls 依赖和 `TlsConnection` 的第二个实现。

**不做的事：** 不模拟 HTTP/2 的 SETTINGS 和帧顺序（Akamai 指纹）。gRPC 和 h2 传输的这部分特征放到 1.7 处理。1.1 只保证 TLS 层。

### 3.4 方案 B（已选）：btls

**btls 现状（2026-09-25 核实，仓库 0x676e67/btls，版本 0.5.6）：**

- 仓库包含 `btls`、`btls-sys`、`tokio-btls` 和 `compio-btls`，是 cloudflare/boring 的硬 fork。
- `btls-sys/patches/` 对 BoringSSL 打了以下补丁：`ffdhe`、`legacy-ciphers`、`tls-options`、`extension-order`、`record-size-limit`、`delegated-credentials`、`cipher-preferences`、`sigalgs`、`zstd-cert-compression` 等。
- 与指纹相关的 API：
  - 扩展：`set_extension_permutation`、`set_permute_extensions`；
  - GREASE：`set_grease_enabled`、`set_grease_sigalgs_enabled`；
  - key share 与 groups：`set_client_key_shares`（含 `X25519_MLKEM768`）、`set_curves_list`；
  - 密码套件与签名算法：`set_cipher_list`、`set_preserve_tls13_cipher_list`、`set_sigalgs_list`、`set_verify_algorithm_prefs`；
  - ALPS：`add_application_settings`、`set_alps_use_new_codepoint`；
  - 证书压缩：`add_certificate_compression_algorithm`；
  - 其他扩展：`set_record_size_limit`、`set_delegated_credentials`、`enable_ocsp_stapling`、`enable_signed_cert_timestamps`、`set_enable_ech_grease`、`set_ech_config_list`；
  - 证书校验：`set_custom_verify_callback`。
- CI 覆盖 Linux（x86_64 / aarch64 / arm / i686）、Android 全架构、iOS 与模拟器、tvOS、macOS 和 Windows。没有 mips。
- `prefix-symbols` feature 使用 BoringSSL 原生的符号前缀，可以与 aws-lc 或 boring-sys 共存。生成前缀时需要 `go run`。

**Reality 需要一个 C 补丁。** btls 没有提供以下能力：拿到 key share 的临时私钥，以及在 ClientHello 序列化之后、写入 transcript 之前改写 session_id。Xray 用 uTLS 的做法是「构建 hello → 计算 → 改写 SessionId → 重新序列化」。在 BoringSSL 中需要补一个通用钩子，大致如下：

```c
// 在 ClientHello 编码完成、加入 transcript 之前调用。
// hello 中 session_id 已置零；回调写入 32 字节的 session_id。
// x25519_priv 取自第一个 X25519 或 X25519MLKEM768 share 中的 X25519 部分。
typedef int (*SSL_client_hello_finalize_cb)(SSL *ssl,
    const uint8_t *hello, size_t hello_len,
    const uint8_t random[32], const uint8_t x25519_priv[32],
    uint8_t session_id_out[32]);
void SSL_set_client_hello_finalize_cb(SSL *ssl, SSL_client_hello_finalize_cb cb);
```

- 预计 60–120 行，改动位于 `handshake_client.cc` 和 X25519MLKEM768 的 key share 实现。钩子与 Reality 无关，可以尝试提交给 btls 上游。
- 服务端证书校验（ed25519 证书的签名 = HMAC(AuthKey, 公钥)）使用现成的 `set_custom_verify_callback`，不需要改 C 代码。
- 以后换成 TLS 库之外的方式（例如 Reality 专用的握手实现）也不会影响指纹部分。

**Vision 直拷贝：** 现有 `ClientTlsStream` 基于 rustls 的 `read_tls` / `write_tls`，需要为 BoringSSL 实现同样的接口。两种做法：

- 使用内存 BIO 对，由我们自己驱动 socket 读写。这与现有 `TlsConnection` trait 的形状一致，可以直接实现该 trait；
- 或者使用 tokio-btls 的 `SslStream`，并关闭 read_ahead，保证切换时 SSL 内部没有多读的数据。

倾向内存 BIO：切换点完全可控，也能沿用 P0.1 的缓冲池。

**分工（已定：只保留一套 btls）：**

| 场景 | 实现 |
| --- | --- |
| 客户端 TCP TLS（普通 TLS、Reality、WS/gRPC over TLS） | btls |
| TLS 入站（包括 1.3 的 Reality 服务端和 VLESS Vision 入站） | btls。与客户端共用 `TlsConnection`（内存 BIO）和 Vision 直拷贝 |
| QUIC | 协议栈仍用 quinn（原生 tokio、可替换拥塞控制和 UDP socket，Hysteria2 和 TUIC 需要这些）；加密层换成 [quinn-btls](https://github.com/0x676e67/quinn-btls)。QUIC 的 ClientHello 可以复用同一套 profile |
| Shadowsocks / VMess 的 AEAD | btls 的 AEAD，替换 `common/crypto.rs` 里的 aws-lc 和 ring 实现 |

Reality 服务端不需要改 C 代码：先自己读出 ClientHello，用服务端私钥和 hello 中的 X25519 公钥完成认证；认证失败就把原始字节转发给目标网站，成功再交给 BoringSSL 握手，并通过 `set_select_certificate_callback` 设置当前连接的临时证书。模仿目标网站响应（记录长度等）的细节留到 1.3 设计。

quinn-btls（核实于 2026-09-25）：作者与 btls 相同；依赖 btls 0.5.5，约 3500 行；2026-03 创建，版本 0.1.0，只有 5 个提交，已支持 ECH retry configs。遇到问题时 fork 修复并向上游提 PR。

**依赖变化：**

- 删除：reality-rs、reality-rustls、rustls、tokio-rustls、rustls-pemfile（新旧两版）、ring、aws-lc-rs，以及 `openssl-tls` / `openssl-aead` 和整套 openssl。quinn 关闭 rustls 相关的 feature。
- 新增：`btls`、`btls-sys`、`tokio-btls`（或只用内存 BIO，不引入 tokio-btls），以及 `quinn-btls`。Reality 补丁用的是 btls 的 fork（T7）。
- 已核实：rustls、ring 和 aws-lc 只有 leaf 自己的 TLS、QUIC 和 AEAD 在用，没有其他依赖会间接引入。进程里只有一套 BoringSSL，就不需要 `prefix-symbols`，构建也不需要 Go。
- 根证书：webpki-roots 只提供 trust anchor，BoringSSL 需要完整的证书，因此改用 `webpki-root-certs`。是否另外加载系统证书，在 1.1a 中确定。
- Cargo feature 精简：`default-ring`、`default-aws-lc`、`default-openssl`、`*-aead`、`rustls-tls-*` 和 `quinn-*` 合并为一套。
- 构建环境：需要 cmake 和 clang。release 用 `cross` 构建 musl 版本，需要确认 cross 镜像里有这些工具，没有就换成自定义镜像。mips 不在 btls 的 CI 中，需要时自行验证。
- 体积：BoringSSL 替换 aws-lc 加 ring，预计与现在持平或略小，1.1a 完成后实测。

**profile 的实现：** 每个 profile 是一个函数 `fn apply(&mut SslConnectorBuilder / SslRef)`，按浏览器的抓包调用上述 API，并注明浏览器版本和抓包来源。Chrome 基本只需打开 GREASE、扩展随机排列、ALPS、brotli 证书压缩和 X25519MLKEM768。Firefox 和 Safari 依赖 btls 的补丁，逐项核对 fixture；拼不出来的扩展记录在 profile 注释里。

**实施估算：** 5–7 周。其中 Reality C 补丁和 Vision 流约 1.5 周，入站、quinn-btls 和 AEAD 迁移约 1 周，交叉编译 CI 约 1 周。

## 4. 服务端证书热更新

入站使用 btls：

- 入站持有 `ArcSwap<SslAcceptor>`（或在 `set_select_certificate_callback` 中按 SNI 取当前证书）。握手开始时无锁读取，替换证书时整体换掉 acceptor。
- 两个触发来源：P0.2 已有的按组件热更新（入站配置变化），以及可选的证书文件监听（`notify`，带去抖）。sing-box 的做法也是证书文件修改后自动重载。
- 新证书解析失败时保留旧证书，并记录错误日志，已有连接不受影响。
- ACME 不在 1.1 范围内。

## 5. 验证方法

| 层级 | 做法 |
| --- | --- |
| 抓包 fixture | 在 `tests/fixtures/tls/` 下放真实浏览器的 ClientHello（Chrome 稳定版、Firefox 稳定版、Safari/iOS 26），记录浏览器版本和采集日期；只保留握手字节，不保留其他流量 |
| 单元测试 | 固定随机源生成 hello，按 fixture 比较 JA4 和 JA3（Chrome 需去掉 GREASE 并对扩展排序），并逐一比对扩展集合、groups、sigalgs、padding 长度等结构，而不只是比较 hash |
| 回环测试 | 本地 TLS 服务端解析收到的 hello，用 sniff 模块的解析器计算 JA4，分别覆盖普通 TLS、Reality、WS over TLS 和 gRPC over TLS（gRPC 待 1.7 实现后补上） |
| 互操作 | Xray-core v26.9.x 的 Reality 服务端（必须能连上）、sing-box TLS 入站、nginx / Caddy 的 TLS 1.2 和 1.3，以及启用 ALPS 的 BoringSSL 服务端 |
| 更新流程 | 浏览器每个大版本改动指纹时，重新抓包并更新 fixture；过期检测放进 P5 的定期任务 |

## 6. 实施顺序（按方案 B）

| 步骤 | 内容 | 验收 |
| --- | --- | --- |
| 1.1a | 引入 btls；实现 BoringSSL 版的 `TlsConnection`（内存 BIO）；TLS 出站和入站都切换到 btls，Vision 直拷贝可用；CI 覆盖 macOS、Linux musl、Android、iOS | 现有 TLS 和 Vision 测试全部通过；各发布目标都能编译 |
| 1.1b | quinn 的加密层换成 quinn-btls；AEAD 换成 btls；删除 rustls、ring、aws-lc 和 openssl，精简 Cargo feature | `cargo tree` 中不再有 rustls、ring、aws-lc 和 openssl；QUIC、Shadowsocks、VMess 的测试通过；记录体积变化；数据通路性能不低于 P0.2 基线 |
| 1.1c | Reality C 补丁（fork btls，在 `btls-sys/patches/` 下加一个补丁），Reality 出站迁移到 btls，默认发送 X25519MLKEM768；删除 reality-rs 和 reality-rustls | 能连上 Xray v26.9.x 的 Reality 服务端 |
| 1.1d | Chrome profile、`utls` 配置，普通 TLS 和 Reality 默认使用 chrome，附 fixture 和 JA4 测试 | JA4 与 Chrome fixture 一致；各项互操作通过 |
| 1.1e | Firefox 和 Safari profile | JA4 分别与各自的 fixture 一致 |
| 1.1f | 入站证书热更新 | 替换证书文件后新连接使用新证书，已有连接不中断 |

**1.1a 的实施记录（2026-09-25）：**

- **构建：** btls 从 crates.io 引入（0.5.6）。不开 `prefix-symbols` 也能与 aws-lc 同进程链接（aws-lc 的符号自带前缀）。构建只需要 cmake 和 C/C++ 编译器，不需要 Go。
- **btls 待提交上游的两处改进：**
  - `btls-sys` 没有把 Apple 的部署目标传给 CMake，导致 BoringSSL 按 SDK 版本编译。补丁已在本地验证：打上后 iOS 目标文件按 13.0 编译，链接警告消失。
  - `SslRef` 上没有 `set_connect_state` / `set_accept_state`，目前通过 btls-sys 直接调用。
- **iOS 最低版本：** 提高到 13（BoringSSL 需要 `___chkstk_darwin`）。
- **已验证的平台：** macOS 测试、aarch64-apple-ios（leaf-ffi）、aarch64-unknown-linux-musl（容器内构建）。Android 在本机没有 NDK，只能依赖 CI。

Reality 的故障修复（1.1c）依赖 1.1a；1.1b 与 1.1c 互不依赖，可以对调。如果需要更快恢复 Reality，可以先在现有 reality-rustls 上改用 aws-lc provider 并加 hybrid share，作为临时修复（见 T10）。

## 7. 待决策

| # | 问题 | 选项 | 建议 |
| --- | --- | --- | --- |
| T1 | TLS 后端 | A. rustls fork；B. BoringSSL（btls）；C. 自写 TLS 1.3 客户端 | **已定：B（btls）**，2026-09-25 |
| T2 | 配置形态 | A. 对齐 sing-box：`tls.utls: { enabled, fingerprint }`，但默认值改为启用 chrome；B. 平铺为 `tls.fingerprint: "chrome"`，用 `"rustls"` 表示不伪装 | **已定：A**，默认 chrome |
| T3 | 首批 profile | chrome / firefox / safari（iOS 与 macOS 共用）/ edge（chrome 的别名）/ random（按会话在前几项中随机选） | **已定：chrome、firefox、safari**，edge 作为 chrome 的别名 |
| T4 | 精简 TLS 后端 | — | **已定：只保留一套 btls**，删除 rustls、ring、aws-lc 和 openssl |
| T5 | QUIC | — | **已定：协议栈仍用 quinn，加密层用 quinn-btls**。QUIC 的指纹 profile 在 1.5 / 1.6 启用 |
| T6 | 交付方式 | 按 §6 每步一个提交 | 1.1a 之后优先做 1.1c，尽快恢复 Reality |
| T7 | Reality C 补丁放在哪里 | A. fork btls，在 `btls-sys/patches/` 中多加一个补丁，跟随上游 rebase；B. 用 `BORING_BSSL_SOURCE_PATH` 指向我们自己打过补丁的 BoringSSL（但这样 btls 的补丁都要自己重打） | **已定：A**，同时把钩子提交给上游 |
| T8 | 入站是否也换成 BoringSSL | — | **已定：换**。客户端和服务端共用同一套 TLS 栈 |
| T9 | C 密码库 | — | **已定：只有 BoringSSL**。不需要 `prefix-symbols`；上游的问题由我们 fork 修复并提交 PR |
| T10 | 是否先临时修复 Reality | 1.1a 和 1.1c 需要约 2–3 周。可以先在 reality-rustls 上改用 aws-lc provider，加 X25519MLKEM768 并实现 `extract_reality_key`，约 2–3 天 | **已定：不做**（目前没有用户），等 1.1c |

## 来源

- [SagerNet/sing-box#4520：Xray v26.9.8+ 要求 X25519MLKEM768](https://github.com/SagerNet/sing-box/issues/4520)
- [XTLS/REALITY commit 8cdf7bf：hybrid share 的 X25519 部分参与 ECDH](https://github.com/XTLS/REALITY/commit/8cdf7bf9c7f0)
- [MetaCubeX/mihomo#3193](https://github.com/MetaCubeX/mihomo/issues/3193)、[Leadaxe/LxBox#142：hybrid share 首包被丢弃](https://github.com/Leadaxe/LxBox/issues/142)
- [rustls#1932](https://github.com/rustls/rustls/issues/1932)、[rustls#2498（not planned）](https://github.com/rustls/rustls/issues/2498)
- [btls releases](https://github.com/0x676e67/btls/releases)（源码于 2026-09-25 克隆核实：补丁目录、API、CI 目标）
- [craftls](https://github.com/3andne/craftls)、[btls](https://github.com/0x676e67/btls)、[meow-rs](https://github.com/meow-rs/meow-rs)、[shoes](https://github.com/cfal/shoes)、[webclaw-tls](https://github.com/0xMassi/webclaw-tls)
- [Xray REALITY 文档](https://xtls.github.io/en/config/transports/reality.html)
