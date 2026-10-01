---
title: CLI 参考
description: 使用命令行运行、验证、测试与调优 Sail。
---

`sail-cli` crate 生成 `sail` 可执行文件。未传参数时，程序默认读取当前目录的 `config.json`。

配置格式由扩展名决定：`.json` 为 sing-box JSON（允许注释和末尾逗号），`.yaml` 或 `.yml` 为 Clash/Mihomo YAML，`.conf` 为 Surge 配置。其他扩展名直接报错。三种格式由同一个加载器直接读取，无需先转换。

## 常用命令

```sh
sail -c config.json                 # 启动
sail -c config.json -T              # 验证后退出
sail -c config.json --auto-reload   # 文件变化后重载
sail -V                             # 显示版本
```

## 出站连通性测试

按标签单独测试一个出站，不启动常规监听：

```sh
sail -c config.json -t edge
sail -c config.json -t edge -d 10
```

Sail 会分别报告 TCP、UDP 的耗时或错误。默认超时为 4 秒，`-d` 可调整。该命令只测试指定出站，不代表完整的“应用—入站—路由—出站”链路。

## 运行时配置档

运行时配置档调整内存预算、队列和并发度，不改动可移植的配置文件。

| 配置档 | 适用宿主 |
| --- | --- |
| `mobile` | 手机与内存敏感进程 |
| `desktop` | 默认通用配置 |
| `server` | 高并发与吞吐优先 |
| `router` | 资源紧张的小型设备 |

```sh
sail -c config.json --profile server
```

用可重复的 `--set key=value` 覆盖单个参数。键是以点分隔的路径，值可以是数字、`true`/`false`，或 `10s` 这样的时长。键不存在或值类型不对都会报错。

```sh
sail -c config.json --profile server \
  --set relay.buffer_size=32 \
  --set dns.max_retries=3
```

这些参数描述宿主资源预算，不改变代理行为。协议、DNS 和路由仍应写入配置文件。

参数分组为 `relay`（TCP 转发缓冲区与半关闭后的空闲超时）、`udp`、`netstack`（TUN 协议栈的预算、批量、队列与 TCP 窗口）、`inbound`（握手超时、多路复用接受并发、TCP 发送缓冲区）、`quic`、`ws`、`dns`（`max_retries`、`dualstack_delay`）、`stats`、`lifecycle` 和 `mux`。几个随配置档变化的值：

| 参数 | `desktop` | `mobile` | `router` | `server` |
| --- | --- | --- | --- | --- |
| `relay.buffer_size`（KiB） | `16` | `8` | `4` | `16` |
| `relay.buffer_max_size`（KiB） | `128` | `64` | `16` | `256` |
| `quic.max_concurrent_streams` | `1024` | `256` | `128` | `4096` |
| `inbound.tcp_send_buffer`（KiB，`0` 表示交给系统） | `0` | `0` | `256` | `0` |
| `lifecycle.drain_timeout` | `0` | `0` | `0` | `30s` |

`lifecycle.drain_timeout` 指收到 SIGTERM 或 Ctrl-C、停止接受新连接后，已有 TCP 连接最多还能继续多久；`0` 表示立即停止，第二次信号总是立即停止。

多路复用连接（sing-mux 的 smux 与 yamux、AnyTLS、amux）上的流使用其中三项：

| 参数 | 默认值 | 含义 |
| --- | --- | --- |
| `mux.stream_window_max` | `16384`（KiB）；`mobile` 与 `router` 为 `8192` | 单条流接收窗口的上限（yamux、amux）。窗口从 256 KiB 起步，流读得比窗口放进来的快时翻倍。h2mux 单流取其四分之一，整条连接取其两倍。 |
| `mux.stream_buffer` | `256`（KiB） | 无窗口协议（smux、AnyTLS）的单条流最多积压的未读数据，超过后暂停读取整条连接。 |
| `mux.stall_timeout` | `60s` | 数据积压且这么久没人读的流被单独重置，并记录 `event=stream_stalled`；h2mux 的流同样适用。QUIC 流（Hysteria2、TUIC）固定 60 秒。 |

API 的 `/api/v1/runtime/stat/mux` 按协议给出会话数、流数和被重置的停滞流数。

## 数据与状态目录

```sh
sail -c config.json \
  --data-dir /opt/sail/data \
  --cache-dir /var/lib/sail
```

数据目录存放 `geo.mmdb`、`site.dat` 和相对路径证书，默认是可执行文件所在目录。缓存目录默认存放 `experimental.cache_file`（选择器的选择、Clash 模式，以及开启 `store_fakeip` 时的 fake IP），还缓存下载的远程规则集和 Surge 配置远程 include 的副本。

## 资源文件

部分规则读取数据目录中的数据文件：`geoip` 与 `mmdb:` 外部规则读 `geo.mmdb`，`geosite` 与 `site:` 读 `site.dat`，`ip_asn`（Surge 的 `IP-ASN`）和 `smart` 组的 `prefer_asn` 读 `asn.mmdb`；外部规则或 `asn_file` 也可以指定别的文件。Sail 加载配置时不会下载这些文件；配置需要的文件不存在时加载失败，并给出路径。

```sh
# 配置读取哪些文件、在哪里、是否存在
sail -D /opt/sail/data assets config.json

# 下载缺少的，或全部重新下载
sail -D /opt/sail/data assets config.json --fetch
sail -D /opt/sail/data assets config.json --update

# 换一个地址
sail assets config.json --fetch --source geo.mmdb=https://example.com/Country.mmdb

# 启动前先下载缺少的
sail -c config.json --fetch-assets
```

`sail assets` 每个文件一行：名称、`present` 或 `missing`、路径，以及读取它的字段（如 `route.rules[3].ip_asn`）。下载的文件只有能按 MaxMind 数据库或站点列表读出时才会替换原文件，且不会留下半个文件。默认来源：

| 文件 | 来源 |
| --- | --- |
| `asn.mmdb` | GeoLite2-ASN，与 Mihomo 默认相同：`https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/GeoLite2-ASN.mmdb` |
| `geo.mmdb` | GeoLite2-Country 格式：`https://github.com/Loyalsoldier/geoip/releases/latest/download/Country.mmdb` |
| `site.dat` | V2Ray 站点列表：`https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat` |

规则自行指定的文件没有默认来源，用 `--source name=url`（启动时用 `--asset-source name=url`）给出。从文件读取或下载的规则集也可能需要 `asn.mmdb`，这只有在加载时才知道，其错误会给出文件路径。

CLI 启动时使用的来源成为宿主的 `asset_sources`，运行中的更新接口从这里取地址：

| 接口 | 用途 |
| --- | --- |
| `GET /api/v1/runtime/assets` | 运行中配置读取的资源文件，内容同 `sail assets`，JSON 格式 |
| `POST /api/v1/runtime/assets/{name}/update` | 下载一个文件：地址取请求体的 `url`，否则取宿主的来源；经请求体的 `detour` 出站，否则经默认出站；能读出才替换，随后重载使规则读到新文件。响应说明重载是否成功。配置不读取该名称时 404，没有地址时 400，下载或文件无效时 502 |

## Surge include、Sub-Store 与面板

```sh
# 读取前先下载 Surge 配置 include 的 URL
sail -c profile.conf --cache-dir /var/lib/sail --fetch-includes

# 把 sub.store 地址解析到你自己的 Sub-Store 后端
sail -c profile.conf --sub-store https://substore.example.com/secret-path
```

`--fetch-includes` 把 Surge 配置中每个 `#!include https://...`，以及它们再 include 的内容，下载到缓存目录，配置从那里读取。它需要 `--cache-dir`，且配置必须是 `.conf` 文件。某个下载失败时保留已有副本；没有副本则启动失败。

`--sub-store` 指定基础 URL（含密钥路径），用来替换订阅和规则集 URL 中的 `sub.store`——这是 Sub-Store 在 Surge、Loon 和 Quantumult X 中使用的地址。

`--ui-download-url` 是配置未指定地址时，Clash API 下载到空 `external_ui` 目录的 ZIP。默认是 metacubexd；传空值则不下载。

## 生成密钥

`sail generate` 输出一个密钥或密码后退出：

```sh
sail generate uuid                              # 随机 UUID，供 VLESS、VMess、TUIC 用户使用
sail generate rand 16 --base64                  # 随机字节：原始、--base64 或 --hex
sail generate reality-keypair                   # PrivateKey（服务端）与 PublicKey（客户端）
sail generate wg-keypair                        # WireGuard 密钥对
sail generate ss2022 2022-blake3-aes-128-gcm    # 长度符合该加密方式的密钥
sail generate secret                            # Clash API 密钥（clash_api.secret）
```

`ss2022` 接受 `2022-blake3-aes-128-gcm`、`2022-blake3-aes-256-gcm` 或 `2022-blake3-chacha20-poly1305`。

## 导入分享链接

`sail import` 读取分享链接（`ss://`、`trojan://`、`vless://`、`vmess://`、`hysteria2://` 或 `hy2://`、`tuic://`、`anytls://`），以 JSON 输出为 sing-box 出站：

```sh
sail import 'vless://...'
sail import subscription.txt
cat subscription.txt | sail import
```

输入可以是一条链接、一个订阅文件（base64 或每行一条链接），或标准输入。无法读取的行会连同行号输出到 stderr；只有一条链接都没读出时命令才失败。标签会自动去重。ShadowsocksR、Hysteria v1 和 WireGuard 链接不导入。

## 线程

Sail 默认使用多线程运行时。`--single-thread` 适合资源受限的宿主、可复现的调试，或自带外层并发的嵌入场景。`--thread-stack-size` 以字节为单位设置工作线程栈大小（release 构建默认 256 KiB，debug 构建 2 MiB）；除非性能分析表明确有需要，否则保持默认。

在 Unix 上，CLI 启动时会把打开文件数的软限制提高到硬限制（macOS 上不超过 `kern.maxfilesperproc`）。

## 参数速查

| 参数 | 用途 |
| --- | --- |
| `-c`, `--config` | 配置文件，默认 `config.json`；按扩展名区分格式：`.json`、`.yaml`/`.yml`、`.conf` |
| `--auto-reload` | 监听文件变化并重载 |
| `--single-thread` | 使用单线程运行时 |
| `--thread-stack-size` | 工作线程栈大小（字节） |
| `-T`, `--test` | 验证配置后退出 |
| `-t`, `--test-outbound` | 测试指定出站标签 |
| `-d`, `--test-outbound-timeout` | 出站测试超时秒数，默认 `4` |
| `--profile` | `mobile`、`desktop`、`server` 或 `router` |
| `--set` | 覆盖一个运行时参数，可重复 |
| `-D`, `--data-dir` | 资源与相对证书目录 |
| `--cache-dir` | `experimental.cache_file` 的默认位置，也缓存远程规则集和 Surge include |
| `--sub-store` | 自有 Sub-Store 后端的基础 URL，替换 `sub.store` |
| `--ui-download-url` | Clash API 下载到空 `external_ui` 的 ZIP；默认 metacubexd，空值表示不下载 |
| `--fetch-includes` | 启动前把 Surge 配置的远程 include 下载到缓存目录 |
| `--fetch-assets` | 启动前下载缺少的资源文件 |
| `--asset-source` | `name=url`：资源文件的下载地址，可重复 |
| `assets [config]` | 列出资源文件（未给出时用 `-c` 的配置）；`--fetch`、`--update`、`--source name=url` |
| `generate <kind>` | `rand`、`uuid`、`reality-keypair`、`wg-keypair`、`ss2022`、`secret` |
| `import [input]` | 把分享链接转为 sing-box 出站 JSON |
| `-V`, `--version` | 显示版本 |
| `--help` | 显示用法；也可放在子命令之后 |
