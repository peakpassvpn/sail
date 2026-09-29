---
title: CLI 参考
description: 使用命令行运行、验证、测试与调优 Sail。
---

`sail-cli` crate 生成 `sail` 可执行文件。未传参数时，程序默认读取当前目录的 `config.conf`。

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

| 配置档 | 适用宿主 |
| --- | --- |
| `mobile` | 手机与内存敏感进程 |
| `desktop` | 默认通用配置 |
| `server` | 高并发与吞吐优先 |
| `router` | 资源紧张的小型设备 |

```sh
sail -c config.json --profile server \
  --set relay.buffer_size=32 \
  --set dns.max_retries=3
```

这些参数描述宿主资源预算，不改变代理行为。协议、DNS 和路由仍应写入配置文件。

多路复用连接（sing-mux 的 smux 与 yamux、AnyTLS、amux）上的流使用其中三项：

| 参数 | 默认值 | 含义 |
| --- | --- | --- |
| `mux.stream_window_max` | `16384`（KiB）；`mobile` 为 `8192`，`router` 为 `4096` | 单条流接收窗口的上限（yamux、amux）。窗口从 256 KiB 起步，流读得比窗口放进来的快时翻倍。h2mux 单流取其四分之一，整条连接取其两倍。 |
| `mux.stream_buffer` | `256`（KiB） | 无窗口协议（smux、AnyTLS）的单条流最多积压的未读数据，超过后暂停读取整条连接。 |
| `mux.stall_timeout` | `60s` | 数据积压且这么久没人读的流被单独重置，并记录 `event=stream_stalled`；h2mux 的流同样适用。QUIC 流（Hysteria2、TUIC）固定 60 秒。 |

API 的 `/api/v1/runtime/stat/mux` 按协议给出会话数、流数和被重置的停滞流数。

## 数据与状态目录

```sh
sail -c config.json \
  --data-dir /opt/sail/data \
  --cache-dir /var/lib/sail
```

数据目录存放 `geo.mmdb`、`site.dat` 和相对路径证书；缓存目录保存选择器当前成员等跨重启状态。

## 资源文件

部分规则读取数据目录中的数据文件：`geoip` 与 `mmdb:` 外部规则读 `geo.mmdb`，`geosite` 与 `site:` 读 `site.dat`，`ip_asn`（Surge 的 `IP-ASN`）和 `smart` 组的 `prefer_asn` 读 `asn.mmdb`；外部规则或 `asn_file` 也可以指定别的文件。Sail 自身从不下载这些文件；配置需要的文件不存在时加载失败，并给出路径。

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

## 参数速查

| 参数 | 用途 |
| --- | --- |
| `-c`, `--config` | 配置文件，默认 `config.conf` |
| `--auto-reload` | 监听文件变化并重载 |
| `-T`, `--test` | 验证配置后退出 |
| `-t`, `--test-outbound` | 测试指定出站标签 |
| `-d` | 出站测试超时秒数 |
| `--profile` | `mobile`、`desktop`、`server` 或 `router` |
| `--set` | 覆盖一个运行时参数，可重复 |
| `-D`, `--data-dir` | 资源与相对证书目录 |
| `--cache-dir` | `experimental.cache_file` 的默认位置，远程规则集也缓存在这里 |
| `--single-thread` | 使用单线程运行时 |
| `--fetch-assets` | 启动前下载缺少的资源文件 |
| `--asset-source` | `name=url`：资源文件的下载地址，可重复 |
| `assets <config>` | 列出资源文件；`--fetch`、`--update`、`--source name=url` |
| `-V`, `--version` | 显示版本 |
