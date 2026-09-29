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
| `-V`, `--version` | 显示版本 |
