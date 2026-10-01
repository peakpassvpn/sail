---
title: MPTP 多路径传输
description: 将多个出站路径组合成一条逻辑客户端/服务端隧道。
---

MPTP（Multi-path Transport Protocol）建立多条可靠子连接，并把它们呈现为一条逻辑隧道。每条路径都携带一份数据副本，接收端保留最先到达的那一份：只要另一条路径跟得上，慢的或出故障的路径就不会拖住隧道。常见部署是：客户端有本地 SOCKS 入站和跨多条路径的 MPTP 出站，服务端有 MPTP 入站。

```text
应用 → SOCKS → MPTP 客户端 ⇒ 路径 A ┐
                          ⇒ 路径 B ├→ MPTP 服务端 → 目标
                          ⇒ 路径 C ┘
```

MPTP 及其两个端点是 Sail 自有的，包含在默认构建中。sing-box 与 Mihomo 没有它们。

## 客户端配置

```json
{
  "inbounds": [
    {
      "type": "socks",
      "tag": "local-socks",
      "listen": "127.0.0.1",
      "listen_port": 1086
    }
  ],
  "outbounds": [
    {
      "type": "mptp",
      "tag": "multipath",
      "outbounds": ["path-a", "path-b"],
      "server": "mptp.example.com",
      "server_port": 3001
    },
    {
      "type": "direct",
      "tag": "path-a"
    },
    {
      "type": "direct",
      "tag": "path-b"
    }
  ],
  "route": {
    "final": "multipath"
  }
}
```

`mptp` 出站接受 `outbounds`、`server` 与 `server_port`。`outbounds` 中每个值都是一条子路径的标签，Sail 经由它连接 `server`。真实部署中应让这些路径具有实际差异，例如不同接口、上游代理或 detour；两个完全相同的 direct 出站不会自动产生两张独立的物理网络。

## 服务端配置

```json
{
  "inbounds": [
    {
      "type": "mptp",
      "tag": "mptp-server",
      "listen": "0.0.0.0",
      "listen_port": 3001
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "internet"
    }
  ],
  "route": {
    "final": "internet"
  }
}
```

`mptp` 入站除监听字段外没有自己的选项。

:::caution
MPTP 本身没有认证，也没有加密。任何能访问服务端端口的人都可以借它连接任意目标，路径上传输的是应用发出的原始数据。请把端口限制为客户端地址可访问，或让路径经过加密的出站。
:::

在主机防火墙和云安全组中只对客户端开放监听端口。

## 启动与验证

服务端：

```sh
sail -c server.json -T
sail -c server.json --profile server
```

客户端：

```sh
sail -c client.json -T
sail -c client.json
```

然后测试本地监听：

```sh
curl --socks5-hostname 127.0.0.1:1086 https://example.com
```

## 一条连接的过程

1. 客户端为应用流生成一个随机会话 ID。
2. 它同时经由每个路径出站建立子连接，并在每条子连接上发送会话 ID、命令（TCP 或 UDP）和目标。
3. 会话随第一条连上的子连接开始；其他子连接连上后陆续加入，连接失败的路径被略过。
4. 每次写入成为一个带编号的帧，发往所有还有空间的路径：排队数据达到 64 KiB 的路径会被跳过，直到其排空。
5. 接收端保留每个帧最先到达的副本，丢弃重复，并按序交付。服务端连接目标，双向以同样方式转发。

UDP 以数据报形式经同一可靠隧道传输。数据流结束时会话结束；若所有路径在数据完整之前都已关闭，会话失败。

路径层独立于路由：路由器选择 `multipath` 出站，由 MPTP 决定每个帧由哪些成员连接承载。

## 运行建议

- 至少配置两条真正独立的路径，才能获得多路径效果。
- 每个成员标签都必须存在，并能访问 MPTP 服务端。
- 先单独测试各成员出站，再测试 MPTP 出站。
- 只要跟得上，每条路径都会传输完整的数据流：流量及其费用按路径数成倍增加。MPTP 的设计目的是让隧道扛住变慢或故障的路径，而不是叠加各路径的带宽。
- 承载大量并发会话的中继使用服务端运行时调优。

仓库中的 [`docs/mptp_architecture.md`](https://github.com/peakpassvpn/sail/blob/master/docs/mptp_architecture.md) 还描述了协议时序。
