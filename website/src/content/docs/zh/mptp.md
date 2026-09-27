---
title: MPTP 多路径传输
description: 将多个出站路径组合成一条逻辑客户端/服务端隧道。
---

MPTP（Multi-path Transport Protocol）建立多条可靠子连接，并把它们呈现为一条逻辑隧道。

```text
应用 → SOCKS → MPTP 客户端 ⇒ 路径 A ┐
                          ⇒ 路径 B ├→ MPTP 服务端 → 目标
                          ⇒ 路径 C ┘
```

## 客户端配置

```json
{
  "inbounds": [
    { "type": "socks", "tag": "local-socks", "listen": "127.0.0.1", "listen_port": 1086 }
  ],
  "outbounds": [
    {
      "type": "mptp",
      "tag": "aggregate",
      "outbounds": ["path-a", "path-b"],
      "server": "mptp.example.com",
      "server_port": 3001
    },
    { "type": "direct", "tag": "path-a" },
    { "type": "direct", "tag": "path-b" }
  ],
  "route": { "final": "aggregate" }
}
```

`outbounds` 中每个值都是一条子路径的标签。真实部署中应让这些路径具有实际差异，例如不同接口、上游代理或 detour；两个完全相同的 direct 出站不会自动产生两张独立物理网络。

## 服务端配置

```json
{
  "inbounds": [
    { "type": "mptp", "tag": "mptp-server", "listen": "0.0.0.0", "listen_port": 3001 }
  ],
  "outbounds": [{ "type": "direct", "tag": "internet" }],
  "route": { "final": "internet" }
}
```

在主机防火墙和云安全组中开放监听端口。服务端运行 `sail -c server.json -T` 后使用 `--profile server` 启动；客户端也应先验证，再通过本地 SOCKS5 测试。

## 工作方式与运行建议

客户端为应用流创建会话，经各子路径连接 MPTP 服务端；帧在可用路径间调度，服务端重组字节流或数据报后连接目标。路由器只选择 `aggregate`，具体帧由哪个成员承载由 MPTP 决定。

- 至少准备两条真正独立且健康的路径。
- 每个成员标签都必须存在并能访问服务端。
- 先单独测试各成员，再测试聚合出站。
- 延迟与丢包差异会影响重组和实际吞吐。
