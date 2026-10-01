---
title: 故障排查
description: 逐层定位配置、监听、路由、DNS、TLS、TUN 与 MPTP 问题。
---

按从内到外的顺序排查：先验证文件，再测试出站，然后测试本地入站，最后检查应用或系统级代理/TUN 设置。

## 最短诊断流程

```sh
sail -c config.json -T
sail -c config.json -t edge -d 10
sail -c config.json   # 需要详细日志时，在文件中设置 "log": { "level": "debug" }
curl --socks5-hostname 127.0.0.1:1080 https://example.com
```

这能把核心配置问题与操作系统代理或 TUN 问题分离。

## 配置无法验证

错误信息会给出出错字段的路径，例如 `route.rules[0].ip_accept_any: unknown field`。sing-box JSON 中的未知字段直接报错。sing-box 或 Mihomo 支持而 Sail 未实现的字段，如果忽略它会改变流量的路由或安全性，就报错；否则只在日志中警告。Clash 和 Surge 中 Sail 不认识的键只警告，不拒绝。

常见原因包括：从 leaf 或其他项目复制了形状不同的字段，或用了 Sail 未实现的功能；路由、策略组、MPTP 成员或 detour 引用了不存在的标签；协议不支持所附传输模块；`route` 或 `reject` 规则没有任何条件（应改用 `route.final`）；同时设置了 `route.default_interface` 和 `route.auto_detect_interface`；时长缺少单位（如写成 `5` 而不是 `5s`）；文件扩展名不是 `.json`、`.yaml`、`.yml` 或 `.conf`。

把配置缩减为一个入站、一个 direct 出站和一个 final 路由，再逐段恢复。Clash 和 Surge 配置可直接读取，无需转换；但不要仅凭同名字段就假设语义与原项目完全相同。

## 监听无法访问

`127.0.0.1` 只能从本机访问。局域网访问应绑定合适的接口地址，并通过协议认证或网络策略保护监听。确认端口未被占用，且应用使用正确代理类型；HTTP 客户端连接 SOCKS 端口不会完成有效握手。

## 出站测试失败

- DNS 错误：检查服务器名称与解析器。
- 连接超时：检查防火墙、路由、接口绑定和服务端端口。
- 认证错误：检查密码、UUID 或协议用户。
- TLS 错误：检查系统时间、`server_name`、信任链、ALPN 与 REALITY 参数。

TCP 与 UDP 结果应分别阅读，协议可能两者都支持，而网络路径只放行其一。临时把 `log.level` 设为 `debug` 定位问题，完成后恢复 `info`。

## 域名规则不匹配

如果应用已在本地解析域名，Sail 可能只看到 IP。可改用代理远程 DNS、启用 DNS 反向映射，或为 TLS/HTTP 添加靠前的 `sniff` 规则。嗅探只读取连接开头的字节：TCP 上的 TLS 和 HTTP，UDP 上的 QUIC。它不能从所有协议恢复域名，也不会解密 TLS。

## TUN 启动后断网

默认路由可能捕获 Sail 自身出站并形成回环。设置 `route.auto_detect_interface: true` 或固定 `default_interface`，但不能同时设置，否则配置报错。Android 还要确认启动前宿主已提供可用的 `protect_socket` 回调（调用 `VpnService.protect`）。

如果只有大流量传输失败，检查 MTU 与网络切换处理。宿主网络变化时，应通过 `sail_network_changed` 通知嵌入的实例，并传入新的 MTU。

## MPTP 性能不佳

分别测试每条路径。若多个成员共享同一受限物理链路，聚合未必优于最佳单路径。先用两条健康且独立的路径，确认服务端可以直连目标，再逐步增加成员。

## 重载后行为没有变化

先用 `-T` 单独验证新文件。只有以下情况会重载：启用了 `--auto-reload`、收到 SIGHUP（`systemctl reload` 即发送它）、调用运行时 API（`POST /api/v1/runtime/reload`），或宿主调用了重载接口。新文件加载失败时继续运行旧配置，错误写入日志。启用 `experimental.cache_file` 后，部分状态会从缓存文件恢复，例如选择器的选择、Clash 模式，以及（开启 `store_fakeip` 时的）fake IP；只有确实不再需要这些状态时才删除该文件。

## 报告可复现问题

请提供 Sail 版本、操作系统、构建 feature、脱敏后的最小配置、完整错误，以及目标出站是否通过 `-t`。不要在公开问题中包含密码、UUID、私钥或完整证书。
