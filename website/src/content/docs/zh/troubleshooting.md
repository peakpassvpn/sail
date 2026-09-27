---
title: 故障排查
description: 逐层定位配置、监听、路由、DNS、TLS、TUN 与 MPTP 问题。
---

按从内到外的顺序排查：先验证文件，再测试出站，然后测试本地入站，最后检查应用或系统级代理/TUN 设置。

## 最短诊断流程

```sh
sail -c config.json -T
sail -c config.json -t edge -d 10
sail -c config.json --profile desktop
curl --socks5-hostname 127.0.0.1:1080 https://example.com
```

这能把核心配置问题与操作系统代理或 TUN 问题分离。

## 配置无法验证

常见原因包括：复制了 Clash、sing-box、Surge 或 leaf 中形状不同的字段；路由、策略组、MPTP 成员或 detour 引用了不存在的标签；协议不支持所附传输模块；终止规则没有条件；超时为零。

把配置缩减为一个入站、一个 direct 出站和一个 final 路由，再逐段恢复。第三方配置应先转换为 Sail 模型，不要仅凭同名字段假设语义相同。

## 监听无法访问

`127.0.0.1` 只能从本机访问。局域网访问应绑定合适的接口地址，并通过协议认证或网络策略保护监听。确认端口未被占用，且应用使用正确代理类型；HTTP 客户端连接 SOCKS 端口不会完成有效握手。

## 出站测试失败

- DNS 错误：检查服务器名称与解析器。
- 连接超时：检查防火墙、路由、接口绑定和服务端端口。
- 认证错误：检查密码、UUID 或协议用户。
- TLS 错误：检查系统时间、`server_name`、信任链、ALPN 与 REALITY 参数。

TCP 与 UDP 结果应分别阅读。临时启用 `debug` 日志定位层级，完成后恢复 `info`。

## 域名规则不匹配

如果应用已在本地解析域名，Sail 可能只看到 IP。可改用代理远程 DNS、启用 DNS 反向映射，或为 TLS/HTTP 添加靠前的 `sniff` 规则。嗅探不能从所有协议恢复域名，也不会解密 TLS。

## TUN 启动后断网

默认路由可能捕获 Sail 自身出站并形成回环。设置 `auto_detect_interface` 或固定 `default_interface`，但不要同时设置。Android 还要确认启动前已注册可用的 `VpnService.protect` 回调。

## MPTP 性能不佳

分别测试每条路径。若多个成员共享同一受限物理链路，聚合未必优于最佳单路径。先用两条健康且独立的路径，确认服务端可以直连目标，再逐步增加成员。

## 报告可复现问题

请提供 Sail 版本、操作系统、构建 feature、脱敏后的最小配置、完整错误，以及目标出站是否通过 `-t`。不要在公开问题中包含密码、UUID、私钥或完整证书。
