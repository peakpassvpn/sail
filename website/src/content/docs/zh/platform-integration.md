---
title: 平台集成
description: 通过核心与 FFI 边界将 Sail 嵌入移动端、桌面端、服务端和路由器。
---

Sail 将代理行为保留在 Rust 核心，把宿主特有能力注入边界。同一套配置、路由和协议实现可以运行在 CLI、移动 VPN 应用或其他原生宿主中。

## 集成分层

| 层 | 职责 |
| --- | --- |
| 宿主应用 | 生命周期、UI、权限和平台网络变化 |
| `sail-ffi` 或 Rust API | 启动、重载、关闭、测试和回调 |
| `sail` | 配置、DNS、路由、协议与传输层 |
| `sail-netstack` | TUN 流量的用户态 TCP/IP 数据面 |
| 系统适配器 | TUN 设备、套接字保护、接口与日志 |

## 生命周期

典型宿主流程是：准备配置；注册 Android 套接字保护等平台回调；用唯一 runtime ID 启动实例；转发网络变化；配置更新后重载；释放宿主资源前关闭实例。

宿主调优与可移植代理配置分开传入：

```json
{
  "profile": "mobile",
  "set": ["relay.buffer_size=32"],
  "data_dir": "/path/to/assets",
  "cache_dir": "/path/to/state",
  "log_to_system": true
}
```

同一代理定义因此可以在应用中使用移动端预算，在中继服务器中使用 server 预算。

## Android 与 Apple 平台

Android VPN 应用必须在启动前注册基于 `VpnService.protect` 的回调，让 Sail 出站套接字绕过 VPN 接口。回调可能从多个运行时线程调用，宿主实现必须线程安全；Wi-Fi/移动网络切换时也应转发网络变化。

Apple 平台由宿主管理 Network Extension 生命周期。项目包含生成 Apple 库与 XCFramework 的脚本。iOS 默认使用 `mobile` 配置档；证书、GeoIP 与 GeoSite 资源放在应用控制的数据目录。

## 集成检查清单

- 为并发实例分配唯一 runtime ID。
- Android 启动前注册套接字保护。
- 配置、静态资源和持久化状态使用不同宿主目录。
- 主动转发网络变化。
- 重载前离线验证配置与关键出站。
- 自动 TUN 路由必须配套出口接口策略。
- 销毁回调或平台网络对象前先关闭实例。
