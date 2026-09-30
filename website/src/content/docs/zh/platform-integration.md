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

`asset_sources` 按资源文件名给出下载地址，如 `{"asn.mmdb": "https://..."}`：运行时 API 的 `POST /api/v1/runtime/assets/{name}/update` 在请求未给地址时使用它。Sail 没有默认来源，CLI 的默认来源属于 CLI 自己。

## 资源文件

配置读取的数据文件（`asn.mmdb`、`geo.mmdb`、`site.dat`，或规则指定的文件）由宿主放到数据目录。`sail_required_assets(config_path, settings)` 以 JSON 返回它们：`{"assets": [{"name", "kind", "path", "used_by", "present"}]}`，或 `{"error": "..."}`；字符串用 `sail_free_string` 释放。启动前下载缺少的文件：需要的文件不存在时启动失败，并给出路径。CLI 使用的默认来源见 CLI 参考。

## 网络状态

按宿主所在网络匹配的规则与分组（`wifi_ssid`、`wifi_bssid`、`network_type`、`network_is_expensive`、`network_is_constrained`）读取每个实例的一份网络状态。知道网络状态的宿主（移动端、桌面端应用）在其变化时推送：`sail_set_network_state(rt_id, json)` 或 `PUT /api/v1/runtime/network`（`GET` 读回）：

```json
{
  "interface": "en0",
  "addresses": ["192.168.1.2/24", "fd00::2/64"],
  "type": "wifi",
  "ssid": "Home",
  "bssid": "aa:bb:cc:dd:ee:ff",
  "gateway": "192.168.1.1",
  "mcc_mnc": "310260",
  "expensive": false,
  "constrained": false
}
```

`type` 为 `wifi`、`cellular`、`ethernet` 或 `other`；每个字段都可省略，针对未知字段的条件不匹配。宿主推送过一次后，该实例余下的生命周期内不再使用 Sail 自己的检测。

没有推送时，Sail 检测系统在无需额外权限时给出的信息：

| 系统 | 接口、网关、地址 | 类型 | SSID 与 BSSID | 跟随变化 |
| --- | --- | --- | --- | --- |
| Linux | 主路由表默认路由（rtnetlink） | `/sys/class/net` | nl80211 | 是，基于路由与地址监视 |
| macOS | IPv4 默认路由 | 接口的功能类型 | 无：CoreWLAN 需要定位权限 | 是，基于路由 socket 的消息 |
| Windows | 有网关且跃点数最低的适配器 | 适配器接口类型 | WLAN 服务（Windows 11 24H2 需要定位权限） | 是，基于路由与接口变化通知 |
| Android、iOS | -- | -- | -- | 由宿主推送 |

蜂窝网络视为按流量计费（expensive）；上述系统都不提供低数据模式（constrained），只能由宿主推送。状态变化以 `info` 级别记录类型、接口和网关；SSID 与 BSSID 只在 `debug` 级别记录。

### 网络变化时

只有旧网络上建立的连接无法延续时才算网络变化：默认网卡、网关或网络类型变了，或地址变了（IPv6 按 /64 比较）。同一网卡、同一地址下换了 SSID 或接入点（漫游）不算：按网络匹配的规则会看到新状态，连接保留。`sail_network_changed(rt_id, mtu)` 无论状态如何都算一次变化。

发生变化时，Sail 丢弃属于旧网络的东西：缓存的 DNS 答案和 DNS 服务器保持的连接、正在进行的连接、TUN 的流；新连接在当前网络上建立。同时以 `info` 级别记录一行，测试据此计时：

```
network changed: generation 3, reason=default-interface, interface=en0→en1, closed=12, dns_flushed=true, took=4ms
```

`reason` 为 `default-interface`、`state`（Sail 自己检测到的）、`host`（宿主推送或 `sail_network_changed`）或 `wake`。

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
