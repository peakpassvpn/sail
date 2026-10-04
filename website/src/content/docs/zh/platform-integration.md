---
title: 平台集成
description: 通过核心与 FFI 边界将 Sail 嵌入移动端、桌面端、服务端和路由器。
---

Sail 将代理行为保留在 Rust 核心，把宿主特有能力注入边界。同一套配置、路由和协议实现可以运行在 CLI、移动 VPN 应用或其他原生宿主中。

## 集成分层

| 层 | 职责 |
| --- | --- |
| 宿主应用 | 生命周期、UI、权限和平台网络变化 |
| `sail-ffi`（C ABI）或 Rust API | 实例、控制、事件、命令服务与平台回调 |
| `sail` | 配置、DNS、路由、协议与传输层 |
| `sail-netstack` | TUN 流量的用户态 TCP/IP 协议栈 |
| 系统适配器 | TUN 设备、路由、套接字保护、接口与日志 |

这条边界让平台代码不会渗入协议处理器。

## C ABI

`sail-ffi` 构建静态与动态的 `libsail`，C 接口声明在 `sail-ffi/include/sail.h`。头文件由 cbindgen 生成并提交到仓库，其中的注释是每个函数的参考。各函数共同遵守的约定（句柄、错误码、内存、线程、取消与释放）见仓库中的 [`docs/ffi.md`](https://github.com/peakpassvpn/sail/blob/master/docs/ffi.md)，本页只做概述。

- 实例是一个 64 位句柄，0 永远不是有效句柄。已释放或未知的句柄返回 `SAIL_ERR_NO_INSTANCE`，不会产生未定义行为。一个进程可同时运行任意多个实例，各有自己的日志和事件。
- 每个调用都返回稳定的 `SAIL_*` 错误码，并通过 `char **err` 给出错误信息，由宿主用 `sail_free_string` 释放。
- 结构化数据为 JSON：直接序列化 Sail 的控制类型，snake_case，带类型。管理 API 返回同一种 JSON，它不是 Clash API 的格式。它不带版本号：只增不减，宿主忽略不认识的内容。`sail_capabilities` 给出 sail 的发布版本和编译进来的模块。C ABI 也只增不减：已发布的函数不再改动，要改就新增一个函数。破坏性改动随 sail 的发布一起，并写进发布说明。

## 生命周期

典型宿主流程如下：

1. 在 `SailPlatform` 中填好回调，调用 `sail_instance_new(settings, &platform, &instance, &err)`。实例此时处于空闲状态。
2. 用 `sail_instance_start`（配置文本）或 `sail_instance_start_file` 启动。Sail 能读的格式都可以：sing-box JSON、Clash YAML 或 Surge 配置。实例运行起来后调用返回，失败时返回原因。
3. 推送网络状态，并用 `sail_subscribe` 跟随实例。
4. 用 `sail_instance_reload` 重载：传入新配置，或重新读取原文件。`sail_instance_reload_report` 做同样的事，并说明每个入站的结果（只有被移除或被替换的入站会断开连接），以及是否只重建了入站。
5. 用 `sail_instance_stop(instance, timeout_ms, &err)` 停止，再调用 `sail_instance_free`。实例停止后调用平台的 `release`，此后 Sail 不再调用任何回调。

实例停止或启动失败后可以再次启动。启动过程中调用停止会结束这次启动，返回 `SAIL_ERR_CANCELLED`。

启动后，应用通过同一句柄读取和跟随实例：状态、流量、连接（及关闭连接）、出站与策略组（及选择成员）、延迟测试、模式、日志和网络。无需实例的 `sail_check_config`、`sail_import_share_links`、`sail_required_assets` 与 `sail_test_outbounds` 分别用于检查配置、读取分享链接、列出资源文件和测试出站。

### 平台回调

`SailPlatform` 以 `struct_size` 开头，宿主将其设为 `sizeof(SailPlatform)`；这样用旧头文件构建的宿主，后续版本新增的回调会被读作空。每个回调都可以为空。

| 回调 | 宿主做什么 |
| --- | --- |
| `protect_socket` | 在出站套接字连接前让它绕过宿主的 VPN（Android 的 `VpnService.protect`）。在实例拨号时由实例线程调用。 |
| `open_tun` | 按 JSON 请求打开 TUN 入站需要的 TUN 设备，返回文件描述符。之后由宿主为设备配置路由，Sail 不改动任何路由。 |
| `find_connection_owner` | 告知连接由哪个应用发起：uid、用户和包名。 |
| `service_stop`、`service_reload` | 命令服务客户端请求时，按系统要求的方式停止或重载实例。 |
| `release` | 释放宿主的上下文，只调用一次。 |

在实例线程上调用的回调不得等待 Sail：在那里会等待的调用返回 `SAIL_ERR_WRONG_THREAD`。事件回调在实例的事件线程上依次、按序调用。

## 启动设置

宿主调优作为 `sail_instance_new` 的设置传入，与可移植的代理配置分开：

```json
{
  "profile": "mobile",
  "set": ["relay.buffer_size=32"],
  "data_dir": "/path/to/assets",
  "cache_dir": "/path/to/state",
  "log_to_system": true
}
```

同一代理定义因此可以在应用中使用移动端内存预算，在中继中使用服务器预算。

核心还接受 `socket_protect`、`sub_store`、`ui_download_url` 与 `asset_sources`。FFI 另有自己的设置：`log_lines`（保留的日志行数，默认 3000），`worker_threads`（不设或为 0 时单线程）和 `stack_size`，以及 `stop_within_ms`（停止时等待实例任务结束的时长，默认 2000）。未知设置是错误。在 iOS 与 Android 上，默认使用 `mobile` 配置档并写入系统日志。

`asset_sources` 按资源文件名给出下载地址，如 `{"asn.mmdb": "https://..."}`：运行时 API 的 `POST /api/v1/runtime/assets/{name}/update` 在请求未给地址时使用它。Sail 没有默认来源，CLI 的默认来源属于 CLI 自己。

## 资源文件

配置读取的数据文件（`asn.mmdb`、`geo.mmdb`、`site.dat`，或规则指定的文件）由宿主放到数据目录，Sail 不会下载它们。`sail_required_assets(path, settings, &out, &err)` 以 JSON 写入 `out`：`{"assets": [{"name", "kind", "path", "used_by", "present"}]}`；字符串用 `sail_free_string` 释放。启动前下载缺少的文件：需要的文件不存在时启动失败，并给出路径。CLI 使用的默认来源见 [CLI 参考](/sail/zh/cli/)。

## 网络状态

按宿主所在网络匹配的规则与分组（`wifi_ssid`、`wifi_bssid`、`network_type`、`network_is_expensive`、`network_is_constrained`）读取每个实例的一份网络状态。知道网络状态的宿主（移动端、桌面端应用）在其变化时推送：`sail_set_network_state(instance, json)` 或 `PUT /api/v1/runtime/network`（`GET` 读回）：

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
  "constrained": false,
  "interfaces": [
    { "name": "en0", "type": "wifi", "addresses": ["192.168.1.2/24", "fd00::2/64"] },
    { "name": "pdp_ip0", "type": "cellular", "addresses": ["10.1.2.3/32"], "expensive": true }
  ]
}
```

`interfaces` 列出 Sail 可以从中拨出的所有接口（包括默认接口），用于按连接选择网络：每项有 `name`（不可重复）和必填的 `type`，可带 `addresses`、`expensive` 与 `constrained`。列表外的字段描述默认网络，由 `interface` 指明；两者都给出时，列表中必须包含它。规则和网络变化以默认网络为准；只有列表变化不算网络变化。宿主不推送状态时，Sail 在 Linux、macOS 与 Windows 上自己检测并列出接口：所有已启用、非回环、且有链路本地以外地址的接口，类型与默认接口的判定方式相同，蜂窝接口视为按流量计费。虚拟接口（其他 VPN 的隧道、网桥、容器网络，以及 macOS 上所有点对点接口）类型为 `other`；Sail 自己的 TUN 不会列入。sing-box 只在 Android 与 Apple 的图形客户端里列出接口，因此它的 `network_strategy` 只在那里有效；Sail 的在桌面和服务端同样有效。

`type` 为 `wifi`、`cellular`、`ethernet` 或 `other`；每个字段都可省略，针对未知字段的条件不匹配。宿主推送过一次后，该实例余下的生命周期内不再使用 Sail 自己的检测。

没有推送时，Sail 检测系统在无需额外权限时给出的信息：

| 系统 | 接口、网关、地址 | 类型 | SSID 与 BSSID | 跟随变化 |
| --- | --- | --- | --- | --- |
| Linux | 主路由表默认路由（rtnetlink） | `/sys/class/net` | nl80211 | 是，基于路由与地址监视 |
| macOS | IPv4 默认路由 | 接口的功能类型；点对点接口为 `other` | 无：CoreWLAN 需要定位权限 | 是，基于路由 socket 的消息 |
| Windows | 有网关且跃点数最低的适配器 | 适配器接口类型 | WLAN 服务（Windows 11 24H2 需要定位权限） | 是，基于路由、接口与地址变化通知 |
| Android、iOS | -- | -- | -- | 由宿主推送 |

蜂窝网络视为按流量计费（expensive）；上述系统都不提供低数据模式（constrained），只能由宿主推送。状态变化以 `info` 级别记录类型、接口和网关；SSID 与 BSSID 只在 `debug` 级别记录。

### 网络变化时

只有旧网络上建立的连接无法延续时才算网络变化：默认网卡、网关或网络类型变了，或地址变了（IPv6 按 /64 比较）。同一网卡、同一地址下换了 SSID 或接入点（漫游）不算：按网络匹配的规则会看到新状态，连接保留。`sail_network_changed(instance, mtu)` 无论状态如何都算一次变化；它需要有 TUN 入站，`mtu` 不为 0 时协议栈改用新的 MTU。

发生变化时，Sail 丢弃属于旧网络的东西：缓存的 DNS 答案和 DNS 服务器保持的连接、正在进行的连接、TUN 的流；新连接在当前网络上建立。同时以 `info` 级别记录一行，测试据此计时：

```
network changed: generation 3, reason=default-interface, interface=en0→en1, closed=12, dns_flushed=true, took=4ms
```

`reason` 为 `default-interface`、`state`（Sail 自己检测到的）、`host`（宿主推送或 `sail_network_changed`）或 `wake`。宿主用 `sail_subscribe(..., SAIL_EVENT_NETWORK, ...)` 跟随这些变化：每个事件给出代次、原因以及新旧网络状态。

完全没有网络时（曾知道状态、现在为空），定时的健康检查与更新暂停；网络恢复即一次变化，它们立即重新检查。从休眠唤醒也算一次变化：Sail 以“含休眠时间的时钟”与“不含休眠时间的时钟”之差察觉，Linux、macOS、Windows 做法相同。

桌面上的网络如果只有 IPv6 地址、没有 IPv4 地址，Sail 按 RFC 7050（查询 `ipv4only.arpa`）找到网络的 NAT64 前缀，经它访问 IPv4 地址：字面地址、DNS 给出的 A 记录、TUN 里应用发往 IPv4 的流量都一样。手机由系统自己转换 IPv4；推送状态的宿主不走这一套。

### Captive portal

宿主发现网络处于 captive portal（认证页）之后时，推送 `"captive": true`。在它推送不含此项的状态之前，**所有连接都直连，不看路由规则**，便于用户登录；被规则劫持的 DNS 仍按配置回答。Sail 自己不探测认证页。进入与解除都以 `info` 级别记录。

## Android

Android VPN 应用必须让 Sail 的出站套接字绕过 VPN 接口。在创建实例所用的 `SailPlatform` 中设置基于 `VpnService.protect` 的 `protect_socket`。回调可能从多个运行时线程同时调用，实现必须线程安全。

`open_tun` 收到 TUN 请求（`interface_name`、`mtu`、`ipv4`、`ipv6`、`auto_route`），返回 `VpnService.Builder.establish` 得到的描述符。路由由宿主配置。

分应用代理由 VpnService 执行，与 sing-box 的应用相同。请求中带有 tun 入站的 `include_package` 与 `exclude_package`，宿主将它们交给 `addAllowedApplication` 与 `addDisallowedApplication`。`include_uid`、`exclude_uid`、它们的范围形式以及 `include_android_user` 在宿主打开 TUN 时被拒绝，与 libbox 一致：VpnService 无法执行它们。

设置了 `find_connection_owner` 时，每条连接在路由前都会询问其所属应用。宿主用 `ConnectivityManager.getConnectionOwnerUid` 回答，再用 `PackageManager.getPackagesForUid` 取包名。此时路由规则与 DNS 规则中的 `package_name`、`package_name_regex`、`user` 和 `user_id` 才能匹配，连接列表中也会给出 `uid` 与 `packages`。没有这个回调时，这些规则是错误。`getConnectionOwnerUid` 需要 Android 10（API 29）；更低版本宿主无法判断，这些规则不会匹配。

推送网络状态，并在 Wi-Fi 与移动数据切换时调用 `sail_network_changed`，让 DNS、接口和长连接传输立即响应。

## Apple 平台

项目包含生成 Apple 库与 XCFramework 的脚本。Network Extension 的生命周期由宿主管理；`open_tun` 把 packet flow 的 utun 描述符交给 Sail。iOS 默认使用 `mobile` 配置档，除非实测证明需要更大预算。

相对路径的证书、GeoIP 与 GeoSite 资源应放在应用控制的数据目录，并通过启动设置传入。

## 命令服务

UI 与隧道运行在不同进程的应用（iOS 或 macOS 的 Network Extension、Android 上单独运行的服务）通过 Sail 的命令服务访问实例，与 sing-box 的应用访问 libbox 命令服务器的方式相同。

- 在隧道进程中，`sail_instance_serve(instance, options, &err)` 在 Unix socket 上提供服务，`{"path"}`，文件只有当前用户可读写。没有共享目录的宿主可用环回 TCP，`{"port", "secret"}`；secret 至少 32 个字符（`sail generate secret`）。
- 在 UI 进程中，`sail_client_connect(options, &client, &err)` 返回一个句柄，它响应与实例相同的调用，JSON 与错误码也相同。客户端也可以直接接收一个已连接的套接字，`{"fd"}`。
- 启动、提供服务和网络相关调用只属于隧道进程：经客户端调用时返回 `SAIL_ERR_UNSUPPORTED`。客户端的停止与重载在宿主设置了 `service_stop` 与 `service_reload` 时调用它们。
- 客户端不会自动重连。连接断开后，其调用返回 `SAIL_ERR_IO`，每个订阅收到一次 `SAIL_EVENT_DISCONNECTED`。

协议为 gRPC，调用及其含义与 libbox 相同，但使用 Sail 自己的包名（`sail.command.v1`），与 sing-box 线路上不兼容。不含 `command-server` feature 的构建没有命令服务。

## Swift 与 Kotlin

`bindings/swift` 是 SwiftPM 包 `Sail`，支持 iOS 15 与 macOS 13。它的 manifest 是仓库根目录的 `Package.swift`，应用用 URL 引用：`.package(url: "https://github.com/peakpassvpn/sail", from: "<版本>")`，再加 `.product(name: "Sail", package: "sail")`；发布版的 tag 链接该版本发布的 XCFramework。`bindings/kotlin` 是带 JNI 胶水层 `jni/sail_jni.c` 的 Kotlin 库。两者都把 C ABI 封装为一个类 `Sail`，可表示实例或命令服务客户端。调用失败时抛出 `SAIL_*` 错误码与信息，返回值解码为数据类型，事件以流的形式提供（`AsyncThrowingStream`、`Flow`）；结束流即结束其订阅。

## 桌面端与服务端

CLI 是最简单的宿主，即使最终产品嵌入库也很有用。先用它验证配置、隔离测试出站，再把同一模型迁入应用。

在桌面端与服务端，Sail 自己打开 TUN。`auto_route` 在 Linux、macOS 与 Windows 上自行安装路由，不改动系统默认路由；见[防止 TUN 回环](/sail/zh/routing/)。Windows 上的 TUN 是 wintun 适配器：`wintun.dll` 须放在可执行文件旁，或 Windows 能找到 DLL 的位置。Sail 从磁盘加载它；sing-box 与 Mihomo 则把它内嵌在程序中。

服务端在并发重要时使用 `server` 配置档。路由器从 `router` 开始，只在测量内存压力与吞吐后再提高单项运行时参数。

## 错误边界

FFI 调用返回稳定的错误码：`SAIL_ERR_INVALID_ARGUMENT`、`SAIL_ERR_NO_INSTANCE`、`SAIL_ERR_STATE`、`SAIL_ERR_CONFIG`、`SAIL_ERR_IO`、`SAIL_ERR_NOT_FOUND`、`SAIL_ERR_UNSUPPORTED`、`SAIL_ERR_CANCELLED`、`SAIL_ERR_TIMEOUT`、`SAIL_ERR_WRONG_THREAD`、`SAIL_ERR_INTERNAL`、`SAIL_ERR_PANICKED`、`SAIL_ERR_NEEDS_RESTART`、`SAIL_ERR_TUN_NAME_TAKEN` 与 `SAIL_ERR_INBOUND_LOST`；头文件没有列出的错误码（来自更新的 Sail）按 `SAIL_ERR_INTERNAL` 处理。实例失败后，`sail_instance_state` 给出失败类别（`error_kind`）以及这次运行在系统里留下的东西（`left`，每项附手动清理的命令）；`sail_instance_stop_report` 给出上一次停止没能结束或撤销的内容。XCFramework 与 AAR 在 panic 时会展开（unwind）：Sail 内部的 panic 不会结束 App 或网络扩展。连接任务中的 panic 只结束该任务（发出 `SAIL_EVENT_FAULT`），关键任务中的 panic 使实例以 `SAIL_ERR_PANICKED` 失败，调用本身的 panic 使该调用返回 `SAIL_ERR_PANICKED`。sail-cli 与路由器安装包遇到 panic 仍会终止进程。

配置错误设计为可离线发现。在把新配置用于正在运行的 VPN 会话前，先运行 `sail_check_config` 与 `sail_test_outbounds`。

## 集成检查清单

- 在 `sail_instance_new` 之前设置好 `struct_size` 与回调；Android 上启动前设置 `protect_socket`。
- 配置、资源文件和缓存文件使用不同的宿主目录。
- 主动推送网络状态及其变化，不要等连接失败。
- 重载前离线检查配置。
- 桌面端开启 `auto_route` 时，Sail 自己把出站套接字绑定到物理接口；只有出口接口必须固定时才设置 `route.default_interface`。
- 先停止并释放实例，再销毁回调用到的对象；在 `release` 之前它们都可能被使用。
