---
title: 路由规则
description: 使用域名、IP、端口、入站、进程和用户条件构建有序路由。
---

Sail 从上到下评估路由规则。`route`、`reject` 和 `hijack-dns` 会停止匹配；`sniff`、`resolve` 与 `route-options` 补充连接信息后继续处理下一条规则。没有被任何规则停下的连接交给 `route.final`。

## 匹配模型

同一字段中的值为“或”，不同条件族之间为“与”。下面规则匹配来自 `local-socks`、目标为 `example.com` 或其子域名的 TCP 连接：

```json
{
  "domain_suffix": ["example.com"],
  "network": ["tcp"],
  "inbound": ["local-socks"],
  "action": "route",
  "outbound": "secure"
}
```

与 sing-box 一致，目标类条件（各域名字段、GeoSite、IP CIDR、GeoIP 与 external 集合）之间为“或”，端口类条件之间、源地址类条件之间也各为“或”；每一组再与规则上的其他条件取“与”。`invert` 对整条规则取反。

## 条件速查

| 字段 | 示例 | 含义 |
| --- | --- | --- |
| `domain` | `api.example.com` | 精确域名 |
| `domain_suffix` | `example.com` | 域名及其子域名 |
| `domain_keyword` | `cdn` | 包含字符串的域名 |
| `domain_regex` | `^api\.` | 匹配正则表达式的域名 |
| `ip_cidr` | `10.0.0.0/8` | 目标网络 |
| `ip_is_private` | `true` | 目标地址不是公网地址 |
| `geoip` | `cn` | `geo.mmdb` 中的国家或地区（Sail 扩展） |
| `geosite` | `category-ads-all` | `site.dat` 中的网站组（Sail 扩展） |
| `external` | `site:custom.dat:work` | 其他数据文件中的分组（Sail 扩展） |
| `ip_asn` | `13335` | `asn.mmdb` 中的自治系统（Sail 扩展） |
| `rule_set` | `geosite-cn` | 所列规则集中的任意规则 |
| `port`、`port_range` | `443`、`1000:2000` | 目标端口或闭区间；`:1024`、`8000:` 为单侧开放区间 |
| `source_ip_cidr`、`source_port` | `192.168.0.0/16` | 连接来源 |
| `network` | `tcp`, `udp` | 传输协议 |
| `protocol` | `tls`, `quic` | `sniff` 规则识别出的协议 |
| `inbound` | `tun-in` | 来源入站标签 |
| `auth_user` | `alice` | 入站认证用户 |
| `process_name`、`process_path` | `curl` | 可用时的来源进程 |
| `package_name` | `com.example.app` | 宿主报告的 Android 应用 |
| `wifi_ssid`、`network_type` | `Home`、`cellular` | 主机当前所在网络 |
| `clash_mode` | `Global` | Clash API 当前模式 |

全部条件见[路由参考](/sail/zh/reference/route/)。GeoIP、GeoSite 与 ASN 文件从数据目录读取；文件不在可执行文件旁边时，用 `-D` 或 `--data-dir` 指定。

## 规则动作

| 动作 | 效果 |
| --- | --- |
| `route`（默认） | 把连接交给 `outbound`，停止匹配 |
| `reject` | 关闭连接，停止匹配；`method: drop` 时不作应答 |
| `hijack-dns` | 应答连接中携带的 DNS 查询，停止匹配 |
| `route-options` | 设置连接的承载方式，如 `override_address`、`udp_timeout`、`tls_fragment`，继续匹配 |
| `sniff` | 从开头字节读取协议和域名，继续匹配 |
| `resolve` | 解析域名，让后续规则能匹配其地址，继续匹配 |
| `bypass` | 在 Linux `auto_redirect` 下由内核直接转发、不经过 Sail；其他情况下路由到其 `outbound`，没有出站时跳过该规则 |
| `direct` | 接受但给出警告；与 sing-box 1.14.1 一样不起作用 |

`route` 规则可以带上与 `route-options` 相同的选项。sing-box 的 `evaluate`、`respond`、`predefined` 路由动作，以及 `ssh`、`rdp`、`ntp` 嗅探器，均未实现，会报错。

## 最终路由与拒绝

```json
{
  "route": {
    "rules": [
      { "ip_cidr": ["10.0.0.0/8"], "action": "route", "outbound": "direct" },
      { "domain_suffix": ["ads.example"], "action": "reject" }
    ],
    "final": "secure"
  }
}
```

兜底路径使用 `final`；未设置时，未匹配任何规则的连接交给第一个出站。没有条件的 route/reject 规则会在验证阶段被拒绝，因为它会遮蔽所有后续规则。

## 逻辑规则

`"type": "logical"` 的规则用 `"mode": "and"` 或 `"or"` 组合其他规则。内部规则只写条件，动作写在逻辑规则上：

```json
{
  "type": "logical",
  "mode": "and",
  "rules": [
    { "network": ["udp"] },
    { "port": [443] }
  ],
  "action": "reject"
}
```

## 规则集

`route.rule_set` 声明规则集，规则通过 `rule_set` 引用。规则集分为 `inline`（`rules` 直接写在配置中）、`local`（`path` 指向文件）和 `remote`（`url` 下载，每隔 `update_interval` 重新下载，默认一天，可经 `download_detour` 或 `http_client` 下载）。格式为 sing-box 的 `source`（JSON）或 `binary`（`.srs`），未设置 `format` 时按文件扩展名判断。

作为 Sail 扩展，规则集也可以是 Clash 的 rule-provider（`mrs`、`clash-yaml`、`clash-text`）或 Surge 的规则集、域名集（`surge-text`），并用 `behavior` 指定 `domain`、`ipcidr` 或 `classical`。

```json
{
  "route": {
    "rule_set": [
      {
        "type": "remote",
        "tag": "geosite-cn",
        "url": "https://example.com/geosite-cn.srs"
      }
    ],
    "rules": [
      { "rule_set": ["geosite-cn"], "action": "route", "outbound": "direct" }
    ]
  }
}
```

## 跳过规则（PASS）

`pass` 出站是 Sail 的扩展，对应 Mihomo 的 PASS：`{ "type": "pass", "tag": "PASS" }`。规则指向它，或者指向当前选中 PASS 的 `selector`、`urltest`、`fallback`、`network` 组（嵌套组逐层往下看）时，这条规则被跳过：它的路由选项不生效，由后面的规则决定。在 selector 里选 PASS，就能在不改配置的情况下关掉指向它的规则。`final` 经由组解析到 PASS 时，连接走直连。

`final`（未设置 `final` 时为第一个出站）直接写 pass 出站属于配置错误；PASS 出现在 `load-balance` 或 `smart` 组里（包括经由嵌套组）也是配置错误。`urltest` 和 `fallback` 从不测试 PASS，并把它视为不可用，所以永远不会选中它。这一点与 Mihomo 不同：Mihomo 的组在第一次测试之前可能选中 PASS；fallback 在全部成员不可用、且 PASS 排在第一位时也会选中它。如果连接仍然到达 PASS（例如路由之后 selector 才切到 PASS），连接会失败，错误为 "routed to PASS"。

## 路由前嗅探域名

应用直接连接 IP 地址时，Sail 可以检查连接开头的字节，得到协议和域名：TLS 或 QUIC 的服务器名，或 HTTP Host。它还能识别 DNS、STUN、BitTorrent 和 DTLS。

```json
{
  "route": {
    "rules": [
      {
        "action": "sniff",
        "sniffer": ["tls", "http", "quic"],
        "timeout": "300ms"
      },
      {
        "domain_suffix": ["example.com"],
        "action": "route",
        "outbound": "secure"
      }
    ],
    "final": "direct"
  }
}
```

`sniffer` 列出要识别的协议，为空时全部识别；`timeout` 默认 300 毫秒。嗅探只获取元数据，不会解密 TLS。

Sail 另外提供三个字段：`override_destination` 改为连接嗅探到的域名，而不是原地址；`skip_rule_set` 忽略所列规则集匹配到的嗅探域名，对应 Mihomo 的 `skip-domain`；`on_demand` 只预备而不立即嗅探，等后续规则需要结果时才执行。

## IP 匹配前先解析

`resolve` 动作解析域名，让后续 IP、CIDR 或 GeoIP 规则能匹配其地址：

```json
{
  "domain_suffix": ["example.net"],
  "action": "resolve"
}
```

把它放在需要解析结果的 IP 类规则之前。`server` 和 `strategy` 可为这次解析覆盖 DNS 规则与 `dns.strategy`。与 sing-box 一致，域名解析失败时连接失败；Sail 的 `ignore_failure` 改为不带地址继续匹配，Sail 的 `on_demand` 则只在后续规则需要地址时才解析。DNS 策略与缓存行为来自顶层 [`dns`](/sail/zh/configuration/#dns) 配置。

## 选择网络（network_strategy）

`network_strategy` 决定在主机的哪些网卡之间选择。它是所有出站都有的拨号字段；写在 `route` 或 `route-options` 规则上时，只在连接经直连出站发出时生效。

- `default`：默认网卡，或 `network_type` 所列类型的全部网卡。
- `hybrid`：同时使用全部网卡，或 `network_type` 所列类型的全部网卡。
- `fallback`：先按 `default`；超过 `fallback_delay` 或这些网卡失败后，改用 `fallback_network_type` 所列类型的网卡，未列出时用其余全部网卡。

网络类型有 `wifi`、`cellular`、`ethernet` 和 `other`。sing-box 只在其 Android 和 Apple 客户端中处理这些字段；Sail 在 Linux、macOS 和 Windows 上也会根据自己检测到的网卡处理，这是有意的扩展。在这些系统上，`other` 类型的网卡（例如其他 VPN 的隧道、网桥）只有在 `network_type` 或 `fallback_network_type` 列出 `other` 时才会参与选择。`route.default_network_strategy` 为未设置策略的连接提供默认值，并且需要开启 `route.auto_detect_interface`。

## 策略组与提供者

策略组出站为每个连接选择一个成员。除 sing-box 的 `selector` 和 `urltest` 外，Sail 还提供 `fallback`、`load-balance`、`smart`、`network` 和 `tryall`，各自的选择方式见[协议与兼容性](/sail/zh/protocols/#流量控制出站)。规则通过标签指向策略组。

`outbound_providers` 是 Sail 扩展，像 Mihomo 的 proxy-providers 一样为策略组提供成员。提供者分为 `remote`（订阅地址）、`local`（文件）和 `inline`。订阅内容可以是带 `proxies` 的 Clash YAML，也可以是分享链接。`filter`、`exclude_filter`、`exclude_type` 和 `override` 决定取用哪些出站以及如何改写。

```json
{
  "outbound_providers": [
    { "type": "remote", "tag": "sub", "url": "https://example.com/sub.yaml" }
  ],
  "outbounds": [
    { "type": "urltest", "tag": "auto", "providers": ["sub"] }
  ]
}
```

`selector`、`urltest`、`fallback`、`load-balance` 和 `smart` 组都可以在自身 `outbounds` 之外使用 `providers`。

## 防止 TUN 回环

开了 `auto_route` 的 TUN 入站会接管系统流量，Sail 自己的出站套接字本会绕回 TUN。Sail 把它们绑定到物理网卡：目标所在网段的那块网卡，否则是默认网卡。网络变化时 Sail 会跟着切换，默认网卡变了就重置 TUN 上的连接。开了 `auto_route` 时，即使没写 `route.auto_detect_interface`，这个机制也会自动开启；出口必须固定时改用 `route.default_interface`。

在 Linux 上，`auto_route` 不改主路由表：TUN 的路由放在表 2022（`iproute2_table_index`），从优先级 9000（`iproute2_rule_index`）开始的 ip 规则把流量引过去。设备消失时内核会一并删掉这些路由，崩溃留下的规则会在下次启动时清掉。`route_address`、`route_exclude_address` 及其规则集形式、`include_interface`/`exclude_interface`、`include_uid`/`exclude_uid` 和 `strict_route` 决定接管哪些流量，含义和 sing-box 相同。配置了 `route_address` 或 `route_exclude_address` 时，列出的前缀会优先于局域网自己的路由，所以局域网需要显式排除。

在 macOS 上，`auto_route` 经 utun 添加比默认路由更具体的路由：1.0.0.0/8、2.0.0.0/7 … 128.0.0.0/1，IPv6 同样按这种方式对半切分；配置了 `route_address` 时改为添加这些前缀。`route_exclude_address` 及其规则集形式会在这些路由中挖出空洞。默认路由本身始终不变，utun 消失时这些路由也随之消失。`strict_route`、网卡列表和 uid 列表在 macOS 上不起作用，与 sing-box 相同。

在 Windows 上，`auto_route` 经 wintun 网卡以跃点数 0 添加 0.0.0.0/0 和 ::/0：它们靠跃点数优先于默认路由，但不替换默认路由。网卡的 DNS 指向 TUN 地址的下一个地址。`route_address`、`route_exclude_address` 及其规则集形式选择路由的方式与其他系统相同。`strict_route` 会添加防火墙规则，阻止 DNS 走其他网卡。

## 在内核中绕过（Linux `auto_redirect`）

开启 `auto_redirect` 后，Linux TUN 入站不改主路由表：nftables 把系统的 TCP 重定向到本地监听器，UDP 和 ICMP 通过标记路由进 TUN。Sail 自己的套接字带输出标记，不会被接管，因此不需要 `auto_detect_interface`。

```json
{
  "inbounds": [
    {
      "type": "tun",
      "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
      "auto_route": true,
      "auto_redirect": true
    }
  ]
}
```

每个连接的第一个包在重定向前会经 NFQUEUE 预匹配：命中 `bypass` 的连接由内核直接转发，不经过 Sail；命中 `reject` 的连接由内核重置或丢弃。

```json
{
  "ip_cidr": ["192.0.2.0/24"],
  "action": "bypass"
}
```

预匹配只能看到第一个包的信息：地址、端口和网络类型。遇到需要嗅探的规则时，预匹配结束，连接照常重定向。带 `outbound` 的 `bypass` 在连接到达 Sail 后路由到该出站；没有 auto_redirect 时，不带出站的 `bypass` 会被跳过。

`route_address_set` 和 `route_exclude_address_set` 只取规则集的目标地址，规则集重新下载时会同步刷新。在 OpenWrt 上，Sail 还会写入 fw4 片段，放行 TUN 的流量。
