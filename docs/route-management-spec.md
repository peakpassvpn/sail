# sing-tun `auto_route` without `auto_redirect`: how routes are managed (spec for the sail port)

Sources. Line numbers refer to these trees under `~/go/pkg/mod/github.com/sagernet/` unless marked otherwise:

- `sing-tun@v0.9.6-0.20260924001923-ddaa4ca25e3b` (**T**, the primary source)
- `sing-tun@v0.8.2` (**T8**, the version sing-box v1.13.2 actually pins in `go.mod:42`)
- `sing-box@v1.13.2` (**SB**)
- `sing@v0.8.2` (**S**)

Everything in this spec assumes `auto_route=true`, `auto_redirect=false`, no platform interface (plain CLI: not the Android VpnService or Apple NetworkExtension builds), and no `EXP_ExternalConfiguration`. Where T8 differs from T, the difference is called out.

---

## 0. Inputs and defaults (sing-box → sing-tun)

| sing-box field | sing-tun Option | Default / transform | Cite |
|---|---|---|---|
| `interface_name` | `Name` | empty → `CalculateInterfaceName`: `tun<N>` (Linux/Windows) or `utun<N>` (macOS), where N = highest existing index + 1 | SB inbound.go:295-297; T tun.go:230-253 |
| `address` | `Inet4Address` / `Inet6Address` | split by family | SB inbound.go:71-77 |
| `mtu` | `MTU` | 0 → 65535 (4064 under a Network Extension, 9000 on Android) | SB inbound.go:96-108 |
| `iproute2_table_index` | `IPRoute2TableIndex` | 0 → **2022** | SB inbound.go:131-134; T tun.go:58 |
| `iproute2_rule_index` | `IPRoute2RuleIndex` | 0 → **9000** | SB inbound.go:135-138; T tun.go:59 |
| `route_address` / `route_exclude_address` | `Inet{4,6}Route{,Exclude}Address` | split by family | SB inbound.go:79-93 |
| `route_address_set` / `route_exclude_address_set` | appended to the lists above, **once, at Start** | see §1.4 | SB inbound.go:298-349 |
| `include_uid(_range)` / `exclude_uid(_range)` | `IncludeUID` / `ExcludeUID` | ranges | SB inbound.go:116-129 |
| `include_interface` / `exclude_interface` | same names | | SB inbound.go:185-186 |
| `include_android_user` / `include_package` / `exclude_package` | converted to UID ranges; **Android only** | | SB inbound.go:292-294; T tun_rules.go:22-90 |
| `loopback_address` | `Inet{4,6}LoopbackAddress` | **no effect on routes or rules**; the stacks use it to rewrite TCP to that address back to the source | T stack_system.go; SB docs tun.md:333-339 |
| `strict_route` | `StrictRoute` | | SB inbound.go:184 |
| (none) | `Inet{4,6}Gateway` | unset; derived per OS (below) | T tun.go:178-228 |
| (none) | `DNSMode` | "" → `hijack` (T only; T8 has `EXP_DisableDNSHijack` instead) | T tun.go:127-132 |

**Route gateway** (`Inet4GatewayAddr` and `Inet6GatewayAddr`, T tun.go:178-228):

- Linux: `addr[0].Next()` if it lies inside `addr[0]`'s prefix, else no gateway. The code comment "Do not create gateway on linux by default" at tun_linux.go:652 is stale.
- macOS: the TUN's own address, `addr[0].Addr()`.
- Windows: `addr[0].Next()` if it lies inside the prefix, else `addr[0].Addr()`. This assumes `InterfaceScope=false`, which sing-box never sets.

**DNS server address** (`Inet4DNSAddress`, T tun.go:146-176): the configured `DNSAddress` if set, else `addr[0].Next()`. Example: 172.18.0.1/30 gives 172.18.0.2.

### Route set (all OSes): `BuildAutoRouteRanges(false)`, T tun_rules.go:109-212

This is computed separately for each family that has a TUN address. A family with no TUN address gets no routes.

```
base =
  route_address non-empty → route_address                    (+ on darwin: each own addr.Masked() if Bits<32)
  else (auto_route)       → darwin: 1/8,2/7,4/6,8/5,16/4,32/3,64/2,128/1
                                    (IPv6: 100::/8,200::/7,…,8000::/1)
                            linux/windows: 0.0.0.0/0 and ::/0
routes = exclude empty ? base (verbatim, NOT deduplicated)
                       : IPSet(base) − route_exclude_address → minimal prefix list
```

Notes on the route set:

- The macOS sub-ranges deliberately leave **0.0.0.0/8 and ::/8** out.
- They also never create a /0 route, so the physical default route stays the "default".
- macOS bug: the own-subnet addition checks `Bits()<32` for IPv6 too (tun_rules.go:165-170, 187-192). A /64 or /126 IPv6 TUN subnet is therefore never added.

---

## 1. Linux

### 1.1 Interface setup

`New` → `open` + `configure` (T tun_linux.go:53-191):

- `open /dev/net/tun`, `TUNSETIFF` with `IFF_TUN|IFF_NO_PI` (plus `IFF_VNET_HDR` if GSO), then set nonblocking (104-130). The device is non-persistent, so it disappears when the fd is closed.
- `LinkSetMTU(MTU)` (133). If this fails with **EPERM**, `configure` returns nil and **skips all address setup** (the "non-privileged" mode).
- `AddrAdd` for each v4 and v6 address; EEXIST is ignored (140-157).
- GSO (gvisor stack only) and ethtool RX checksum offload on (160-173).

`Start` → `start()` (292-371):

1. `RegisterMyInterface(name)` (295).
2. `LinkSetUp` (323).
3. **T only**: write `2` to `/proc/sys/net/ipv4/conf/<tun>/rp_filter` (332). T8 does not do this.
4. If the table index is 0, pick a random unused table (334-342). sing-box always passes 2022, so this does not happen.
5. `setRoute` (344). On failure it calls `unsetRoute0` and returns an error.
6. **`unsetRules()` first**: this is the stale cleanup. Then `setRules()`; on failure, `unsetRules` (350-358).
7. `resolvectl` DNS setup (360-365), see §5.

### 1.2 Routes

`routes()` (T tun_linux.go:647-668); `RouteAdd` uses `NLM_F_EXCL`, so a duplicate fails (1099-1111).

For each prefix P in the route set:

```
ip route add P via <gw4|gw6> dev <tun> table 2022
```

`via` is omitted when the gateway is unspecified.

- Only table 2022 is touched. **The main table and the existing default route are never modified.**
- Every route has `dev <tun>`, so the kernel deletes them when the TUN device goes away.

### 1.3 ip rules: `rules()` (T tun_linux.go:686-1097)

Notation:

- S = 9000 (rule index)
- T = 2022 (table)
- NOP = S+10 = 9010
- `p4`/`p6` = the family has a TUN address
- v4 and v6 each keep their own counter (`p`, `p6`), and both start at S
- Rules that share a priority are listed in insertion order, which is the kernel's evaluation order for equal priorities.

Construction algorithm (the exact order):

```
excl = ExcludedRanges()   # include_uid non-empty ? complement_[0,0xFFFFFFFE](include − exclude) : exclude_uid ; merged   (tun_rules.go:92-105)
for r in excl:   p:  uidrange r.start-r.end  goto NOP      (v4 and v6)          797-814
if excl: p++                                                                   815-822
if include_interface:                                                          823-877
    for i in include_interface:  p: iif i goto p+2
    p++ ;  p: goto NOP   (all else skipped)
    p++ ;  p: nop        (landing pad = old p+2)
    p++
elif exclude_interface:                                                        878-904
    for i: p: iif i goto NOP ;  p++
[android + VPN only: fwmark 0x20000/0x20000 goto NOP]                          906-934
if strict_route:                                                               936-953
    if !p4: p:  (v4) unreachable ; p++
    if !p6: p6: (v6) unreachable ; p6++
v4: p:  to <each inet4 addr .Masked()> lookup T ; p++                          956-965
v4: p:  lookup T suppress_prefixlength 0 ;       p++                           967-973
v6: p6: lookup T suppress_prefixlength 0 ;       p6++                          975-983
v4: p:  not dport 53 lookup main suppress_prefixlength 0   (no ++)             984-993
v6: p6: not dport 53 lookup main suppress_prefixlength 0   (no ++)             994-1003
v4: p:  iif <tun> goto NOP ; p++                                               1005-1012
v4: p:  not iif lo lookup T
    p:  iif lo from 0.0.0.0/32 lookup T
    p:  iif lo from <each inet4 addr .Masked()> lookup T                       1014-1038
v6: p6: iif lo from <each inet6 addr .Masked()> lookup T ; p6++                1041-1051
v6: p6: iif <tun> goto NOP
    p6: iif lo from ::/1 goto NOP
    p6: iif lo from 8000::/1 goto NOP ; p6++                                   1053-1075
v6: p6: lookup T                                                               1077-1081
NOP: nop (v4 and v6)                                                           1084-1095
```

(The "to/suppress/lo" block is skipped on Android.)

A rule with no table and no goto is sent as `FR_ACT_NOP` (netlink@…/rule_linux.go:45-55).

**Default result** (both families, no uid, interface or strict options), with the example address `172.18.0.1/30` and `fdfe:dcba:9876::1/126`:

```
# IPv4                                              # IPv6
9000: from all to 172.18.0.0/30 lookup 2022         9000: from all lookup 2022 suppress_prefixlength 0
9001: from all lookup 2022 suppress_prefixlength 0  9001: not from all dport 53 lookup main suppress_prefixlength 0
9002: not from all dport 53 lookup main supp..0     9001: from fdfe:dcba:9876::/126 iif lo lookup 2022
9002: from all iif tun0 goto 9010                   9002: from all iif tun0 goto 9010
9003: not from all iif lo lookup 2022               9002: from ::/1 iif lo goto 9010
9003: from 0.0.0.0 iif lo lookup 2022               9002: from 8000::/1 iif lo goto 9010
9003: from 172.18.0.0/30 iif lo lookup 2022         9003: from all lookup 2022
9010: from all nop                                  9010: from all nop
```

What each rule is for:

| Rule | Purpose |
|---|---|
| `to <tun subnet> lookup T` (v4) | Traffic to the TUN subnet, including the DNS address `.2`, always goes into the TUN. |
| `lookup T suppress_prefixlength 0` | A non-default match in T wins over main. With `route_address` or `route_exclude_address`, T holds only specific prefixes, so these override even more-specific main routes such as the LAN. With only 0/0 in T, this rule never matches. |
| `not dport 53 lookup main suppress_prefixlength 0` | Any **specific** main-table route (LAN, docker, other VPNs) bypasses the TUN, **except DNS (dport 53)**, which falls through to the TUN so hijack still catches LAN DNS servers. The main default route is suppressed. |
| `iif <tun> goto NOP` | Packets arriving from the TUN are never re-routed into it. |
| `not iif lo lookup T` (v4) / final `lookup T` (v6) | **Forwarded** traffic (the router/gateway case) goes to the TUN. |
| `iif lo from 0.0.0.0/32` (v4) | Local sockets with **no source bound yet** (the first `ip_route_connect` lookup) go to the TUN. |
| `iif lo from <tun subnet>` | Sockets whose source is the TUN address go to the TUN. |
| v6: `iif lo from ::/1` and `from 8000::/1 goto NOP` | These match only when the flow **has** a source address (`RT6_LOOKUP_F_HAS_SADDR`, kernel `fib6_rule_match`). An unbound v6 socket's first lookup skips them and reaches `lookup T`. A socket explicitly bound to a physical source address skips T and goes to main. This is the v6 equivalent of the v4 `from 0.0.0.0/32` trick. |

T8 difference: it places `iif lo from <inet6 subnet> lookup T` **after** the `::/1` and `8000::/1` goto-NOP rules (T8 tun_linux.go:898-938). A v6 socket bound to the TUN address therefore went to main; T fixed this. T8 also used the v4 `matchPriority` for the v6 include_interface goto; T fixed that too.

How each option changes the rules:

| Option | Effect on Linux rules and routes |
|---|---|
| `route_address` | T gets only those prefixes. They win at the `suppress 0` rule, ahead of the main-table specifics. |
| `route_exclude_address` | T = base − exclude. Excluded destinations miss T at every rule and end in main. |
| `route_address_set` (no auto_redirect) | Same as `route_address`, snapshotted at Start. See the §1.4 caveat. |
| `include_uid`/`exclude_uid` | `uidrange a-b goto 9010` rules at the first priority. With include, the **complement** is what gets excluded. |
| `include_interface` | `iif X goto p+2`; everything else `goto NOP`. Only forwarded traffic from X is captured. `lo` must be listed explicitly for local traffic, since local output has iif=lo. |
| `exclude_interface` | `iif X goto NOP`. |
| `include_android_user/package` | Android only: become uid ranges (user*100000 + appid). Ignored elsewhere. |
| `loopback_address` | None. |
| `strict_route` | See §2. |

### 1.4 Caveats seen in the code (not verified at runtime)

- SB inbound.go:299 already sets `routeAddressSet = FlatMap(ExtractIPSet)`, then the loop at 300-306 **appends the same sets again**. Without an exclude list, `BuildAutoRouteRanges` passes the list through verbatim. On Linux, `RouteAdd` with `NLM_F_EXCL` should then fail with EEXIST on the duplicates, and Windows `row.Create()` should fail the same way. macOS survives because it deletes and re-adds on EEXIST. **A port should deduplicate.**
- Without auto_redirect, rule-set updates do **not** refresh routes. The callbacks are registered only when `autoRedirect != nil` (SB inbound.go:307-309, 319-321), and sing-box never calls `UpdateRouteOptions`.
- The sing-box docs claim that without strict_route "all ICMP will not go through TUN" (docs tun.md, the strict_route section). **No ipproto rule exists** in T or T8, so that doc text is stale.

---

## 2. strict_route

### Linux (T tun_linux.go:936-953)

strict_route only adds `unreachable` rules for a **family that has no TUN address**:

```
if no IPv4 address:  <p>:  from all unreachable     (IPv4)
if no IPv6 address:  <p6>: from all unreachable     (IPv6)
```

- The rule is placed after the uid and interface excludes, so excluded uids and interfaces still reach main.
- It does apply to sing-box's own interface-bound sockets. The local table (pref 0) is unaffected.
- **When both families are configured, strict_route adds nothing on Linux** without auto_redirect. It is also used by the nftables rules (T redirect_nftables_rules.go:1149), but only with auto_redirect.
- Crash hazard: a leftover `unreachable` rule persists after a crash and blackholes that family until the next start or a manual cleanup.

### Windows (T tun_windows.go:188-367): WFP

- Skipped with a warning on Windows versions below 10 (189-195).
- Engine opened with `FWPM_SESSION_FLAG_DYNAMIC` (197-202), so **every object disappears when the engine handle closes or the process dies**.
- One sublayer: random GUID, weight 0xFFFF (204-216).

All filters are in that sublayer, on the **ALE_AUTH_CONNECT** layers (outbound connect, and the first send of each UDP flow). Higher weight is evaluated first:

| Weight | Layer | Condition | Action | When added |
|---|---|---|---|---|
| 13 | CONNECT_V4 and V6 | `ALE_APP_ID == <own exe>` | PERMIT + `FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT` (hard permit) | always |
| 12 | CONNECT_V6 | none | BLOCK | only if no IPv6 address. The v4 counterpart is commented out (261-273), so **IPv4 is never blocked**. |
| 11 | CONNECT_V4 / V6 | `LOCAL_INTERFACE_INDEX == tun ifindex` | PERMIT | for each family with an address |
| 10 | CONNECT_V4 and V6 | `IP_REMOTE_PORT == 53` | BLOCK | T: `DNSMode == hijack` (the default); T8: always |

Net effect:

- Port-53 traffic leaving on any non-TUN interface is blocked for every process except sing-box. This defeats Windows smart multi-homed name resolution.
- All IPv6 is blocked if the TUN has no IPv6 address.
- Nothing else is blocked.

Close (553-569) calls `FwpmEngineClose0`.

### macOS

**strict_route has no effect.** Nothing in `tun_darwin.go` or `monitor_darwin.go` reads `StrictRoute`; a grep across T and T8 finds it only in the Linux, Windows and nftables files.

---

## 3. macOS

### 3.1 Interface setup (T tun_darwin.go:94-150, 234-342)

- `socket(AF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)`, `CTLIOCGINFO "com.apple.net.utun_control"`, `connect(sc_unit = N+1)`. The name must be `utunN`.
- MTU: `SIOCSIFMTU` (250-258).
- IPv4 (262-297): `SIOCAIFADDR` with addr = **dstaddr = own address**, plus the netmask. This makes it point-to-point, so no subnet route comes from the kernel. That is why the route set adds `addr.Masked()`.
- IPv6 (298-340): `SIOCAIFADDR_IN6` with the prefix mask, flags `IN6_IFF_NODAD|IN6_IFF_SECURED`, infinite lifetimes, and dstaddr = next address only if /128.
- The interface comes up with the address; there is no separate link-up call.

### 3.2 Routes (T tun_darwin.go:152-158, 457-570)

`Start`: `RegisterMyInterface` and then `setRoutes`.

For each prefix P in the route set (the sub-ranges by default), write one message on a PF_ROUTE socket:

```
RTM_ADD  flags = RTF_UP|RTF_STATIC|RTF_GATEWAY   dst=P  netmask=P.mask  gateway=<utun own IPv4 / IPv6 addr>
         (+RTF_IFSCOPE + ifindex only if InterfaceScope; sing-box CLI: never)
on EEXIST: RTM_DELETE dst/mask/gw, then RTM_ADD again                               (480-494)
```

- This amounts to `route add -net P <utun-addr>`. The kernel resolves the gateway to the utun.
- The **main default route is never touched**: 0/1..128/1 are more specific than 0/0.
- EEXIST handling does delete a foreign or stale route with the same destination, such as another VPN's 0/1 or a crashed run's route.
- `dscacheutil -flushcache` runs asynchronously after the routes are set, and again on Close (496, 168, 572-574).
- Nothing else: no rules, no firewall (pf), no strict_route.

### 3.3 Close (160-174, 503-525)

`RTM_DELETE` for each route, but only if `routeSet`; then close the fd. The utun is destroyed with the fd, and the kernel purges routes whose interface is detached, so a crash leaves nothing behind in practice.

---

## 4. Windows

### 4.1 Interface setup (T tun_windows.go:39-163)

- `wintun.CreateAdapter(name, "sing-tun", GUID = md5("wintun"+name))`. The GUID is deterministic.
- T only: on `ErrExist` it falls back to `OpenAdapter`, which reuses a leftover adapter (45-53).
- `StartSession(0x800000)`.
- For each family with an address:
  - `SetIPAddressesForFamily`.
  - DNS: `SetDNS(tun, [dnsaddr])` if `AutoRoute` and DNS is not disabled, otherwise `SetDNS(nil)`. See §5.
- `DisableDNSRegistration()` (120-122).
- `MIB_IPINTERFACE_ROW` per family:
  - `ForwardingEnabled=true` (v4 only)
  - `RouterDiscoveryBehavior=Disabled`, `DadTransmits=0`, `Managed`/`OtherStateful=false`
  - `NLMTU=MTU`
  - with auto_route: **`UseAutomaticMetric=false, Metric=0`** (123-161)

### 4.2 Routes (T tun_windows.go:169-187, 600-629)

- `RegisterMyInterface`.
- For each prefix P (0.0.0.0/0 and ::/0 by default): `CreateIpForwardEntry2{InterfaceLUID=tun, Dst=P, NextHop=gw (next address, e.g. 172.18.0.2), Metric=0}`.
- `FlushResolverCache`.
- The wintun route (metric 0 plus interface metric 0) beats the physical default route by metric, and longest-prefix still wins, so LAN routes bypass the TUN. **The existing default route is never modified.**
- These routes live in the active store only and are tied to the wintun LUID.
- Then strict_route WFP (§2).
- `UpdateRouteOptions` (571-598) = `FlushRoutes(LUID)` and re-add. sing-box never calls it.

### 4.3 Close (553-569)

- `session.End()`
- `adapter.Close()`: WintunCloseAdapter removes an adapter this process created, which takes its routes, addresses and DNS with it.
- `FwpmEngineClose0`: the dynamic filters vanish.
- `FlushResolverCache`.
- There is no explicit route deletion; it relies on the adapter going away.

On a crash, the dynamic WFP session is removed by the OS. The wintun adapter is expected to disappear with the process (Wintun ≥0.14 ties the software-device lifetime to the handle). The T `OpenAdapter` fallback exists for cases where it does not.

---

## 5. How sing-box keeps its own traffic out of the TUN, and what happens when the default interface changes

### 5.1 The mechanism: bind every outbound socket to the physical interface

Neither sing-tun nor sing-box adds fwmark rules or "protect" rules without auto_redirect. Loop avoidance is **per-socket interface binding**, enabled by `route.auto_detect_interface`, `route.default_interface`, or a per-outbound `bind_interface`. The docs' `auto_route` section says so explicitly.

- **Without any of these on Linux, macOS or Windows, sing-box's own outbound traffic loops into the TUN.** There is no warning.
- `route.default_mark` does **not** help without auto_redirect: no fwmark rule exists.

Dialer wiring (SB common/dialer/default.go:69-133):

- `bind_interface` → `BindToInterface(name)`.
- Otherwise `default_interface` → the same, with the static name.
- Otherwise, if `auto_detect_interface` is on and there is no bind address → `NetworkManager.AutoDetectInterfaceFunc()`.

`AutoDetectInterfaceFunc` (SB route/network.go:340-366) picks the interface per dial or listen:

1. If the destination IP falls in a local interface's address or prefix (`InterfaceFinder.ByAddr`, S bind_finder_default.go:94-112: exact address first, then prefix containment, across *all* interfaces including the TUN), use that interface.
2. Otherwise use `interfaceMonitor.DefaultInterface()`. If that is nil → `ErrNoRoute`.

Loopback and multicast destinations are never bound (S bind.go:31-33).

Socket options (S common/control):

| OS | Option | Cite |
|---|---|---|
| Linux | `SO_BINDTOIFINDEX`; on ENOPROTOOPT/EINVAL, fall back to `SO_BINDTODEVICE` (name) | bind_linux.go:15-41 |
| macOS | `IP_BOUND_IF` (v4) / `IPV6_BOUND_IF` (tcp6/udp6/ip6) = ifindex | bind_darwin.go:10-29 |
| Windows | `IP_UNICAST_IF` (=31, ifindex in **network byte order**) / `IPV6_UNICAST_IF` (=31, host order). For an unspecified address both are set, and the v6 error is ignored. | bind_windows.go:12-57 |

Why a bound socket bypasses the TUN:

- **Linux**: with `oif=eth0`, looking up table 2022 finds only `dev tun0` next hops, and the fib next-hop check rejects an oif mismatch. So every `lookup 2022` rule misses and falls through. `main suppress 0` suppresses the default route, so the lookup reaches rule 9010 nop and then 32766 main, which has the default via eth0. IPv6 behaves the same way: a strict-iface lookup fails in T, and the lookup continues. No special rule is needed.
- **macOS**: `IP_BOUND_IF` forces a scoped route lookup on en0, and en0's scoped default route ignores the utun's non-scoped 0/1..128/1.
- **Windows**: `IP_UNICAST_IF` constrains the route choice to that interface's routes.

The Android and Apple platform builds use `ProtectFunc` / `AutoDetectInterfaceControl` (VpnService.protect and similar; SB network.go:368-377), plus `protect_path`. These are out of scope for the CLI.

### 5.2 How the default interface is detected

The monitor is created whenever the network monitor can be created, even without auto_detect_interface (SB network.go:107-126).

**Change sources** (`NetworkUpdateMonitor`):

- **Linux** (T monitor_linux.go:17-24, 65-138): a raw `NETLINK_ROUTE` socket subscribed to `RTMGRP_LINK|IPV4_IFADDR|IPV6_IFADDR|IPV4_ROUTE|IPV6_ROUTE`, with 1 MiB receive buffer (`SO_RCVBUFFORCE`). Any message triggers `emit()`, rate-limited to at most 1 per second with a trailing emit. T8 used `netlink.RouteSubscribe` and `LinkSubscribe` instead.
- **macOS** (T monitor_darwin.go:36-100): a `PF_ROUTE` socket; any `RouteMessage` triggers `emit()`.
- **Windows** (T monitor_windows.go:29-46): `NotifyRouteChange2` and `NotifyIpInterfaceChange`; any callback triggers `emit()`.

**Debounce** (T monitor_shared.go:67-105): each emit (re)arms a 1 s timer. When it fires, `postCheckUpdate` runs `interfaceFinder.Update()` (`net.Interfaces`) and then `checkUpdate()`. On error it retries after 1 s. On `ErrNoRoute` it emits `nil` once.

**`checkUpdate` per OS:**

- **Linux** (monitor_linux_default.go:12-40): the first route in the **main** table (`FAMILY_ALL`) with `Dst == nil` (default) gives its `LinkIndex`. Because sing-tun's own routes are in table 2022, the TUN is never picked.
- **macOS** (monitor_darwin.go:109-178): `sysctl NET_RT_DUMP` (`route.FetchRIB`), then the first **IPv4** route with dst 0.0.0.0/0 and `RTF_UP|RTF_GATEWAY` (IFSCOPE is not excluded). The utun has no /0, so it is never picked. Under a Network Extension it instead does a connect() to 10.255.255.255:80 and reads the source address.
- **Windows** (monitor_windows.go:60-115): `GetIpForwardTable2(AF_INET)`, keeping rows where:
  - the prefix length is 0,
  - the interface is `OperStatus==Up`,
  - the type is **not** `PROP_VIRTUAL` (53) or `SOFTWARE_LOOPBACK` (wintun is `PROP_VIRTUAL`, so it is excluded),
  - `IPInterface.Connected`.

  Among those, pick the one with the lowest `route.Metric + iface.Metric`.
- A change is detected when the index, MTU, name, MAC, flags or address networks differ (v6 compared at /64) (monitor_shared.go:159-175).

### 5.3 On change (SB network.go:480-521, 453-478)

- `nil` → `pauseManager.NetworkPause()` and log "missing default interface".
- New interface →
  1. `NetworkWake`
  2. log
  3. `UpdateWIFIState`
  4. **`ResetNetwork()`**: `connectionManager.CloseAll()`, then `InterfaceUpdated()` on every endpoint, inbound and outbound (resets mux, QUIC and WireGuard sessions)
- Windows power resume also calls `ResetNetwork` (523-535).
- **Routes and rules are NOT refreshed** on Linux, macOS or Windows. They reference only the TUN, never the physical gateway, so nothing goes stale. The one exception is Android: `resetRules` on `FlagAndroidVPNUpdate` (T tun_linux.go:367-369, 1204-1214).
- New sockets pick up the new interface automatically, because the bind function reads `DefaultInterface()` on every dial.

---

## 6. Cleanup

| | On Close | At start (stale state from a crash) | Removed by the OS on process death | Left behind after a crash |
|---|---|---|---|---|
| **Linux** | `resolvectl revert <tun>`; `AddrDel` for each address; `RouteDel` for each computed route; `unsetRules` = delete **every** rule with priority in [S, S+10] for all families (T tun_linux.go:373-387, 1123-1197) | `unsetRules()` before `setRules()` (350-353) removes any rule at 9000-9010, **including rules that are not ours**. Routes are not pre-cleaned; `RouteAdd` is exclusive, but stale routes die with the old device. `AddrAdd` ignores EEXIST. | The TUN device (non-persistent), so every table-2022 route (`dev tun`) and its addresses; systemd-resolved drops the link's DNS | **ip rules at 9000-9010.** These are harmless while table 2022 is empty (lookups miss and fall through to main), **except a strict_route `unreachable` rule**, which blackholes that family |
| **macOS** | `RTM_DELETE` for each route (if set); `dscacheutil -flushcache` | EEXIST on `RTM_ADD` → delete and re-add | The utun, and with it the routes whose gateway or ifp is the utun | Nothing expected |
| **Windows** | End session, close the adapter (removes it), close the WFP engine, flush the DNS cache | T: reuse an existing adapter with the same GUID (`OpenAdapter`). The routes' `Create` would fail if they are still present. | The dynamic WFP session; the wintun adapter (with routes and DNS) | Nothing expected (edge: a leftover adapter) |

**Is the main table or the default route ever changed?** No, on all three OSes. What each one does instead:

- **Linux**: a separate table plus policy rules.
- **macOS**: more-specific sub-ranges.
- **Windows**: a /0 route on the TUN, winning on metric.

Sail's current approach (replacing the main-table default with `ip route` or `route`) is the one thing sing-tun avoids. The upstream design leaves nothing that breaks the host after a crash, apart from Linux ip rules (inert) and a strict_route unreachable rule.

---

## 7. DNS configuration of the host

| OS | What sing-tun does | Cite |
|---|---|---|
| Linux | If `resolvectl` exists on PATH: `resolvectl domain <tun> ~.`, `resolvectl default-route <tun> true`, `resolvectl dns <tun> <dns4…> <dns6…>`. These run asynchronously and errors are ignored. Close runs `resolvectl revert <tun>`. There is **no `/etc/resolv.conf` editing**. The condition is **not** tied to auto_route: T: `DNSMode != disabled && NetNs == ""`; T8: `!EXP_DisableDNSHijack`, and skipped if there is no next address. | T tun_linux.go:360-365, 380-382, 1216-1239; T8 tun_linux.go:1073-1108 |
| macOS | **Nothing.** No network-service DNS, scutil or SCDynamicStore. Only the DNS-cache flush. Hijack catches only DNS that is *routed* into the utun, meaning public resolvers; a LAN resolver on the connected subnet goes direct. (The Apple GUI app sets DNS through NetworkExtension, which is outside this code.) | T tun_darwin.go (no DNS code); grep across SB, T and S finds no networksetup or SCDynamicStore |
| Windows | Interface DNS on the wintun via `SetInterfaceDnsSettings` (Win10 1809+; netsh/registry fallback), family-filtered, nameserver = `Inet{4,6}DNSAddress` (default `addr.Next()`); plus `DisableDNSRegistration`. **No NRPT.** Leak prevention comes from the strict_route port-53 WFP block. Metric 0 makes the TUN the preferred DNS interface. The settings vanish with the adapter. | T tun_windows.go:78-122; internal/winipcfg/luid.go:336-411 |

---

## 8. Minimal faithful port (sail)

### Linux (required)

1. Create a non-persistent TUN. Set the MTU (default 65535), add the addresses (ignore EEXIST), set the link up.
2. Compute the route set: route_address, else 0/0 and ::/0; minus route_exclude; plus deduplicated route_address_set.
3. `ip route add P [via addr.Next()] dev tun table 2022` for each P.
4. Delete all rules with priority 9000..9010 (both families), then install the §1.3 rule list exactly: priorities, the v4 `from 0.0.0.0/32` / v6 `::/1`+`8000::/1` source tricks, `not dport 53 lookup main suppress_prefixlength 0`, and `nop` at 9010.
5. Close: delete the routes, rules and addresses.
6. **Outbound sockets**: `SO_BINDTOIFINDEX` (fallback `SO_BINDTODEVICE`) to the interface that owns the destination's subnet, else the default interface = the first main-table default route's oif.
7. Netlink monitor with 1 s debounce. On a change of default interface, close all connections and reset pooled sessions. Do not touch routes.
8. Do not modify the main table.

Optional: resolvectl (on by default in sing-box when present), rp_filter=2 (T only), uid and interface include/exclude, strict_route (only the unreachable rule for a missing family), checksum offload and GSO.

### macOS (required)

1. utun via the control socket; `SIOCSIFMTU`; `SIOCAIFADDR` (point-to-point, dst = self); `SIOCAIFADDR_IN6` (NODAD|SECURED, infinite lifetime).
2. `RTM_ADD RTF_UP|RTF_STATIC|RTF_GATEWAY` for 1/8,2/7,…,128/1 (and 100::/8…8000::/1), plus the own v4 subnet, with gateway = own address. On EEXIST, delete and re-add.
3. Close: `RTM_DELETE` each.
4. Outbound sockets: `IP_BOUND_IF` / `IPV6_BOUND_IF`. Default interface = the first v4 0/0 `RTF_UP|RTF_GATEWAY` route in the RIB. PF_ROUTE monitor with 1 s debounce.

Optional: `dscacheutil -flushcache`. **No strict_route and no DNS setting** (faithful = none).

### Windows (required)

1. wintun with a deterministic GUID. Set the addresses; interface rows with metric 0 (not automatic), NLMTU, no RA or DAD.
2. `SetInterfaceDnsSettings(nameserver = addr.Next())` and `DisableDNSRegistration`.
3. `CreateIpForwardEntry2` 0/0 and ::/0 on the LUID, next hop `addr.Next()`, metric 0. `FlushResolverCache`.
4. Close: remove the adapter.
5. Outbound sockets: `IP_UNICAST_IF` (big-endian index) / `IPV6_UNICAST_IF`. Default interface = the lowest route+interface metric among up, connected, non-virtual v4 0/0 routes. Route and interface change notifications with 1 s debounce.

Optional: strict_route WFP. If implemented, reproduce the §2 table exactly: a dynamic session, a sublayer of weight 0xFFFF, weights 13/12/11/10, ALE_AUTH_CONNECT v4/v6.

### All platforms

Treat "no default_interface, no bind_interface and no auto_detect" as a **loop**. sing-box silently allows it; given the no-backward-compatibility policy, sail should either make auto_detect implicit when `auto_route` is on or make its absence a config error.
