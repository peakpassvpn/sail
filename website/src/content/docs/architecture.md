---
title: Architecture
description: How Sail separates configuration, routing, endpoint factories, transports and its user-space network stack.
---

Sail is organized around a reusable core rather than a client-only executable. Clients, servers and relays share the same configuration model, router, protocols and transports; only the host and active endpoints change.

## Request path

```text
Host / OS
   ↓
Inbound listener → Session metadata → Router → Outbound handler
                                             ↓
                                  transport and TLS layers
                                             ↓
                                      network socket
```

An inbound creates a session containing the source, destination, network type, inbound tag and any authenticated user. Optional sniffing or DNS resolution enriches that session. The router chooses an outbound tag, then the outbound manager invokes the already-built handler graph.

## Workspace

| Crate | Role |
| --- | --- |
| `sail` | Core runtime, protocols, transports, DNS, routing and platform integration |
| `sail-cli` | Command-line host and runtime option parsing; builds the `sail` binary |
| `sail-ffi` | C ABI (`libsail`, `sail.h`): instances, control, events, the command service and platform callbacks |
| `sail-netstack` | User-space TCP/IP stack in safe Rust, with bounded memory |
| `sail-plugins/shadowsocks` | An example outbound plugin, built as a dynamic library for the `plugin` feature |

Protocol and transport modules stay inside `sail` so they can share common session, adapter and network abstractions. `bindings/swift` and `bindings/kotlin` wrap the C ABI for apps; see [Platform integration](/sail/platform-integration/).

## Modules of the core

| Module | Holds |
| --- | --- |
| `config` | The model, and the readers of sing-box JSON, Clash YAML, Surge profiles and share links |
| `adapter` | Handler traits and the registry of inbound and outbound factories |
| `app` | The instance: inbound and outbound managers, dispatcher, router, DNS, providers, health checks, statistics, the Clash API and the management API |
| `protocol` | Inbounds, outbounds, groups and endpoints, a directory each |
| `transport` | TLS, REALITY, WebSocket, HTTP Upgrade, gRPC, QUIC, multiplexing and UDP over TCP |
| `net` | Dialing, the network state and its changes, NAT64, and the runtime that drives `sail-netstack` |
| `platform` | Operating-system integration: routes, interfaces, network detection, wintun, nftables |
| `control` | What an instance is controlled and watched through; the Clash API, the FFI and the command service all use it |
| `runtime` | Runtime profiles and options, start settings, the cache file |
| `user` | The users inbounds authenticate, with their traffic and limits |
| `sniff`, `session` | Protocol sniffing, and the session a connection carries |

## Configuration pipeline

sing-box's JSON is Sail's own format: it maps directly into `config::model`. Clash and Mihomo YAML and Surge profiles are read as they are and lowered into the same model. A file's extension picks the reader (`.json`; `.yaml` or `.yml`; `.conf`), and configuration text passed by a host is recognised by its content.

```text
sing-box JSON / Clash YAML / Surge profile → model → structural validation
                                                    → endpoint dependency graph
                                                    → handlers and listeners
```

A field sing-box accepts and Sail does not implement is an error when ignoring it would route or secure traffic otherwise than the configuration says, and a warning when it would not. A field sing-box does not know either is an error.

The model owns shared concepts such as tags, DNS, routes and reusable endpoint blocks. Each protocol owns its own option structure and rejects unknown fields when its factory is built.

## Endpoint registry

Inbound and outbound protocols register factories by name. The registry provides three useful properties:

- Feature flags decide which protocols exist in a build.
- Adding a protocol does not require a central switch statement in the managers.
- Factories declare dependencies and supported shared blocks before construction.

Composite outbounds such as selectors, URL tests, fallback, load balancing and MPTP depend on other outbound tags. Sail orders the dependency graph and reports missing references or cycles before serving traffic.

## Transport composition

TLS, REALITY, WebSocket, HTTP Upgrade, gRPC, QUIC, multiplexing, dial options and detours are blocks around an endpoint protocol. Internally they form a handler chain; configuration keeps them nested on the outbound that uses them, as in sing-box. A detour is not a layer: it is the outbound's dialer, which dials through the named outbound in place of a socket.

For a stream proxy, the conceptual order is:

```text
proxy protocol → multiplex/transport → TLS or REALITY → detour/dialer → socket
```

Some protocols own the connection differently. AnyTLS keeps sessions alive across logical streams, while Hysteria2 and TUIC operate directly over QUIC. Their factories therefore accept a different set of blocks.

## Router

The router receives normalized session metadata and checks ordered rules. Terminal actions (`route`, `reject`, `hijack-dns`, `bypass`) end the evaluation. Non-terminal actions (`route-options`, `sniff`, `resolve`) set connection options, sniff application metadata or resolve a domain, then resume rule evaluation.

The router only knows outbound tags. Selection, health checking and multipath scheduling stay inside their outbound handlers, keeping policy separate from transport behavior.

## TUN and user-space networking

The TUN inbound sends IP packets into `sail-netstack`. The stack owns TCP state, UDP delivery, fragmentation and reassembly, memory budgets and scheduling. Accepted flows re-enter the same session and routing pipeline as socket-based inbounds. The WireGuard endpoint runs the same stack over its tunnel.

This gives every platform one data-plane implementation while preserving host control over the TUN device, route installation and outbound socket protection. On desktops and servers Sail installs the routes itself; a host that opens the TUN through the FFI routes it.

## Runtime and resources

Runtime profiles select coherent starting budgets for mobile, desktop, server or router hosts. They tune relay buffers, UDP, the netstack, inbounds, QUIC, WebSocket, DNS, statistics, multiplexing and shutdown, without changing the portable proxy configuration.

Long-lived resources—health checks, selectors, sessions and listeners—belong to an instance and are torn down on reload or shutdown through explicit handles. Selector choices, the Clash mode and fake IPs persist only with `experimental.cache_file`, whose file is kept in `cache_dir` (the data directory without one), outside the configuration.

When the network changes so that its connections do not survive, the instance flushes its DNS cache, closes its connections and resets the TUN's flows; see [When the network changes](/sail/platform-integration/#when-the-network-changes).

## Design boundaries

- Protocols parse their own fields and build adapter handlers.
- Transports do not decide routing policy.
- The router does not know concrete protocol implementations.
- Platform adapters provide capabilities without owning proxy semantics.
- Configuration describes behavior; runtime settings describe resource budgets.

These boundaries are what allow the same core to serve a local client, a public server or an intermediate relay.
