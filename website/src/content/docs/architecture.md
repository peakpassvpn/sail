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
| `sail` | Core runtime, protocols, transports, DNS, routing and platform traits |
| `sail-cli` | Command-line host and runtime option parsing |
| `sail-ffi` | C-compatible lifecycle and platform boundary |
| `sail-netstack` | User-space TCP/IP data plane for TUN traffic |

Protocol and transport modules stay inside `sail` so they can share common session, adapter and network abstractions.

## Configuration pipeline

JSON maps directly into `config::model`. Legacy `.conf` input is translated into the same model before validation.

```text
JSON or .conf → normalized model → structural validation
                                  → endpoint dependency graph
                                  → handlers and listeners
```

The model owns shared concepts such as tags, DNS, routes and reusable endpoint blocks. Each protocol owns its own option structure and rejects unknown fields when its factory is built.

## Endpoint registry

Inbound and outbound protocols register factories by name. The registry provides three useful properties:

- Feature flags decide which protocols exist in a build.
- Adding a protocol does not require a central switch statement in the managers.
- Factories declare dependencies and supported shared blocks before construction.

Composite outbounds such as selectors, fallback, load balancing and MPTP depend on other outbound tags. Sail topologically orders the dependency graph and reports missing references or cycles before serving traffic.

## Transport composition

TLS, REALITY, WebSocket, HTTP Upgrade, gRPC, multiplexing, dial options and detours are blocks around an endpoint protocol. Internally they form a handler chain; configuration keeps them nested on the outbound that uses them.

For a stream proxy, the conceptual order is:

```text
proxy protocol → multiplex/transport → TLS or REALITY → detour/dialer → socket
```

Some protocols own the connection differently. AnyTLS keeps sessions alive across logical streams, while Hysteria2 and TUIC operate directly over QUIC. Their factories therefore accept a different set of blocks.

## Router

The router receives normalized session metadata and checks ordered rules. Terminal actions return an outbound or reject the connection. Non-terminal actions sniff application metadata or resolve a domain, then resume rule evaluation.

The router only knows outbound tags. Selection, health checking and multipath scheduling stay inside their outbound handlers, keeping policy separate from transport behavior.

## TUN and user-space networking

The TUN inbound sends IP packets into `sail-netstack`. The stack owns TCP state, UDP delivery, fragmentation behavior, memory budgets and scheduling. Accepted flows re-enter the same session and routing pipeline as socket-based inbounds.

This gives supported platforms one data-plane implementation while preserving host control over the TUN device, route installation and outbound socket protection.

## Runtime and resources

Runtime profiles select coherent starting budgets for mobile, desktop, server or router hosts. They tune buffers, queues, worker behavior, DNS resilience, QUIC limits and netstack budgets without changing the portable proxy configuration.

Long-lived resources—health checks, selectors, sessions and listeners—belong to an instance and are torn down on reload or shutdown through explicit handles. Persisted selector state is kept outside the configuration in `cache_dir`.

## Design boundaries

- Protocols parse their own fields and build adapter handlers.
- Transports do not decide routing policy.
- The router does not know concrete protocol implementations.
- Platform adapters provide capabilities without owning proxy semantics.
- Configuration describes behavior; runtime settings describe resource budgets.

These boundaries are what allow the same core to serve a local client, a public server or an intermediate relay.
