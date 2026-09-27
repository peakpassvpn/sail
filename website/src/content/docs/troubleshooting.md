---
title: Troubleshooting
description: Isolate configuration, listener, routing, DNS, TLS and TUN failures.
---

Debug Sail from the inside out: first validate the file, then test the outbound, then test the local inbound, and only then inspect application or system-wide routing.

## A short diagnostic sequence

```sh
# 1. Parse and validate references
sail -c config.json -T

# 2. Test the outbound itself
sail -c config.json -t edge -d 10

# 3. Start with detailed logs
sail -c config.json --profile desktop

# 4. Test through a local SOCKS inbound
curl --socks5-hostname 127.0.0.1:1080 https://example.com
```

This sequence separates core configuration from the operating system's proxy or TUN setup.

## Configuration does not validate

Sail rejects unknown fields and reports the tag of the endpoint being built. Common causes are:

- A field copied from leaf, sing-box or another project with a different shape.
- A route, group, MPTP member or detour referencing a missing tag.
- A transport block attached to a protocol that does not support it.
- A `route` or `reject` rule without any conditions.
- A duration set to zero.

Reduce the file to one inbound, one direct outbound and a final route, then restore sections one at a time.

## The listener is unreachable

Check the configured `listen` address. `127.0.0.1` is reachable only from the same host. For LAN access, choose an appropriate interface address and protect the listener with protocol authentication or network policy.

Confirm the port is not already in use and that the application is using the correct proxy type. An HTTP client pointed at a SOCKS port will not complete a valid handshake.

## The outbound test fails

Read TCP and UDP results independently. A protocol may support both while the network path allows only one.

- DNS error: test the server name and configured resolvers.
- Connect timeout: inspect firewall, route, interface binding and server port.
- Authentication error: confirm password, UUID or protocol-specific user.
- TLS error: confirm system time, `server_name`, trust chain, ALPN and REALITY parameters.

Enable `debug` logs temporarily for the failing layer, then return to `info` after diagnosis.

## Domain rules do not match

If the application resolved the domain locally, Sail may receive only an IP address. Prefer remote DNS through the proxy, enable DNS reverse mapping, or add an early `sniff` rule for TLS and HTTP traffic.

Remember that sniffing applies to the first bytes of a TCP stream. It cannot recover a domain from every protocol and does not decrypt TLS.

## TUN starts but traffic stops

An automatic default route can capture Sail's own outbound sockets and create a loop. Set either:

```json
{ "route": { "auto_detect_interface": true } }
```

or a fixed `default_interface`, but not both. On Android, also verify that the host registered a working `VpnService.protect` callback before startup.

If only large transfers fail, inspect MTU and network-change handling. Forward the current MTU to an embedded instance when the host network changes.

## MPTP connects but performs poorly

Test every path tag separately. Two configured members are not useful if they share the same constrained physical route. Large latency differences, loss or a blocked server port can make aggregation worse than the best single path.

Begin with two healthy paths, confirm the server can reach targets directly, then add more members.

## Reload does not change behavior

Validate the new file separately and confirm `--auto-reload` is enabled or the host called the reload API. Some state, such as selector choice, can be restored from `cache_dir`; clear or change it only when that persisted state is intentionally no longer wanted.

## Report a reproducible issue

Include the Sail version, target operating system, build features, a redacted minimal configuration, exact validation or runtime error, and whether the named outbound passes `-t`. Never include passwords, UUIDs, private keys or full certificates in a public report.
