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

# 3. Start, with "log": { "level": "debug" } in the file for detailed logs
sail -c config.json

# 4. Test through a local SOCKS inbound
curl --socks5-hostname 127.0.0.1:1080 https://example.com
```

This sequence separates core configuration from the operating system's proxy or TUN setup.

## Configuration does not validate

Errors name the path of the field at fault, such as `route.rules[0].ip_accept_any: unknown field`. In sing-box JSON an unknown field is an error. A field sing-box or Mihomo accepts but Sail does not implement is an error when ignoring it would change how traffic is routed or secured, and otherwise a warning in the log. Clash and Surge keys Sail does not know are warned about, not refused. Common causes are:

- A field copied from leaf or another project with a different shape, or a feature Sail does not implement.
- A route, group, MPTP member or detour referencing a missing tag.
- A transport block attached to a protocol that does not support it.
- A `route` or `reject` rule without any conditions; use `route.final` instead.
- Both `route.default_interface` and `route.auto_detect_interface` set.
- A duration without a unit, such as `5` instead of `5s`.
- A file extension other than `.json`, `.yaml`, `.yml` or `.conf`.

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

Set `log.level` to `debug` temporarily, then return to `info` after diagnosis.

## Domain rules do not match

If the application resolved the domain locally, Sail may receive only an IP address. Prefer remote DNS through the proxy, enable DNS reverse mapping, or add an early `sniff` rule for TLS and HTTP traffic.

Remember that sniffing reads only the first bytes of a connection: TLS and HTTP on TCP, QUIC on UDP. It cannot recover a domain from every protocol and does not decrypt TLS.

## TUN starts but traffic stops

An automatic default route can capture Sail's own outbound sockets and create a loop. Set either:

```json
{ "route": { "auto_detect_interface": true } }
```

or a fixed `default_interface`, but not both; setting both is a configuration error. On Android, also verify that the host gave a working `protect_socket` callback, which calls `VpnService.protect`, before startup.

If only large transfers fail, inspect MTU and network-change handling. When the host network changes, an embedded instance should be told so with `sail_network_changed`, which also takes the new MTU.

## MPTP connects but performs poorly

Test every path tag separately. Two configured members are not useful if they share the same constrained physical route. Large latency differences, loss or a blocked server port can make aggregation worse than the best single path.

Begin with two healthy paths, confirm the server can reach targets directly, then add more members.

## Reload does not change behavior

Validate the new file separately with `-T`. A reload happens only with `--auto-reload`, on SIGHUP (as `systemctl reload` sends it), or through the runtime API (`POST /api/v1/runtime/reload`) or a host's reload call. A file that fails to load leaves the previous configuration running, and the error is logged. With `experimental.cache_file` enabled, some state, such as selector choice, the Clash mode and (with `store_fakeip`) fake IPs, is restored from the cache file; delete the file only when that persisted state is intentionally no longer wanted.

## Report a reproducible issue

Include the Sail version, target operating system, build features, a redacted minimal configuration, exact validation or runtime error, and whether the named outbound passes `-t`. Never include passwords, UUIDs, private keys or full certificates in a public report.
