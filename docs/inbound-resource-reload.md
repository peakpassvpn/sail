# Inbound users and certificate reload

Inbound resource reload supports **Trojan, VLESS, AnyTLS, VMess, Shadowsocks
(legacy and 2022), Hysteria2, TUIC, HTTP, SOCKS and mixed**. Supported layers
include TLS, REALITY, WebSocket, HTTPUpgrade, gRPC, QUIC, AMUX and sing-mux
where the protocol permits those combinations. It does not rebind listeners.

## Entry points

- Replace `users` or the ordinary TLS `certificate` / `certificate_path`
  and `key` / `key_path` fields, then call the existing configuration
  reload entry point (`sail::reload`, or `RuntimeManager::reload`).
- REALITY `private_key` / `short_id` and legacy Shadowsocks `password`
  use the same entry points. SS2022's server identity PSK, method and
  presence/absence of identity headers are structural, not user resources.
- For file-backed runtimes, with the `auto-reload` feature and
  `StartOptions::auto_reload = true`,
  changes to the configuration, supported certificate/key files and local
  `route.rule_set` files also
  trigger reload. Parent directories are watched, so atomic rename-over
  replacement keeps working. Events are coalesced with a 250 ms quiet
  period. A temporarily invalid certificate/key pair retains the old
  resources; writing its other half triggers another attempt.
- An embedding host can call
  `RuntimeManager::update_inbound_resources(inbound).await`, passing the
  complete inbound configuration with the same tag and static fields.
  Only that inbound is rebuilt. This does **not** persist the change to
  disk: a subsequent file/configuration reload uses the file as authority.
  No new HTTP management endpoint or authentication policy is added.

Paths use the existing `Host::data_dir` resolution. An explicit reload
re-reads the PEM files even when the configured paths have not changed.
After a successful configuration reload, watches follow the new paths.

## Connection and failure semantics

All replacements are built and validated before any live inbound resource
is changed. This includes UUID/flow/password-table checks, PEM parsing and
certificate/private-key matching. A failed configuration reload leaves
the current inbound resources, DNS, outbounds and routing in place.

Each inbound publishes an immutable credential/pipeline generation through
`HotResource<T>`. A connection snapshots it before its first TLS/protocol
handshake. Its users and certificate cannot come from different generations.
Existing connections and handshakes already in progress continue with
their generation. Existing AnyTLS, gRPC, AMUX, QUIC and sing-mux sessions may also
open new logical streams under that session's original generation.
Removing a user from an inbound revokes it there at once, which differs
from sing-box: the connections it has through that inbound are closed,
the QUIC, AnyTLS and sing-mux connections carrying its streams too, and
any stream it would still open under the old generation (a gRPC, AMUX or
QUIC-transport session kept open) is refused when it is dispatched. Its
connections through other inbounds are kept. Adding it back lets it in
again.
An empty tunnel-protocol user table authenticates nobody new (configured
fallback behavior is retained). **HTTP, SOCKS and mixed retain their existing
configuration semantics: an empty user table enables anonymous access.**
Duplicate Trojan passwords are rejected rather than silently
overwriting one user's identity.

VMess generations share one listener-lifetime auth-ID replay filter, including
handshakes still using old users. Renaming, removing and re-adding a user,
emptying the table, or replacing certificates does not erase replay history.
Different inbounds have separate filters. Explicitly removing/recreating an
inbound creates a new listener lifetime; history is not persisted across that
operation or process restarts. VMess UDP/XUDP carried inside TCP keeps its
existing connection; this does not add native UDP listener reload support.

Hysteria2, TUIC and generic QUIC retain their live endpoint. Each incoming
connection uses one snapshot for both its certificate and authentication;
old connections retain their original stream and UDP authentication.
Generic QUIC retains an endpoint-wide authentication concurrency budget
across those connection generations; cancellation releases its permit.
SS2022 retains its TCP salt replay cache and authenticated UDP sessions/replay
windows. A UDP session pins the PSK hash and original user name, not the
user's array index; reordering, renaming or removing users cannot reattribute
it. New session IDs use the current table; idle sessions expire after 300 s.

Legacy SS has no UDP session ID: an authenticated source address pins its
password generation while its NAT session is alive (including inbound and
route-specific UDP timeouts), and until 300 s without authenticated uplink or
successful downlink activity once no session owns it. A new source address must use
the current password. Changing passwords at the same source address requires
expiry or a new client socket. The table is capped at 16,384 peers; invalid
packets cannot create/refresh entries, and a full table refuses new peers
instead of evicting active ones. Existing TCP streams keep their cipher.
SOCKS/mixed retain their shared UDP-association capacity counter across reloads.

Rule-sets use the same `HotResource<T>` snapshot primitive. Configuration and
local file reloads validate rules before publishing a new routing/DNS view;
remote downloads validate before publishing to existing shared readers. Failed
parsing retains the previous rules. Local file watches follow successful
configuration changes and remain installed during host inbound updates.

Publication is atomic **per inbound**, not a global transaction across
every listener, DNS and router. All candidates are validated first, but
independent connections can observe different inbounds during publication.
Socket preparation/acceptance hooks, including TCP Brutal, are retained.

## Deliberate boundaries

- Listener tags, protocols, addresses, ports, UDP timeouts, transport,
  multiplex and fallback settings cannot change through resource reload.
  Unsupported edits return an error; use the existing add/remove API or
  restart for structural changes. Inbound additions/removals in a file
  reload are also rejected rather than silently ignored.
- Custom inbound dependency graphs remain rejected for resource edits rather
  than silently keeping a stale referenced handler. No built-in inbound
  factory currently declares another inbound as a dependency. Unchanged
  unsupported device inbounds continue to operate.
- TUN/NF devices, routing setup and NAT session identity are untouched.
- This implements the resource mechanism and embedding-host entry point,
  not the separate 3.5 authenticated HTTP management platform, nor arbitrary
  structural inbound migration. Add/remove APIs remain available separately.

## Regression coverage

`sail/tests/it/test_inbound_resources.rs` exercises real TLS connections,
certificate fingerprints, new/removed users, retained connections and
in-flight handshakes, invalid UUID/key rollback, empty tables, the host
entry point, unchanged PEM paths, and repeated atomic replacement of both
certificate files and the configuration file. Unit tests cover VLESS and
AnyTLS authentication snapshots, unsupported edits and watcher filtering.
VMess tests cover shared replay history across generations, identity changes,
in-flight old authentication, invalid candidates, empty tables, user removal
and re-addition, and isolation between inbounds.
`test_quic_resources.rs` covers live QUIC/AMUX endpoints and both Shadowsocks
families over TCP and UDP. `test_reality.rs` rotates REALITY keys, short IDs
and VLESS users. Further unit tests cover SS replay/session identity and
candidate rollback, and HTTP/SOCKS/mixed user snapshots. File tests cover
local rule-set replacement and invalid-content rollback as well as PEM files.
