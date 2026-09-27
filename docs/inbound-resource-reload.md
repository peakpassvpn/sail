# Inbound users and certificate reload

The first part of roadmap 3.4 supports **Trojan, VLESS and AnyTLS over
TCP**, including ordinary TLS, WebSocket, HTTPUpgrade, gRPC and sing-mux
where the protocol supports those layers. It does not rebind listeners.

## Entry points

- Replace `users` or the ordinary TLS `certificate` / `certificate_path`
  and `key` / `key_path` fields, then call the existing configuration
  reload entry point (`sail::reload`, or `RuntimeManager::reload`).
- With the `auto-reload` feature and `StartOptions::auto_reload = true`,
  changes to the configuration and supported certificate/key files also
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

Each inbound publishes one immutable stream-pipeline generation through
`HotResource<T>`. A connection snapshots it before its first TLS/protocol
handshake. Its users and certificate cannot come from different generations.
Existing connections and handshakes already in progress continue with
their generation. Existing AnyTLS, gRPC and sing-mux sessions may also
open new logical streams under that session's original generation.
Removing a user is **not** active session revocation; that is separate work.
An empty user table authenticates nobody new (configured fallback behavior
is retained). Duplicate Trojan passwords are rejected rather than silently
overwriting one user's identity.

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
- VMess and Shadowsocks have replay state; Hysteria2, TUIC and QUIC
  transports have long-lived endpoint state. They are not rebuilt.
  REALITY, AMUX, and initially dependent inbound graphs are not supported
  by this first implementation either. They need state-preserving,
  protocol-specific resource updates. Unchanged unsupported inbounds
  continue to operate, and their resource files are not watched here.
- TUN/NF devices, routing setup and NAT session identity are untouched.
- Rule-sets still use their existing reload/updater implementation. The
  generic snapshot primitive is reusable, but this does not claim to
  complete the entire shared-resource/management-API roadmap item.

## Regression coverage

`sail/tests/test_inbound_resources.rs` exercises real TLS connections,
certificate fingerprints, new/removed users, retained connections and
in-flight handshakes, invalid UUID/key rollback, empty tables, the host
entry point, unchanged PEM paths, and repeated atomic replacement of both
certificate files and the configuration file. Unit tests cover VLESS and
AnyTLS authentication snapshots, unsupported edits and watcher filtering.
