# sail embedded in a Rust host

`sail::embed` runs sail inside a host's own process, as a library. An
in-process engine, a desktop service or a command-line tool links the
`sail` crate and drives instances through it. It is the only stable part of
the crate. The C ABI (`sail-ffi`, docs/ffi.md) is built on it, so the two
behave the same.

```rust
use sail::embed::{Config, Instance, Options};

let instance = Instance::new(Options::new().data_dir(state_dir))?;
let mut states = instance.states();            // subscribe first (see below)
instance.start(Config::Json(sing_box_json)).await?;
let traffic = instance.traffic().await?;
let stream = instance.dial_tcp("node-1", target, timeout).await?;
instance.reload(Some(Config::Json(changed))).await?;
instance.stop().await?;
```

## Compatibility

- **What is stable.** Everything in `sail::embed` only grows. Its structs
  and enums are `non_exhaustive`, and functions and variants are added,
  never changed. `ErrorKind` and its `code()` strings only grow too, so a
  host can map them to its own error codes.
- **Breaking changes.** Before 1.0 a breaking change raises the minor
  version (0.16 → 0.17) and is listed in the release notes, so a host
  should pin the version it builds with.
- **Everything else.** Every other module of the crate is public only for
  sail's own crates. It is hidden from the docs and changes without notice.
- **Configuration.** sing-box's JSON is the configuration contract. Clash
  YAML and Surge profiles are read too, as the CLI reads them.

## Building against sail

sail builds with forks of a few crates (BoringSSL bindings, QUIC, TUN route
management) through `[patch.crates-io]`. A `[patch]` section applies only
in the workspace that declares it, so a workspace that depends on sail, even
through another crate, copies sail's section exactly. Its CI checks that the
copy is still exact, after `cargo fetch`:

```sh
python3 path/to/sail/tools/embed-patch-check.py
```

The check finds the sail that the lock file pins, wherever it is in the
dependency graph. It resolves the graph with all the workspace's features,
so it finds sail behind an optional dependency too. Arguments after `--` go
to `cargo metadata` in place of that: `embed-patch-check.py . -- --features
rust-core` checks one feature set. It names each entry that is missing or different, and
passes when every entry matches. Extra entries of the host's own are
allowed.

## Checking a configuration

`sail::embed::check(&config, &options)` reads and builds a configuration
as a start with those options would. It starts nothing: no listener,
no dial, no download. It returns the warnings a start would log (as
`sail -T` prints them), or a `Config` error saying why it does not build.
It blocks while it builds, on a thread of its own, so it may be called
from any thread.

## Runtime and threads

- **Where it runs.** Each instance runs on a tokio runtime of its own, on
  threads of its own:
  - one thread with the `mobile` profile;
  - a worker per core with every other profile, as `sail` the CLI runs;
  - or what `Options::threads` says.
- **Calling it.** The calls are `async` and runtime-agnostic: the host
  awaits them on its own runtime, or on any executor. The work runs on the
  instance's runtime, and the host's future waits for the answer.
- **Stopping.** `stop().await` returns once the instance's thread has ended
  and its runtime is gone. By then its listeners are closed and its
  connections dropped. A stream or datagram socket that was dialled through
  the instance then fails; it does not hang.
- **Dropping.** Dropping the last clone of an `Instance` asks it to stop but
  does not wait. Await `stop()` first.
- **Errors.** `ErrorKind::WrongThread` never comes from these async calls.
  Only the blocking wrappers the C ABI uses give it, when they are called on
  one of the instance's own threads (from a `Platform` callback, for
  example). It means a misuse.

Running on the host's own runtime is planned (stage E2), with the same API.

## Logging

- **Without a subscriber of your own.** sail logs as its configuration's
  `log` says, to standard output, a file or the system log.
- **With your own subscriber.** A host that installs a `tracing` subscriber
  of its own adds `sail::embed::tracing_layer()` to it. Each instance's
  lines then reach its `Instance::logs()`, filtered at that instance's
  `log.level`. The host's own layers see sail's lines (targets `sail::…`)
  as they see any crate's, and a configuration's `log.output` is then the
  host's business.
- **The host's global filters apply first.** Let `sail` targets through at
  the levels the instances log at.

## Certificates

An inbound's certificate and key files, replaced on disk, are served from
the next handshake on, with no reload, whether or not the configuration
file is watched. This needs sail built with its `auto-reload` feature (on
by default in sail-ffi). A Rust host that picks sail's features keeps it.


## Reload

`reload(Some(config))` changes a running instance in place. It builds
everything new before it replaces anything, so a reload that fails changes
nothing.

| | after a reload |
|---|---|
| inbound listeners | kept: no listener is closed or rebound. An inbound's users and certificates are replaced. An inbound added or removed in the configuration takes a restart, or `add_inbound`/`remove_inbound` |
| connections already open | kept, on the outbound they were routed through (tested for a direct outbound over a socks inbound, with only `dns.servers` changed) |
| outbounds | rebuilt from the new configuration. Endpoints (WireGuard) and the outbounds they are built on are kept. Tasks the replaced outbounds ran (health checks, idle-session cleanup) stop. The replaced outbounds' sessions (AnyTLS, sing-mux) carry the connections they hold, and close when those connections end |
| group selections, pins | kept, for groups of the same tag |
| delays measured | kept |
| DNS client | rebuilt from the new `dns`. **Its cache starts empty** |
| routing, rule-sets | rebuilt; rule-sets the configuration still names, and already downloaded, are not downloaded again |
| traffic counters | kept. Counters of inbounds and outbounds that are gone are dropped once nothing counts to them |

So a reload that changes only `dns.servers` swaps the servers and does not
interrupt established connections. New queries go to the new servers, with
an empty cache. That holds for connections carried over multiplexed
sessions too: an AnyTLS outbound's, and a sing-mux (smux) one's, are
tested. The rebuilt outbound opens new sessions for new connections, and
the old sessions carry theirs until they close.

The tests that hold this: `sail/tests/it/test_reload.rs`
(`a_reload_of_the_dns_servers_keeps_connections_and_asks_the_new_ones`):
a connection made before the reload goes on, a name looked up after it is
asked of the new server, and the old server is asked nothing more. Also
`sail/tests/it/test_embed.rs`, through `Instance::reload`, and
`sail/tests/it/test_reload_sessions.rs`, over AnyTLS and sing-mux sessions,
which close once their connections end. A TUN staying
up across such a reload needs root and is not among sail's tests.

## A snapshot, then what follows

To read a state and then follow it without a gap, **subscribe first, then
read**:

```rust
let mut states = instance.states();     // 1. subscribe
let now = instance.state();             // 2. read the snapshot
loop { states.changed().await?; /* 3. each change after it */ }
```

A subscription made before a change sees that change. `states()` and
`logs()` outlive an instance's runs, so a subscription made before
`start()` sees the start. A reload leaves the state `Running`. What a
reload changes (groups, providers, rule-sets) comes as events, with the
same rule: subscribe first, then read `outbounds()` and the rest.

## Errors

`Error` has a kind and a message. The kinds are:

| `ErrorKind` | `code()` | when |
|---|---|---|
| `Config` | `config` | the configuration or settings do not read or build |
| `InvalidArgument` | `invalid_argument` | a group that is no selector, a member it refuses, a bad URL |
| `NotRunning` | `not_running` | the instance does not run |
| `State` | `state` | starting or running already, stopping |
| `NotFound` | `not_found` | no outbound, group, member, provider, rule-set, inbound or user so named |
| `Unsupported` | `unsupported` | not in this build or on this platform |
| `Timeout` | `timeout` | the call's time ran out |
| `Cancelled` | `cancelled` | the start was stopped |
| `WrongThread` | `wrong_thread` | blocking wrappers only: a misuse |
| `Failed` | `failed` | a dial, a delay test or an update failed |
| `Io` | `io` | a system call failed |
| `Panicked` | `panicked` | sail panicked. The instance has failed and may be started again |
| `Internal` | `internal` | a bug: the message says what |

## Panics

A host built with `panic = "unwind"` keeps running when sail panics:

- **On the instance's thread.** A panic there ends the run, and the
  instance becomes `State::Failed` with `ErrorKind::Panicked`. Its runtime
  goes with the thread, and `start()` begins clean again.
- **Inside a BoringSSL callback.** A panic in a certificate check, an ALPN
  choice or the REALITY or ShadowTLS hooks fails that handshake and nothing
  else. Unwinding through C would abort the process even under unwind, so
  sail catches it there.
- **In one of the instance's tasks.** Tokio catches the panic and the
  instance goes on without that task. Stage E2 turns this into a failed
  instance too.
