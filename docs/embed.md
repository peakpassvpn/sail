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

## Which sail

`sail::embed::BUILD` says which sail a host runs, for its diagnostics:
`version` (the release) and `commit` (the short hash it was built from).
The commit is the release build's (`CFG_COMMIT_HASH`, or a `SAIL_COMMIT`
override). Without that, it is git's HEAD when sail is built in a checkout
of its own, which includes the checkout Cargo makes of a git dependency, or
that checkout's revision. It is `unknown` when none of these tells, never
empty. The CLI's `--version` and the C ABI's `sail_capabilities` give the
same.

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
  does not wait: the instance's own thread stops it in the background,
  in the order of a `stop()` (below), within `stop_within` and the
  teardown steps' bounds (5 s each). A host that drops it and exits at
  once can leave routes, rules or a TUN behind. Await `stop()` first.
- **Errors.** `ErrorKind::WrongThread` never comes from these async calls.
  Only the blocking wrappers the C ABI uses give it, when they are called on
  one of the instance's own threads (from a `Platform` callback, for
  example). It means a misuse.

Running on the host's own runtime is planned (stage E2), with the same API.

## Memory

sail leaves the allocator to whoever links it, and never calls one. A
start, a reload, and a provider's or rule-set's update parse a document and
drop it; an allocator that gives freed memory back to the system only as
later allocations run keeps that peak while the instance idles.
`sail::runtime::memory::on_memory_freed` registers what gives it back.
sail runs it after a start, after each reload, and after a provider's or a
rule-set's update, whether the document was taken or refused: on the task
that loaded it, never on a connection's path. It is process-wide, and the
first registration stays: two instances run the same one, each after its
own loads. The `sail` command registers mimalloc's collect. A host
registers what its own allocator needs, or nothing: glibc's malloc keeps
freed memory too, which `malloc_trim(0)` gives back; an allocator that
returns memory by itself needs nothing.

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

**What did not change is left alone.** A configuration that differs from
what runs in its `inbounds` (and `user_limits`) alone changes the
inbounds and builds nothing else again: the outbounds are those that
ran, with the multiplexed and QUIC sessions they hold; the groups keep
their member, their checks and what they measured; the DNS client keeps
its cache; the routing and the rule-sets are untouched.
`ReloadReport::path` says which it was: `InboundsOnly`, or `Full`, where
the rest of this section applies.

- "The same" is told of the configuration as it is read, not of its
  text: spacing, the order of keys and defaults written out do not count.
- A file the configuration names is not seen by that comparison. Those
  sail follows itself are taken when they change, with no reload: an
  inbound's certificate and key, a local rule-set. Those it reads once,
  when what names them is built, are looked at by size and time of
  modification at each reload, and one written since makes the reload a
  full one: root certificates (`certificate_path`,
  `certificate_directory_path`), an outbound's certificate and key files,
  a provider's or a rule-set's file other than a followed local one, the
  geo databases. A directory is seen to change when an entry is added or
  removed, not when a file in it is rewritten.
- An outbound added or removed while it ran (`add_outbound`,
  `remove_outbound`) is not in the configuration: the reload after is a
  full one, and goes by the configuration.
- A reload with the very configuration that runs is one of the inbounds
  alone that finds them untouched: it no longer empties the DNS cache or
  starts the groups' checks over. To have everything built again, change
  something else, or stop and start.

`ReloadReport::notes` tells what a reload took and did not reach
everything with. Today there is one: an endpoint (WireGuard) is only set
up at a start, so a reload that changes the defaults every dial goes by
(`route.default_interface`, `auto_detect_interface`, `default_mark`,
`default_domain_resolver`, the `default_network_*` options,
`dns.strategy`) while an endpoint runs is taken, applies to everything
else, and gives `ReloadNote::EndpointKeepsDefaults` for each endpoint
with the options that changed: the endpoint, and the outbounds it is
built on, go on with those they were built with until the next start.
The log has the same as a warning.

A full reload:

| | after a full reload |
|---|---|
| inbounds | those the configuration has are those that run. Compared by tag with those running: one that is the same is not touched; one whose users, certificate or key alone changed gets them, its listener kept; a new one is built and listens; one the configuration no longer has is removed; one changed otherwise (its port, its type, its transport) is replaced. A TUN is set up only at a start: see below |
| connections already open | kept, on the outbound they were routed through, except those of an inbound removed or replaced, which are closed (tested: `sail/tests/it/test_reload_inbounds.rs`, where connections on an untouched inbound carry on through a reload byte for byte) |
| outbounds | rebuilt from the new configuration. Endpoints (WireGuard) and the outbounds they are built on are kept. Tasks the replaced outbounds ran (health checks, idle-session cleanup) stop. The replaced outbounds' sessions (AnyTLS, sing-mux) carry the connections they hold, and close when those connections end |
| group selections, pins | kept, for groups of the same tag |
| delays measured | kept |
| DNS client | rebuilt from the new `dns`. **Its cache starts empty** |
| routing, rule-sets | rebuilt; rule-sets the configuration still names, and already downloaded, are not downloaded again |
| traffic counters | kept. Counters of inbounds and outbounds that are gone are dropped once nothing counts to them |

**The inbounds.** `reload` returns a `ReloadReport`: each inbound of the
configuration, in its order, then those it no longer has, with what
became of it.

| `InboundChange` | the inbound | its connections |
|---|---|---|
| `Untouched` | as it was | go on |
| `Reloaded` | new users, certificate or key; the listener kept | go on (a removed user's are closed) |
| `Added` | built, listening | — |
| `Removed` | stopped | closed |
| `Replaced` | the one before stopped, this one in its place | the one before's are closed |

- **The configuration is what runs.** An inbound added with
  `add_inbound` and not in the configuration reloaded is removed by the
  reload. A host that adds one keeps it in the configuration it reloads
  with, and finds it `Untouched`.
- **Nothing is half applied.** What is new is built and bound before
  anything running is touched, and a reload that cannot bind what it adds
  fails with all as it was. An inbound replaced on the address it has
  must stop before the new one binds: if that bind fails, the one before
  listens again, its connections never touched, and the reload fails.
- **Two errors of their own.**
  - `ErrorKind::NeedsRestart`: the configuration adds, removes or changes
    an inbound that only a start sets up, a TUN. Nothing changed; stop
    and start to apply it.
  - `ErrorKind::InboundLost`: an inbound was to be replaced on its
    address, the new one did not bind, and the one before could not
    listen again (another program took the port meanwhile). The reload
    failed, all else is as it was, and that inbound, which the message
    names, listens no more: reload again, or add it.
- New and replaced inbounds accept once the new routing is in place.
- sing-box closes every connection on a reload: it builds the instance
  anew. sail closes those of the inbounds removed or replaced, and no
  others.

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

## The network

`instance.network()` is the network now: the default interface (name and
index; none when offline), its kind, gateway and addresses, and whether
it is metered, constrained or behind a captive portal, with a
`generation`. `instance.events(Kinds::NETWORK)` gives each change of it
that connections do not survive, as `Event::Network`:

| `change` | when |
|---|---|
| `InterfaceChanged` | another default interface: its name or index differs |
| `Moved` | the same interface on another network: its gateway, kind or addresses (IPv6 by /64) differ; or the host, or a wake, says the network changed |
| `Offline` | the default interface is gone |
| `Restored` | a default interface is back after none |

- **Roams.** A roam to another access point with the same addresses is no
  change, and no event.
- **Settled.** Every change is settled before it is told: sail's detection
  waits until the system has been quiet for 100 ms (1 s at most) before it
  looks. A state the host pushes (`set_network_state`) is taken as given.
- **Old and new.** Each event carries the old and the new state, the
  `reason` (default interface, detected, host, wake) and the generation.
  Generations count from 1 in each run.
- **Settled at start.** The network is settled first thing in a start,
  before anything of the instance is built, and `network()` answers from
  then, in `Starting`: the default interface, or explicitly offline, at
  generation 1, with no event for it. It is the machine's interface, never
  a TUN of sail's own, which is not opened yet. Detection gets 1 s; past
  that the snapshot says offline and the interface found later comes as
  `Restored`. Before that point, as in any state but `Starting`,
  `Running` and `Stopping`, `network()` is `NotRunning`. On Android and iOS the host pushes the state, and the
  generation is 0 until its first push.
- **Pairing with the snapshot.** Subscribe first, then read `network()`,
  then skip the events whose generation is the snapshot's or lower. None is
  missed, and none is taken twice.
- **Falling behind.** A subscriber that falls more than 64 changes behind
  gets `Event::Lagged { kind: Kinds::NETWORK, missed }`; it should then
  read the snapshot again.
- **Restarts.** The subscription goes on through stops and starts. After a
  start, read the snapshot again.

`events(kinds)` takes several kinds at once: `Kinds::STATE` gives each
change of the instance's state as `Event::State`, `Kinds::NETWORK` the
network's. More kinds come; match with `_ => {}`.

`Kinds::ROUTE` gives every connection once, as `Event::Routed`: a TCP
connection, a UDP session or a stream of a multiplexed connection, when
the rules have decided of it and, where they sent it to an outbound, when
its dial has ended, well or not. It tells what a polled list of the
connections open cannot: a connection shorter than the poll, a dial that
failed, a reject, a drop, a hijacked DNS query. Its fields:

- `id`: as `connections()` lists it; none where it never opened.
- `network`, `inbound` (the tag), `source`, `destination`.
- `request_destination`: what the outbound was asked to reach, after the
  rules' overrides and the name `override_destination` has it dialled as.
- `domain` and `domain_source`: the destination's own name (`Request`),
  the name a fake IP stands for (`FakeIp`, TCP only), a sniffed TLS
  server name or HTTP Host (`Sniffed`), or the DNS answers sail gave for
  the address (`ReverseMapping`).
- `sniffed_protocol`.
- `rule`: the index of the rule that decided in the configuration's
  `route.rules`, from 0, each entry of the list counted once, a logical
  rule and one naming rule-sets too; none for `route.final` and for the
  host's own `dial`. `rule_text` is the rule as the log tells it.
- `action`: `Outbound`, `Reject`, `Drop` or `HijackDns`.
- `chain`: the outbounds it went through, outermost first: the outbound
  the rules named, then the member each group on the way took, down to
  the outbound that carried it, which is the last. For a rule that names
  the group `F`, which took the group `G`, which took the member `m`, it
  is `["F", "G", "m"]`: the order of `DialFailed`'s `chain` (`F>G>m`) and
  of the log's `out=`. For a dial that failed, the last is the member
  tried last. `connections()` and `watch_connections` list the same
  outbounds the other way round, as the Clash API does: their `chains`
  is `["m", "G", "F"]`.
- `target`: the address its TCP connection out was made to, the
  destination's for a direct outbound and the server's for a proxy.
- `connect`: how long the dial and the outbound's handshake took, or the
  kind of error they failed with.

These addresses and the domain are whole: `log.redact` governs sail's
log, not what it tells its host, which redacts what it passes on as it
sees fit. (`DialFailed`'s destination is redacted, as the log's is.)

The events are built only while a subscription to `Kinds::ROUTE` is
held; without one a connection costs one load of a counter. A subscriber
may fall 1024 events behind; further behind it gets
`Event::Lagged { kind: Kinds::ROUTE, missed }` and goes on from the oldest
kept. The struct and its enums are `#[non_exhaustive]`: fields and
variants are added.

`Kinds::DNS` gives every DNS query answered or failed, as
`Event::DnsExchange`: those of the clients of sail's DNS (a TUN's, a DNS
inbound's, a hijacked query) and those the instance makes itself, to
dial a domain or reach a server by name. Its fields:

- `name` (without the final dot), `qtype` (`A`, `AAAA`, ...) and
  `qtype_code`.
- `server`: the tag of the server that answered or failed; for a race or
  a sequential server, the member that answered. None where a rule did.
- `source`: `Exchanged` (a server was asked), `Cached`, `Optimistic` (an
  expired answer given under `dns.optimistic` while the server is asked
  again, which is told too) or `Rule` (a `reject` or `predefined` rule).
- `outcome`: `Answered { rcode, rcode_code }` (`NOERROR`, `NXDOMAIN`,
  `REFUSED`, ..., and the code's number)
  or `Failed { error }`.
- `answers`: the data of the answer's first 16 records (an address, a
  name); `answers_total` counts them all; `ttl` the least of their TTLs.
- `duration`: how long the server took; none from the cache or a rule.
- `attempt`: a sequential server's attempt, from 1. Each member that
  fails is told with its own attempt and time, then the one that
  answered; a race tells only the member that won.
- `for_instance`: the instance asked for itself, not for a client.

The names asked and the records are whole, as the addresses of
`Kinds::ROUTE` are: `log.redact` governs sail's log, not what it tells
its host, which redacts what it passes on itself.
Built only while a subscription to `Kinds::DNS` is held; a subscriber may
fall 1024 events behind, then gets
`Event::Lagged { kind: Kinds::DNS, missed }`.

A host that shows the instance polls snapshots instead of following
events: `instance.status(every)` (the traffic and its rate),
`instance.watch_connections(every)` and `instance.watch_outbounds(every,
groups_only)`, the last at once on a group's change and else only when
something differs. They are quiet while the instance does not run, and
need a tokio runtime. The C ABI's subscriptions are these.

`instance.tun_names()` gives each TUN inbound's device name, by tag. It
is the name configured, or the one sail chose at start (`chosen`; on
macOS one past the highest `utunN`) when none was. A host that opens the
device itself (Android, iOS) has no entry. A chosen name that another
program takes before the device opens fails the start ("chosen at start
as free, was taken before it opened"); starting again chooses another.

## Dialling

`dial_tcp` and `dial_udp` go through the outbound named, whatever the
rules say.

**While the instance starts.** A host whose own service the instance
asks during its start, a DNS server in the host's process that the
configuration names, say, can serve it: the start goes in this order,
and the calls work from the point named.

1. The network is settled: `network()` answers.
2. The outbounds are built: `dial_tcp` and `dial_udp` work, in
   `Starting`, through every outbound and group.
3. The instance asks for the names its start needs: remote rule-sets,
   outbound providers, and the groups' first checks.
4. The TUN is opened and routed, the inbounds listen, and it is `Running`.

- A dial made in `Starting` before step 2 waits for it, within its own
  timeout, and then dials; it is not refused. The groups' first checks
  begin as the outbounds are built, a few milliseconds before step 2 is
  told: a lookup they cause may wait that long. If the start fails or is
  stopped meanwhile, the dial is `NotRunning`. The wait needs no runtime
  of the host's.
- One kind is not served that early: an endpoint (WireGuard), whose
  tunnel is driven only once the instance is `Running`. A dial through
  it made earlier waits for the endpoint, 10 s at most or the dial's own
  timeout if that is shorter, and fails if the instance does not run by
  then.
- A direct dial made before the TUN is up stays out of it afterwards:
  the socket is bound, marked or protected when it is dialled, as the
  configuration says, and that is settled before the outbounds are built.
- In `Idle`, `Stopped` and `Failed`, and once a run has ended, a dial is
  `NotRunning`. The C ABI's `dial` works once the instance is `Running`.

Through the direct outbound, two things hold:

- **The zone reaches the kernel unchanged.** A link-local IPv6 address
  given with its scope (`SocketAddrV6::new(ip, port, 0, ifindex)`, the
  index from `if_nametoindex`) keeps it all the way to the socket.
  `sail/tests/it/test_embed.rs` sends to a link-local address of the
  machine: lo0's on macOS, the Ethernet's on Linux. sail does not parse
  "fe80::1%en0": a host turns the name into its index.
- **The socket is the direct outbound's.** It is bound and marked as that
  outbound's dialer says (`bind_interface`, `auto_detect_interface`'s
  default interface, `routing_mark`, `network_strategy`), as a direct
  connection the rules route is.

So a zone that names an interface other than the one the socket is bound
to fails to send. To reach a link-local server on another interface, dial
through a direct outbound whose `bind_interface` is that interface.

A UDP socket's family is the first destination's. An IPv6 one also sends
to IPv4 addresses, and an IPv4 one cannot reach IPv6. On a network with
NAT64 and no IPv4, IPv4 destinations go through its prefix.

## Leftovers after a kill

An instance that changes the system (a TUN, its routes and rules) writes
down each change under its run directory, and undoes it when it stops.
Every start first sweeps what a killed instance left there.

- **Where.** `Options::run_dir(RunDir)` chooses the directory: `Default`
  (`/run/sail` on Linux; none elsewhere yet), `Dir(path)`, or `Off`.
- **Without an instance.** `sail::embed::sweep(&run_dir)` sweeps with no
  instance, as a desktop service does at its start, and returns one line
  per thing undone.
- **What is left alone.** An instance that changes nothing never creates
  the directory. An entry whose TUN is still up in this network namespace
  belongs to a live instance and is left.

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
| `TunNameTaken` | `tun_name_taken` | a TUN's device name is in use. A configured one: change it. One sail chose: each free name it tried was taken before it opened, and starting again may well succeed |
| `NeedsRestart` | `needs_restart` | a reload whose configuration adds, removes or changes an inbound that only a start sets up (a TUN). Nothing changed: stop and start to apply it |
| `InboundLost` | `inbound_lost` | a reload that was to replace an inbound on the address it had: the new one did not bind, and the one before could not listen again. The reload failed, all else is as it was, and the inbound the message names listens no more: reload again, or `add_inbound` it |

## Panics

Build a host with `panic = "unwind"` (Cargo's default). Under it no panic
in sail takes the host down. Assert it at start:
`assert!(sail::embed::PANICS_ARE_CAUGHT)`. Under `panic = "abort"` any
panic ends the process, as in sail-cli's release build.

**The released libraries are built with `panic = "abort"`:** the
XCFramework, the AAR and the C libraries a release ships, as sail-cli and
the router packages. In them a panic anywhere in sail, in one connection's
task as well, ends the host process (on iOS the network extension, which
the system restarts only with on-demand rules; on Android the process the
`VpnService` runs in), and nothing below holds: no task is caught, no
teardown runs (the next start's sweep clears what the process left on
Linux and macOS; Windows's filters go with the process). Everything this
section says holds in a build with `panic = "unwind"`: a host that builds
sail itself, or a debug build. `PANICS_ARE_CAUGHT` says which a host has.

Every task sail runs for an instance is in the instance's scope, of one of
two classes:

- **Contained:** work bound to one connection, stream, session, request
  or probe. A panic there ends that task alone. It is logged, counted
  (`faults()`, and `Status::faults`), and told as `Event::Fault` under
  `Kinds::FAULT`, with the task's name, class, message and the running
  count. The instance goes on; a host may rebuild it if they repeat.
- **Essential:** what the instance cannot do its job without (listeners,
  its DNS and outbound state, the TUN and netstack drivers, the network
  monitor, group checks, updaters). A panic there fails the instance:
  `State::Failed` with `ErrorKind::Panicked` and the task's name. A lock an
  earlier panic poisoned fails it the same way, rather than cascading.

The instance's start thread and the BoringSSL callbacks are caught as
before. A failed instance is dropped and a new one made; nothing of it is
left.

## Stopping

`stop()` aborts the instance's tasks and waits for them to end, for 2 s
unless `Options::stop_within` says otherwise.

- **Guaranteed:** async tasks end at their next poll after the abort.
- **Reported only:** a blocking call (a DNS lookup on the blocking pool,
  file I/O) or a host callback cannot be interrupted. One that outlasts
  the bound is named in `stop()`'s `Timeout` error and in `stop_report()`
  (the tasks still running by name and count, and how long the stop
  waited).

**What the instance changed in the system** (a TUN's routes, policy rules,
nftables, DNS, Windows filters) is undone however the run ends: a
`stop()`, a failure (an essential task's panic, a root task's), or a start
that fails after the TUN came up. Every end goes the same way: what it
changed in the system first, then the device, then the instance's tasks
within the bound, then the runtime, shut down within the bound too, so
that a blocking thread stuck past it does not hold the end up. A step that fails, panics or outlasts its bound is
named, and the others still run:

- `stop_report().left`: each `Left { kind, resource, why, clear }`, with
  `clear` the one command that clears it by hand where there is one.
- `stop()`'s error (`ErrorKind::Failed` when only resources are left), the
  `Failed` state's error, and a failed start's error say the same in their
  message, after "left in the system:".

`stop()` on an instance that is not running (failed, stopped, or never
started) is safe to call any number of times and returns at once: it
asks for nothing and undoes nothing a second time, and tells again what
the last run left, if anything.

