# Sweeping what a killed instance left

Status: design, for review. The sweep logic belongs to the TUN owner. Its
entry point is the embedding API's instance creation (stage E3).

## The problem

A sail instance that runs a TUN changes the system: devices, ip rules,
routes, firewall tables. A clean stop undoes all of this. A `SIGKILL`, a
crash or a power loss undoes nothing, and whatever the kernel does not
remove by itself stays behind. Two things go wrong:

- The next instance starts on top of the leftovers. Today it removes only
  what its own configuration names: the same rule priorities, the same
  table, the same adapter name.
- A host that switches engines, or starts sail without a TUN, inherits the
  leftovers. Stale ip rules point at a table nothing fills, and on Windows a
  stale adapter keeps its routes.

The requirement: **creating an instance
idempotently sweeps what an earlier sail instance on this host left.** The
sweep covers only what sail itself creates and can reliably tell apart from
anyone else's. System DNS overrides (scutil on macOS) belong to the desktop
service, not to sail.

## What the kernel already removes

Verified in the code (sail/src/protocol/tun, sail/src/platform) unless
marked *to verify*:

| System | Made by sail | Gone when the process dies? |
|---|---|---|
| Linux | TUN device (no `IFF_PERSIST`) | yes: the device goes when its last fd closes, and every route through it with it |
| Linux | systemd-resolved settings on the TUN link | yes: they belong to the link, which is gone |
| Linux | auto_route ip rules (priorities `rule_index..=rule_index+10`, both families): lookup, goto, nop and `unreachable` rules, as sing-tun's | **no**, and the `unreachable` ones can black-hole traffic until removed |
| Linux | routes in table `table_index` through the TUN | yes, with the device |
| Linux | auto_redirect's `throw` routes in that table (route_exclude_address) | **no**: they name no device |
| Linux | auto_redirect ip rules, incl. the fallback rule at `fallback_rule_index` | **no** |
| Linux | auto_redirect nftables table `inet sail_<tun>` | **no** |
| OpenWrt | fw4 drop-in `/etc/nftables.d/0-sail-auto-redirect-<tun>.nft` | **no** (a file) |
| macOS | utun device and the routes through it | yes: utun goes with its control socket *(measured: the tun-macos CI job)* |
| Windows | Wintun adapter (named, GUID from the name) | yes: Wintun removes it when the process that created it dies *(measured, see below)* |
| Windows | routes and DNS on that adapter | yes: they go with the adapter *(measured)* |
| Windows | strict_route WFP filters and sublayer | yes: they are in a dynamic WFP session (`FWPM_SESSION_FLAG_DYNAMIC`) *(measured)* |

So the sweep has three jobs:
- on Linux: ip rules, routes, the nftables table and the fw4 drop-in;
- on Windows: nothing for the TUN (measured, its WFP filters too);
- on macOS: nothing (measured: after a kill -9 the routing table of both
  families equals the one before the start, on every tun-macos CI run).

### A kill, and a reboot

A reboot clears more than a kill. The ledger has to last exactly as long
as the leftovers it lists:

| System | Left by a kill | Left by a reboot | Ledger kept in |
|---|---|---|---|
| Linux | ip rules, `inet sail_<tun>`, fw4 drop-in | the fw4 drop-in only (a file; rules and nftables are kernel state) | tmpfs `/run/sail` |
| macOS | nothing (measured) | nothing | none needed |
| Windows | nothing of the TUN (measured) | nothing (measured) | none needed for the TUN |

So on Linux a ledger clears on reboot just as the kernel state it
describes does. On macOS and Windows nothing of the TUN outlives the
process, so they need no ledger.

Measured on Windows (2026-10-04, Windows 11, sail 0.16.0 windows-gnu,
Wintun 0.14.1, a TUN with IPv4 and IPv6 addresses and auto_route):
after `Stop-Process -Force`, and after the session that started sail
ended and took it with it, the adapter, its 0.0.0.0/0 and ::/0 routes
(metric 0) and its DNS servers were gone within 3 s, and the default
route was the Ethernet adapter's again; after a reboot with sail running
there was no adapter, no device of it, no route and no DNS. A start after
a kill created the adapter again with the same GUID.

With strict_route and route_exclude_address as well (the same day and
build, excluding 10.0.0.0/8 and 192.168.0.0/16): while it ran, its six
WFP filters and its sublayer were listed (`netsh wfp show filters`,
`netsh wfp show state`), and the excluded ranges left by the Ethernet
adapter. After `Stop-Process -Force` the filters, the sublayer, the
adapter, its routes and its DNS were gone at the first look, within
about 0.5 s, and still at 1, 3 and 10 s; DNS and TCP left by the
Ethernet adapter again. A second start and kill did the same. Not
covered: other Windows or Wintun versions, and sail embedded in a host's
process, whose dynamic WFP session lasts as long as that process unless
sail is stopped.

## How leftovers are identified: a ledger

A rule priority or table number from the *current* configuration is not
enough. The earlier instance may have used other `iproute2_*` indexes,
another interface name or another table, and a sweep that guesses could
delete someone else's rules: priorities 9000–9010 are sing-box's defaults
too.

So each instance writes down what it is about to create **before** it
creates it, in a ledger file:

- one file per instance, in a directory only root writes. By default it
  is `/run/sail/` on Linux and OpenWrt, and there is none elsewhere:
  macOS and Windows have nothing to sweep. The directory is made with the
  first entry, so an instance that changes nothing (an unprivileged one,
  say) needs none;
- a host can choose the directory (`run_dir`: a path, or `false` for
  none), so a mobile or sandboxed host can give its own or none;
- it records each change exactly as it is made: every ip rule with all
  its attributes, the routes that name no device (auto_redirect's
  `throw` routes), the nftables table, and the fw4 drop-in;
- it is written before each piece is added (write-ahead), so a kill between
  the two still leaves an entry;
- it also records sail's pid, the process start time and an instance id,
  so that a running instance's entries are never swept. The id is unique
  for the process's lifetime, from a process-wide counter taken when the
  instance's run begins. Several instances can share one process when sail
  is embedded, and a host may drop an instance that panicked and create
  another in the same process: the pid alone cannot tell them apart;
- a clean stop removes its ledger after undoing everything.

sail keeps a process-wide set of the instance ids that are running. An id
goes in when its run writes its first entry, and comes out when the run
returns or unwinds (a drop guard, so a panic out of the run removes it
too). An entry is stale when its process is gone (the pid is dead, or now
belongs to a process with another start time), or when it is this
process's and its instance id is not in the set. A panic inside one of an
instance's tasks leaves the run, and its id, alive, which is right: the
instance still holds its TUN.

At instance creation, the sweep reads every stale entry.
For each one, it removes exactly what the ledger lists: a rule is deleted
by all its attributes, so only that rule matches, never another's at the
same priority. Each removal tolerates "already gone". What cannot be
removed stays in the ledger for the next sweep; the ledger goes once it is
empty. Running the sweep twice does nothing the second time.

There is no fallback for leftovers without a ledger: sail has none
deployed from before the ledger, and guessing by priority would delete
other software's rules.

## On each system

- **Linux**: netlink, which sail already speaks (platform/rtnetlink), plus
  the existing nft batch `del_table_if_exists`. Rules and device-less
  routes are deleted as recorded; the routes through the TUN go with it.
  sail adds nothing to the main table and no bypass route through the
  physical interface. The TUN device itself
  needs no sweep, because it is not persistent. If a device by the
  ledger's name still exists with no live owner, it is not sail's to judge
  and is left alone.
- **macOS**: every route the route code (2.14) adds goes through the utun,
  with the utun's own address as gateway. When the utun is detached, the
  kernel purges the routes on that interface (if_detach, rt_if_remove).
  The tun-macos CI job confirms it on every run: nothing to sweep.
- **Windows**: nothing to sweep for the TUN. An adapter
  `WintunCreateAdapter` made is removed when the handle to it closes,
  which the kernel does when the process dies, and its routes and DNS go
  with it (measured above); WFP's dynamic session goes with the process
  too.
- **Android/iOS**: the host's VPN service owns the device and routes, so
  sail has no sweep there and writes no ledger.

## Two instances on one host

Two sail instances can run side by side: a desktop service's two, or a
CLI beside an embedded one, each with its own run directory. Neither may
lose anything to the other's sweep:

- **Names.** What auto_redirect makes is named after the TUN: the
  nftables table `inet sail_<tun>` and the fw4 drop-in
  `0-sail-auto-redirect-<tun>.nft`. sing-tun uses one fixed table name;
  sail does not, so that two instances with different TUNs never share a
  table. Rule priorities and the routing table come from the
  configuration, as in sing-box: two instances need their own
  `iproute2_rule_index` (and `auto_redirect_iproute2_fallback_rule_index`,
  `iproute2_table_index`). A start that finds rules at its priorities that
  no ledger accounted for removes them, as sing-tun does, and warns naming
  those fields.
- **Ownership.** A ledger records the TUN its changes belong to. On Linux
  and macOS the TUN dies with its process, so while a device of that name
  is up, a live instance holds the name and, through its own setup, what
  is named after it. The sweep then leaves that ledger alone and tries
  again at a later start. The kernel allows one device per name, so this
  is a reliable sign, unlike guessing about other processes or run
  directories.
- **Windows** removes a Wintun adapter with its process, so an adapter
  of the name means a live instance holds it, as a device of the name
  does on Linux.

## Where it runs

At every start, in sail's `run()` (lib.rs) before the instance is built,
so the CLI, the FFI and the embedding API all get it from one call. An
embedder's `new()` touches nothing in the system; `start()` reaches
`run()`. The ledger directory is `run_dir` in `runtime::Host`, next to
`data_dir` and `cache_dir`. It can be set from the FFI's start settings,
the CLI and the embedding options, takes the per-OS default when unset,
and can be turned off.

The embedding API also offers it on its own: `sweep(ledger_dir)`, without
creating an instance. A desktop service can then sweep when it starts,
before it decides which engine to run. Both forms take the ledger
directory from the host, with the per-OS defaults above. It is synchronous, bounded by
the ledgers' contents, and logs one line per removed item at info.
Failures are warnings: an instance does not refuse to start because a
stale rule could not be deleted. The TUN's own setup still replaces what it
needs.

## Tests that prove it

1. **Linux netns, kill -9:** in a namespace of its own (as
   tests/scripts/auto_route_netns.sh does), start sail with auto_route and
   `kill -9` it. Check:
   - the rules, the nftables table and the ledger are left;
   - starting an instance **without a TUN** removes all three;
   - starting it again changes nothing.

   Then run the same with auto_redirect, and with custom `iproute2_*`
   indexes. A neighbour rule at priority 9005 with another shape survives
   every sweep.
2. **Linux, two instances:** a live instance's ledger is not swept by a
   second instance's creation, in another process or in the same one.
3. **Same process, after a panic:** create an instance with a TUN in
   process, drop it without a stop (as a host does after a panic), create
   another in the same process: it starts clean.
4. **Unit:** a dead process's ledger swept once; a running instance's
   left, and swept once its run ends; a live process's left and a reused
   pid's swept; what is undone forgotten; rules and routes reading back
   as written; `run_dir` settings.
5. **Windows VM (done, 2026-10-04):** kill -9 an instance with a TUN, then
   create one; reboot with one running: nothing of the TUN is left either
   way (measured above). Still to run: the same with strict_route and
   route_exclude_address, checking `netsh wfp show filters` and the
   routing table after the kill.
6. **macOS (CI, tun-macos):** after a kill -9 the utun and every route
   through it are gone, and the routing table of both families equals the
   one before the start.

## An instance that fails while its process lives on

The sweep is for a process that died. An embedding host's process (a privileged service, an app) outlives its instances: one that fails, from an essential task's panic or a start that fails partway, must leave nothing behind while the process goes on, or say exactly what it left.

Each resource registers a step that undoes it (`runtime/teardown.rs`) as soon as it exists, and the steps run newest first, so a TUN's routes, rules and filters go before the TUN itself. On a normal stop the order is the same.

| system | steps (newest first) |
|---|---|
| Linux, auto_route | systemd-resolved's DNS for the link (`resolvectl revert`); the ip rules at its priorities; its routes |
| Linux, auto_redirect | fw4's drop-in; the nftables table `sail_<tun>`; the ip rules and the routes of its table |
| macOS | its routes through the utun, then the DNS cache is flushed |
| Windows | WFP, the adapter's DNS, the routes, the Wintun adapter |

Each step runs at most once, on a thread of its own, within 5 s (a judgment value; the calls take milliseconds). A command it runs (resolvectl, `fw4 reload`) is killed at the bound, and the netlink and nftables sockets have a receive timeout. A step that fails, panics or times out leaves its resource, and the others still run.

What is left is reported (`Left`): a kind for a program to act on, the resource, why, and the one command that clears it by hand where there is one, e.g. `nft delete table inet sail_tun0`. On Linux the ledger keeps what a failed step left, so the next start, in this process or another, sweeps it.

Nothing on this path may panic, as it also runs while a panic unwinds, where a second panic would abort the host:

- The Teardown itself takes poisoned locks as they are, indexes nothing, and catches a step's panic on the step's thread.
- The Drops of AutoRoute and AutoRedirect only run their own steps.
- StrictRoute's Drop closes a handle, and the Wintun packet I/O's Drop shuts its session; neither can panic.

`tests/test_teardown.rs` runs sail in the test's own process. A fault it arms (feature `fault-injection`, which no shipped build has: CI fails a release workflow or cross script that names it) fails the instance: an essential task's panic, the TUN runner's, a start that fails once the TUN is routed, or one step's panic. The test then checks that the routing tables, rules, nftables tables and links are as before, and that the instance starts again. It runs on Linux in the netns suite and on macOS in CI's tun-macos job.

## Open questions

- Windows: answered. A Wintun adapter, with its routes and DNS, survives
  neither a kill nor a reboot. The strict_route WFP filters after a kill
  are still to be observed.
- macOS: answered by the tun-macos CI job (test 6).
- The ledger directory for the FFI embedder: a parameter of create, with
  the per-OS default above?
