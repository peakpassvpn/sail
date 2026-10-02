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
| Linux | auto_redirect nftables table `inet sail` | **no** |
| OpenWrt | fw4 drop-in `/etc/nftables.d/0-sail-auto-redirect.nft` | **no** (a file) |
| macOS | utun device and the routes through it | yes: utun goes with its control socket *(to verify with kill -9 on a Mac)* |
| Windows | Wintun adapter (named, GUID from the name) | **no** *(to verify)*: sail reopens it by name today |
| Windows | routes and DNS on that adapter | **no**, while the adapter stays *(to verify)* |
| Windows | strict_route WFP filters | yes: they are in a dynamic WFP session (`FWPM_SESSION_FLAG_DYNAMIC`) |

So the sweep has three jobs:
- on Linux: ip rules, routes, the nftables table and the fw4 drop-in;
- on Windows: the adapter, or at least its routes and DNS;
- on macOS: possibly nothing (to verify).

### A kill, and a reboot

A reboot clears more than a kill. The ledger has to last exactly as long
as the leftovers it lists:

| System | Left by a kill | Left by a reboot | Ledger kept in |
|---|---|---|---|
| Linux | ip rules, `inet sail`, fw4 drop-in | the fw4 drop-in only (a file; rules and nftables are kernel state) | tmpfs `/run/sail` for kernel state; the drop-in is also found by its fixed path, ledger or not |
| macOS | nothing expected (to verify) | nothing | tmpfs `/var/run/sail` |
| Windows | adapter, its routes and DNS (to verify) | the adapter, possibly with its persistent routes and DNS (to verify) | persistent `%ProgramData%\sail\run` |

So on Linux and macOS a ledger clears on reboot just as the kernel state
it describes does. On Windows the ledger persists, and lists what outlives
a reboot.

## How leftovers are identified: a ledger

A rule priority or table number from the *current* configuration is not
enough. The earlier instance may have used other `iproute2_*` indexes,
another interface name or another table, and a sweep that guesses could
delete someone else's rules: priorities 9000–9010 are sing-box's defaults
too.

So each instance writes down what it is about to create **before** it
creates it, in a ledger file:

- one file per instance, in a directory only root writes. By default it
  is `/run/sail/` on Linux and OpenWrt, and there is none elsewhere yet:
  macOS has nothing to sweep, and the Windows TUN does not write a ledger
  until the adapter work above is settled (its directory will be
  persistent, under `%ProgramData%`). The directory is made with the
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
  So if the kill -9 test confirms it, there is nothing to sweep. If the test shows otherwise, the ledger lists the routes, and
  the sweep deletes them through the route socket.
- **Windows**: the adapter is found by the ledger's GUID (or the default
  GUID) and deleted: opened, then closed, which removes an adapter
  `WintunCreateAdapter` made. Its routes and DNS go with it. Creating it
  again is quick, because the driver stays installed. Whether an adapter
  survives a kill at all (Wintun may remove it on process death) is to be
  measured on the Windows VM. The sweep works either way: an adapter
  already gone is "already gone". WFP needs nothing.
- **Android/iOS**: the host's VPN service owns the device and routes, so
  sail has no sweep there and writes no ledger.

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
5. **Windows VM:** kill -9 an instance with a TUN, then
   create one: the adapter, its routes and its DNS end as the decision
   above says.
6. **macOS (to verify):** kill -9 an instance with a TUN; `netstat -rn`
   shows no route through a missing utun. If none is left, this test is
   what the "nothing to sweep" claim rests on.

## Open questions

- Windows: does a Wintun adapter, with its routes and DNS, survive a kill,
  and a reboot? To be measured on the VM. The sweep deletes the adapter in
  either case.
- macOS: the kill -9 check (`netstat -rn -f inet | grep utun`; `ifconfig |
  grep utun`, both empty) still has to be run.
- The ledger directory for the FFI embedder: a parameter of create, with
  the per-OS default above?
