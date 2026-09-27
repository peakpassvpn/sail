# sail-netstack N0 contracts and baseline

This file turns `rust-netstack-design.md` into merge gates. It is intentionally
separate from the design draft so implementation evidence can evolve without
silently changing the design baseline.

## Integration boundary (2026-09-26)

- `sail-netstack` is the only TUN engine. The lwIP and smoltcp adapters, their
  Cargo features and dependencies, the `tun2socks` inbound option, and the
  `.conf` `tun2socks-backend` key are removed without a rollback value.
- `sail/src/protocol/tun/inbound.rs` builds the stack from the `netstack`
  runtime options (`budget`, `batch_size`, `max_queues`, `offload`, and the
  command and UDP channel sizes), which every `--profile` presets and
  `--set netstack.<name>=<value>` overrides.
- Accepted TCP streams become a `Session` and enter `Dispatcher::dispatch_stream`.
- UDP datagrams enter `NatManager::send`; its return channel sends replies back
  through the stack adapter.
- FakeDNS rewriting and DNS interception live in the TUN adapter, outside
  `sail-netstack`.
- The instance keeps the stack's control handle. `sail::network_changed` and
  the FFI `sail_network_changed(rt_id, mtu)` start a new network generation
  (and apply a new MTU), and shutdown, Ctrl-C, and SIGTERM stop the stack
  while its runners still run.
- `bench/` is local-only on `dev`: `bench/netstack/run.py` and `compare.py`
  are not in the repository, and CI runs the crate's tests and Clippy only.

## Non-negotiable contracts

1. `sail-netstack` has no dependency on sail, proxy protocols, routing, NAT, or
   FakeDNS.
2. Every payload byte and flow state is charged before it becomes reachable.
   Failed acquisition cannot mutate protocol state or advertised TCP credit.
3. A lease cannot exceed its pool or the global byte ceiling, and dropping the
   lease returns exactly its charge.
4. `max_batch = 1` and one queue are supported configurations.
5. Partial packet sends retain the unsent suffix and its ownership tokens.
6. Network generation participates in flow identity; stale TCP and UDP handles
   fail closed after reset.
7. A runner failure is observable and terminates the stack; shutdown and abort
   eventually release every waiter and resource lease.
8. No `unsafe` enters the crate except in separately reviewed platform/buffer
   modules with Miri, fuzzing, or equivalent boundary tests. N0 forbids it for
   the entire crate.

## Milestones and merge evidence

| Milestone | Deliverable | Required evidence |
| --- | --- | --- |
| N0 | API types, hard budget ledger, benchmark schema, RFC matrix | unit/property-style tests; existing leaf baseline recorded |
| N1a | slab chain, packet arena, virtual-clock timer wheel | randomized conservation; split/merge/reclaim; clock jump tests |
| N1b | single-shard runner and UDP loop | mock PacketIo lifecycle, partial I/O, bounded queue and fairness tests |
| N1c | shard routing and byte DRR | model test for bounded admission and no starvation; 1/2/4/8 shard microbench |
| N2 | TCP handshake, stream I/O, RTO, close, dispatcher adapter | reference model plus Linux/macOS black-box interop |
| N3 | SACK/NewReno/scaling/timestamps/persist, IP errors and fragments | impairment matrix, parser fuzzing, PMTU and fragment budgets |
| N4 | platform batching/offload and hardening | mobile/router/desktop/server profiles, fault injection and soak |
| N5 | default engine, then old adapter removal | core-compare plus packet-path gates; rollback removed after one release window |

## Current implementation evidence

Provenance: the stack and its integration were developed on a tree based on
upstream-era commit `11c74ad`, then ported to `dev` after the P0.2
restructure and the rename to sail. Crate-level evidence (tests, fuzzing,
MIPS32 QEMU) applies unchanged: the crate moved without code changes. Evidence
that names the `leaf` library, its feature sets, or cross-target library
checks was gathered on the pre-port tree and has not been repeated on `dev`
unless a paragraph says so; `dev` replaced OpenSSL/AWS-LC with BoringSSL, so
those cross-target library checks need to be rerun.

- N0 API types now cover packet capabilities and ownership tokens, flow and
  network-generation identity, transparent forwarding decisions, resource
  profiles, statistics, and explicit partial-send retention.
- The lock-free resource ledger enforces both per-pool and global byte ceilings.
  RAII leases cover flow metadata, payload chunks, packet arena allocations,
  and flow counts; peak, denial, and pressure snapshots are observable.
  Each shipping profile now carves a separate `control_packet_bytes` pool out
  of its existing total/packet budget. Pure TCP control input, TCP-generated
  ACK/RST/close/timer output, ICMP output, and cross-shard forwarding of
  payload-free TCP and non-data IP packets use that pool; UDP, fragments, and
  payload packets cannot consume it. Cross-shard statistics expose the
  forwarded control-packet total independently. Runner construction requires
  enough control credit for one MTU-sized RX packet plus one headroom-bearing
  TX packet.
  Tests exhaust ordinary PacketBytes after establishing a flow and prove FIN,
  half-close, local ACK, and cross-shard ACK progress still complete, while
  exhausting the control pool proves TCP state does not advance without output
  credit. Scheduler validation also rejects a zero control-service quota, so
  an accepted configuration cannot silently strand this reserved work.
  `BudgetSnapshot` exposes resource-kind accessors so consumers do not depend
  on enum-to-array layout. The aggregate stack snapshot now includes current
  and monotonic shard-local peak TCP/UDP/SYN-RECEIVED/accept/TIME-WAIT state,
  buffered bytes, lifecycle totals, RX/TX batch counts and maxima, scheduler
  queue/work/time-budget
  counters (including processed control packets and active-flow visits for
  per-shard fairness sampling), and shutdown/abort/reset/MTU-change events in
  addition to protocol and resource counters. Aggregate peak fields are
  saturating sums of shard-local high-watermarks, deliberately forming a
  conservative capacity envelope rather than claiming a time-coincident
  process-wide maximum.
  Packet drops are additionally partitioned into mutually exclusive wire,
  resource, policy, rate-limit, output-capacity, and fallback classes; their
  saturating sum therefore matches the aggregate drop total. Fragment limiter
  drops now also appear in the per-step outcome instead of only the lifetime
  snapshot, so callers see the same event at both observation boundaries.
  RX and TX I/O futures count every executor resumption after their initial
  poll as a wakeup, independently from the existing cross-shard forwarding
  waker counters. A deterministic Pending-to-Ready PacketIo test covers both
  directions without relying on runtime timing.
  Every pressure-level change observed while running is counted, with separate
  entry totals for Constrained, Critical, and Exhausted. The opt-in trace ring
  records the exact old/new levels; a Normal-to-Exhausted-and-back model test
  proves both rising pressure and recovery transitions remain visible.
  The runner also has an opt-in diagnostic trace ring for lifecycle, RX/TX
  batches, partial sends, scheduler work, drops, network resets, MTU changes,
  and failures. It is disabled by default, has a hard per-shard ceiling of
  4,096 events, reports overwritten entries, and copies state out through a
  snapshot rather than exposing mutable protocol internals.
  All long-lived UDP, TCP, PMTU, fragment, runner, and shared cross-shard
  cumulative counters now saturate at their integer maximum instead of
  wrapping or panicking. A boundary test exercises both shard-local `u64` and
  MIPS-compatible shared `AtomicUsize` counters at their maximum values;
  bounded current-state gauges retain exact add/remove accounting.
  Pressure classification includes saturation of each individual byte pool,
  not only aggregate bytes. At Critical or Exhausted, the runner continues
  existing-flow traffic but rejects unknown TCP/UDP tuples before flow
  admission and exports a dedicated rejection counter. On the transition into
  either level it also drains the ordered SYN-RECEIVED index oldest-first,
  cancels each embryonic retransmission timer, and returns its flow, metadata,
  SYN-slot, and receive-credit leases without allocating a candidate list.
  Normal handshake completion, RST/abort, and reset remove the same index
  entry; table and runner tests prove creation-order reclamation, timer cleanup,
  aggregate counting, and zero residual resources. The shared multi-queue
  ingress also atomically enters a cache-free routing mode on the first
  Critical/Exhausted observation: it releases the striped flow directory and
  every queue-local route cache, then uses the same stable hash without
  allocating optional metadata until pressure recovers to Normal. Dedicated
  counters expose transitions and reclaimed directory/local entries; a model
  test proves packet delivery, suppression, hysteresis through Constrained,
  and cache recovery. Every runner step now
  advances a shard-local UDP idle timer wheel (closing a production-path leak
  where only explicit control calls expired flows), so normal expiry work is
  proportional to elapsed wheel slots and due flows rather than the complete
  UDP table. Constrained, Critical, and Exhausted pressure shorten UDP and
  incomplete-fragment retention by 2x, 4x, and 8x; the UDP wheel performs one
  bounded deadline rebuild only when that divisor changes, including recovery
  to Normal. Reply operations also advance the wheel before token lookup, so a
  late reply cannot revive an idle flow merely because it races the runner's
  periodic step. If a direct table caller jumps ingress time beyond the wheel
  horizon without an explicit expiry pass, admission performs one bounded
  large-jump advance and retries the deadline instead of leaking or reviving
  old state.
- The shipping `sail-netstack` crate is MIT-licensed, has no normal/runtime
  third-party dependencies, and forbids unsafe code both in its crate root and
  Cargo lint policy. `futures` and independently implemented `smoltcp` are
  test-only dependencies, the latter as an independent interoperability peer.
- N1a foundations include zero-copy slab-chain splitting, transactional append,
  writable packet arena allocations, and a four-level virtual timer wheel with
  bounded large-jump handling. Timer buckets are ordered sets whose active ID
  is removed synchronously on cancellation; repeated TCP/UDP/PMTU/fragment
  deadline refresh can no longer accumulate unbounded bucket tombstones. Tests cover 10,000
  cancel/reschedule cycles, a 10,000-operation deterministic differential model
  spanning schedule/cancel/cascade/large-jump/rollback operations, pressure
  shortening and recovery, stale-deadline suppression, selective UDP expiry,
  and the maximum representable timestamp.
- The shard scheduler uses weighted byte DRR with bounded global/per-flow
  admission and simultaneous packet, byte, elapsed-time, per-flow contiguous
  byte, and control-work budgets. Only processing can exhaust the elapsed-time
  budget: a round always processes at least one queued item. A thread
  preempted between taking the round's start time and visiting its first flow
  previously ended the round with queued work, no progress, and no registered
  wakeup, stalling forwarded packets until unrelated traffic arrived. Under
  eight concurrent MIPS32 QEMU copies it failed at least 19 of 400 runs of
  `two_single_shard_runners_process_a_flow_only_on_its_owner` with the
  production 2 ms budget, and 0 of 400 after the fix.
  `an_exhausted_budget_still_processes_one_data_packet` fails without the fix.
- The initial wire boundary parses and emits checksummed IPv4/IPv6 UDP, bounds
  IPv6 extension traversal, and refuses fragmented transport delivery before
  reassembly. A hard-budgeted IPv4/IPv6 reassembly table runs before flow
  creation, supports out-of-order completion and IPv6 atomic fragments, drops
  the entire datagram on overlap/conflicting bounds, and expires incomplete
  state through a shard-local timer wheel. IPv4 reserved flags and DF/fragment
  combinations, a repeated IPv6 Fragment Header, and a non-leading Hop-by-Hop
  Options header fail closed at the shared wire boundary before consuming
  reassembly budget. IPv6 Fragment Header reserved fields are ignored on
  receive as RFC 8200 requires, while source-generated fragments initialize
  both reserved fields to zero. Reassembly also
  accounts for the IPv4 header or IPv6 unfragmentable extension chain before
  reserving a piece, and revalidates a final length learned before an IPv4
  offset-zero fragment; a datagram that cannot fit its IP length field cannot
  pin fragment credit. IPv4 ingress options are walked as bounded TLVs; invalid
  or truncated lengths and nonzero bytes after End-of-Option-List are rejected
  before transport or reassembly admission. IPv6 Hop-by-Hop and Destination
  Options receive the same bounded TLV treatment: malformed lengths and
  nonzero PadN bytes fail closed, while an unrecognized option's top action
  bits are preserved with the option's absolute wire offset. Action `01`
  silently discards, action `10` requests an error even for multicast, and
  action `11` requests one only for unicast. For an eligible unicast packet,
  the runner applies its existing ICMP error limiter and emits an ICMPv6
  Parameter Problem Code 2 whose pointer identifies the exact Option Type;
  invalid source/destination addresses remain suppressed rather than becoming
  an invalid ICMP source. Because the stack implements no IPv6 Routing Type,
  an unrecognized Routing Header with zero Segments Left is skipped, while a
  nonzero value is discarded with ICMPv6 Parameter Problem Code 0 pointing at
  the Routing Type, as required by RFC 8200. IPv6 No Next Header terminates
  local protocol dispatch and silently ignores any trailing octets instead of
  misclassifying value 59 as an unsupported upper-layer protocol. A zero Next
  Header value encountered after the IPv6 header is discarded with ICMPv6
  Parameter Problem Code 1 pointing to the preceding header's exact field;
  the same exact-pointer path is exercised for an otherwise unknown upper-layer
  protocol following Destination Options.
  The TCP boundary ignores received reserved header bits as RFC 9293 requires,
  while still rejecting nonzero padding after End-of-Option-List rather than
  silently normalizing malformed option bytes.
  Pressure timeout changes rebuild
  that wheel only on transitions; active-datagram and buffered-fragment gauges
  are maintained incrementally instead of scanning every assembly on ingress.
  Expiry has 10 ms no-early granularity and reports
  active/completed/expired/overlap metrics. A fixed-seed 4,096-input arbitrary
  packet corpus exercises the reassembly boundary and repeatedly proves that
  `clear` returns fragment slots and bytes to zero.
  A separate fixed-seed 4,096-packet wire corpus forces both IP versions and
  TCP, UDP, and ICMP payload boundaries while retaining arbitrary lengths and
  bytes; it runs in ordinary CI without a native fuzz runtime. An exact IPv6
  extension-chain boundary test accepts seven traversed headers and rejects an
  eighth before transport delivery. The independent `sail-netstack/fuzz`
  package adds native libFuzzer/AddressSanitizer `wire_parse` and
  `fragment_reassembly` targets without adding fuzz-only dependencies to
  Sail's workspace or release graph. Wire mutations are parsed raw and through
  bounded synthesized IPv4 and IPv6 outer headers, allowing TCP, UDP, ICMP,
  and ICMPv6 parsing to receive arbitrary transport bytes before checksums
  converge. Fragment mutations start from valid source-fragmented IPv4 and
  IPv6 UDP packets, then vary order, duplication, loss, offsets, and final
  markers; completed datagrams are reparsed and every iteration clears the
  reassembler and asserts fragment-slot, fragment-byte, and metadata leases
  return to zero. The latest development-Mac smokes completed 3,199,847 wire
  executions in 21 seconds and 113,305 fragment executions in 21 seconds with
  no crash or sanitizer report; generated
  corpus and artifacts remain local, while crashes must become deterministic
  regression tests before a fix is accepted.
  Two TCP targets extend this. `tcp_state` drives one `TcpTcb` through
  arbitrary segments, application events, timers, RTT samples, and SACK loss,
  asserting after every operation that buffered bytes stay within capacity,
  the advertised right edge never precedes `recv_next` or retreats, the
  advertised window fits the remaining credit, and `send_next` never precedes
  `send_unacked`; the high bit of the scale byte also puts FIN on the initial
  SYN. `tcp_table` drives the complete `TcpTable` with emitted IPv4 wire
  packets from two peers, including SYN options, timestamps, SACK blocks,
  accept, read, write, close, abort, timers, and clock jumps. Every peer byte
  is a function of its sequence number and every application byte a function
  of its stream offset, so overlap, reordering, trimming, retransmission, and
  resegmentation cannot change the expected bytes: delivered and emitted
  payload must match exactly, emitted packets must reparse, table invariant
  errors fail the run, and a network reset must return the ledger to zero.
  Four real defects were found and fixed, each with a deterministic
  regression test: an in-order FIN exactly at the receive-window right edge
  advanced `recv_next` past it; initial SYN payload beyond a window-scale
  quantized window left the right edge behind `recv_next` after the handshake
  (the minimized 49-byte input wraps every sequence number past `u32::MAX`);
  a SYN+FIN whose payload filled the window placed the FIN beyond the right
  edge; and a `write` after `close` into a zero peer window entered the persist
  buffer, whose probe later emitted data beyond the local FIN. The initial
  SYN now extends the right edge to cover its admitted payload and admits a
  FIN only strictly inside the window, and `TcpTable::write` checks the TCB
  send state before its persist and Nagle buffering. The first `tcp_table`
  failure was a harness error (payload generated from the SYN's own sequence
  number) and was corrected in the harness only.
  After the fixes, all 16 `tcp_state` artifacts and all 16 `tcp_table`
  artifacts replay cleanly. A 30-minute, 6-worker `tcp_state` campaign
  completed about 239 million executions (coverage rose from 705 to 711 edges
  with the initial-FIN extension), and a 30-minute, 6-worker `tcp_table`
  campaign on the fixed code completed about 13.8 million executions at
  3,611-3,614 edges, both without a new failure.
  Budget denial now walks a synchronized oldest-first index keyed by creation
  time and stable insertion serial, evicts incomplete datagrams until the new
  piece can be admitted, and reports a separate eviction counter. A same-time
  two-datagram test constrains both fragment slots and bytes, proves the older
  assembly and timer are removed, completes the newer datagram, and returns
  every lease to zero without a normal-path full-table scan. Reassembly
  timeout now retains at most the caller's bounded quote allowance and only
  when offset zero was received; the runner emits IPv4/IPv6 ICMP Time Exceeded
  code 1 through the existing ICMP error limiter, TX queue ceiling, and packet
  budget while releasing every fragment lease. Model tests verify exact IPv4
  and IPv6 first-fragment reconstruction, suppression without a first fragment,
  and the complete runner send path. ICMPv4/ICMPv6
  parsing verifies the correct checksum domain, echo requests receive local replies,
  unsupported protocols receive bounded errors, oversized IPv6 and IPv4-DF
  input receives Packet Too Big/fragmentation-needed feedback, and error loops,
  multicast sources/destinations, and non-initial fragments are suppressed.
  IPv4 error generation also applies RFC 1122's non-unique-source rule to the
  complete `0/8`, loopback `127/8`, multicast, Class E `240/4`, and limited
  broadcast ranges; these inputs cannot provoke a reflected error. IPv6
  loopback remains a valid single-node source. The RFC 4443 multicast
  exceptions for Packet Too Big and Parameter Problem Code 2 still require a
  configured unicast interface source, which the transparent core does not
  own, so those otherwise-invalid reverse-source cases remain safely
  suppressed at this layer.
  Echo responses likewise require unicast source and destination addresses, so
  reversing a multicast, broadcast, or unspecified request destination can
  never manufacture an invalid reply source address.
  Echo replies and error generation have independent virtual-time token
  buckets. Authenticated
  Packet Too Big quotes feed a generation-scoped, expiring, hard-budgeted PMTU
  cache only after their TCP/UDP reverse tuple matches a live flow; unmatched
  quotes are counted and cannot poison later fragmentation decisions. Its
  IPv4 path also accepts authenticated RFC 1191 old-style code-4 feedback whose
  Next-Hop MTU is zero: it corrects the quoted Total Length for the documented
  4.2BSD header-length ambiguity, selects the greatest strictly lower standard
  plateau, never goes below 68 bytes, and still cannot increase a cached PMTU.
  Its
  shard-local timer wheel removes only due entries with 10 ms
  no-early granularity, refreshed entries cancel their stale deadline, and
  a synchronized ordered expiry index makes deterministic capacity eviction
  O(log n) rather than scanning up to every server-profile entry. Refresh,
  expiry, clear, and network reset maintain both indexes transactionally; UDP
  fragmentation and new TCP writes honor the learned ceiling. A
  locally emitted IPv6 datagram can be fragmented across a bounded extension
  chain: the Fragment header is placed after the RFC 8200 unfragmentable
  portion, raw post-Fragment extension bytes remain in the reassembly offset
  space, and out-of-order reconstruction reproduces the original datagram.
  IPv4 source fragmentation validates option TLVs, retains all options on the
  first fragment, copies only copy-bit options to later fragments, and sizes
  each aligned payload against that fragment's actual IHL. If an already
  fragmented IPv4 datagram still exceeds the requested MTU, the source-only
  API fails closed instead of erasing its original offset/MF semantics during
  an incorrect second fragmentation pass.
  shard-local UDP table charges flow state, issues generation tokens, expires
  idle sessions, and emits reverse-path replies.
- `PacketIo` now drives a single-shard TCP/UDP loop with budgeted persistent
  RX/TX queues, partial-send retention, `WouldBlock`, hard failure propagation,
  drain/abort/reset/MTU semantics, and packet/byte/time scheduling budgets.
  TCP control capacity is reserved before state advancement; accepted flows can
  be claimed, read, and written through generation-checked runner APIs,
  including receive-window updates. Sent payload remains charged and retained
  until ACK, partial ACK retransmits only the unacknowledged suffix, and RTO
  arm/disarm requests are explicit. The runner owns those requests in its timer
  wheel, retransmits autonomously, cancels stale SYN/data deadlines on ACK, and
  retries timer work under TX backpressure without advancing protocol state.
  When ICMP Packet Too Big feedback is black-holed, the default table policy
  treats the second consecutive data RTO as a PMTU black-hole signal and
  lowers that flow to the IPv4 576-byte or IPv6 1,280-byte minimum path MTU.
  Retained unacknowledged chunks are resegmented in place without duplicating
  payload credit; a successful ACK resets the consecutive-RTO count, and the
  policy can be disabled for a platform build. IPv4, IPv6, and disabled-policy
  model tests verify the exact 536/1,220-byte payload ceilings and an aggregate
  fallback counter.
  The send side pipelines budgeted segments up to the smaller of the peer and
  NewReno congestion windows; cumulative and partial ACKs immediately release
  acknowledged payload credit. Initial-window, slow-start,
  congestion-avoidance, duplicate-ACK fast retransmit, partial-ACK recovery,
  and timeout collapse are modeled explicitly. The peer MSS from SYN is
  enforced by both the flow table and the sail stream adapter. SYN-ACK now
  advertises the local MSS, negotiates window scaling in both directions, and
  negotiates SACK; the send queue retains SACK state and skips selectively
  acknowledged segments when choosing a fast-retransmit hole. The scoreboard
  also applies RFC 6675 loss inference from three discontiguous SACKed
  sequences (or three MSS of data above a hole), can enter recovery before
  three duplicate ACKs, and clears SACK state on RTO to tolerate receiver
  reneging. Recovery now maintains a retransmission scoreboard, recomputes a
  conservative RFC 6675 `Pipe`, applies `NextSeg` lost-hole and fallback-hole
  selection under `cwnd`, and permits only one rescue retransmission after
  cumulative ACK progress. Partially covering SACK blocks split retained send
  chunks into exact SACKed/unsacked byte ranges under the metadata budget;
  the split uses a two-phase plan that reserves every new metadata lease before
  ACK or congestion state can change. A hard-budget model test proves a failed
  reservation leaves `SND.UNA`, retained payload, and the next retransmission
  unchanged. Retransmitted/rescue counters are exported. RFC 5681 Limited Transmit grants
  one MSS for each of the first two duplicate ACKs, constrained by the peer
  window, and emits a writable event when an application write was blocked at
  zero capacity. RFC 6582 partial ACK processing now deflates the current
  recovery window by newly acknowledged bytes and adds back one MSS, retaining
  duplicate-ACK inflation until full recovery; entering or leaving recovery
  clears stale congestion-avoidance credit. MSS-derived initial, threshold,
  and recovery window arithmetic saturates at the integer boundary. TCP
  SACK sender feedback is admitted only when the carrying segment is in the
  receive window, its ACK covers current send sequence space, and it carries
  neither SYN nor RST. An out-of-window SACK therefore cannot allocate split
  metadata, mark retained bytes as received, or alter retransmission output.
  Blocks outside `SND.UNA..SND.NXT` are also excluded from SACK recovery
  admission: duplicate ACKs still drive ordinary NewReno fast retransmit but
  cannot create SACK recovery state or counters from invalid scoreboard data.
  timestamps are negotiated and emitted on subsequent
  segments. `TS.Recent` advances only when a segment with sequence-space
  length covers the previous receive edge, so a pure ACK cannot make later
  valid data look stale; the PAWS value is invalidated after the RFC 7323
  24-day idle interval. Stale/current and missing timestamps fail closed, and
  echoed timestamps feed deterministic RTTM samples into the RTO estimator.
  Every sample is now tied to an outstanding sequence probe and the exact
  locally emitted `TSval`; a forged, stale, or unrelated `TSecr` consumes no
  sample and therefore cannot inflate the connection RTO. Retransmission still
  clears the probe to preserve Karn ambiguity suppression. Stateless resets
  generated for timestamped unknown segments carry `TSval=0` and echo the
  triggering `TSval`, without allocating flow state.
  Connections without negotiated timestamps retain one bounded sequence-space
  RTT probe, beginning with SYN-ACK and then fresh payload. Cumulative ACKs
  feed that sample into the same estimator; any RTO, fast retransmit, or SACK
  retransmit invalidates the probe according to Karn's ambiguity rule.
  Zero-window application writes are retained as one hard-budgeted pending
  chunk per flow. A runner-owned persist timer emits sequence-stable one-byte
  probes with bounded exponential backoff; partial window reopening slices the
  pending chunk without changing aggregate payload credit, and a full reopen
  cancels persist after transferring the bytes to the retransmission queue.
  Receive-window updates apply receiver silly-window avoidance: consumed
  credit is accumulated until it reaches the smaller of half the reserved
  receive buffer and the local MSS, with the threshold rounded up to the
  negotiated window-scale quantum. Smaller reads do not advance the advertised
  right edge; an application payload write piggybacks and cancels any pending
  delayed ACK rather than emitting a tiny standalone window update. The receive
  right edge is also rounded down to the negotiated scale quantum and capped at
  the largest wire-representable window, so internal admission never extends
  beyond bytes actually advertised to the peer. A sub-quantum reserved-credit
  remainder cannot make a zero-window pure ACK fail sender-window processing;
  receive admission and sender feedback share the same sequence acceptability
  rule.
  Keepalive is an opt-in table policy with independent idle/interval/probe
  bounds; valid peer traffic resets the probe budget, runner timers send
  sequence-space-safe probes, and an unresponsive idle flow is closed with all
  resources released. The native sail adapter enables the conventional
  two-hour idle, 75-second interval, nine-probe policy.
  TCP live gauges are cached per flow: ingress, ACK, application I/O, and timer
  paths update only the touched flow plus O(1) table-size counters instead of
  rescanning every active connection. The 100,000-connection release churn
  workload completes three consecutive runs with zero drops and full
  TIME-WAIT/resource reclamation; target-hardware performance gates remain
  separate release evidence.
  Close-state models cover passive half-close, active close, and simultaneous
  close. In the simultaneous case a peer FIN that has not acknowledged our FIN
  enters `CLOSING`; only the later exact FIN acknowledgment enters `TIME-WAIT`
  and arms its compact-table expiry.
  Initial SYN data and an optional FIN remain hard-budgeted and queued while
  `SYN-RECEIVED`: SYN-ACK only acknowledges the SYN, the exact final ACK uses
  the post-data/post-FIN peer sequence, and handshake completion processes the
  queued bytes before atomically emitting peer-half-close and the FIN ACK. If
  that exact final ACK also carries payload or FIN, it is reserved once against
  the post-SYN receive edge and appended after the queued SYN payload rather
  than being misclassified as pre-handshake out-of-order data. Its payload is
  preflighted together with queued SYN data against the single reserved receive
  credit before the TCB can leave `SYN-RECEIVED`; an overcommit therefore
  cannot partially complete the handshake. Pre-handshake retransmissions and
  reordered data are normalized against the prospective post-SYN-data/post-FIN
  receive edge, so an overlapping prefix is discarded while a new suffix is
  retained for delivery immediately after handshake completion; a FIN exactly
  following that overlapping prefix is likewise retained as the receive-stream
  boundary.
  Before flow lookup, stateless-reset generation, rate limiting, or resource
  admission, TCP and UDP share one unicast endpoint predicate. TCP silently
  rejects IPv4 sources in `0/8`, `127/8`,
  multicast, or Class E space and IPv4 destinations that are unspecified,
  multicast, limited broadcast, or Class E. IPv6 unspecified/multicast sources
  and destinations are rejected on the same path while IPv6 loopback remains
  valid. A dedicated aggregate counter distinguishes these RFC 1122 endpoint
  drops from malformed wire packets; model coverage proves invalid SYNs do not
  consume flow, SYN, payload, or metadata budget and invalid unknown ACKs do
  not elicit a stateless reset. UDP applies the same predicate and reports a
  policy drop plus `udp_invalid_address_drops`, matching the default
  non-broadcast filter of the smoltcp engine it replaces. Before this, a
  host's LLMNR and mDNS queries sent on every interface became proxied UDP
  flows; privileged Linux runs observed the TUN address's LLMNR query as the
  first datagram of the kernel round-trip test.
  The receive-credit, metadata, accept, and close lifecycle returns to zero.
  A peer FIN is also an explicit receive-stream boundary: an earlier queued
  FIN truncates and releases overlapping or later out-of-order bytes,
  promotion cannot cross that sequence, and new payload after the FIN is
  acknowledged without being delivered or consuming chunk metadata. A FIN is
  eligible to become that boundary only after its ACK/flags pass sender-space
  validation and the FIN sequence itself lies inside the receive window;
  future-ACK or right-edge FIN injection cannot later manufacture EOF when a
  legitimate gap closes.
  Sender feedback is likewise gated by the original segment's sequence-space
  acceptability: data or FIN arriving at a zero receive window cannot be
  normalized into a pure ACK that advances `SND.UNA` or changes the peer
  window; a genuine zero-length ACK at `RCV.NXT` remains valid.
  Negotiated timestamp enforcement follows RFC 7323's distinct rejection
  paths: a missing timestamp is silently dropped without aborting the flow,
  while a current PAWS failure emits a timestamped, independently rate-limited
  defensive ACK and cannot advance sender or receiver state. Both outcomes
  have dedicated aggregate counters.
  A peer window-scale offer above 14 is clamped to 14 rather than rejecting
  the SYN, as required by RFC 7323; the negotiated sender window uses the
  clamped exponent and an aggregate counter records each admitted clamp.
  Closing with application data still in flight retains sequence-space order:
  retransmission timeout and SACK recovery resend the oldest payload while it
  remains unacknowledged, and only retransmit the FIN after the cumulative ACK
  reaches the FIN sequence. State and wire-table tests cover the transition so
  loss cannot turn an earlier payload sequence into a premature EOF.
  A compact TIME-WAIT record acknowledges non-RST traffic but rearms its 2MSL
  deadline only when an ACK-bearing FIN ends at the already acknowledged final
  FIN sequence. Arbitrary FIN and `RST|FIN` traffic cannot perpetually retain a
  slot; a model test covers both rejection paths and the valid retransmission.
  Transition reuses and shrinks the full TCB's metadata lease instead of
  transiently allocating at peak pressure. If the independent TIME-WAIT slot
  budget is full, the creation-order index deterministically evicts the oldest
  compact record, cancels its timer, invalidates its token, and increments an
  exported eviction counter before admitting the new record.
  Nagle is likewise opt-in at the protocol layer and enabled by the native
  adapter: while data is in flight, one additional small write is retained in
  the same hard-budgeted pending slot and released after cumulative ACK clears
  the flight. It never creates an unbounded coalescing buffer. The stream
  bridge queries the live congestion/peer-window capacity before taking
  ownership, so a window smaller than the caller's write produces a truthful
  partial write instead of an unretryable oversized segment. That handoff is a
  two-phase reservation/commit protocol: a `Pending` `poll_write` may reserve
  capacity but never copies or submits the caller's bytes, and only a later
  poll that can enqueue the current buffer's committed prefix returns `Ready`.
  Cancelling a write future therefore cannot transmit its abandoned buffer or
  misattribute its completion count to a later write; deferred commit errors
  are reported by the next write, flush, or shutdown. Once committed, the
  bounded payload stays owned by the bridge across transient packet-budget or
  TX backpressure and is retried without requiring or consuming a second
  reservation; a runtime test exhausts packet credit, observes the denial,
  restores credit, and verifies the unchanged payload is emitted.
  Dropping an accepted `NativeTcpStream` now sends its flow token through a
  dedicated cleanup path instead of attempting a lossy `try_send` on the
  ordinary bounded command queue. Its O(1) token queue is capped at
  `max_tcp_flows`. Each stream and its runtime `FlowBridge` share an atomic live
  bit: runtime closure clears it, while application drop atomically clears a
  still-live bit and submits its token. If stale queued tokens ever saturate
  that hard-bounded queue, a coalescing `Notify` triggers one fallback scan of
  the owner's hard-budgeted local flow table; this preserves cleanup without
  an unbounded overflow allocation or imposing an O(flows) scan on the normal
  drop path. A bridge-level test fills the ordinary command queue before drop,
  a stale-stream test proves runtime-closed flows submit nothing, an overflow
  test proves the bounded fallback fires, and a runtime test proves the owning
  shard still aborts a live dropped flow and returns its `TcpFlows` lease to
  zero.
  Peer-window updates track RFC 9293 `SND.WL1/SND.WL2`: invalid handshake ACKs,
  stale sequence space, unacceptable receive-window positions, and ACKs
  outside `SND.UNA..SND.NXT` cannot shrink or reopen the send window. In
  `SYN-RECEIVED`, a sequence-acceptable ACK that does not acknowledge the
  SYN receives `<SEQ=SEG.ACK><CTL=RST>` while the passive half-connection and
  its retransmission timer remain available for a later valid final ACK.
  Negotiated SACK also covers the receive side: non-overlapping out-of-order
  chunks are admitted only inside the pre-reserved receive window, charged for
  metadata, deduplicated, reported in bounded SACK options, and promoted in
  sequence when a gap closes. The merged block containing the most recently
  admitted out-of-order data is encoded first as required by RFC 2018, without
  an input-sized temporary allocation; a fully duplicate out-of-order segment
  refreshes that first-block hint without allocating another receive chunk. A
  retransmission overlapping `RCV.NXT` has its
  already-received prefix trimmed, and payload beyond the advertised right edge
  is trimmed independently; only a FIN whose sequence remains inside the window
  is applied. These transformations are restricted to admissible ACK data and
  never normalize an RST sequence. Overlapping head retransmissions are also
  trimmed at the first queued range; partially overlapping out-of-order
  segments retain their nearest novel prefix or suffix while control handling
  still observes the original segment, and a non-contiguous FIN is not applied
  early. A single bounded pending-FIN sequence is retained when FIN arrives
  behind an out-of-order gap; closing the gap promotes the queued bytes and FIN
  atomically, emits the cumulative ACK, and reports the peer half-close without
  waiting for a FIN retransmission.
  RTO retries are bounded per flow (12 by default), reset only by forward ACK
  progress, and close/reclaim an unresponsive SYN or established flow after
  the configured retry budget; timeout and terminal-failure counters are
  exported in the stack snapshot.
  RFC 5961 reset validation accepts an RST only when its sequence number is
  exactly `RCV.NXT`, sends a challenge ACK for a non-exact sequence number
  inside the receive window, and silently drops an out-of-window RST. Challenge
  ACKs use an independent virtual-time token bucket and expose
  sent/rate-limited counters; an out-of-window reset never consumes a token, so
  spoofed resets cannot consume an unbounded control-packet share.
  Unknown non-SYN traffic receives RFC 9293 stateless resets with the correct
  ACK-vs-non-ACK sequence rules, incoming RST never creates a loop, and an
  independent limiter bounds reset amplification without allocating a flow.
  New-flow SYN admission has its own virtual-time token bucket and drops before
  reserving flow, SYN-RECEIVED, metadata, or receive-credit resources; the
  rate-limited count is exported independently from budget exhaustion.
  ACKs generated solely to defend against unacceptable sequence space,
  ACKs beyond `SND.NXT`, or out-of-order payload use another independent
  limiter, while normal cumulative/delayed/window-update ACKs remain outside
  that abuse budget.
  Non-atomic fragments pass an independent runner-level token bucket before
  they can reserve a reassembly slot or fragment bytes; rate-limited fragment
  packets and ordinary budget denial remain separately observable.
  TCP's four reserved header bits are zero on emitted segments and ignored on
  receive as required by RFC 9293; a checksum-valid SYN carrying every
  reserved bit still completes passive flow admission without being counted
  as malformed.
  RFC 9293 segment acceptability is evaluated before ACK/window processing;
  an ACK whose sequence is outside the advertised receive window elicits only
  the current ACK and cannot advance `SND.UNA` or release payload credit.
  Synchronized-state ACK processing also rejects ACKs beyond `SND.NXT`, drops
  ordinary segments without ACK, and routes unexpected SYN through the
  challenge-ACK limiter before any payload admission.
  The batch-size-one path has an end-to-end mock TUN handshake, bidirectional
  payload, RTO, and stale-deadline cancellation test.
  Multi-hole SACK recovery is capped by the runner's currently available TX
  slots and queues each resulting retransmission safely even when PacketIo has
  `max_batch = 1`; it no longer relies on the obsolete one-output-per-ACK
  invariant.
- UDP ingress advances its own idle timer before tuple lookup. A packet that
  arrives after the prior session's deadline therefore receives a new
  generation-qualified flow capability; a delayed reply carrying the retired
  token is rejected, and replacing the tuple leaves exactly one flow lease.
  Reply construction validates address-family and length constraints before
  refreshing that idle timer, so rejected application output cannot keep a
  flow or its resource leases alive.
- Multi-shard foundations include a budgeted first-packet directory, stable
  shard assignment, and per-target bounded byte-DRR forwarding queues. TCP and
  UDP capability tokens now carry their owning shard as well as the local flow
  ID and network generation. Shard-local tables reject a token presented to a
  different shard, so independently allocated local flow IDs cannot collide
  when the platform runner is expanded to multiple queues. Router snapshots
  expose current directory/queue depth plus cumulative local, forwarded,
  admitted, dropped, and drained packet/byte counters; network reset clears
  queued state while preserving those diagnostic totals.
  The public `ShardRouter` model bounds its directory by the scheduler's
  `max_active_flows`, replaces the oldest cached entry during churn, and
  releases the evicted metadata lease before admission. A regression test
  constrains it to one entry and proves repeated replacement keeps both the
  entry count and metadata charge constant.
  `ShardedPacketIo::group` now wraps a complete platform queue set (accepting
  both per-handle and group-wide queue capability reporting), classifies
  TCP, UDP, ICMP, unsupported protocols, and IP fragments before protocol
  execution, and makes each queue appear as one owner-shard `PacketIo`.
  Mismatched input is forwarded through the bounded router and all fragments
  of a datagram use one synthetic ownership key. Its striped flow directory
  now has the same count bound as the model (`max_active_flows`, divided over
  the 64 stripes, oldest entry replaced first). Closed flows never remove
  their entries, and before the bound the directory grew by one 64-byte
  metadata lease per new flow key until metadata pressure cleared every
  routing cache: the first kernel soak accumulated about 6 MB in 20 minutes.
  Every entry stores the hash owner, so eviction cannot change routing.
  `flow_directory_stays_bounded_across_many_short_flows` routes 4,096 short
  flows through a 64-entry configuration and fails with 4,096 entries
  without the bound. A two-runner test proves that
  a flow injected on either queue is delivered only by its stable owner and
  that emitted UDP tokens name that shard. Consumer-limited scheduler draining
  preserves the queued suffix. Network reset atomically clears directory and
  forwarding state while changing the classification generation.
  A cross-shard enqueue wakes an owner blocked in its platform `recv`; the
  adapter races that notification against the platform future, cancels the
  losing read, and immediately drains forwarded work. Dropping a pending recv
  unregisters its waker, with deterministic wake and cancellation tests.
  The runtime hot path no longer serializes all shards behind one router
  mutex: the directory is split across 64 independently locked stripes and
  every target shard owns a separate scheduler/waker lock. Each input shard
  also has a bounded route cache, charged to MetadataBytes, so repeat packets
  in a stable flow avoid the shared directory stripe. At entry capacity it
  replaces the oldest inserted route, which prevents short-connection churn
  from permanently degrading all later flows to the shared lock; metadata
  budget exhaustion still falls back to the stable directory/hash route
  without dropping traffic. Reset synchronously clears both cache maps and
  insertion queues and releases their leases. Forwarded packets
  hold PacketBytes plus metadata leases until owner drain, and exhaustion
  drops them without leaking either lease. Generation reset uses a write lock
  to exclude concurrent classification while clearing every stripe and queue.
  A four-thread stress regression concurrently routes packets on every shard
  while a control thread repeatedly resets the generation and reads router
  statistics; the final reset proves that directory, local-cache, forwarding
  queue, packet, control-packet, and metadata leases all return to zero. The
  same regression passes under the MIPS32 big-endian QEMU runner.
  The directory is a bounded cache rather than a correctness dependency: if
  its metadata lease cannot be acquired, the target stripe drops its oldest
  cached route and retries once. This recycles directory-owned metadata during
  long connection churn; if unrelated metadata users still prevent admission,
  the same stable hash is used without caching, the failure is counted, and
  the owner runner remains responsible for normal pressure admission. A
  same-stripe collision test constrains metadata to one directory entry and
  proves replacement preserves the owner, entry count, and byte charge.
- The TCP prototype has a pure server-side handshake/close state machine, a
  shard-local flow table, generation-checked connection handles, a bounded
  accept queue, pre-reserved receive credit, metadata-charged receive chunks,
  read-driven window reopening, control-packet emission, explicit timer
  requests, sequence wrap handling, an initial RFC 6298 estimator,
  challenge-ACK behavior, compact separately-budgeted TIME-WAIT records, and
  bounded TCP option parsing for MSS, window
  scaling, SACK, and timestamps. Admission failures occur before handshake or
  receive state changes. Accept-queue overflow is an explicit build-time table
  policy: the default drops the completing ACK while retaining SYN-RECEIVED
  for a later retry, while `RejectWithReset` sends a reset through the existing
  stateless-reset limiter, cancels the embryonic retransmission timer, and
  immediately returns all flow credit. Both outcomes have dedicated aggregate
  counters; table and runner tests cover retry, rejection, timer cleanup, and
  exact resource reclamation.
- The sail TUN adapter now has an internal `native` integration path: the async
  TUN device implements `PacketIo`, accepted TCP streams implement Tokio
  `AsyncRead`/`AsyncWrite` and enter `Dispatcher`, and bounded UDP endpoint
  channels enter `NatManager` while preserving FakeDNS request/reply mapping.
  Runner failures are surfaced to the owning inbound future. An async
  in-memory PacketIo black-box now drives the complete native runtime through
  TCP handshake, accepted-stream write/read, UDP uplink, and reverse UDP reply
  wire validation without requiring a privileged TUN device. A loss-path
  variant drops the first application data segment and verifies that the
  runtime timer retransmits the same sequence and payload through the bridge.
  `PacketIo` now requires `Send` receive/send futures, making the executor
  contract explicit instead of relying on concrete-type inference. The sail
  product path always wraps its platform queue set with `ShardedPacketIo` and
  constructs one `NativeRuntime` per owner shard; accepted TCP streams share a
  central sink while retaining their owner command channel, and UDP replies
  route by the shard-qualified token. The sail adapter keys its bounded UDP
  reply-token cache by both client and intercepted destination, preventing one
  client socket's concurrent destinations from overwriting each other. A
  deterministic test sends two such flows and returns their replies in reverse
  order. Sail's domain-associated direct UDP socket now also retains a bounded
  resolved-address-to-original-target map shared by its send and receive
  halves. This prevents the generic outbound layer from relabeling every reply
  with the session's first destination when one client session reaches several
  domain ports. Its unit test records two targets and looks them up in reverse
  order. A two-queue runtime test covers
  cross-queue handshake forwarding and an application write on the owner.
  `NativeRuntimeControl` now broadcasts acknowledged shutdown, abort, network
  reset, MTU update, and snapshot commands to every owner shard. Network reset
  changes the shared router generation and clears its directory/forwarding
  queues before resetting protocol state, so transition traffic can be lost
  but cannot establish new ownership under the retired generation. Snapshot
  aggregation rejects mixed generations, sums shard-local counters and gauges,
  preserves batch maxima, reads the shared resource ledger exactly once, and
  includes shared routing/forwarding counters. Cross-shard blocked-receive
  waker registrations and actual wakeups are independently counted and covered
  by the forwarding wake test. The two-shard test exercises all
  five commands, verifies aggregate flow/counter values, and proves reset
  clears both protocol and router state.
  TUN construction now returns this control surface alongside its runner.
  `RuntimeManager` owns a bounded acknowledged network-change request channel,
  and the Rust `network_changed(runtime_id, mtu)` API plus
  `sail_network_changed(runtime_id, mtu)` C ABI entry point advance a monotonic
  generation across every shard. C ABI MTU zero preserves the current MTU;
  other values are validated and applied after reset. A legacy-backed runtime
  reports that no native control surface exists instead of returning a false
  success. Mobile/desktop host lifecycle code must invoke this entry point when
  its OS reports a path or interface change; automatic OS listeners are not
  embedded in the portable core.
  A separate interoperability test uses upstream smoltcp 0.12 as an
  independently implemented IPv4/TCP client: it completes handshake,
  bidirectional payload transfer, a deliberately dropped server segment plus
  RTO retransmission/ACK, three out-of-order server segments with real SACK
  blocks and fast retransmit of the missing hole, and graceful close against
  `TcpTable` over an in-memory IP device.
  The integration selects Mobile on Android/iOS, Router on MIPS/MIPS64, and
  Desktop elsewhere; explicit `native-mobile`, `native-router`,
  `native-desktop`, and `native-server` backend values make all four hard
  budget profiles available for deployments whose role cannot be inferred
  from the target triple.
  The TUN adapter reuses its MTU-sized read scratch buffer and drains already
  ready packets into profile-bounded userspace bursts (Mobile 1, Router 4,
  Desktop 32, Server 64). Linux-owned native devices now use Apache-2.0
  `tun-rs` 2.8.11 and create real `IFF_MULTI_QUEUE` groups: up to four queues
  for Desktop and eight for Server, capped by available parallelism. A
  privileged Linux container test created a TUN, attached its second kernel
  queue, enabled `IFF_VNET_HDR`, sent a real kernel UDP socket packet through the sharded native
  runtime, and routed the reply by shard token back to that socket. The same
  test completes a Linux kernel `TcpStream` handshake through the TUN and
  verifies bidirectional application payload through `NativeTcpStream`. Its
  fault adapter then discards the first server application segment while
  reporting the exact accepted packet prefix; the Linux peer receives the
  unchanged payload after the native runner's RTO retransmission. A second
  fault mode accepts and holds one segment, delivers its successor first,
  waits 25 ms, then delivers the held segment and a duplicate successor. The
  real kernel reassembles the unchanged 4 KiB stream; an explicit completion
  flag proves the reorder/delay/duplicate path ran. This passed three
  consecutive privileged runs. The same
  dual-stack TUN also completes real Linux-kernel IPv6 UDP and TCP round trips
  in both directions. The IPv4 kernel peer also completes a bidirectional
  half-close, and a separate `SO_LINGER=0` peer proves an abrupt kernel RST
  promptly terminates the native stream. The test shuts the runtime group down
  through its acknowledged control/completion path rather than cancelling its
  task. 4 KiB IPv4 and IPv6 UDP round trips prove
  kernel-originated fragment reassembly on ingress and native fragmentation
  plus kernel reassembly on egress without changing the application datagram.
  A second privileged process-level test starts sail from JSON configuration,
  obtains a mapped address
  through the real TUN FakeDNS interception path, and drives kernel TCP and UDP
  sockets through `sail-netstack`. TCP traverses `Dispatcher` to a direct local
  echo server; UDP traverses `NatManager`/`Dispatcher`, resolves the mapped
  domain through the static DNS host table, and restores the fake source on
  the return packet. The same kernel UDP socket sends to two mapped destination
  ports; coordinated echo peers return the second datagram first, and the
  client observes both payloads with their respective fake source ports. This
  covers both bounded target maps through the complete product path. All round
  trips complete through the multi-queue adapter and the actual runtime
  lifecycle. The test then invokes the public runtime network-change
  path with MTU 1400 and proves a fresh kernel FakeDNS flow succeeds after the
  generation reset.
  The Linux Server profile enables offload only when its packet batch can hold
  every segment from a worst-case 65,535-byte frame. Its receive path uses
  `recv_multiple` to turn a kernel GSO frame back into ordinary MTU-bounded
  packets before classification. Its transmit path supplies valid virtio-net
  framing and now coalesces a complete TCP batch when tun-rs can represent
  every original packet as exactly one GSO frame. The adapter validates that
  there is one GSO candidate, its segment count equals the input count, and
  its aggregate payload equals the sum of the original checksum-valid TCP
  payloads. It then performs one atomic TUN write: a full-length result
  acknowledges the complete `PacketIo` prefix, while an error acknowledges
  none. Mixed, non-contiguous, partially coalescible, or otherwise ineligible
  batches fall back to the existing exact per-packet path. This avoids the
  ambiguous partial-prefix reporting that would result from a multi-frame
  `send_multiple` failure. Scratch buffers are fixed by MTU and profile batch
  size and reused across operations.
  Borrowed-FD/mobile and non-Linux paths retain the mature single-queue `tun`
  adapter. Both adapters report `vectored=false` and no transmit GSO to the
  stack: Linux offload is deliberately contained below the `PacketIo` packet
  boundary. Deferred read/write failures preserve a successfully received or
  sent batch prefix instead of duplicating it on retry. Advertised GSO is
  treated strictly as transmit capability and can never make an oversized
  receive packet bypass MTU validation without explicit GRO metadata. Pure
  Linux tests coalesce three sequential segments and split the resulting GSO
  frame back into the original checksum-valid payloads, while a non-contiguous
  batch proves the fallback decision. A privileged native x86_64 Linux test
  also proves that the kernel accepts the complete batch as one atomic TUN GSO
  write; the existing multi-queue kernel TCP/UDP impairment test still passes.
  Runtime-group joining now waits for every normally terminating shard while
  still cancelling peers on the first error. If an accept or datagram bridge
  ends first, the product path retains the runner future, captures a final
  aggregate snapshot, sends an acknowledged zero-grace shutdown to every
  shard, and waits for the complete group instead of silently dropping the
  remaining runners. The top-level `RuntimeManager` shutdown monitor uses the
  same control path and then waits on the runtime group's completion signal;
  consequently the outer `select_all` cannot win by merely acknowledging a
  command and dropping live shard futures. The privileged process test covers
  this global shutdown path. Platform applications still need to connect their
  OS network callbacks to the exported network-change entry point.
  `PacketIo` now states its cancellation contract. The native runtime races
  each runner step against a 10 ms timer and application commands, so a step
  (and the `send` inside it) is routinely dropped at an await point. `send`
  may therefore await only before accepting the first packet of a batch and
  must report a partial send instead of awaiting again; the runner records a
  send only after it completes, so a dropped `send` has accepted nothing and
  the retry cannot duplicate packets. The Linux offload path previously
  awaited device writability for every packet: a cancellation after packet
  `k` lost the count and resent the prefix, and under sustained TUN
  backpressure each 10 ms retry could spend queue space on the same prefix.
  It and the single-queue `tun` adapter now use a non-blocking send after the
  first accepted packet. The impairment wrappers in the privileged test
  violated the contract more severely: one slept 25 ms after sending the
  trigger segment, so every step was cancelled before the held segment was
  released, the same segment was re-sent every tick with a frozen timestamp,
  and the connection never recovered. The multi-queue kernel test hung or
  failed in all 7 control runs on the x86_64 Linux host (5 hangs, 2 LLMNR
  datagrams) and passed 10 of 10 runs in about one second each after the
  contract, adapter, wrapper, and UDP endpoint fixes. The wrapper's delay is
  now a deadline rechecked on retry rather than an await.
- Active open, step 1 of the WireGuard work (the control block): `TcpTcb::connect`
  sends a SYN and waits in SYN-SENT, retransmitting it with RTO backoff. It
  follows RFC 9293 3.10.7.3: an ACK other than ISS+1 draws a reset (unless it
  is a reset), a reset counts only when it acknowledges the SYN, and a
  SYN-ACK opens the connection and is acknowledged. Data and FIN on the
  SYN-ACK are not taken, so the peer resends them. A crossing SYN without
  ACK moves to SYN-RECEIVED for a simultaneous open, which completes on
  either the peer's SYN-ACK or its plain ACK (figure 8). Completion reports
  `Connected`, not `Accepted`. Close or abort in SYN-SENT sends nothing.
  SYN and SYN-ACK windows are no longer scaled (RFC 7323 2.2); the passive
  SYN-ACK used to shift its window, which understated larger credits. The
  `tcp_state` fuzz target now also starts from an active open, with operations
  that can aim the ACK and sequence at the current edges, and checks that
  only the SYN is outstanding in SYN-SENT. A 20-minute, 6-worker campaign ran
  about 25 million executions and raised coverage from 711 to 815 edges
  without a failure, and every earlier `tcp_state` artifact still replays
  cleanly. The flow table, UDP originate, and the runtime API follow in the
  next steps.
- `cargo test -p sail-netstack` currently runs 271 deterministic contract,
  randomized-model, scheduler, timer, wire, and UDP lifecycle tests. Strict
  `cargo clippy -p sail-netstack --all-targets -- -D warnings` is clean. Both
  are required by the macOS/Linux CI matrix.
- `cargo check -p sail-netstack` passes for `aarch64-apple-ios`,
  `x86_64-apple-darwin`, and `x86_64-pc-windows-msvc`; the complete leaf
  library also checks for iOS. A complete Windows leaf cross-check from this
  macOS host stops in `ring`/`aws-lc-sys` because Windows SDK C headers are not
  installed, before Rust reaches the native adapter.
- `cargo check -p sail-netstack --target aarch64-linux-android` passes. A
  read-only build-std run in the official cross-rs Android/NDK image also
  checks the complete default-feature `leaf` library and `sail-ffi` for
  `aarch64-linux-android`, including AWS-LC/ring, JNI, TUN dependencies, the
  native adapter, and the exported control API. The library emits only the
  pre-existing manifest warning that Android's target-specific `cc` dependency
  is unused. The existing Android CI job independently installs NDK 25.2 and
  builds the same FFI artifact. This is full compile evidence, not an Android
  device traffic or performance qualification.
- A read-only `mips-unknown-linux-musl` build-std run in the official cross-rs
  toolchain image exposed and then verified the removal of the only
  unconditional 64-bit atomic in `sail-netstack`: the denial counter now uses
  a saturating `AtomicUsize` while preserving the public `u64` snapshot field.
  `cargo check -p sail-netstack --locked -Z build-std=std,panic_abort --target
  mips-unknown-linux-musl` passes without warnings. The current 271-test
  library and integration suite, including the wire-validation and legacy
  zero-MTU PMTU cases, passes under the image's MIPS32 big-endian QEMU runner
  (latest run 271 of 271, including every fix in this revision).
  Protocol tests use a relaxed test-only scheduler time ceiling so emulation
  speed cannot masquerade as a packet/state failure; the production 2 ms
  ceiling and its dedicated scheduler test are unchanged. This proves the
  independent core compiles and executes its deterministic suite on the router
  architecture. On the pre-port tree, a complete library check with the
  Router feature set also passed once its unconditional `AtomicU64` traffic
  counters fell back to a mutex-guarded counter on targets without 64-bit
  atomics. That compatibility change was not carried to `dev`, where
  `stat_manager` and several newer protocols (AnyTLS, Hysteria2, TUIC) use
  `AtomicU64`; the complete-library MIPS32 check is open on `dev`. The
  integration itself keeps its network generation behind a mutex for this
  reason. None of this substitutes for a router firmware link/image build or
  target-hardware traffic/performance tests.
- `bench/netstack/run.py` now drives eight release-mode core workloads (packet
  parsing, UDP flow admission, TCP bulk/short wire paths, deterministic
  NewReno loss recovery, 64-flow byte-DRR, parameterized 1/2/4/8-shard
  routing, and hard memory pressure), measures each in an
  isolated child process, and
  emits the fixed schema-v1 JSONL including CPU time, peak RSS, and p50/p99.
  A ninth explicit `tcp-connection-churn` stress workload is deliberately
  excluded from the default/CI set. Every iteration performs a passive
  handshake, accept, orderly bidirectional FIN exchange, advances beyond the
  default 30-second virtual TIME-WAIT deadline, and verifies reclamation. It
  checks the complete ledger every 1,024 connections and retains at most
  100,000 latency samples. A local Router-profile release run completed
  1,000,000 connections (7,000,000 wire packets, zero drops) in 3.12 seconds
  with 4.81 MiB peak RSS and all flow/resource counters back at zero. The same
  workload completed 10,000 connections under MIPS32 big-endian QEMU with zero
  drops. These are deterministic core-lifecycle and portability gates, not
  substitutes for real endpoint or target-hardware connection-rate results.
  The shard workload now runs one actual `ShardedPacketIo` owner thread per
  shard over preloaded platform queues, including packet classification,
  bounded cross-shard forwarding, owner drain, and wake-capable adapters. It
  uses 16 packets per flow, 90% owner affinity, and 10% deliberate queue
  mismatch so the result measures the cached stable fast path and forwarding.
  The fixture stores one shared wire image per flow plus lightweight queue
  descriptors rather than preloading 100,000 full packet objects, reducing
  measured peak RSS from roughly 155 MiB of fixture-dominated memory to
  21–26 MiB. After replacing the global mutex with striped
  directory/per-shard queue locks and adding the shard-local cache, the latest
  100,000-packet 1/2/4/8 release run completed with zero drops in
  44.9/73.6/60.6/57.3 ms respectively. This
  userspace model shows the cached single-shard fast path clearly, along with
  non-linear coordination overhead at higher shard counts; it is evidence,
  not a claim of ideal scaling. Kernel-endpoint impaired-goodput, connection
  rate, production kernel queue scaling, and target-specific acceptance
  thresholds remain black-box performance gates.
  `bench/netstack/compare.py` now makes the target gate executable: it groups
  repeated schema-v1 records by profile/workload/MTU/shards, compares same-host
  medians, and fails on configurable duration, CPU, p99, RSS, or drop
  regressions (defaults 20%/20%/25%/15%/any increase). It rejects mixed-host,
  missing, non-finite, incorrectly typed, and out-of-range inputs before
  calculating medians. A self-comparison of all eight workloads passes;
  current local evidence includes two three-sample Router-profile groups at
  100,000 iterations and two three-sample iOS-single groups at 1,000,000
  iterations. Shorter iOS samples showed phase-dependent host noise, so the
  longer run is used to keep sub-millisecond workloads from turning tiny
  absolute jitter into misleading percentage failures; no threshold was
  relaxed. These simulated profile runs prove budget behavior and harness
  stability on the development Mac, not target-device performance.
  checked-in baselines still require representative
  iOS, router, desktop, and Linux server hardware rather than numbers from the
  development host. The runner can reuse one release driver for an exact repeat
  count or a wall-clock soak, flushing each schema record immediately; every
  child workload verifies that resource leases return to baseline, and a
  failing cycle terminates the soak without discarding prior records. A local
  30-second Desktop smoke completed 21 full eight-workload cycles (168 records)
  and passed schema validation; this validates the harness, not the required
  24-hour target-hardware soak.

`sail-netstack` is the only TUN engine, and privileged Linux coverage proves
real multi-queue/offload TCP and UDP round trips through the complete process
path, including FakeDNS, `Dispatcher`, and `NatManager`. It is not yet fully
release-qualified: macOS kernel coverage, Android device-path coverage, a
router firmware link/image and device-path build, 24-hour target-hardware
soak, and target-specific performance gates remain. There is no rollback
engine; a regression is fixed forward.

A dedicated x86_64 Linux host (Debian 13, kernel 6.12, 4 vCPU VM) now runs the
x64 and privileged gates from a synchronized copy of this worktree, committed
there as a provenance snapshot because `bench/netstack/run.py` records the
commit. At snapshot `055a2e8`, which contains every fix in this revision, it
passes the 257-test `sail-netstack` suite, strict Clippy, the default `leaf`
library suite (108 passed; 4 ignored privileged tests), and all three
privileged kernel tests (atomic GSO batch, multi-queue TCP/UDP impairment,
and the full process path through FakeDNS, `Dispatcher`, and `NatManager`),
the latter while the kernel soak below was running. The `linux-server` core
benchmark (three samples per group, zero drops) measured shard-routing
medians of 83.3, 76.9, and 48.6 ms for 1, 2, and 4 shards on this VM; that is
host evidence, not the target-server baseline. After the port, the `dev`
branch passes on the same host: the 258-test `sail-netstack` suite and its
strict Clippy, the `sail` library suite (362 passed on `dev` at `bd5680e`;
5 ignored privileged tests), all three privileged kernel tests, and Linux
Clippy with no warning in the ported files. `sail-ffi` also checks for `aarch64-apple-ios`.

The ignored `linux_native_kernel_soak` test keeps one TUN device and native
runtime alive and repeats real kernel traffic: a UDP round trip of 1 to 4,000
bytes (exercising fragmentation and reassembly) and a bidirectional TCP bulk
transfer of up to 256 KiB with an orderly close. It prints progress every
minute and, after traffic stops, requires every flow, TIME-WAIT, payload,
packet, fragment, and accept lease to return to zero; router metadata is a
bounded cache and is only reported. A 60-second debug run completed 1,190
iterations (313 MB) and reclaimed every counted resource. The first release
soak (snapshot `2757208`) was stopped after 20 minutes, 143,727 iterations,
and 38 GB because its ledger kept growing: the unbounded flow directory
described above. Its throughput also fell from 14,594 to about 5,200
iterations per minute, and RSS rose from 26.5 to 69 MiB. The only drops
were 8 policy drops, 6 of them host multicast datagrams rejected by the UDP
endpoint predicate, and no retransmission timeout occurred. Two 24-hour
soaks then restarted at 2026-09-25T23:24:42Z against snapshot `055a2e8`
(release build, directory bound included; a snapshot of the pre-port tree,
whose `sail-netstack` code is identical to `dev`'s but whose integration is
the pre-restructure one): this kernel-path soak, and the
core-workload soak `run.py --profile linux-server --duration-seconds 86400`,
which checks lease reclamation after every workload cycle. The core soak
stopped at 2026-09-26T00:54:20Z, after 18,592 records, when build
directories on the shared host filled its disk (a write failure, not a
workload failure); it restarted at 2026-09-26T00:55:43Z on the same
snapshot. The kernel soak failed at 2026-09-26T00:24:08Z, after 3,542 s,
149,329 iterations, and 39.7 GB at 38 MiB RSS and a steady 0.4 MB ledger,
because a concurrent verification run started another soak on the same
10.205.0.0/24 and the kernel routed that test's datagrams into this
device. That was a harness collision, not a stack failure: the soak, GSO,
and multi-queue tests now use distinct subnets (10.206, 10.207, 10.203). The
24-hour kernel soak restarted on the `dev` port at 2026-09-26T00:33:54Z
(release build) and ran 15,074 iterations (4.0 GB) in its first minute.

Every kernel soak so far also slowed down steadily while its ledger stayed
flat: from about 15,000 iterations per minute to about 30 within an hour,
with one CPU saturated and RSS creeping from 14 to 41 MiB. A fresh process
started beside a degraded one ran at full speed, so the cause was state the
process accumulated, not host contention. Stack samples from a symbolized
build (in `/root/sail-soak/run3-kernel-leak`) show the native runtime's
10 ms `retry_pending` pass over its `FlowBridge` map dominating after 15
minutes: the map grew by about one entry per connection. A step fired the
TIME-WAIT expiry, put the resulting `Closed` event in its local outcome,
and then awaited the idle device; the runtime dropped the step on the next
timer tick, so the event was lost and the bridge entry for that closed flow
was never removed. A step now returns its events before any await. TIME-WAIT
eviction, which removed the oldest entry without any event, and a flow that
could not get a TIME-WAIT slot now also report `Closed`.
`a_timer_event_survives_a_step_dropped_while_the_device_is_idle` polls each
step once and drops it the way the runtime does; it fails without the fix,
and the TIME-WAIT eviction test asserts the evicted flow's `Closed` event.
The leaking soak was stopped and the 24-hour kernel soak restarted on the
fixed code.
Completion status is appended to `/root/sail-soak/status`; the stopped and
interrupted runs' logs are kept in `/root/sail-soak/run1-prefix` and
`/root/sail-soak/run2-kernel-interrupted`. A VM soak does not replace the
24-hour soak on target router, mobile, and server hardware.

The ignored `macos_kernel_tcp_udp_round_trips` test now provides the missing
real-utun IPv4 UDP/TCP harness on an isolated `10.204.0.0/30`: it compiles on
the development Mac and uses the same native adapter plus acknowledged runtime
shutdown. Both sandboxed and unsandboxed execution reach utun configuration but
fail with `EPERM`; `sudo -n` confirms this host requires an administrator
password. Consequently this is a ready privileged gate, not evidence that the
macOS kernel path has passed yet.

## RFC coverage matrix

| Area | RFC / behavior | Status | Test oracle |
| --- | --- | --- | --- |
| TCP base | RFC 9293 | partial: passive flow table, handshake/receive/close/credit core, queued initial controls, bidirectional receive-window trimming, ordered FIN promotion; control-block active open (SYN-SENT, 3.10.7.3 checks, simultaneous open) | deterministic state/table model + independent smoltcp peer + Linux kernel peer |
| RTO | RFC 6298 | partial: estimator/backoff, timestamp RTTM, plain-TCP sequence probe, Karn ambiguity suppression | virtual clock and loss traces + deliberately dropped segment against Linux kernel peer |
| NewReno | RFC 5681, 6582 | partial: IW, slow start/CA, fast retransmit, partial/full ACK recovery, RTO collapse | state model + packet impairment model |
| SACK | RFC 2018, 6675 | implemented core: negotiated scoreboard, loss inference, Pipe/NextSeg hole scheduling, bounded rescue; independent and impaired Linux peers pass | scoreboard model + smoltcp peer + Linux peer |
| scaling/time | RFC 7323 | partial: negotiated scaling/timestamps, RTTM, PAWS sequence-space update rule and 24-day aging, unscaled SYN and SYN-ACK windows | option vectors, pure-ACK/data ordering, aging, RTTM and PAWS model |
| delayed ACK | RFC 9293 | implemented: first segment timer, second-segment/FIN/window-update cancellation | virtual timer and two-segment model |
| reset safety | RFC 5961 | partial: exact RST acceptance, in-window challenge, out-of-window silent drop, independent rate limit | three-way RST classification vectors and virtual-time limiter |
| ISN | RFC 6528 | keyed tuple/generation hash plus wrapping 4-microsecond monotonic component | reconnect/time vectors |
| IPv4/IPv6 fragments | RFC 8200 / RFC 6946 | partial: budgeted reassembly, overlap drop, atomic pass-through, expiry, atomic UDP source fragmentation | overlap/atomic fragment corpus + reassembly round trip |
| ICMP/PMTU | RFC 792 / RFC 4443 / RFC 1191 / RFC 8201 | partial: echo/errors, suppression/rate limit, authenticated budgeted PMTU cache, UDP/TCP new-send enforcement | checksum/error vectors + runner wire capture |

## Baseline commands

```sh
cargo test -p sail-netstack
cargo test -p sail --lib
(cd sail-netstack && cargo +nightly fuzz run wire_parse)
(cd sail-netstack && cargo +nightly fuzz run fragment_reassembly)
cargo test -p sail --lib linux_kernel_accepts_one_atomic_tcp_gso_frame_for_a_complete_batch -- --ignored # privileged Linux
cargo test -p sail --lib linux_multiqueue_kernel_tcp_udp_round_trips -- --ignored # privileged Linux
cargo test -p sail --lib linux_default_native_process_dispatcher_nat_fakedns_round_trips -- --ignored # privileged Linux
SAIL_NETSTACK_SOAK_SECONDS=86400 cargo test --release -p sail --lib linux_native_kernel_soak -- --ignored --nocapture # privileged Linux soak
python3 bench/netstack/run.py --profile linux-server --duration-seconds 86400 --output soak.jsonl
(cd sail-netstack && cargo +nightly fuzz run tcp_state -- -jobs=6 -workers=6 -max_total_time=1800)
(cd sail-netstack && cargo +nightly fuzz run tcp_table -- -jobs=6 -workers=6 -max_total_time=1800)
(cd sail-netstack && TCP_TABLE_TRACE=1 cargo +nightly fuzz run tcp_table ARTIFACT) # replay with an operation trace
# MIPS32 big-endian, in ghcr.io/cross-rs/mips-unknown-linux-musl:main with a nightly toolchain,
# CARGO_TARGET_MIPS_UNKNOWN_LINUX_MUSL_LINKER=mips-linux-muslsf-gcc and _RUNNER=qemu-mips:
cargo test -p sail-netstack --locked -Z build-std=std,panic_abort --target mips-unknown-linux-musl --no-fail-fast
cargo test -p sail --lib macos_kernel_tcp_udp_round_trips -- --ignored # privileged macOS
python3 bench/netstack/run.py --profile desktop --iterations 100000
python3 bench/netstack/compare.py --baseline BASELINE.jsonl --candidate CANDIDATE.jsonl
(cd bench/core-compare && ./run.py --group ios --rounds 5)
(cd bench/core-compare && ./run.py --group desktop --rounds 5)
```

The first two are local merge checks. The `bench/` commands need the local-only
benchmark directory, which is not in the repository. Core-compare may require generated TLS
material and external binaries; record exact host metadata and failures rather
than substituting proxy-only numbers for TUN packet-path measurements.
