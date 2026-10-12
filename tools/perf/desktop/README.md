# The desktop cell

sail against sing-box as a local client, on the system it runs on. sail's
other throughput and CPU numbers are Linux's; this cell is for Windows and
macOS, and runs on Linux too.

## What it measures

On loopback, nothing else:

    netgen bulk -> SOCKS inbound of the client -> protocol -> sing-box server -> netgen serve

- Protocols: Trojan over TLS, VLESS with REALITY and vision, Hysteria2.
- The client is sail (its default preset, desktop) or sing-box; the server
  is the same sing-box for both.
- Each turn moves 4 streams × 256 MiB up, then down. netgen checks every
  byte, so a transfer that came short or corrupt is a failure, not a number.
- Per transfer: Mbit/s (netgen's), the client's CPU seconds per GiB (user +
  system of its process, read by psutil before and after) and its peak
  resident size (sampled every 0.2 s).
- 3 rounds. In each, both clients run one after the other; sail first in
  odd rounds, sing-box first in even ones.
- Several builds of sail can be compared in one run, or one build started
  with different arguments (below). Each runs in every round and sing-box
  once; each round starts one client further on.

The certificate and the REALITY keys are made at each run by
`sing-box generate`. REALITY's handshake target is a TLS inbound of the
same local server. Hysteria2 has no `up_mbps` or `down_mbps` on either
side, so both clients and the server use BBR.

## Running it

    pip install psutil
    (cd scripts/netem/netgen && go build -o ../../../bin/ .)
    cargo build --profile dist -p sail-cli
    python3 tools/perf/desktop/run.py --sail target/dist/sail --sing-box PATH/sing-box \
        --netgen bin/netgen --work cell-work

`--protocols`, `--streams`, `--bytes`, `--rounds` and `--out` (default
`results.json`) change the defaults above. On Windows the `.exe` suffix
may be left out. The Markdown table goes to stdout, each transfer's line to
stderr, and every sample to the JSON file; configs and logs stay in
`--work`.

It exits 1 when a transfer of sail's failed. A transfer of sing-box's that
failed is listed under the tables as a warning, and its round has no ratio
(a ratio no round gave is shown as –); it does not fail the run.

To compare builds of sail, name each: `--sail NAME=PATH`, as often as
there are builds. A bare `PATH` is named `sail`. There is a table for each
build, with its ratios to the sing-box of the same round:

    python3 tools/perf/desktop/run.py --sail sail=target/dist/sail \
        --sail sail-mimalloc=other/sail --sing-box PATH/sing-box \
        --netgen bin/netgen --work cell-work

One build serves several of them when they differ only by sail's
arguments: `--sail-args NAME=ARGS`, once for each name that has any. ARGS is
split as a shell splits it and appended to that one's command line, after
the cell's own arguments; the report says who was started with what:

    python3 tools/perf/desktop/run.py --sail sail=target/dist/sail \
        --sail sail-buf7m=target/dist/sail \
        --sail-args "sail-buf7m=--set quic.udp_receive_buffer=7168 --set quic.udp_send_buffer=7168" \
        --sing-box PATH/sing-box --netgen bin/netgen --work cell-work

On GitHub: the workflow `perf-desktop`, by hand, with `os` = `windows` (the
default), `macos` or `both`. The tables are in the job's summary and
`results.json` in its artifact. Its input `builds` says what is compared.

`buffers`, the default: one build at the dist profile, started four ways,
over Hysteria2 alone and for five rounds. sail leaves the UDP sockets of
QUIC the system's buffers unless told otherwise, and Windows' are 64 KiB:

- `sail`: as it ships, the system's buffers;
- `sail-buf1m`: `quic.udp_receive_buffer` and `quic.udp_send_buffer` at
  1024 KiB, as Chromium asks;
- `sail-buf7m`: both at 7168 KiB, as sing-box's QUIC asks;
- `sail-rcv7m`: the receive buffer alone at 7168 KiB.

The summary also says what the runner gives a socket that asks for those
sizes. The buffers are all that is varied: Windows' UDP receive offload
(URO) is not a candidate, as it corrupts datagrams on some Windows 11
systems.

`allocators`: all three protocols; on macOS its one build, and on Windows
three builds of the commit, all at the dist profile:

- `sail`: MSVC, the system's allocator;
- `sail-mimalloc`: the same with mimalloc, built with
  `RUSTFLAGS="--cfg sail_measure_mimalloc"`. That is sail-cli's measurement
  switch: no release is built with it, and without it nothing changes;
- `sail-gnu`: the `x86_64-pc-windows-gnu` cross build, which is what a
  release ships for Windows, built on Linux as a release builds it.

Between builds, compare their ratios to sing-box, or their own columns of
the same run.

## Reading it

Each cell is the median of the rounds, with the smallest and largest in
brackets.

The two ratios are computed per round, from the two clients' transfers of
that round, and the median of those is shown; so a ratio is not exactly
one column's median divided by the other's. **Above 1 is better for sail in
both:**

- throughput: sail ÷ sing-box;
- CPU: sing-box ÷ sail. It is inverted, since less CPU per GiB is better:
  1.25 says sing-box spent a quarter more CPU than sail on the same bytes.

Read the ratios, not the absolute numbers: a hosted runner's speed differs
between runs and during one, and its loopback is not a network. A ratio
whose bracket spans 1 says nothing either way; run it again, or with more
rounds. Throughput here is bounded by whichever of the client, the server
and netgen is slowest on the runner's few cores, so CPU per GiB is the
steadier of the two. The server's CPU per GiB is in the JSON
(`server_cpu_s_per_gib`), to see when it was the server.
