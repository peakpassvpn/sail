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
`--work`. It exits 1 when a transfer failed.

On GitHub: the workflow `perf-desktop`, by hand, with `os` = `windows` (the
default), `macos` or `both`. The table is in the job's summary and
`results.json` in its artifact.

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
