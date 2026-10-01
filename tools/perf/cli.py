#!/usr/bin/env python3
"""sail-cli's numbers for the performance regression checks (roadmap 5.4).

For each profile, on loopback (Linux): starts a measurement build of sail
(`cargo build -p sail-cli --release --features alloc-stats`) with a SOCKS
inbound and a direct outbound, drives netgen's load through it, and prints
one line per profile and round:

    PERF {"profile": ..., "round": ..., "idle_rss_kb", "held_kb_per_connection",
          "allocations_per_connection", "allocations_per_mib",
          "allocated_bytes_per_mib", "peak_rss_kb"}

    tools/perf/cli.py --sail target/release/sail --netgen netgen \\
        [--profiles desktop,server,router] [--rounds 5]

Allocations are counted by the build's allocator (sail/src/alloc_stats.rs),
read from the file SAIL_ALLOC_STATS names before and after each load.
"""

import argparse
import json
import os
import socket
import subprocess
import sys
import tempfile
import time

# Loads, as the design gives them (judgment, calibrated at its step 1).
SHORT_CONNECTIONS = 200
BULK_STREAMS = 4
BULK_BYTES = 64 << 20
HELD = 2000
SETTLE = 3.0
# The counts file is rewritten every 100 ms.
COUNTS_SETTLE = 0.5


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def rss_kb(pid):
    with open(f"/proc/{pid}/status") as f:
        for line in f:
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    raise RuntimeError("no VmRSS")


def peak_rss_kb(pid):
    with open(f"/proc/{pid}/status") as f:
        for line in f:
            if line.startswith("VmHWM:"):
                return int(line.split()[1])
    raise RuntimeError("no VmHWM")


def counts(path):
    time.sleep(COUNTS_SETTLE)
    with open(path) as f:
        c = json.load(f)
    return c["allocations"], c["bytes"]


def wait_port(port, limit=10.0):
    end = time.time() + limit
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"nothing listens on {port}")


def netgen(binary, *args):
    out = subprocess.run([binary, *args], capture_output=True, text=True, check=True)
    result = json.loads(out.stdout)
    if result.get("failed") or result.get("corrupt"):
        raise RuntimeError(f"netgen {args[0]}: {result}")
    return result


def measure(sail, net, profile, work):
    serve_port, socks_port = free_port(), free_port()
    server = subprocess.Popen(
        [net, "serve", "-listen", f"127.0.0.1:{serve_port}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    config = os.path.join(work, f"{profile}.json")
    with open(config, "w") as f:
        json.dump(
            {
                "log": {"level": "warn"},
                "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": socks_port}],
                "outbounds": [{"type": "direct"}],
            },
            f,
        )
    stats = os.path.join(work, f"{profile}.counts")
    env = dict(os.environ, SAIL_ALLOC_STATS=stats)
    proc = subprocess.Popen(
        [sail, "-c", config, "--profile", profile],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        wait_port(serve_port)
        wait_port(socks_port)
        proxy, target = f"127.0.0.1:{socks_port}", f"127.0.0.1:{serve_port}"
        time.sleep(SETTLE)
        idle = rss_kb(proc.pid)

        # Held first, before a load leaves freed memory for it to take.
        held = subprocess.Popen(
            [net, "concurrent", "-proxy", proxy, "-target", target,
             "-conns", str(HELD), "-hold", f"{int(SETTLE * 3)}s"],
            stdout=subprocess.PIPE,
            text=True,
        )
        time.sleep(SETTLE * 2)
        during = rss_kb(proc.pid)
        out, _ = held.communicate()
        result = json.loads(out)
        if result.get("failed") or result.get("corrupt"):
            raise RuntimeError(f"netgen concurrent: {result}")
        time.sleep(SETTLE)

        before = counts(stats)
        netgen(net, "setup", "-proxy", proxy, "-target", target, "-n", str(SHORT_CONNECTIONS))
        short = counts(stats)

        for direction in ("down", "up"):
            netgen(net, "bulk", "-proxy", proxy, "-target", target,
                   "-streams", str(BULK_STREAMS), "-bytes", str(BULK_BYTES), "-dir", direction)
        bulk = counts(stats)
        mib = BULK_STREAMS * BULK_BYTES * 2 / (1 << 20)

        return {
            "profile": profile,
            "idle_rss_kb": idle,
            "held_kb_per_connection": (during - idle) / HELD,
            "allocations_per_connection": (short[0] - before[0]) / SHORT_CONNECTIONS,
            "allocations_per_mib": (bulk[0] - short[0]) / mib,
            "allocated_bytes_per_mib": (bulk[1] - short[1]) / mib,
            "peak_rss_kb": peak_rss_kb(proc.pid),
        }
    finally:
        proc.terminate()
        server.terminate()
        proc.wait(10)
        server.wait(10)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--sail", required=True, help="a build with --features alloc-stats")
    parser.add_argument("--netgen", required=True)
    parser.add_argument("--profiles", default="desktop,server,router")
    parser.add_argument("--rounds", type=int, default=5)
    args = parser.parse_args()
    if not os.path.exists("/proc/self/status"):
        sys.exit("cli.py measures on Linux: it reads /proc")
    with tempfile.TemporaryDirectory(prefix="sail-perf-") as work:
        for rnd in range(1, args.rounds + 1):
            for profile in args.profiles.split(","):
                row = measure(args.sail, args.netgen, profile, work)
                row["round"] = rnd
                print("PERF " + json.dumps(row), flush=True)


if __name__ == "__main__":
    main()
