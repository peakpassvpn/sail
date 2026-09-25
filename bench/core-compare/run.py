#!/usr/bin/env python3
"""Compare leaf and sing-box as local SOCKS5 clients.

Topology (all on 127.0.0.1):

    loadgen --socks5--> client under test (:1081) --direct or shadowsocks--> sing-box ss server (:8388) --> sink (:9000)

For every client config the harness records, per phase, the client's peak RSS
(sampled at 10 Hz), its CPU time, and phys_footprint snapshots (the metric iOS
uses to kill a Network Extension) at idle, with all concurrent connections open,
and after the load has stopped.

Usage: ./run.py [--group desktop|ios] [--rounds 3] [--leaf PATH] [--singbox PATH] [--out FILE]
"""

import argparse
import json
import os
import re
import resource
import socket
import statistics
import subprocess
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONFIGS = HERE / "configs"
LOADGEN = HERE / "loadgen" / "loadgen"
PROXY = "127.0.0.1:1081"
TARGET = "127.0.0.1:9000"

# name -> (command, extra env), per group.
def clients(group, leaf, singbox, singbox_lowmem, base_leaf=None, base_configs=None):
    if group == "regression":
        # The build under test against a baseline build, which reads the
        # configuration format of its own commit from base_configs.
        rows = []
        for label, path, configs in (("base", base_leaf, Path(base_configs)), ("new", leaf, CONFIGS)):
            for proto in ("direct", "ss"):
                cfg = configs / f"client-leaf-{proto}.json"
                rows.append((f"{label}/{proto}", [path, "-c", cfg], {}))
                rows.append((f"{label}/{proto} 1T", [path, "--single-thread", "-c", cfg], {}))
        return rows
    if group == "desktop":
        return [
            ("leaf/direct", [leaf, "-c", CONFIGS / "client-leaf-direct.json"], {}),
            ("sing-box/direct", [singbox, "run", "-c", CONFIGS / "client-singbox-direct.json"], {}),
            ("leaf/ss", [leaf, "-c", CONFIGS / "client-leaf-ss.json"], {}),
            # sing-box relays with 32 KB buffers; leaf starts at 16 KB and grows to 128 KB on bulk transfers.
            ("leaf/ss fixed 16K",
             [leaf, "--set", "relay.buffer_max_size=16", "-c", CONFIGS / "client-leaf-ss.json"], {}),
            ("sing-box/ss", [singbox, "run", "-c", CONFIGS / "client-singbox-ss.json"], {}),
        ]
    # Mirrors how each core runs inside an iOS Network Extension: libbox is built
    # with with_low_memory (16 KB buffers) and sets GOGC=10 and a 45 MiB limit
    # (experimental/libbox/memory.go); leaf apps typically use a single thread.
    return [
        ("leaf/ss 1T", [leaf, "--single-thread", "-c", CONFIGS / "client-leaf-ss.json"], {}),
        ("leaf/ss 1T init=2K",
         [leaf, "--single-thread", "--set", "relay.buffer_size=2", "-c", CONFIGS / "client-leaf-ss.json"], {}),
        ("sing-box/ss lowmem", [singbox_lowmem, "run", "-c", CONFIGS / "client-singbox-ss.json"],
         {"GOGC": "10", "GOMEMLIMIT": "45MiB"}),
    ]

PHASES = [
    ("throughput_down", ["throughput", "-streams", "8", "-bytes", str(64 << 20), "-dir", "down"]),
    ("throughput_up", ["throughput", "-streams", "8", "-bytes", str(64 << 20), "-dir", "up"]),
    ("latency", ["latency", "-n", "500"]),
    ("concurrent", ["concurrent", "-conns", "2000", "-hold", "5s"]),
]


def wait_port(addr, timeout=15):
    host, port = addr.rsplit(":", 1)
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            socket.create_connection((host, int(port)), 0.2).close()
            return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"{addr} did not come up")


def wait_port_free(addr, timeout=15):
    host, port = addr.rsplit(":", 1)
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            socket.create_connection((host, int(port)), 0.2).close()
            time.sleep(0.1)
        except OSError:
            return
    raise RuntimeError(f"{addr} still in use")


def wait_time_wait_drain(limit=3000, timeout=90):
    """Short-lived connections leave sockets in TIME_WAIT, which can exhaust
    macOS's 16k ephemeral ports and make loadgen itself fail to dial."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        out = subprocess.run(["netstat", "-an", "-p", "tcp"], capture_output=True, text=True).stdout
        ours = [l for l in out.splitlines() if "TIME_WAIT" in l
                and any(f".{port} " in l for port in ("1081", "8388", "9000"))]
        if len(ours) < limit:
            return
        time.sleep(1)


def rss_kb(pid):
    out = subprocess.run(["ps", "-o", "rss=", "-p", str(pid)], capture_output=True, text=True).stdout.strip()
    return int(out) if out else 0


def cpu_seconds(pid):
    # Linux: utime + stime from /proc, in clock ticks; ps only has seconds.
    stat = Path(f"/proc/{pid}/stat")
    if stat.exists():
        fields = stat.read_text().rsplit(")", 1)[1].split()
        return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")
    # ps cputime: [[dd-]hh:]mm:ss.ss
    out = subprocess.run(["ps", "-o", "cputime=", "-p", str(pid)], capture_output=True, text=True).stdout.strip()
    days, _, rest = out.rpartition("-")
    parts = [float(p) for p in rest.split(":")]
    secs = 0.0
    for p in parts:
        secs = secs * 60 + p
    return secs + (int(days) * 86400 if days else 0)


def footprint_mb(pid):
    # macOS only; elsewhere RSS is what there is.
    try:
        out = subprocess.run(["footprint", "-p", str(pid)], capture_output=True, text=True).stdout
    except FileNotFoundError:
        return None
    m = re.search(r"Footprint:\s*([\d.]+)\s*(KB|MB|GB)", out)
    if not m:
        return None
    return float(m.group(1)) * {"KB": 1 / 1024, "MB": 1, "GB": 1024}[m.group(2)]


class Sampler(threading.Thread):
    """Tracks the peak RSS of a process until stopped."""

    def __init__(self, pid):
        super().__init__(daemon=True)
        self.pid, self.peak_kb, self._stop = pid, 0, threading.Event()

    def run(self):
        while not self._stop.is_set():
            self.peak_kb = max(self.peak_kb, rss_kb(self.pid))
            time.sleep(0.1)

    def stop(self):
        self._stop.set()
        self.join()
        return self.peak_kb / 1024


def run_phase(pid, args):
    wait_time_wait_drain()
    sampler = Sampler(pid)
    sampler.start()
    cpu0 = cpu_seconds(pid)
    proc = subprocess.Popen([LOADGEN, *args, "-proxy", PROXY, "-target", TARGET],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    fp_hold = None
    if args[0] == "concurrent":
        # Snapshot the footprint once every connection is open.
        for line in proc.stderr:
            if line.startswith("HOLDING"):
                time.sleep(1)
                fp_hold = footprint_mb(pid)
                break
    out, err = proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(f"loadgen {args[0]} failed: {err}")
    result = json.loads(out)
    result["cpu_seconds"] = cpu_seconds(pid) - cpu0
    result["peak_rss_mb"] = sampler.stop()
    if fp_hold is not None:
        result["footprint_hold_mb"] = fp_hold
    return result


def run_client(name, cmd, env):
    wait_port_free(PROXY)
    proc = subprocess.Popen([str(c) for c in cmd], env={**os.environ, **env},
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        wait_port(PROXY)
        time.sleep(1)
        res = {"idle_rss_mb": rss_kb(proc.pid) / 1024, "idle_footprint_mb": footprint_mb(proc.pid)}
        for phase, args in PHASES:
            print(f"  {name}: {phase}", file=sys.stderr, flush=True)
            res[phase] = run_phase(proc.pid, args)
        time.sleep(3)
        res["after_rss_mb"] = rss_kb(proc.pid) / 1024
        res["after_footprint_mb"] = footprint_mb(proc.pid)
        return res
    finally:
        proc.terminate()
        try:
            proc.wait(10)
        except subprocess.TimeoutExpired:
            proc.kill()


def median_of(runs, path):
    vals = []
    for r in runs:
        v = r
        for k in path:
            v = v.get(k) if isinstance(v, dict) else None
        if isinstance(v, (int, float)):
            vals.append(v)
    return statistics.median(vals) if vals else None


def summarize(results):
    rows = [
        ("空闲内存 RSS (MB)", ("idle_rss_mb",), "{:.1f}"),
        ("空闲 footprint (MB)", ("idle_footprint_mb",), "{:.1f}"),
        ("下行吞吐 (MB/s)", ("throughput_down", "mbps"), "{:.0f}"),
        ("下行 CPU (秒/GB)", ("throughput_down", "cpu_per_gb"), "{:.2f}"),
        ("下行峰值 RSS (MB)", ("throughput_down", "peak_rss_mb"), "{:.1f}"),
        ("上行吞吐 (MB/s)", ("throughput_up", "mbps"), "{:.0f}"),
        ("上行 CPU (秒/GB)", ("throughput_up", "cpu_per_gb"), "{:.2f}"),
        ("上行峰值 RSS (MB)", ("throughput_up", "peak_rss_mb"), "{:.1f}"),
        ("新建连接 p50 (ms)", ("latency", "p50_ms"), "{:.3f}"),
        ("新建连接 p99 (ms)", ("latency", "p99_ms"), "{:.3f}"),
        ("已建连接 RTT p50 (ms)", ("latency", "rtt_p50_ms"), "{:.3f}"),
        ("已建连接 RTT p99 (ms)", ("latency", "rtt_p99_ms"), "{:.3f}"),
        ("2000 并发峰值 RSS (MB)", ("concurrent", "peak_rss_mb"), "{:.1f}"),
        ("2000 并发 footprint (MB)", ("concurrent", "footprint_hold_mb"), "{:.1f}"),
        ("2000 并发建连耗时 (s)", ("concurrent", "open_seconds"), "{:.2f}"),
        ("并发失败数", ("concurrent", "failures"), "{:.0f}"),
        ("负载结束 3s 后 RSS (MB)", ("after_rss_mb",), "{:.1f}"),
        ("负载结束 3s 后 footprint (MB)", ("after_footprint_mb",), "{:.1f}"),
    ]
    names = list(results)
    lines = ["| 指标 | " + " | ".join(names) + " |", "| --- |" + " --- |" * len(names)]
    for label, path, fmt in rows:
        cells = []
        for n in names:
            v = median_of(results[n], path)
            cells.append(fmt.format(v) if v is not None else "-")
        lines.append(f"| {label} | " + " | ".join(cells) + " |")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=1)
    ap.add_argument("--leaf", default=str(HERE.parents[1] / "target" / "release" / "leaf"))
    ap.add_argument("--singbox", default="sing-box")
    ap.add_argument("--singbox-lowmem", default=str(HERE / "bin" / "sing-box-lowmem"))
    ap.add_argument("--group", choices=["desktop", "ios", "regression"], default="desktop")
    ap.add_argument("--base-leaf", help="regression: the baseline leaf binary")
    ap.add_argument("--base-configs", help="regression: its client configs directory")
    ap.add_argument("--out")
    a = ap.parse_args()

    # Each proxied connection holds two sockets, plus the sink's and loadgen's.
    resource.setrlimit(resource.RLIMIT_NOFILE, (65536, 65536))

    sink = subprocess.Popen([LOADGEN, "sink", "-listen", TARGET])
    server = subprocess.Popen([a.singbox, "run", "-c", CONFIGS / "server-singbox.json"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    results = {}
    try:
        wait_port(TARGET)
        wait_port("127.0.0.1:8388")
        if a.group == "regression" and not (a.base_leaf and a.base_configs):
            ap.error("--group regression needs --base-leaf and --base-configs")
        cl = clients(a.group, a.leaf, a.singbox, a.singbox_lowmem, a.base_leaf, a.base_configs)
        for rnd in range(a.rounds):
            # Alternate the order so neither side always runs on a warmer machine.
            order = cl if rnd % 2 == 0 else list(reversed(cl))
            for name, cmd, env in order:
                print(f"round {rnd + 1}/{a.rounds}", file=sys.stderr)
                r = run_client(name, cmd, env)
                for ph in ("throughput_down", "throughput_up"):
                    r[ph]["cpu_per_gb"] = r[ph]["cpu_seconds"] / (r[ph]["bytes"] / 1e9)
                results.setdefault(name, []).append(r)
    finally:
        server.terminate()
        sink.terminate()

    Path(a.out or HERE / f"results-{a.group}.json").write_text(json.dumps(results, indent=2, ensure_ascii=False))
    print(summarize(results))


if __name__ == "__main__":
    main()
