#!/usr/bin/env python3
"""The desktop cell: sail against sing-box as a local client, on the
system it runs on (Windows, macOS or Linux).

On loopback: netgen -> SOCKS inbound of the client -> protocol -> a
sing-box server -> netgen's server. The server is the same sing-box for
every client. For each protocol and round the clients run one after the
other, in an order that turns by round; each moves `--streams` x
`--bytes` up, then down, and its process's CPU time (user + system, its
children's too) is read before and after each transfer.

    pip install psutil
    python3 tools/perf/desktop/run.py --sail PATH --sing-box PATH --netgen PATH --work DIR \\
        [--protocols trojan,reality,hysteria2] [--streams 4] [--bytes 268435456] \\
        [--rounds 3] [--out results.json] [--sail-args NAME=ARGS ...]

Several builds of sail are compared in one run by naming each:
`--sail NAME=PATH`, as often as there are builds (a bare PATH is named
`sail`). Each runs in every round, with sing-box once, the reference.
One build serves several of them when they differ by sail's arguments:
`--sail-args NAME=ARGS` appends ARGS, split as a shell would, to that
one's command line, as in `--sail-args "big=--set quic.udp_receive_buffer=7168"`.

It prints a Markdown table for each build of sail (medians, the range in
brackets, and that build against the sing-box of the same round as
ratios), writes the same and every sample as JSON, and on GitHub appends
the tables to the job's summary. It exits 1 when a transfer of sail's
failed. One of sing-box's that failed is a warning in the report, and its
round has no ratio: the reference failing says nothing about sail.

Only the standard library and psutil. Nothing leaves loopback: the keys,
the certificate and REALITY's handshake target are made here.
"""

import argparse
import json
import os
import platform
import re
import secrets
import shlex
import socket
import statistics
import subprocess
import sys
import threading
import time

try:
    import psutil
except ImportError:
    sys.exit("psutil is needed for a process's CPU time: pip install psutil")

WINDOWS = os.name == "nt"
LOCAL = "127.0.0.1"
PASSWORD = "desktop-cell-password"
UUID = "9b2b4b81-6125-4a7c-9a83-847cb325758f"
PROTOCOLS = ("trojan", "reality", "hysteria2")
# The reference client: every build of sail is read against it.
REFERENCE = "sing-box"
# A build's name is part of file names and of a table's headings.
VARIANT_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
DIRECTIONS = ("up", "down")
GIB = 1 << 30
# Before the measured transfers: the chain works, and its connections' first
# handshakes are not in the numbers.
WARMUP_BYTES = 1 << 20


def executable(path):
    """The path as given, or with Windows' suffix when only that one exists."""
    if WINDOWS and not os.path.isfile(path) and os.path.isfile(path + ".exe"):
        path += ".exe"
    if not os.path.isfile(path):
        sys.exit(f"no such file: {path}")
    return os.path.abspath(path)


def free_port(udp=False):
    """A loopback port nothing holds now. Each is asked for once, right
    before its listener starts."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM) as s:
        s.bind((LOCAL, 0))
        return s.getsockname()[1]


def wait_port(port, proc, limit=20.0):
    end = time.monotonic() + limit
    while time.monotonic() < end:
        if not proc.alive():
            raise RuntimeError(f"{proc.name} exited with {proc.p.returncode}: see {proc.log_path}")
        try:
            socket.create_connection((LOCAL, port), timeout=0.5).close()
            return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"{proc.name}: nothing listens on {LOCAL}:{port} after {limit:.0f} s")


# ------------------------------------------------------------- processes
class Proc:
    """A child in a process group of its own, its output in a log file."""

    def __init__(self, name, argv, log_path):
        self.name = name
        self.log_path = log_path
        self.log = open(log_path, "ab")
        kwargs = {}
        if WINDOWS:
            # No Ctrl-C of the console reaches it; it is ended by stop().
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            kwargs["start_new_session"] = True
        self.p = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=self.log,
                                  stderr=subprocess.STDOUT, **kwargs)
        try:
            self.ps = psutil.Process(self.p.pid)
        except psutil.Error:
            self.ps = None

    def alive(self):
        return self.p.poll() is None

    def family(self):
        """The process and whatever it started."""
        if self.ps is None:
            return []
        try:
            return [self.ps] + self.ps.children(recursive=True)
        except psutil.Error:
            return [self.ps]

    def cpu_seconds(self):
        total = 0.0
        for proc in self.family():
            try:
                times = proc.cpu_times()
                total += times.user + times.system
            except psutil.Error:
                pass
        return total

    def rss(self):
        total = 0
        for proc in self.family():
            try:
                total += proc.memory_info().rss
            except psutil.Error:
                pass
        return total

    def stop(self):
        family = self.family()[1:]
        if self.alive():
            # SIGTERM, or TerminateProcess on Windows, which has no softer
            # way to end a process without a console.
            self.p.terminate()
            try:
                self.p.wait(5)
            except subprocess.TimeoutExpired:
                self.p.kill()
                self.p.wait()
        for child in family:
            try:
                child.kill()
            except psutil.Error:
                pass
        self.log.close()


class RssPeak(threading.Thread):
    """The largest resident size seen of a process while a transfer runs."""

    def __init__(self, proc, interval=0.2):
        super().__init__(daemon=True)
        self.proc = proc
        self.interval = interval
        self.peak = proc.rss()
        self.done = threading.Event()

    def run(self):
        while not self.done.wait(self.interval):
            self.peak = max(self.peak, self.proc.rss())

    def finish(self):
        self.done.set()
        self.join()
        self.peak = max(self.peak, self.proc.rss())
        return self.peak


# ------------------------------------------------------------- keys
def generate(sing_box, *args):
    return subprocess.run([sing_box, "generate", *args], check=True,
                          capture_output=True, text=True).stdout


def make_keys(sing_box, work):
    """A self-signed certificate for localhost and a REALITY key pair, by
    sing-box's own subcommands: Python's ssl makes neither."""
    pem = generate(sing_box, "tls-keypair", "localhost")
    blocks = {}
    current = None
    for line in pem.splitlines():
        if line.startswith("-----BEGIN "):
            current = "key" if "PRIVATE KEY" in line else "cert"
            blocks.setdefault(current, [])
        if current:
            blocks[current].append(line)
        if line.startswith("-----END "):
            current = None
    if not blocks.get("key") or not blocks.get("cert"):
        sys.exit("sing-box generate tls-keypair: no key and certificate in its output")
    paths = {}
    for kind in ("key", "cert"):
        paths[kind] = os.path.join(work, f"{kind}.pem")
        with open(paths[kind], "w", newline="\n") as f:
            f.write("\n".join(blocks[kind]) + "\n")
    reality = dict(line.split(": ", 1) for line in generate(sing_box, "reality-keypair").splitlines()
                   if ": " in line)
    return {"cert": paths["cert"], "key": paths["key"],
            "reality_private": reality["PrivateKey"].strip(),
            "reality_public": reality["PublicKey"].strip(),
            "reality_short_id": secrets.token_hex(8)}


# ------------------------------------------------------------- configs
# The shapes are scripts/netem/run.py's; sail reads sing-box's JSON as it is.
def server_config(proto, keys, port, handshake_port):
    tls = {"enabled": True, "server_name": "localhost",
           "certificate_path": keys["cert"], "key_path": keys["key"]}
    inbounds = []
    if proto == "trojan":
        inbounds.append({"type": "trojan", "listen": LOCAL, "listen_port": port,
                         "users": [{"password": PASSWORD}], "tls": tls})
    elif proto == "reality":
        # REALITY borrows a real TLS 1.3 server's handshake. A local one: a
        # TLS inbound of the same server, which no client of the cell dials.
        inbounds.append({"type": "trojan", "tag": "handshake-target", "listen": LOCAL,
                         "listen_port": handshake_port,
                         "users": [{"password": secrets.token_hex(16)}], "tls": tls})
        inbounds.append({"type": "vless", "listen": LOCAL, "listen_port": port,
                         "users": [{"uuid": UUID, "flow": "xtls-rprx-vision"}],
                         "tls": {"enabled": True, "server_name": "localhost",
                                 "reality": {"enabled": True,
                                             "handshake": {"server": LOCAL,
                                                           "server_port": handshake_port},
                                             "private_key": keys["reality_private"],
                                             "short_id": [keys["reality_short_id"]]}}})
    elif proto == "hysteria2":
        # No up_mbps or down_mbps on either side: BBR both ways, for both
        # clients, and not Brutal at a rate guessed for a runner's loopback.
        inbounds.append({"type": "hysteria2", "listen": LOCAL, "listen_port": port,
                         "users": [{"password": PASSWORD}], "tls": tls})
    else:
        raise ValueError(proto)
    return {"log": {"level": "warn"}, "inbounds": inbounds,
            "outbounds": [{"type": "direct"}]}


def client_config(proto, keys, port, socks_port):
    insecure = {"enabled": True, "server_name": "localhost", "insecure": True}
    if proto == "trojan":
        out = {"type": "trojan", "server": LOCAL, "server_port": port,
               "password": PASSWORD, "tls": insecure}
    elif proto == "reality":
        out = {"type": "vless", "server": LOCAL, "server_port": port, "uuid": UUID,
               "flow": "xtls-rprx-vision",
               "tls": {"enabled": True, "server_name": "localhost",
                       "utls": {"enabled": True, "fingerprint": "chrome"},
                       "reality": {"enabled": True, "public_key": keys["reality_public"],
                                   "short_id": keys["reality_short_id"]}}}
    elif proto == "hysteria2":
        out = {"type": "hysteria2", "server": LOCAL, "server_port": port,
               "password": PASSWORD, "tls": insecure}
    else:
        raise ValueError(proto)
    out["tag"] = "out"
    return {"log": {"level": "warn"},
            "inbounds": [{"type": "socks", "listen": LOCAL, "listen_port": socks_port}],
            "outbounds": [out]}


def write_json(path, value):
    with open(path, "w", newline="\n") as f:
        json.dump(value, f, indent=1)
    return path


# ------------------------------------------------------------- the cell
def bulk(args, socks_port, target_port, direction, size):
    """One netgen bulk transfer through the client; its result, with
    `_error` when it did not move everything."""
    argv = [args.netgen, "bulk", "-proxy", f"{LOCAL}:{socks_port}",
            "-target", f"{LOCAL}:{target_port}", "-streams", str(args.streams),
            "-bytes", str(size), "-dir", direction]
    try:
        done = subprocess.run(argv, capture_output=True, text=True, stdin=subprocess.DEVNULL,
                              timeout=args.transfer_timeout)
    except subprocess.TimeoutExpired:
        # run() has killed it: the transfer is a failed one, and the cell goes on.
        return {"_error": f"not done within {args.transfer_timeout} s"}
    lines = done.stdout.strip().splitlines()
    try:
        res = json.loads(lines[-1]) if lines else {}
    except json.JSONDecodeError:
        res = {}
    if done.returncode != 0 or not res:
        res["_error"] = (done.stderr.strip() or f"exit {done.returncode}")[-300:]
    elif res.get("failed") or res.get("corrupt") or res.get("bytes") != args.streams * size:
        res["_error"] = (f"{res.get('failed', 0)} failed, {res.get('corrupt', 0)} corrupt: "
                         + "; ".join(res.get("errors") or []))[:300]
    return res


def run_client(args, proto, rnd, client, keys, server, server_port, target_port, work):
    """One client's turn: start, warm up, up and down, stop. Returns its
    samples. `client` is REFERENCE or the name of a build of sail."""
    socks_port = free_port()
    name = f"{proto}-{client}"
    config = write_json(os.path.join(work, f"{name}.json"),
                        client_config(proto, keys, server_port, socks_port))
    if client == REFERENCE:
        argv = [args.sing_box, "run", "-c", config, "-D", work]
    else:
        # No record of system changes: it makes none. The desktop preset is the default.
        argv = [args.sail[client], "-c", config, "--no-run-dir", "-D", work]
        argv += args.sail_args.get(client, [])
    samples = []
    proc = Proc(name, argv, os.path.join(work, f"{name}.log"))
    try:
        wait_port(socks_port, proc)
        warm = bulk(args, socks_port, target_port, "down", WARMUP_BYTES)
        if "_error" in warm:
            raise RuntimeError(f"warm-up: {warm['_error']}")
        for direction in DIRECTIONS:
            sample = {"protocol": proto, "round": rnd, "client": client, "direction": direction}
            rss = RssPeak(proc)
            rss.start()
            server_cpu = server.cpu_seconds()
            cpu = proc.cpu_seconds()
            res = bulk(args, socks_port, target_port, direction, args.bytes)
            cpu = proc.cpu_seconds() - cpu
            server_cpu = server.cpu_seconds() - server_cpu
            sample["rss_peak_mib"] = round(rss.finish() / (1 << 20), 1)
            if "_error" in res:
                sample["error"] = res["_error"]
            elif not proc.alive():
                sample["error"] = f"the client exited with {proc.p.returncode}"
            else:
                gib = res["bytes"] / GIB
                sample.update(mbps=round(res["mbps"], 1), seconds=round(res["seconds"], 3),
                              cpu_s=round(cpu, 3), cpu_s_per_gib=round(cpu / gib, 3),
                              server_cpu_s_per_gib=round(server_cpu / gib, 3))
            samples.append(sample)
            print(f"  {proto} round {rnd} {client} {direction}: "
                  + (sample.get("error") or f"{sample['mbps']} Mbit/s, "
                     f"{sample['cpu_s_per_gib']} CPU-s/GiB, {sample['rss_peak_mib']} MiB"),
                  file=sys.stderr, flush=True)
    except RuntimeError as e:
        print(f"  {proto} round {rnd} {client}: {e}", file=sys.stderr, flush=True)
        done = {s["direction"] for s in samples}
        samples += [{"protocol": proto, "round": rnd, "client": client, "direction": d,
                     "error": str(e)} for d in DIRECTIONS if d not in done]
    finally:
        proc.stop()
    return samples


def run_protocol(args, proto, keys, target_port):
    work = os.path.join(args.work, proto)
    os.makedirs(work, exist_ok=True)
    udp = proto == "hysteria2"
    server_port = free_port(udp=udp)
    handshake_port = free_port() if proto == "reality" else None
    config = write_json(os.path.join(work, "server.json"),
                        server_config(proto, keys, server_port, handshake_port))
    samples = []
    server = Proc(f"{proto}-server", [args.sing_box, "run", "-c", config, "-D", work],
                  os.path.join(work, "server.log"))
    try:
        if udp:
            # Nothing to connect to: it is up when it has not exited.
            time.sleep(2)
            if not server.alive():
                raise RuntimeError(f"the server exited with {server.p.returncode}: see {server.log_path}")
        else:
            wait_port(server_port, server)
            if handshake_port:
                wait_port(handshake_port, server)
        clients = list(args.sail) + [REFERENCE]
        for rnd in range(1, args.rounds + 1):
            # Turn about: each round starts one client further on. With one
            # build, sail first in odd rounds, sing-box first in even ones.
            first = (rnd - 1) % len(clients)
            for client in clients[first:] + clients[:first]:
                if not server.alive():
                    raise RuntimeError(f"the server exited with {server.p.returncode}: see {server.log_path}")
                samples += run_client(args, proto, rnd, client, keys, server, server_port,
                                      target_port, work)
    except RuntimeError as e:
        print(f"  {proto}: {e}", file=sys.stderr, flush=True)
        samples.append({"protocol": proto, "error": str(e)})
    finally:
        server.stop()
    return samples


# ------------------------------------------------------------- the report
def spread(values):
    if not values:
        return None
    return {"median": round(statistics.median(values), 3), "min": round(min(values), 3),
            "max": round(max(values), 3), "n": len(values)}


def summarize(samples, protocols, variants):
    """Per protocol and direction: each client's medians, and for each build
    of sail its ratios to sing-box, of the rounds in which both transfers
    were whole."""
    rows = []
    keys = ("mbps", "cpu_s_per_gib", "rss_peak_mib")
    for proto in protocols:
        for direction in DIRECTIONS:
            good = {}
            for s in samples:
                if (s.get("protocol"), s.get("direction")) == (proto, direction) and "error" not in s:
                    good[(s["client"], s["round"])] = s

            def medians(client):
                mine = [s for (c, _), s in sorted(good.items()) if c == client]
                return {key: spread([s[key] for s in mine]) for key in keys}

            row = {"protocol": proto, "direction": direction, REFERENCE: medians(REFERENCE),
                   "sail": {}}
            for name in variants:
                throughput, cpu = [], []
                for rnd in sorted({r for _, r in good}):
                    a, b = good.get((name, rnd)), good.get((REFERENCE, rnd))
                    if a and b:
                        if b["mbps"] > 0:
                            throughput.append(a["mbps"] / b["mbps"])
                        if a["cpu_s_per_gib"] > 0:
                            cpu.append(b["cpu_s_per_gib"] / a["cpu_s_per_gib"])
                # Both read the same way: above 1, sail is the better one.
                row["sail"][name] = dict(medians(name),
                                         throughput_over_sing_box=spread(throughput),
                                         cpu_sing_box_over=spread(cpu))
            rows.append(row)
    return rows


def cell(value, digits, none="failed"):
    if not value:
        return none
    text = f"{value['median']:.{digits}f}"
    if value["n"] > 1:
        text += f" ({value['min']:.{digits}f}–{value['max']:.{digits}f})"
    return text


def told(sample):
    return (f"- {sample.get('protocol')} round {sample.get('round', '-')} "
            f"{sample.get('client', 'server')} {sample.get('direction', '')}: {sample['error']}")


def markdown(meta, rows, failures, warnings):
    builds = meta["sail"]
    lines = [
        f"### Desktop cell: sail against sing-box on {meta['system']} {meta['machine']}",
        "",
        f"{meta['streams']} streams × {meta['bytes'] / (1 << 20):.0f} MiB each way on loopback, "
        f"median of {meta['rounds']} rounds (min–max). "
        + ", ".join(f"{b['name']} `{b['version']}`" for b in builds)
        + f", sing-box `{meta['sing_box_version']}`; "
        f"the server is sing-box. {meta['cpus']} CPUs.",
        "",
    ]
    if any(b.get("args") for b in builds):
        lines += ["Started with more than the cell's own arguments: "
                  + "; ".join(f"{b['name']} with `{' '.join(b['args'])}`"
                              for b in builds if b.get("args")) + ".",
                  ""]
    lines += [
        "Ratios are per round, sail and sing-box of the same round, then the median. "
        "**Above 1 is better for sail in both**: throughput is sail ÷ sing-box, "
        "CPU is sing-box ÷ sail (inverted, as less CPU per GiB is better).",
    ]
    if len(builds) > 1:
        lines += ["", f"{len(builds)} builds of sail, a table each; sing-box's columns are "
                      "the same in all, as it ran once a round."]
    for build in builds:
        name = build["name"]
        if len(builds) > 1:
            lines += ["", f"#### {name}"]
        lines += [
            "",
            f"| protocol | direction | {name} Mbit/s | sing-box Mbit/s | throughput {name}÷sing-box "
            f"| {name} CPU-s/GiB | sing-box CPU-s/GiB | CPU sing-box÷{name} "
            f"| {name} peak RSS MiB | sing-box peak RSS MiB |",
            "|---|---|---|---|---|---|---|---|---|---|",
        ]
        for row in rows:
            sail, other = row["sail"][name], row[REFERENCE]
            lines.append("| " + " | ".join([
                row["protocol"], row["direction"],
                cell(sail["mbps"], 0), cell(other["mbps"], 0),
                # No round had both transfers whole: no ratio.
                cell(sail["throughput_over_sing_box"], 2, "–"),
                cell(sail["cpu_s_per_gib"], 2), cell(other["cpu_s_per_gib"], 2),
                cell(sail["cpu_sing_box_over"], 2, "–"),
                cell(sail["rss_peak_mib"], 0), cell(other["rss_peak_mib"], 0),
            ]) + " |")
    if failures:
        lines += ["", f"{len(failures)} failed:"]
        lines += [told(f) for f in failures]
    if warnings:
        lines += ["", f"Warning: {len(warnings)} of sing-box's, the reference, failed. "
                      "Their rounds have no ratio, and they do not fail the run:"]
        lines += [told(w) for w in warnings]
    return "\n".join(lines) + "\n"


def sail_builds(values):
    """`--sail`'s values as {name: path}, in the order given."""
    builds = {}
    for value in values:
        name, eq, path = value.partition("=")
        if not eq or not VARIANT_NAME.match(name):
            # A bare path, one with a `=` in it too.
            name, path = "sail", value
        if name == REFERENCE:
            sys.exit(f"--sail {value}: {REFERENCE} is the reference's name")
        if name in builds:
            sys.exit(f"--sail {value}: a second build named {name}; name each, NAME=PATH")
        builds[name] = executable(path)
    return builds


def sail_arguments(values, builds):
    """`--sail-args`'s values as {name: [argument, ...]}."""
    extra = {}
    for value in values:
        name, eq, text = value.partition("=")
        if not eq or name not in builds:
            sys.exit(f"--sail-args {value}: NAME=ARGS, NAME one of --sail's "
                     f"({', '.join(builds)})")
        if name in extra:
            sys.exit(f"--sail-args {value}: a second one for {name}; give its arguments in one")
        try:
            extra[name] = shlex.split(text)
        except ValueError as e:
            sys.exit(f"--sail-args {value}: {e}")
    return extra


def version(argv):
    try:
        out = subprocess.run(argv, capture_output=True, text=True, timeout=20).stdout.strip()
        return out.splitlines()[0] if out else "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--sail", required=True, action="append", metavar="[NAME=]PATH",
                    help="a build of sail; may be given several times, each with a name "
                         "of letters, digits, '.', '_' and '-' (a bare PATH is named sail)")
    ap.add_argument("--sail-args", action="append", default=[], metavar="NAME=ARGS",
                    help="more arguments for the build NAME, split as a shell splits them "
                         "and appended to its command line; once a name")
    ap.add_argument("--sing-box", required=True)
    ap.add_argument("--netgen", required=True)
    ap.add_argument("--work", required=True, help="a directory for configs, keys and logs")
    ap.add_argument("--protocols", default=",".join(PROTOCOLS))
    ap.add_argument("--streams", type=int, default=4)
    ap.add_argument("--bytes", type=int, default=256 << 20, help="per stream, each way")
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--out", default="results.json")
    ap.add_argument("--transfer-timeout", type=int, default=600,
                    help="seconds one transfer may take before it counts as failed")
    args = ap.parse_args()
    for stream in (sys.stdout, sys.stderr):
        # A Windows runner's pipe is not UTF-8 by default.
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")

    protocols = [p for p in args.protocols.split(",") if p]
    unknown = [p for p in protocols if p not in PROTOCOLS]
    if unknown or not protocols:
        ap.error(f"--protocols: of {', '.join(PROTOCOLS)}; not {', '.join(unknown) or 'none'}")
    if min(args.streams, args.bytes, args.rounds) < 1:
        ap.error("--streams, --bytes and --rounds are at least 1")
    args.sail = sail_builds(args.sail)
    args.sail_args = sail_arguments(args.sail_args, args.sail)
    args.sing_box = executable(args.sing_box)
    args.netgen = executable(args.netgen)
    args.work = os.path.abspath(args.work)
    os.makedirs(args.work, exist_ok=True)

    meta = {"system": platform.system(), "release": platform.release(),
            "machine": platform.machine(), "cpus": os.cpu_count(),
            "sail": [{"name": name, "version": version([path, "--version"]),
                      "args": args.sail_args.get(name, [])}
                     for name, path in args.sail.items()],
            "sing_box_version": version([args.sing_box, "version"]),
            "streams": args.streams, "bytes": args.bytes, "rounds": args.rounds,
            "protocols": protocols}
    keys = make_keys(args.sing_box, args.work)
    samples = []
    target_port = free_port()
    target = Proc("netgen-serve", [args.netgen, "serve", "-listen", f"{LOCAL}:{target_port}"],
                  os.path.join(args.work, "netgen-serve.log"))
    try:
        wait_port(target_port, target)
        for proto in protocols:
            samples += run_protocol(args, proto, keys, target_port)
    finally:
        target.stop()

    rows = summarize(samples, protocols, list(args.sail))
    # The reference's own failed transfers are told and no more: what fails
    # the run is sail's, and a server that went away (no client named).
    errors = [s for s in samples if "error" in s]
    warnings = [s for s in errors if s.get("client") == REFERENCE]
    failures = [s for s in errors if s.get("client") != REFERENCE]
    table = markdown(meta, rows, failures, warnings)
    with open(args.out, "w", newline="\n") as f:
        json.dump({"meta": meta, "summary": rows, "samples": samples}, f, indent=1)
        f.write("\n")
    print(table)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8", newline="\n") as f:
            f.write(table + "\n")
    if warnings and os.environ.get("GITHUB_ACTIONS"):
        # An annotation on the run, which stays green.
        print(f"::warning title=sing-box::{len(warnings)} of the reference's transfers failed; "
              "see the summary")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
