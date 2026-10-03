#!/usr/bin/env python3
"""Weak-network and long-run tests (roadmap 5.5).

Run as root on the Linux test host, from this directory:

    python3 run.py --work WORK --sail WORK/sail --netgen WORK/netgen \\
        [--protocols direct,ss,trojan] [--clients sail-server,sail-mobile,sing-box] \\
        [--inbound socks|tun] \\
        [--only SUBSTR] [--quick]

Two network namespaces (netns.sh): nc5 (nc$NETEM_NS) holds the client under
test and the traffic tool, ns5 (ns$NETEM_NS) the protocol server (sing-box,
the reference) and the traffic tool's server. Every scenario shapes the link between them with
netem, runs the traffic tool's checked workloads through the client's
SOCKS inbound, and samples the client's memory, CPU, descriptors and TCP
states. Results: <work>/results/<run>/summary.json, and the raw records
of each client, gzipped, kept only where something failed.
"""
import argparse
import gzip
import json
import os
import shlex
import shutil
import signal
import statistics
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
NETNS = os.path.join(HERE, "netns.sh")
# Which pair of namespaces, as netns.sh takes them: NETEM_NS (default 5)
# and NETEM_NET (default 95), so that two runs side by side do not meet.
NETEM_NS = os.environ.get("NETEM_NS", "5")
NETEM_NET = os.environ.get("NETEM_NET", "95")
# Digits without a leading zero, as netns.sh takes them: 10.095 is no
# address, and nc05 is not nc5.
if not (NETEM_NS.isdigit() and not NETEM_NS.startswith("0") and len(NETEM_NS) <= 3):
    sys.exit(f"NETEM_NS: 1 to 999, no leading zero, not {NETEM_NS!r}")
if not (NETEM_NET.isdigit() and not NETEM_NET.startswith("0") and int(NETEM_NET) <= 253):
    sys.exit(f"NETEM_NET: 1 to 253, no leading zero, not {NETEM_NET!r}")
CLIENT_NS, SERVER_NS = f"nc{NETEM_NS}", f"ns{NETEM_NS}"
SERVER_ADDR = f"10.{NETEM_NET}.0.2"
TARGET = SERVER_ADDR + ":9000"
# The same server off the link (netns.sh), for a TUN to take the traffic.
FAR_ADDR = f"10.{int(NETEM_NET) + 1}.0.1"
FAR_TARGET = FAR_ADDR + ":9000"
LISTEN = "0.0.0.0:9000"
SOCKS = "127.0.0.1:1081"
SS_METHOD = "2022-blake3-aes-128-gcm"
SS_KEY = "a8C5QncIl9HvTmenrEb7aw=="
PASSWORD = "netem-password"
UUID = "9b2b4b81-6125-4a7c-9a83-847cb325758f"
# A REALITY key pair for the tests alone (sing-box generate reality-keypair).
REALITY_PRIVATE = "4KN8smrVWzyjgya4o2m-HXYFpB8hejWIldadEUV2iXE"
REALITY_PUBLIC = "Wc6yEq9ozyhP_WaLMbd4ykhtrLcY-K69aF2exVhUAxA"
REALITY_SHORT_ID = "0123456789abcdef"
# REALITY borrows a real TLS server's handshake: one in the server's
# namespace, as there is no internet in there.
REALITY_DEST = (SERVER_ADDR, 9443)

# Recovery after the link returns: roadmap 2.12's acceptance ("3 秒内恢复新连接").
RECOVERY_TARGET_S = 3.0
# The concurrent case of the core comparison (bench/core-compare).
CONCURRENT = 2000
# The descriptor limit every process of a run gets.
NOFILE = 65536


def sh(cmd, check=True, timeout=None):
    return subprocess.run(cmd, shell=True, check=check, capture_output=True,
                          text=True, timeout=timeout)


# The CPUs the processes of each namespace are pinned to (--cpus,
# --server-cpus): a long run shares the host with another on CPUs of its
# own, and a throughput cell keeps the client and server from trading CPUs.
CPUS = {}


# The traffic tool on CPUs of its own (--netgen-cpus), off both the
# client's and the server's.
NETGEN_CPUS = {}


def in_ns_netgen(ns, cmd):
    cpus = NETGEN_CPUS.get(ns) or CPUS.get(ns)
    pin = f"taskset -c {cpus} " if cpus else ""
    return f"ip netns exec {ns} {pin}{cmd}"


def in_ns(ns, cmd):
    cpus = CPUS.get(ns)
    pin = f"taskset -c {cpus} " if cpus else ""
    return f"ip netns exec {ns} {pin}{cmd}"


def netns(*args):
    # Each argument split as a shell would, then quoted: a spec reaches
    # netns.sh as the words it is made of, whatever they hold.
    words = [w for a in args for w in shlex.split(a)]
    sh(f"{NETNS} " + " ".join(shlex.quote(w) for w in words))


# ------------------------------------------------------------- scenarios
# Each shaping applies to both directions: an RTT of R is a delay of R/2
# each way. netem gives each packet a delay of its own, and without a rate
# sends them in the order of those delays: jitter alone reorders, and the
# cell would measure reordering, which reorder5/25 do. With a rate, netem
# sends no packet before the one ahead of it (sch_netem.c, netem_enqueue),
# as a path's queue does; 100gbit is far above any link here, a 1500-byte
# packet's 120 ns. Measured at 100 ms RTT, hy2 bulk: 4-7 Mbit/s reordered,
# 217 in order, 328 without jitter.
ORDERED = "rate 100gbit"


def delay(rtt_ms, jitter=0.1):
    half = rtt_ms / 2
    return f"delay {half}ms {half * jitter}ms distribution normal {ORDERED}"


SHAPED = [
    ("baseline", None),
    ("rtt50", delay(50)),
    ("rtt150", delay(150)),
    ("rtt300", delay(300)),
    ("loss0.5", "delay 10ms loss 0.5%"),
    ("loss2", "delay 10ms loss 2%"),
    ("loss5", "delay 10ms loss 5%"),
    # Gilbert-Elliott: bursts of loss, about 2 % on average.
    ("burst2", "delay 10ms loss gemodel 1% 30% 70% 0.1%"),
    ("reorder5", "delay 20ms reorder 5% 50%"),
    ("reorder25", "delay 20ms reorder 25% 50%"),
    # A queue of about half a second at the rate, as a real bottleneck's:
    # 10 Mbit/s x 0.5 s / 1500 B = 420 packets, 2 Mbit/s: 85.
    ("rate10m", "delay 20ms rate 10mbit limit 420"),
    ("rate2m", "delay 20ms rate 2mbit limit 85"),
]

# rtt_step: one client, its connections kept, first on a link whose RTT
# samples include some near zero (netem sends the reordered quarter of the
# packets without the delay), then on a slower path with a deep queue
# (150 ms, 50 Mbit/s, a 3000-packet queue of about 0.7 s). A congestion
# controller that keeps the first phase's minimum RTT for good sizes its
# window for that path and crawls in the second: quinn's BBR did, before
# sail's fork made the minimum expire after 10 s. Measured 2026-10-03, hy2,
# what sail sends in the second phase, 2 runs each: 2.3-2.8 Mbit/s before,
# 20-27 after as client and 39-41 as server (the first 10 s of it still
# under the old minimum). An unshaped or a plain 10 ms first phase does not
# show it: their bandwidth samples are high, and the window stays large
# (45 Mbit/s before and after).
RTT_STEP_LOW = "delay 20ms reorder 25% 50%"
RTT_STEP_HIGH = "delay 75ms rate 50mbit limit 3000"
# Bytes per stream: the first phase runs at a few Mbit/s, about 10-20 s a
# transfer; the second about 6 s each at the link's rate.
RTT_STEP_BYTES = {"low": 2 << 20, "high": 8 << 20}
# The least a sail side sends at in the second phase: 30 % of the link.
# Between the measurements above (at most 2.8 before, at least 20 after); a
# judgement.
RTT_STEP_MIN_MBPS = 15

# Bytes each bulk stream moves: enough to reach steady state, small enough
# for the slow links.
BULK_BYTES = {"rate10m": 8 << 20, "rate2m": 2 << 20, "rtt300": 16 << 20,
              "loss5": 8 << 20, "burst2": 16 << 20}


# ------------------------------------------------------------- processes
class Proc:
    def __init__(self, name, ns, cmd, log, nofile=None, netgen=False):
        self.name = name
        self.log = open(log, "a")
        # Descriptors as a deployment raises them, for all but a client
        # under test given its own limit (--client-nofile).
        cmd = f"sh -c 'ulimit -n {nofile or NOFILE}; exec {cmd}'"
        self.p = subprocess.Popen((in_ns_netgen if netgen else in_ns)(ns, cmd), shell=True, stdout=self.log,
                                  stderr=subprocess.STDOUT, preexec_fn=os.setsid)

    def pid(self):
        # The process netns exec runs: the shell's only child, or itself.
        try:
            kids = open(f"/proc/{self.p.pid}/task/{self.p.pid}/children").read().split()
            return int(kids[0]) if kids else self.p.pid
        except OSError:
            return None

    def alive(self):
        return self.p.poll() is None

    def stop(self):
        if self.alive():
            os.killpg(self.p.pid, signal.SIGTERM)
            try:
                self.p.wait(5)
            except subprocess.TimeoutExpired:
                os.killpg(self.p.pid, signal.SIGKILL)
                self.p.wait()
        self.log.close()


def server_config(proto, work):
    if proto in ("h2mux", "smux"):
        proto = "mux"
    cc = None
    if proto.startswith("tuic-"):
        proto, cc = "tuic", proto.split("-", 1)[1]
    tls = {"enabled": True, "certificate_path": f"{work}/cert.pem",
           "key_path": f"{work}/key.pem"}
    if proto == "reality":
        inbound = {"type": "vless", "listen": "0.0.0.0", "listen_port": 8443,
                   "users": [{"uuid": UUID, "flow": "xtls-rprx-vision"}],
                   "tls": {"enabled": True, "server_name": "localhost",
                           "reality": {"enabled": True,
                                       "handshake": {"server": REALITY_DEST[0],
                                                     "server_port": REALITY_DEST[1]},
                                       "private_key": REALITY_PRIVATE,
                                       "short_id": [REALITY_SHORT_ID]}}}
    elif proto == "hy2":
        inbound = {"type": "hysteria2", "listen": "0.0.0.0", "listen_port": 8443,
                   "users": [{"password": PASSWORD}], "tls": tls}
    elif proto == "tuic":
        inbound = {"type": "tuic", "listen": "0.0.0.0", "listen_port": 8443,
                   "users": [{"uuid": UUID, "password": PASSWORD}],
                   "congestion_control": cc or "bbr", "tls": dict(tls, alpn=["h3"])}
    elif proto == "vless":
        # Plain VLESS over TLS, no flow.
        inbound = {"type": "vless", "listen": "0.0.0.0", "listen_port": 8443,
                   "users": [{"uuid": UUID, "flow": ""}], "tls": tls}
    elif proto == "mux":
        inbound = {"type": "trojan", "listen": "0.0.0.0", "listen_port": 8443,
                   "users": [{"password": PASSWORD}], "tls": tls,
                   "multiplex": {"enabled": True}}
        return {"log": {"level": "warn"}, "inbounds": [inbound],
                "outbounds": [{"type": "direct"}]}
    elif proto == "ss":
        inbound = {"type": "shadowsocks", "listen": "0.0.0.0", "listen_port": 8388,
                   "method": SS_METHOD, "password": SS_KEY}
    elif proto == "trojan":
        inbound = {"type": "trojan", "listen": "0.0.0.0", "listen_port": 8443,
                   "users": [{"password": PASSWORD}],
                   "tls": {"enabled": True, "certificate_path": f"{work}/cert.pem",
                           "key_path": f"{work}/key.pem"}}
    else:
        return None
    return {"log": {"level": "warn"}, "inbounds": [inbound],
            "outbounds": [{"type": "direct"}]}


def client_config(proto, inbound="socks", server=SERVER_ADDR, auto_detect=False):
    mux_protocol = None
    if proto in ("h2mux", "smux"):
        proto, mux_protocol = "mux", proto
    cc = None
    if proto.startswith("tuic-"):
        proto, cc = "tuic", proto.split("-", 1)[1]
    insecure = {"enabled": True, "server_name": "localhost", "insecure": True}
    if proto == "reality":
        out = {"type": "vless", "server": server, "server_port": 8443, "uuid": UUID,
               "flow": "xtls-rprx-vision",
               "tls": {"enabled": True, "server_name": "localhost",
                       "utls": {"enabled": True, "fingerprint": "chrome"},
                       "reality": {"enabled": True, "public_key": REALITY_PUBLIC,
                                   "short_id": REALITY_SHORT_ID}}}
    elif proto == "hy2":
        out = {"type": "hysteria2", "server": server, "server_port": 8443,
               "password": PASSWORD, "tls": insecure}
    elif proto == "tuic":
        out = {"type": "tuic", "server": server, "server_port": 8443, "uuid": UUID,
               "password": PASSWORD, "congestion_control": cc or "bbr",
               "tls": dict(insecure, alpn=["h3"])}
    elif proto == "mux":
        out = {"type": "trojan", "server": server, "server_port": 8443,
               "password": PASSWORD, "tls": insecure,
               "multiplex": {"enabled": True, "max_connections": 4}}
        if mux_protocol:
            out["multiplex"]["protocol"] = mux_protocol
    elif proto == "vless":
        out = {"type": "vless", "server": server, "server_port": 8443, "uuid": UUID,
               "flow": "", "tls": insecure}
    elif proto == "ss":
        out = {"type": "shadowsocks", "server": server, "server_port": 8388,
               "method": SS_METHOD, "password": SS_KEY}
    elif proto == "trojan":
        out = {"type": "trojan", "server": server, "server_port": 8443,
               "password": PASSWORD,
               "tls": {"enabled": True, "server_name": "localhost", "insecure": True}}
    else:
        out = {"type": "direct"}
    out["tag"] = "out"
    # info: each connection's end is in the log, for what fails rarely.
    cfg = {"log": {"level": "info", "timestamp": True},
           "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": 1081}],
           "outbounds": [out]}
    if auto_detect:
        # Outbound sockets follow the default interface, as on a phone.
        cfg["route"] = {"auto_detect_interface": True}
    if inbound == "tun":
        # The whole namespace's traffic into the TUN; the proxy's own
        # connections leave by the veth they are bound to.
        cfg["inbounds"] = [{"type": "tun", "interface_name": "tun5",
                            "address": ["172.19.0.1/30"], "mtu": 9000,
                            "auto_route": True}]
        cfg["route"] = {"auto_detect_interface": True}
    return cfg


# ------------------------------------------------------------- sampling
class Sampler:
    """Samples the client's RSS, CPU and descriptors and both namespaces'
    TCP states, once a second."""

    def __init__(self, proc, interval=1):
        self.proc = proc
        self.interval = interval
        self.samples = []
        self.stop_ = threading.Event()
        self.t = threading.Thread(target=self.run, daemon=True)
        self.t.start()

    def one(self):
        pid = self.proc.pid()
        s = {"t": time.time(), "pid": pid}
        if pid:
            try:
                for line in open(f"/proc/{pid}/status"):
                    if line.startswith("VmRSS:"):
                        s["rss_kb"] = int(line.split()[1])
                stat = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
                s["cpu_ticks"] = int(stat[11]) + int(stat[12])
                s["fds"] = len(os.listdir(f"/proc/{pid}/fd"))
            except OSError:
                s["gone"] = True
        for ns in (CLIENT_NS, SERVER_NS):
            states = {}
            out = sh(in_ns(ns, "ss -tanH"), check=False).stdout
            for line in out.splitlines():
                st = line.split()[0]
                states[st] = states.get(st, 0) + 1
            s[f"tcp_{ns}"] = states
        return s

    def run(self):
        while not self.stop_.wait(self.interval):
            self.samples.append(self.one())

    def mark(self):
        return len(self.samples)

    def since(self, mark):
        return self.samples[mark:]

    def stop(self):
        self.stop_.set()
        self.t.join()


def proc_ticks(proc):
    """(pid, utime+stime) of a Proc, or None."""
    if proc is None:
        return None
    pid = proc.pid()
    if not pid:
        return None
    try:
        stat = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
        return pid, int(stat[11]) + int(stat[12])
    except OSError:
        return None


def peak(samples, key):
    vals = [s[key] for s in samples if key in s]
    return max(vals) if vals else None


def last(samples, key):
    vals = [s[key] for s in samples if key in s]
    return vals[-1] if vals else None


# ------------------------------------------------------------- runs
class Run:
    def __init__(self, args, proto, client, server, client_bin=None, server_bin=None,
                 tag=""):
        self.args = args
        self.client_bin = client_bin or args.sail
        self.server_bin = server_bin or args.sail
        self.proto = proto
        self.client = client
        self.server = server
        # The server is named only when it is not the reference.
        self.name = (f"{proto}-{client}" + ("" if server == "sing-box" else f"-to-{server}")
                     + ("" if args.inbound == "socks" else f"-{args.inbound}") + tag)
        self.dir = os.path.join(args.out, self.name)
        os.makedirs(self.dir, exist_ok=True)
        self.records = []
        self.failures = []
        self.procs = {}

    def netgen(self, mode, *flags, timeout=600):
        proxy = f"-proxy {SOCKS} " if self.args.inbound == "socks" else ""
        target = (TARGET if self.args.inbound == "socks" and self.args.only != "route_switch"
                  else FAR_TARGET)
        cmd = in_ns_netgen(CLIENT_NS, f"{self.args.netgen} {mode} {proxy}-target {target} "
                    + " ".join(flags))
        t0 = time.time()
        # Its own process group: a timeout ends the traffic tool itself, not
        # only the shell that started it, and the run goes on with the
        # operation counted as failed, as a hung transfer is a result too.
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True, start_new_session=True)
        try:
            stdout, stderr = p.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL)
            p.communicate()
            return {"failed": 1, "_seconds": round(time.time() - t0, 2),
                    "_error": f"{mode} did not finish within {timeout}s"}
        out = stdout.strip().splitlines()
        try:
            res = json.loads(out[-1]) if out else {}
        except json.JSONDecodeError:
            res = {}
        res["_seconds"] = round(time.time() - t0, 2)
        if p.returncode != 0:
            res["_error"] = stderr.strip()[-500:]
        return res

    def start_server(self):
        log = os.path.join(self.dir, "server.log")
        self.procs["netgen"] = Proc("netgen", SERVER_NS,
                                    f"{self.args.netgen} serve -listen {LISTEN}", log, netgen=True)
        if self.proto == "reality":
            self.procs["reality-dest"] = Proc(
                "reality-dest", SERVER_NS,
                f"openssl s_server -quiet -accept {REALITY_DEST[0]}:{REALITY_DEST[1]} "
                f"-cert {self.args.work}/cert.pem -key {self.args.work}/key.pem -www", log)
        cfg = server_config(self.proto, self.args.work)
        if cfg:
            path = os.path.join(self.dir, "server.json")
            json.dump(cfg, open(path, "w"))
            self.procs["server"] = Proc("server", SERVER_NS, self.server_command(path), log)
        time.sleep(1)

    def server_command(self, path):
        if self.server.startswith("sail"):
            return f"{self.server_bin} -c {path} --profile {self.args.server_profile}"
        return f"{self.args.singbox} run -c {path}"

    def start_client(self):
        path = os.path.join(self.dir, "client.json")
        # Switching the default route needs a server only it reaches.
        switching = self.args.only == "route_switch"
        cfg = client_config(self.proto, self.args.inbound,
                            server=FAR_ADDR if switching else SERVER_ADDR,
                            auto_detect=switching)
        json.dump(cfg, open(path, "w"))
        log = os.path.join(self.dir, "client.log")
        if self.client.startswith("sail"):
            profile = self.client.split("-", 1)[1]
            cmd = f"{self.client_bin} -c {path} --profile {profile}"
            cmd += "".join(f" --set {setting}" for setting in self.args.client_set)
        else:
            cmd = f"{self.args.singbox} run -c {path}"
        self.procs["client"] = Proc("client", CLIENT_NS, cmd, log,
                                    nofile=self.args.client_nofile)
        time.sleep(1.5)

    def restart_server(self):
        key = "server" if "server" in self.procs else "netgen"
        self.procs[key].stop()
        log = os.path.join(self.dir, "server.log")
        if key == "server":
            path = os.path.join(self.dir, "server.json")
            self.procs[key] = Proc("server", SERVER_NS, self.server_command(path), log)
        else:
            self.procs[key] = Proc("netgen", SERVER_NS,
                                   f"{self.args.netgen} serve -listen {LISTEN}", log, netgen=True)

    def record(self, scenario, workload, res, samples, idle_before, idle_after):
        rec = {"scenario": scenario, "workload": workload, "result": res,
               "rss_peak_kb": peak(samples, "rss_kb"),
               "fds_peak": peak(samples, "fds"),
               "idle_before": idle_before, "idle_after": idle_after,
               "client_alive": self.procs["client"].alive()}
        self.records.append(rec)
        return rec

    def idle(self, sampler, settle=5):
        """The client at rest: RSS, descriptors and TCP states after
        `settle` seconds with no traffic."""
        time.sleep(settle)
        s = sampler.one()
        return {"rss_kb": s.get("rss_kb"), "fds": s.get("fds"),
                "tcp_client_ns": s.get(f"tcp_{CLIENT_NS}")}

    def fail(self, what):
        self.failures.append(what)
        print(f"  FAIL {self.name}: {what}", flush=True)

    def check(self, scenario, workload, res):
        """The absolute criteria: nothing corrupted, nothing crashed."""
        for part in ([res] + [v for v in res.values() if isinstance(v, dict)]):
            if part.get("corrupt"):
                self.fail(f"{scenario}/{workload}: {part['corrupt']} corrupted transfers")
        if not self.procs["client"].alive():
            self.fail(f"{scenario}/{workload}: the client exited")

    def workloads(self, sampler, scenario):
        quick = self.args.quick
        size = self.args.bulk_bytes or BULK_BYTES.get(scenario, 32 << 20)
        if quick and not self.args.bulk_bytes:
            size //= 4
        plan = [
            ("bulk_down", ["-streams 4", f"-bytes {size}", "-dir down"]),
            ("bulk_up", ["-streams 4", f"-bytes {size}", "-dir up"]),
            ("echo", ["-conns 8", f"-rounds {50 if quick else 150}", "-size 4096"]),
            ("setup", [f"-n {self.args.setup_n or (50 if quick else 150)}"]),
        ]
        if self.args.bulk_only:
            plan = plan[:2]
        cell = {}
        for round_ in range(self.args.rounds):
            for workload, flags in plan:
                idle_before = self.idle(sampler, settle=1)
                m = sampler.mark()
                before = sampler.one()
                srv0 = proc_ticks(self.procs.get("server"))
                res = self.netgen(workload.split("_")[0], *flags)
                srv1 = proc_ticks(self.procs.get("server"))
                after = sampler.one()
                rec = self.record(scenario, workload, res, sampler.since(m), idle_before,
                                  self.idle(sampler, settle=2))
                # The client's CPU over the workload, for its cost per GiB:
                # one process's, so none when the client was replaced.
                ticks0, ticks1 = before.get("cpu_ticks"), after.get("cpu_ticks")
                if (ticks0 is not None and ticks1 is not None and ticks1 >= ticks0
                        and before["pid"] == after["pid"]):
                    rec["cpu_s"] = (ticks1 - ticks0) / os.sysconf("SC_CLK_TCK")
                # The protocol server's CPU over the same span.
                if srv0 and srv1 and srv0[0] == srv1[0] and srv1[1] >= srv0[1]:
                    rec["server_cpu_s"] = (srv1[1] - srv0[1]) / os.sysconf("SC_CLK_TCK")
                rec["round"] = round_ + 1
                self.check(scenario, workload, res)
                print(f"  {self.name} {scenario} {workload}: {brief(res)}", flush=True)
                cell.setdefault(workload, []).append(res)
        if self.args.rounds > 1:
            # A cell's spread beside its median: one run says little on a
            # shared host.
            spread = {}
            for workload, results in cell.items():
                for key, pick in (("mbps", lambda r: r.get("mbps")),
                                  ("p50_ms", lambda r: (r.get("rtt") or {}).get("p50_ms")),
                                  ("p99_ms", lambda r: (r.get("rtt") or {}).get("p99_ms"))):
                    vals = sorted(v for v in map(pick, results) if v is not None)
                    if vals:
                        spread[f"{workload}.{key}"] = {
                            "median": statistics.median(vals), "min": vals[0], "max": vals[-1],
                            "n": len(vals)}
            self.record(scenario, "cell", spread, [], None, None)
            for name, v in spread.items():
                print(f"  {self.name} {scenario} {name}: median {v['median']:.2f} "
                      f"(min {v['min']:.2f}, max {v['max']:.2f}, n {v['n']})", flush=True)

    def disconnect(self, sampler, scenario, outage, how):
        """A probe runs across an outage; recovery is the time from the
        link's return to the first new connection that works."""
        pre, post = 5, 20
        m = sampler.mark()
        probe = threading.Thread(target=lambda: setattr(
            self, "_probe", self.netgen("probe", f"-duration {pre + outage + post}s",
                                        "-interval 100ms", "-timeout 5s",
                                        timeout=pre + outage + post + 60)))
        probe.start()
        time.sleep(pre)
        cut = time.time()
        if how == "blackhole":
            netns("blackhole")
        elif how == "linkdown":
            netns("linkdown")
        elif how == "restart":
            self.restart_server()
        if how != "restart":
            time.sleep(outage)
        restored = time.time()
        if how == "blackhole":
            netns("clear")
        elif how == "linkdown":
            netns("linkup")
        probe.join()
        res = getattr(self, "_probe", {})
        events = res.get("events", [])
        restored_ms = restored * 1000
        first_ok = next((e["at_ms"] for e in events
                         if e["what"] == "new_ok" and e["at_ms"] >= restored_ms), None)
        # With no failure at all, recovery was immediate.
        failed_any = any(e["what"] == "new_fail" for e in events)
        recovery = (first_ok - restored_ms) / 1000 if first_ok else (
            0.0 if not failed_any else None)
        long_fail = next((e for e in events if e["what"] == "long_fail"), None)
        res["recovery_s"] = recovery
        res["first_ok_s"] = first_ok_after(res, restored)
        res["long_ended_after_cut_s"] = (
            round(long_fail["at_ms"] / 1000 - cut, 2) if long_fail else None)
        res["long_reopened"] = any(e["what"] == "long_reopened" and e["at_ms"] >= restored_ms
                                   for e in events)
        self.record(scenario, "probe", res, sampler.since(m), None, self.idle(sampler))
        if recovery is None:
            self.fail(f"{scenario}: no new connection worked after the link returned")
        elif recovery > RECOVERY_TARGET_S:
            # Reported with its cause, not failed: 2.12 or the relay
            # timeouts may own it.
            print(f"  NOTE {self.name} {scenario}: recovery {recovery:.1f}s > "
                  f"{RECOVERY_TARGET_S}s", flush=True)
        self.check(scenario, "probe", res)
        print(f"  {self.name} {scenario}: recovery {recovery}s (first new connection after "
              f"it: {res['first_ok_s']}s), long-lived ended after "
              f"{res['long_ended_after_cut_s']}s, reopened {res['long_reopened']}", flush=True)

    def route_switch(self, sampler):
        """The default route moves to a second interface and the first goes
        down, as a phone leaving Wi-Fi. Recovery is the time from the move
        to the first new connection that works; the client's own account
        of it (2.12's "network changed" line) is kept beside it."""
        pre, post = 5, 20
        m = sampler.mark()
        log = os.path.join(self.dir, "client.log")
        log_before = os.path.getsize(log) if os.path.exists(log) else 0
        probe = threading.Thread(target=lambda: setattr(
            self, "_probe", self.netgen("probe", f"-duration {pre + post}s",
                                        "-interval 100ms", "-timeout 5s",
                                        timeout=pre + post + 60)))
        probe.start()
        time.sleep(pre)
        switched = time.time()
        netns("switch")
        probe.join()
        netns("unswitch")
        res = getattr(self, "_probe", {})
        events = res.get("events", [])
        switched_ms = switched * 1000
        first_ok = next((e["at_ms"] for e in events
                         if e["what"] == "new_ok" and e["at_ms"] >= switched_ms), None)
        failed_any = any(e["what"] == "new_fail" and e["at_ms"] >= switched_ms
                         for e in events)
        recovery = (first_ok - switched_ms) / 1000 if first_ok else (
            0.0 if not failed_any else None)
        long_fail = next((e for e in events if e["what"] == "long_fail"), None)
        res["recovery_s"] = recovery
        res["first_ok_s"] = first_ok_after(res, switched)
        res["long_ended_after_switch_s"] = (
            round(long_fail["at_ms"] / 1000 - switched, 2) if long_fail else None)
        res["long_reopened"] = any(e["what"] == "long_reopened" and e["at_ms"] >= switched_ms
                                   for e in events)
        with open(log, errors="replace") as f:
            f.seek(log_before)
            # sail's summary line; a warning that also starts "network
            # changed:" is not one.
            changes = [line.strip() for line in f if "network changed: generation" in line]
        res["network_changed"] = [parse_network_changed(line) for line in changes]
        self.record("route_switch", "probe", res, sampler.since(m), None, self.idle(sampler))
        if recovery is None:
            self.fail("route_switch: no new connection worked after the switch")
        elif recovery > RECOVERY_TARGET_S:
            print(f"  NOTE {self.name} route_switch: recovery {recovery:.1f}s > "
                  f"{RECOVERY_TARGET_S}s", flush=True)
        self.check("route_switch", "probe", res)
        print(f"  {self.name} route_switch: recovery {recovery}s (first new connection after "
              f"it: {res['first_ok_s']}s), long-lived ended after "
              f"{res['long_ended_after_switch_s']}s, reopened {res['long_reopened']}, "
              f"client saw {res['network_changed'] or 'no network change'}", flush=True)

    def soak(self, sampler, hours):
        """Hours of light, checked traffic under link conditions taken in
        turn, the client never restarted; the client at rest is sampled
        after each round. An hour's line goes to soak.jsonl as it ends, and
        the judgement is the growth of the client's resting RSS from the
        second hour to the last, and its descriptors back at rest."""
        rotation = [("baseline", None),
                    ("rtt150", delay(150)),
                    ("loss2", "loss 2%"),
                    ("rate10m", "rate 10mbit limit 420"),
                    ("burst2", "loss gemodel 1% 30% 70% 0.1%")]
        plan = [("bulk_down", ["-streams 2", "-bytes 16777216", "-dir down"]),
                ("bulk_up", ["-streams 2", "-bytes 16777216", "-dir up"]),
                ("echo", ["-conns 4", "-rounds 50", "-size 4096"]),
                ("setup", ["-n 50"])]
        log = os.path.join(self.dir, "soak.jsonl")
        start = time.time()
        end = start + hours * 3600
        hour, rests, rounds, failed_before = 0, [], 0, 0
        while time.time() < end:
            scenario, spec = rotation[rounds % len(rotation)]
            netns("shape", spec) if spec else netns("clear")
            for workload, flags in plan:
                res = self.netgen(workload.split("_")[0], *flags)
                self.check(f"soak/{scenario}", workload, res)
                if res.get("failed"):
                    self.soak_failed = getattr(self, "soak_failed", 0) + res["failed"]
                    # Which link condition, when, and what the tool said.
                    with open(os.path.join(self.dir, "soak-failures.jsonl"), "a") as f:
                        f.write(json.dumps({
                            "t": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                            "round": rounds + 1, "scenario": scenario,
                            "workload": workload, "failed": res["failed"],
                            "seconds": res.get("_seconds"),
                            "errors": res.get("errors"), "error": res.get("_error"),
                        }) + "\n")
            netns("clear")
            rest = self.idle(sampler, settle=60)
            rest["t"] = time.time()
            rests.append(rest)
            rounds += 1
            # One line an hour, as each ends.
            while time.time() - start >= (hour + 1) * 3600 or time.time() >= end:
                in_hour = [r for r in rests
                           if start + hour * 3600 <= r["t"] < start + (hour + 1) * 3600]
                rss = sorted(r["rss_kb"] for r in in_hour if r.get("rss_kb"))
                fds = sorted(r["fds"] for r in in_hour if r.get("fds") is not None)
                line = {"hour": hour + 1,
                        "rest_rss_kb_median": statistics.median(rss) if rss else None,
                        "rest_rss_kb_max": rss[-1] if rss else None,
                        "rest_fds_median": statistics.median(fds) if fds else None,
                        "rounds": len(in_hour),
                        "failed_ops": getattr(self, "soak_failed", 0) - failed_before,
                        "failures": len(self.failures)}
                failed_before = getattr(self, "soak_failed", 0)
                with open(log, "a") as f:
                    f.write(json.dumps(line) + "\n")
                print(f"  {self.name} soak hour {line['hour']}: rest RSS "
                      f"{line['rest_rss_kb_median']} kB, fds {line['rest_fds_median']}, "
                      f"failed ops {line['failed_ops']}", flush=True)
                hour += 1
                if time.time() >= end or hour >= hours:
                    break
        hours_seen = [json.loads(l) for l in open(log)] if os.path.exists(log) else []
        by_hour = {h["hour"]: h["rest_rss_kb_median"] for h in hours_seen}
        first, last_hour = by_hour.get(2), by_hour.get(max(by_hour) if by_hour else 0)
        growth = (last_hour - first) / first if first and last_hour else None
        res = {"hours": hours, "rounds": rounds, "rss_hour2_kb": first,
               "rss_last_kb": last_hour, "rss_growth": growth,
               "failed_ops": getattr(self, "soak_failed", 0)}
        self.record("soak", "summary", res, [], None, self.idle(sampler))
        if growth is not None and growth >= 0.10:
            self.fail(f"soak: resting RSS grew {growth:.1%} from hour 2 to the last")
        print(f"  {self.name} soak: {json.dumps(res)}", flush=True)

    def rtt_step(self, sampler):
        """A step in RTT under one client: bulk both ways under RTT_STEP_LOW,
        then under RTT_STEP_HIGH, upload first, with nothing restarted. In
        the second phase every stream must arrive, and what a sail side
        sends must reach RTT_STEP_MIN_MBPS."""
        for phase, spec in (("low", RTT_STEP_LOW), ("high", RTT_STEP_HIGH)):
            netns("shape", spec)
            plan = ("bulk_down", "bulk_up") if phase == "low" else ("bulk_up", "bulk_down")
            for workload in plan:
                idle_before = self.idle(sampler, settle=1)
                m = sampler.mark()
                res = self.netgen("bulk", "-streams 4", f"-bytes {RTT_STEP_BYTES[phase]}",
                                  f"-dir {workload.split('_')[1]}")
                self.record(f"rtt_step-{phase}", workload, res, sampler.since(m), idle_before,
                            None)
                self.check(f"rtt_step-{phase}", workload, res)
                print(f"  {self.name} rtt_step {phase} {workload}: {brief(res)}", flush=True)
                if phase != "high":
                    continue
                if res.get("ok") != 4 or res.get("failed"):
                    self.fail(f"rtt_step-high/{workload}: {res.get('ok')} of 4 streams arrived")
                sender = self.client if workload == "bulk_up" else self.server
                if sender.startswith("sail") and (res.get("mbps") or 0) < RTT_STEP_MIN_MBPS:
                    self.fail(f"rtt_step-high/{workload}: {res.get('mbps') or 0:.1f} Mbit/s, "
                              f"under {RTT_STEP_MIN_MBPS}")
        netns("clear")

    def concurrency(self, sampler):
        idle_before = self.idle(sampler, settle=2)
        m = sampler.mark()
        hold = 10 if self.args.quick else 20
        res = self.netgen("concurrent", f"-conns {CONCURRENT}", f"-hold {hold}s")
        rec = self.record("concurrency", "concurrent", res, sampler.since(m), idle_before,
                          self.idle(sampler, settle=10))
        if res.get("established") != CONCURRENT or res.get("survived") != CONCURRENT:
            self.fail(f"concurrency: {res.get('established')} established, "
                      f"{res.get('survived')} survived of {CONCURRENT}")
        self.check("concurrency", "concurrent", res)
        print(f"  {self.name} concurrency: {brief(res)} rss peak {rec['rss_peak_kb']} kB",
              flush=True)
        for rate in self.args.churn_rates:
            m = sampler.mark()
            res = self.netgen("churn", f"-rate {rate}", f"-duration {10 if self.args.quick else 30}s")
            self.record("concurrency", f"churn{rate}", res, sampler.since(m), None,
                        self.idle(sampler))
            self.check("concurrency", f"churn{rate}", res)
            print(f"  {self.name} churn {rate}/s: {brief(res)}", flush=True)

    def halfclose(self, sampler):
        for scenario, spec in (("baseline", None), ("loss2", "delay 10ms loss 2%")):
            netns("shape", spec) if spec else netns("clear")
            m = sampler.mark()
            res = self.netgen("halfclose", "-n 50", "-bytes 1048576")
            self.record(f"halfclose-{scenario}", "halfclose", res, sampler.since(m), None,
                        self.idle(sampler))
            for side in ("client_first", "server_first"):
                part = res.get(side, {})
                if part.get("ok") == 50:
                    continue
                if "sing-box" in (self.client, self.server) and not part.get("corrupt"):
                    # sing-box 1.13 closes both ways when one side shuts
                    # its write side (measured 2026-09-30, as client and as
                    # server): not held against the sail side.
                    print(f"  NOTE {self.name}: halfclose-{scenario}/{side}: sing-box "
                          f"does not keep half-close: {part.get('ok')}/50", flush=True)
                    continue
                self.fail(f"halfclose-{scenario}/{side}: {part}")
            self.check(f"halfclose-{scenario}", "halfclose", res)
            print(f"  {self.name} halfclose {scenario}: {brief(res)}", flush=True)
        netns("clear")

    def scenarios(self, sampler):
        """The shaped, disconnect, concurrency and half-close scenarios."""
        for scenario, spec in SHAPED:
            if self.args.only and not any(o in scenario for o in self.args.only_list):
                continue
            netns("shape", spec) if spec else netns("clear")
            self.workloads(sampler, scenario)
        netns("clear")
        if not self.args.only or any("disconnect" in o for o in self.args.only_list):
            self.disconnect(sampler, "blackhole5", 5, "blackhole")
            self.disconnect(sampler, "blackhole30", 30, "blackhole")
            self.disconnect(sampler, "linkdown10", 10, "linkdown")
            self.disconnect(sampler, "server_restart", 0, "restart")
        # Its own run: the client then dials a server only the default
        # route reaches, and follows the default interface.
        if self.args.only == "route_switch":
            self.route_switch(sampler)
        if not self.args.only or any("rtt_step" in o for o in self.args.only_list):
            self.rtt_step(sampler)
        if not self.args.only or any("concurrency" in o for o in self.args.only_list):
            self.concurrency(sampler)
        if not self.args.only or any("halfclose" in o for o in self.args.only_list):
            self.halfclose(sampler)

    def go(self):
        print(f"== {self.name}", flush=True)
        self.start_server()
        self.start_client()
        # Hours of samples a second would be the run's own load.
        sampler = Sampler(self.procs["client"], interval=10 if self.args.soak else 1)
        start_idle = self.idle(sampler, settle=2)
        try:
            if self.args.soak:
                self.soak(sampler, self.args.soak)
            else:
                self.scenarios(sampler)
        finally:
            netns("clear")
            end_idle = self.idle(sampler, settle=self.args.end_settle)
            sampler.stop()
            for p in self.procs.values():
                p.stop()
        summary = {"name": self.name, "failures": self.failures,
                   "idle_start": start_idle, "idle_end": end_idle,
                   "records": [compact(r) for r in self.records]}
        with gzip.open(os.path.join(self.dir, "raw.jsonl.gz"), "wt") as f:
            for r in self.records:
                f.write(json.dumps(r) + "\n")
            for s in sampler.samples:
                f.write(json.dumps({"sample": s}) + "\n")
        return summary


def brief(res):
    keep = ("ok", "failed", "corrupt", "mbps", "rtt", "setup", "established", "survived",
            "_error")
    out = {k: res[k] for k in keep if k in res}
    for side in ("client_first", "server_first"):
        if side in res:
            out[side] = {k: res[side].get(k) for k in ("ok", "failed", "corrupt")}
    return json.dumps(out)


def compact(rec):
    r = dict(rec)
    res = dict(r["result"])
    res.pop("events", None)
    r["result"] = res
    return r


def first_ok_after(res, reference_s):
    """Seconds from `reference_s` to the end of the first new connection
    started at or after it that worked: what a user who tried right then
    waited. The outcome changes in the events follow completion order, so
    a connection started before the cut that failed slowly can push their
    "new_ok" later than any connection started after it."""
    reference_ms = reference_s * 1000
    ends = [c["end_ms"] for c in res.get("conns", [])
            if c["ok"] and c["start_ms"] >= reference_ms]
    return round((min(ends) - reference_ms) / 1000, 3) if ends else None


def parse_network_changed(line):
    """The fields of sail's "network changed: generation N, reason=R,
    interface=A→B, closed=K, dns_flushed=…, took=Mms" line."""
    fields = {}
    text = line.split("network changed:", 1)[1]
    for part in text.split(","):
        part = part.strip()
        if part.startswith("generation "):
            fields["generation"] = part.split()[1]
        elif "=" in part:
            key, value = part.split("=", 1)
            fields[key] = value
    if "took" in fields:
        fields["took_ms"] = float(fields.pop("took").rstrip("ms") or 0)
    if "closed" in fields:
        fields["closed"] = int(fields["closed"]) if fields["closed"].isdigit() else fields["closed"]
    return fields


def write_summary(out, summaries):
    """The runs, under a schema version that a reader (tools/perf) checks."""
    path = os.path.join(out, "summary.json")
    with open(path + ".tmp", "w") as f:
        json.dump({"schema": 1, "runs": summaries}, f, indent=1)
    os.replace(path + ".tmp", path)


def matrix(args, summaries):
    """--matrix: each client>server pair in turn, rounds outermost, the
    order of pairs and of protocols rotating each round. A side is sb
    (sing-box), sail (--sail), or a name --sail-bin gives a sail binary."""
    bins = dict(args.sail_bins, sail=args.sail)
    pairs = [p.split(">") for p in args.matrix.split(",")]
    rounds, args.rounds = args.rounds, 1
    tcp_bytes = args.bulk_bytes
    protos = args.protocols.split(",")
    for r in range(rounds):
        order = pairs[r % len(pairs):] + pairs[:r % len(pairs)]
        # The protocol order rotates too.
        porder = protos[r % len(protos):] + protos[:r % len(protos)]
        for proto in porder:
            quic = proto == "hy2" or proto.startswith("tuic")
            args.bulk_bytes = (args.bulk_bytes_quic or tcp_bytes) if quic else tcp_bytes
            for c, s in order:
                client = "sing-box" if c == "sb" else "sail-server"
                server = "sing-box" if s == "sb" else "sail"
                tag = f"--{c}-{s}-r{r + 1}"
                run = Run(args, proto, client, server, client_bin=bins.get(c),
                          server_bin=bins.get(s), tag=tag)
                run.pair = f"{c}>{s}"
                summ = run.go()
                summ.update({"proto": proto, "pair": f"{c}>{s}", "round": r + 1})
                summaries.append(summ)
                if not run.failures:
                    os.remove(os.path.join(run.dir, "raw.jsonl.gz"))
                write_summary(args.out, summaries)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--work", default="netem-work")
    ap.add_argument("--sail", default="netem-work/sail")
    ap.add_argument("--singbox", default="/usr/local/bin/sing-box")
    ap.add_argument("--netgen", default="netem-work/netgen")
    ap.add_argument("--protocols", default="direct,ss,trojan")
    ap.add_argument("--clients", default="sail-server,sail-mobile,sing-box")
    ap.add_argument("--soak", type=float, default=0, metavar="HOURS",
                    help="instead of the scenarios: HOURS of light traffic under link "
                         "conditions taken in turn, judged on the client's resting RSS")
    ap.add_argument("--cpus", default=None, metavar="LIST",
                    help="pin the client side (client under test and traffic tool) to "
                         "these CPUs (taskset -c); with --server-cpus, the server side to "
                         "those, else to these too")
    ap.add_argument("--server-cpus", default=None, metavar="LIST",
                    help="pin the server side (protocol server and traffic tool's "
                         "server) to these CPUs")
    ap.add_argument("--rounds", type=int, default=1,
                    help="run each shaped scenario's workloads this many times; the "
                         "summary gives the median, min and max")
    ap.add_argument("--bulk-bytes", type=int, default=None,
                    help="bytes per bulk stream, for transfers long enough to settle")
    ap.add_argument("--client-set", action="append", default=[], metavar="KEY=VALUE",
                    help="a runtime option for a sail client under test, as sail's --set; "
                         "repeatable")
    ap.add_argument("--inbound", choices=["socks", "tun"], default="socks",
                    help="how traffic reaches the client: its SOCKS inbound, or a TUN "
                         "with auto_route that takes the namespace's traffic")
    # sing-box is the reference; sail serves the protocols it takes in too.
    ap.add_argument("--servers", default="sing-box")
    ap.add_argument("--only", default="",
                    help="only these scenarios, comma-separated: each a part of a shaped "
                         "scenario's name, or disconnect, rtt_step, concurrency, halfclose; "
                         "route_switch alone, as a run of its own")
    ap.add_argument("--shape", action="append", default=[], metavar="NAME=SPEC",
                    help="a shaped scenario of one's own, after the fixed ones: NAME, and "
                         "what `tc qdisc ... netem` takes, e.g. rtt100='delay 50ms 5ms "
                         "distribution normal'; a rate needs its own limit (about 100 ms of "
                         "queue, as the fixed rate10m's 'limit 420'), or netns.sh gives it "
                         "100000 packets; with --only NAME, the only one run")
    ap.add_argument("--churn-rates", default="200,500", metavar="LIST",
                    help="the new connections a second of the concurrency scenario's churn "
                         "phases, 30 s each (10 with --quick), comma-separated")
    ap.add_argument("--setup-n", type=int, default=0,
                    help="connections of the setup workload, for rare failures")
    ap.add_argument("--client-nofile", type=int, default=None,
                    help="the client under test's descriptor limit (soft and hard); "
                         "the others keep a deployment's")
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--bulk-only", action="store_true",
                    help="of the workloads, bulk down and up only")
    ap.add_argument("--netgen-cpus", default=None, metavar="LIST",
                    help="CPUs for the traffic tool at both ends, apart from the client's "
                         "and the server's; at least 4 for multi-Gbit cells (with 2, every "
                         "pair stopped near 3.3 Gbit/s on netgen's own CPU)")
    ap.add_argument("--server-profile", default="server",
                    help="the runtime profile of a sail server (default server)")
    ap.add_argument("--end-settle", type=float, default=10, metavar="SECONDS",
                    help="how long the client rests before its last sample (default 10)")
    ap.add_argument("--sail-bin", action="append", default=[], metavar="NAME=PATH",
                    help="another sail binary, named for --matrix (repeatable)")
    ap.add_argument("--matrix", default="",
                    help="client>server pairs, each sb, sail or a --sail-bin name, e.g. "
                         "sb>sb,sail>sb,sb>sail,sail>sail; rounds go outside, the order of "
                         "pairs and protocols rotates each round")
    ap.add_argument("--bulk-bytes-quic", type=int, default=None,
                    help="bulk bytes for hy2 and tuic, in place of --bulk-bytes")
    args = ap.parse_args()
    args.only_list = [o.strip() for o in args.only.split(",") if o.strip()]
    try:
        args.churn_rates = [int(r) for r in args.churn_rates.split(",") if r.strip()]
    except ValueError:
        ap.error(f"--churn-rates {args.churn_rates!r}: numbers, comma-separated")
    if not args.churn_rates or any(r <= 0 for r in args.churn_rates):
        ap.error("--churn-rates: one rate or more, each above 0")
    if "route_switch" in args.only_list and args.only != "route_switch":
        ap.error("--only route_switch is a run of its own")
    for shape in args.shape:
        name, sep, spec = shape.partition("=")
        if not sep or not name or not spec.strip():
            ap.error(f"--shape {shape!r}: NAME=SPEC")
        if any(name == n for n, _ in SHAPED):
            ap.error(f"--shape {name}: a fixed scenario's name")
        SHAPED.append((name, spec.strip()))
    args.sail_bins = {}
    for item in args.sail_bin:
        name, sep, path = item.partition("=")
        if not sep or not name or not path or name in ("sb", "sail"):
            ap.error(f"--sail-bin {item!r}: NAME=PATH, NAME other than sb and sail")
        args.sail_bins[name] = path
    for pair in filter(None, args.matrix.split(",")):
        sides = pair.split(">")
        known = {"sb", "sail", *args.sail_bins}
        if len(sides) != 2 or not set(sides) <= known:
            ap.error(f"--matrix {pair!r}: client>server, each of {sorted(known)}")
    if args.netgen_cpus:
        NETGEN_CPUS[CLIENT_NS] = NETGEN_CPUS[SERVER_NS] = args.netgen_cpus
    if args.cpus:
        CPUS[CLIENT_NS] = args.cpus
        CPUS[SERVER_NS] = args.server_cpus or args.cpus
    elif args.server_cpus:
        CPUS[SERVER_NS] = args.server_cpus

    free = shutil.disk_usage("/").free
    if free < 2 << 30:
        sys.exit(f"only {free >> 20} MiB free on /: not starting")
    run_id = time.strftime("%Y%m%dT%H%M%S")
    args.out = os.path.join(args.work, "results", run_id)
    os.makedirs(args.out, exist_ok=True)
    if not os.path.exists(f"{args.work}/cert.pem"):
        sh(f"openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes "
           f"-subj /CN=localhost -addext subjectAltName=DNS:localhost -days 30 "
           f"-keyout {args.work}/key.pem -out {args.work}/cert.pem")

    netns("up")
    summaries = []
    if args.matrix:
        try:
            matrix(args, summaries)
        finally:
            netns("down")
        write_summary(args.out, summaries)
        failed = [s["name"] for s in summaries if s["failures"]]
        print(f"== done: {len(summaries)} runs, failing: {failed or 'none'}; {args.out}")
        sys.exit(1 if failed else 0)
    try:
        for proto in args.protocols.split(","):
            for server in args.servers.split(","):
                if proto == "direct" and server != "sing-box":
                    continue
                for client in args.clients.split(","):
                    run = Run(args, proto, client, server)
                    summaries.append(run.go())
                    if not run.failures:
                        # Only failing runs keep their raw records.
                        os.remove(os.path.join(run.dir, "raw.jsonl.gz"))
                    # After every run: a long pass stopped halfway keeps
                    # what it finished.
                    write_summary(args.out, summaries)
    finally:
        netns("down")
    write_summary(args.out, summaries)
    failed = [s["name"] for s in summaries if s["failures"]]
    print(f"== done: {len(summaries)} runs, failing: {failed or 'none'}; {args.out}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
