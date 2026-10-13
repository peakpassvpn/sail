#!/usr/bin/env python3
"""Where a process of the desktop cell spent its CPU, from one transfer's
trace (run.py --profile, Windows).

It reads the text xperf makes of a trace, with symbols:

    xperf -i NAME.etl -o NAME.txt -symbols -a dumper
    python3 tools/perf/desktop/profile.py NAME.txt --roles NAME.json --out NAME

and prints Markdown: the samples of the whole system by process, and for
each of `--report`'s parts (the client, unless said otherwise) its samples
by what it was doing (below) and by module, its functions by their own
samples and by the samples they are on the stack of, and its commonest
stacks. NAME.PART.folded gets every
stack of that part with its count, outermost frame first, the frames
joined by `;`, as flame graph tools read them.

A sample is one CPU at one moment, a millisecond apart by default; it
belongs to the process whose thread that CPU ran, so the kernel's work in
that thread is the process's too, and an interrupt's or a deferred call's
is whoever it interrupted. Functions the compiler inlined have no frame of
their own: their samples are their caller's.

What it was doing is read off each stack by the frames that mark it
(MARKERS): a system call that wakes a thread, one that waits, one that
sends to a socket, and so on; a stack with none of them is the kernel's
other work, or the program's own code by the crate of its innermost frame.
Every sample is in one row, so the rows add up, and with the bytes of the
transfer they are CPU seconds per GiB, to set a client's beside another's.
It is an approximation. The markers are Windows' own frames, so they hold
for any program, but a sample between the program and the kernel has only
the program's side to go by: a Go program sends and receives on both kinds
of socket through the same two calls, and its samples there count as TCP's.
A send on loopback also runs the receiver's side of the stack, in the
sender's thread.

Only the standard library.
"""

import argparse
import collections
import json
import re
import sys

PID = re.compile(r"\(\s*(-?\d+)\)\s*$")
# A Rust symbol's hash, which says nothing here.
HASH = re.compile(r"::h[0-9a-f]{16}\b")
# xperf's default, which run.py leaves: a sample a millisecond on each CPU.
SAMPLE_SECONDS = 0.001
GIB = 1 << 30

# What a stack was doing, by a frame anywhere on it; the first that matches
# has the sample. The order matters where one holds another: cancelling a
# poll completes it, and a send on loopback delivers to the receiver.
MARKERS = [(name, re.compile(pattern)) for name, pattern in (
    # tokio unparks a worker, a futex wakes a waiter (NtAlertThreadByThreadId);
    # Go's runtime sets an event.
    ("waking a thread",
     r"!(Nt|Ke)AlertThreadByThreadId|^ntoskrnl\.exe!NtSetEvent"),
    # A parked worker, a contended lock (WaitOnAddress); Go waits on its event.
    ("waiting: a parked thread, a contended lock",
     r"!(Rtl)?WaitOnAddress$|!NtWaitForAlertByThreadId"
     r"|^ntoskrnl\.exe!NtWaitFor(Single|Multiple)Objects?$"),
    # The I/O driver asks the completion port what is ready.
    ("the completion port, asked what is ready",
     r"!(Nt|Zw)RemoveIoCompletion(Ex)?$"),
    # mio's readiness: a poll is given to AFD for a socket, and cancelled
    # when what is wanted of the socket changes.
    ("readiness: a poll cancelled", r"!(Nt|Zw)CancelIoFile(Ex)?$"),
    ("readiness: a poll given to AFD", r"^afd\.sys!Afd(Poll|CompletePollIrp)"),
    # The socket calls. A datagram's are known by AFD's and tcpip's names,
    # or by Winsock's when the call is one that only a datagram socket has.
    ("UDP send",
     r"^afd\.sys!Afd\w*(Datagram|Dgram)\w*Send|^afd\.sys!AfdSendDatagram"
     r"|^mswsock\.dll!(MSAFD_)?WSP(SendMsg|SendTo)$|^tcpip\.sys!UdpSendMessages"),
    ("UDP receive",
     r"^afd\.sys!Afd\w*(Datagram|Dgram)\w*Receive|^afd\.sys!AfdReceiveDatagram"
     r"|^mswsock\.dll!(MSAFD_)?WSP(RecvMsg|RecvFrom)$"),
    ("TCP send", r"^afd\.sys!Afd\w*Send|^mswsock\.dll!WSPSend$"),
    ("TCP receive", r"^afd\.sys!Afd\w*Receive|^mswsock\.dll!WSPRecv$"),
)]
KERNEL = "the kernel's other work (interrupts, page faults, other calls)"
# The program's own code, by the crate of the innermost frame.
CRATES = {"quinn_proto": "quinn_proto", "quinn": "quinn, quinn_udp, quinn_btls",
          "quinn_udp": "quinn, quinn_udp, quinn_btls", "quinn_btls": "quinn, quinn_udp, quinn_btls",
          "tokio": "tokio, mio", "mio": "tokio, mio", "sail": "sail"}
# These wrap another crate's future, which is inlined into their poll: the
# sample is that crate's, the first one named in the type.
WRAPPERS = ("tracing", "futures_util")
CRATE = re.compile(r"(?<![\w:])([a-z_][a-z0-9_]*)::")
HEAP = re.compile(r"Heap|Lfh|Alloc|Free")


def text(path):
    with open(path, "rb") as f:
        utf16 = f.read(2) in (b"\xff\xfe", b"\xfe\xff")
    return open(path, encoding="utf-16" if utf16 else "utf-8", errors="replace")


def read(path):
    """The trace's samples as {(time, thread): [pid, process, function]},
    and their stacks as {(time, thread): [frame, ...]} in the order xperf
    gives them, innermost first: the kernel's frames of a sample, then its
    thread's own, each numbered from 1."""
    samples, stacks = {}, {}
    columns = {}
    in_header = False
    before = 0
    names = {}
    with text(path) as f:
        for line in f:
            line = line.rstrip("\r\n")
            if not in_header and not columns and before > 200:
                # No header where one is expected: the columns as xperf has them.
                columns["Stack"] = ["Stack"]
            if in_header or not columns:
                before += 1
                if line.strip() == "BeginHeader":
                    in_header = True
                elif line.strip() == "EndHeader":
                    in_header = False
                    if "Stack" not in columns:
                        columns["Stack"] = ["Stack", "TimeStamp", "ThreadID", "No.", "Address",
                                            "Image!Function"]
                elif in_header:
                    fields = [c.strip() for c in line.split(",")]
                    columns[fields[0]] = fields
                continue
            kind = line.split(",", 1)[0].strip()
            if kind == "Stack":
                fields = line.split(",", 5)
                if len(fields) < 6:
                    continue
                key = (fields[1].strip(), fields[2].strip())
                frame = fields[5].strip()
                stacks.setdefault(key, []).append(names.setdefault(frame, frame))
            elif kind == "SampledProfile":
                cols = columns.get(kind, [])
                at = {name: i for i, name in enumerate(cols)}
                process = next((i for i, c in enumerate(cols) if c.startswith("Process Name")), 2)
                thread = at.get("ThreadID", 3)
                last = max(process, thread, at.get("CPU", 5))
                fields = line.split(",", last + 1)
                if len(fields) <= last:
                    continue
                name = fields[process].strip()
                pid = PID.search(name)
                pid = int(pid.group(1)) if pid else -1
                # The function sampled, when the stack was not walked: the
                # second of two Image!Function fields, before the count and
                # the type.
                rest = fields[-1].rsplit(",", 2)[0] if len(fields) > last + 1 else ""
                own = re.split(r", (?=[^ ,!<>]+!)", rest)[-1].strip() or "?"
                samples[(fields[at.get("TimeStamp", 1)].strip(), fields[thread].strip())] = \
                    [pid, name, names.setdefault(own, own)]
    return samples, stacks


def module(frame):
    return frame.split("!", 1)[0] if "!" in frame else "?"


def kernel(frame):
    name = module(frame).lower()
    return name.endswith(".sys") or name in ("ntoskrnl.exe", "hal.dll")


def own_code(frame):
    """The row of a sample whose innermost frame is the program's or a
    library's, not the kernel's."""
    name, _, function = frame.partition("!")
    lower = name.lower()
    if lower in ("vcruntime140.dll", "ucrtbase.dll"):
        return "the C runtime (memcpy, malloc)"
    if lower == "ntdll.dll" and HEAP.search(function):
        return "the heap (ntdll)"
    if not lower.endswith(".exe"):
        return "other system libraries (ntdll, Winsock)"
    crates = CRATE.findall(function)
    if not crates:
        # C, as BoringSSL's assembly and its functions without a namespace;
        # or a program without names at all, as a Go one.
        return (f"{name}: C and assembly (BoringSSL)" if re.match(r"[A-Za-z_]\w*$", function)
                else f"{name}: its own code, no names")
    crate = crates[0]
    if crate in WRAPPERS and len(crates) > 1:
        crate = next((c for c in crates[1:] if c in CRATES), crate)
    if crate == "bssl" or "<bssl::" in function:
        return f"{name}: C and assembly (BoringSSL)"
    return f"{name}: {CRATES.get(crate, 'other crates (std, bytes, tracing and the rest)')}"


def doing(stack):
    """The row of MARKERS' table a sample is in."""
    for name, marker in MARKERS:
        if any(marker.search(frame) for frame in stack):
            return name
    return KERNEL if kernel(stack[0]) else own_code(stack[0])


def short(frame, width):
    frame = HASH.sub("", frame).replace("|", "\\|")
    return frame if len(frame) <= width else frame[:width - 1] + "…"


def table(title, counts, total, rows, width=110):
    lines = [f"**{title}**", "", "| % | samples | |", "|---:|---:|---|"]
    for name, n in counts.most_common(rows):
        lines.append(f"| {100 * n / total:.1f} | {n} | `{short(name, width)}` |")
    return lines + [""]


def partition(parts, total, gib):
    """What the process was doing, as a table: the marked rows in MARKERS'
    order, then the kernel's rest, then its own code, largest first."""
    order = [name for name, _ in MARKERS] + [KERNEL]
    rows = [name for name in order if parts[name]]
    rows += [name for name, _ in parts.most_common() if name not in order]
    per_gib = SAMPLE_SECONDS / gib if gib else None
    lines = ["**By what it was doing (by the frames that mark it: an approximation)**", "",
             "| | samples | % |" + (" CPU-s/GiB |" if per_gib else ""),
             "|---|---:|---:|" + ("---:|" if per_gib else "")]
    for name in rows + ["all"]:
        n = total if name == "all" else parts[name]
        lines.append(f"| {name} | {n} | {100 * n / total:.1f} |"
                     + (f" {n * per_gib:.2f} |" if per_gib else ""))
    return lines + [""]


def report(part, pids, samples, stacks, args, gib):
    mine = {key: s for key, s in samples.items() if s[0] in pids}
    total = len(mine)
    lines = [f"#### The {part} ({', '.join(sorted({s[1] for s in mine.values()})) or 'no samples'})",
             ""]
    if not total:
        return lines + [f"No sample of its process ({pids}).", ""], {}
    modules, own, inclusive, parts = (collections.Counter() for _ in range(4))
    folded, tops = collections.Counter(), collections.Counter()
    walked = 0
    for key, (_, _, function) in mine.items():
        stack = stacks.get(key)
        if stack:
            walked += 1
        else:
            stack = [function]
        modules[module(stack[0])] += 1
        parts[doing(stack)] += 1
        own[stack[0]] += 1
        for frame in set(stack):
            inclusive[frame] += 1
        # MSVC's names of Rust's generics have the separator in them.
        folded[";".join(frame.replace(";", ",") for frame in reversed(stack))] += 1
        tops[tuple(stack[:args.depth])] += 1
    lines += [f"{total} samples, {walked} of them with a stack "
              f"({100 * walked / total:.0f}%).", ""]
    lines += partition(parts, total, gib)
    lines += table("By module (of the innermost frame)", modules, total, 20)
    lines += table(f"Functions by their own samples, the first {args.functions}", own, total,
                   args.functions)
    lines += table(f"Functions by the samples they are on the stack of, the first {args.functions}",
                   inclusive, total, args.functions)
    lines += [f"**The {args.stacks} commonest stacks, by their innermost {args.depth} frames "
              "(innermost first)**", ""]
    for stack, n in tops.most_common(args.stacks):
        lines += [f"{100 * n / total:.1f}%, {n} samples:", "", "```"]
        lines += ["  " + HASH.sub("", frame)[:160] for frame in stack]
        lines += ["```", ""]
    return lines, folded


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("dump", help="xperf's text of the trace: -symbols -a dumper")
    ap.add_argument("--roles", required=True, help="run.py's .json of the trace")
    ap.add_argument("--out", required=True, help="the prefix of the files written")
    ap.add_argument("--report", default="client",
                    help="the parts to report, of client, server and target, by commas")
    ap.add_argument("--functions", type=int, default=40)
    ap.add_argument("--stacks", type=int, default=15)
    ap.add_argument("--depth", type=int, default=14, help="frames of a stack in the report")
    args = ap.parse_args()
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")

    with open(args.roles) as f:
        roles = json.load(f)
    pids = {part: set(of) for part, of in roles["pids"].items()}
    part_of = {pid: part for part, of in pids.items() for pid in of}
    parts = [p for p in args.report.split(",") if p]
    unknown = [p for p in parts if p not in pids]
    if unknown:
        ap.error(f"--report: of {', '.join(pids)}; not {', '.join(unknown)}")

    samples, stacks = read(args.dump)
    # The transfer's bytes, for CPU seconds per GiB; none of a failed one.
    gib = roles.get("bytes", 0) / GIB

    lines = [f"### Profile: {roles['protocol']}, {roles['direction']}, client {roles['client']}", ""]
    if "mbps" in roles:
        lines += [f"The transfer: {roles['mbps']} Mbit/s in {roles['seconds']} s, the client's CPU "
                  f"{roles['cpu_s']} s ({roles['cpu_s_per_gib']} s/GiB), sampled all the while.", ""]
    total = len(samples)
    if not total:
        print("\n".join(lines + ["No samples in the trace.", ""]))
        sys.exit(1)
    processes = collections.Counter()
    for pid, name, _ in samples.values():
        processes[f"{name}, the {part_of[pid]}" if pid in part_of else name] += 1
    lines += [f"{total} samples of the whole system, {len(stacks)} with a stack.", ""]
    lines += table("By process", processes, total, 12)
    for part in parts:
        told, folded = report(part, pids[part], samples, stacks, args, gib)
        lines += told
        with open(f"{args.out}.{part}.folded", "w", encoding="utf-8", newline="\n") as f:
            for stack, n in folded.most_common():
                f.write(f"{stack} {n}\n")
    out = "\n".join(lines) + "\n"
    with open(args.out + ".md", "w", encoding="utf-8", newline="\n") as f:
        f.write(out)
    print(out)


if __name__ == "__main__":
    main()
