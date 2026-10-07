#!/usr/bin/env python3
"""Interop matrix: sail against sing-box and Mihomo, both ways.

Run as root on a Linux host, from this directory:

    python3 run.py --work WORK --sail SAIL --sing-box SING_BOX --mihomo MIHOMO \\
        [--dirs sail>sb,sb>sail,sail>mh,mh>sail] [--only REGEX] [--part K/N] \\
        [--jobs N] [--netns NAME] [--bulk-mib 64]
    python3 run.py --list [...]          # the matrix and its skips, nothing run

Everything runs inside one network namespace of its own (--netns, created
and deleted here): the servers and clients on 127.0.0.1, the echo and bulk
targets on an address of a dummy interface (10.233.0.1), with no route out,
so nothing leaves the host. Each cell starts a server (sail, sing-box or
Mihomo) and a client, and through the client's SOCKS inbound checks a TCP
echo, a UDP echo where the protocol carries UDP, and a checksummed bulk
transfer each way. Configurations are sing-box JSON for sail and sing-box,
Clash YAML for Mihomo (and for sail as `sailY`, which reads the same YAML
Mihomo does). Results: WORK/results/<run>/summary.json and summary.md, and
per cell its configurations, logs and result.json.
"""
import argparse
import base64
import hashlib
import json
import os
import random
import re
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import traceback
import uuid as uuidlib

HERE = os.path.dirname(os.path.abspath(__file__))

# ------------------------------------------------------------- constants
TARGET = "10.233.0.1"   # the dummy interface's address: echo and bulk
ECHO_PORT = 7           # TCP and UDP echo
BULK_PORT = 9           # checksummed bulk, both ways
HS_PORT = 9443          # a TLS 1.3 server for REALITY and ShadowTLS handshakes
LOCAL = "127.0.0.1"
# Ports of worker k: server BASE+100k, client SOCKS BASE+100k+1.
PORT_BASE = 20000

UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"
PASSWORD = "interop-password"
USER = "interop"
SS_KEYS = {
    "2022-blake3-aes-128-gcm": "Kdv6Zv3G3k1cw3aJkdeBBw==",
    "2022-blake3-aes-256-gcm": "Fyra5lGqq7m8AxbD8l3Y2yVwGRtzx0GmKCDs5wTFG9o=",
    "2022-blake3-chacha20-poly1305": "Fyra5lGqq7m8AxbD8l3Y2yVwGRtzx0GmKCDs5wTFG9o=",
}
SERVER_NAME = "localhost"
ECH_PUBLIC_NAME = "ech-public.invalid"
WS_PATH = "/ws"
UP_PATH = "/up"
GRPC_SERVICE = "interop"

# info names each destination, which the check that traffic went through
# the server reads; --log-level debug for a failure's details.
LOG_LEVEL = "info"

IMPLS = ("sail", "sailY", "sb", "mh")
IMPL_NAMES = {"sail": "sail", "sailY": "sail (Clash YAML)", "sb": "sing-box", "mh": "Mihomo"}
DEFAULT_DIRS = "sail>sb,sb>sail,sail>mh,mh>sail"


# ------------------------------------------------------------- cases
class Case:
    """One row of the matrix: a protocol with its transport, TLS and mux."""

    def __init__(self, proto, transport="tcp", tls="off", mux=None, udp=True, **opt):
        self.proto = proto
        self.transport = transport
        self.tls = tls          # off, tls, reality, ech
        self.mux = mux          # None, smux, yamux, h2mux
        self.udp = udp
        self.opt = opt
        parts = [proto + (f"({opt['variant']})" if opt.get("variant") else ""),
                 transport, tls, mux or "-"]
        self.id = "/".join(parts)

    def __repr__(self):
        return self.id


def cases():
    out = []
    mux_list = [None, "smux", "yamux", "h2mux"]
    # Shadowsocks: a 2022 method and a classic AEAD, each with sing-mux.
    for method in ("2022-blake3-aes-128-gcm", "aes-256-gcm"):
        for mux in mux_list:
            out.append(Case("ss", mux=mux, method=method, variant=method))
    for method in ("2022-blake3-chacha20-poly1305", "chacha20-ietf-poly1305", "aes-128-gcm"):
        out.append(Case("ss", method=method, variant=method))
    out.append(Case("ss", method="2022-blake3-aes-128-gcm", uot=True,
                    variant="2022-blake3-aes-128-gcm+uot"))
    for mode in ("http", "tls"):
        out.append(Case("ss", method="aes-128-gcm", obfs=mode, variant=f"aes-128-gcm+obfs-{mode}"))
    # VMess and VLESS: every transport, TLS off and on, sing-mux.
    for proto in ("vmess", "vless"):
        for transport in ("tcp", "ws", "grpc", "httpupgrade"):
            for tls in ("off", "tls"):
                for mux in mux_list:
                    out.append(Case(proto, transport, tls, mux))
        for tls in ("off", "tls"):
            out.append(Case(proto, "ws-ed", tls))
        out.append(Case(proto, "tcp", "ech"))
    for security in ("chacha20-poly1305", "none", "zero"):
        out.append(Case("vmess", security=security, variant=security))
    # VLESS flows and REALITY.
    out.append(Case("vless", "tcp", "tls", flow="xtls-rprx-vision", variant="vision"))
    out.append(Case("vless", "tcp", "reality"))
    out.append(Case("vless", "tcp", "reality", flow="xtls-rprx-vision", variant="vision"))
    out.append(Case("vless", "grpc", "reality"))
    for mux in mux_list[1:]:
        out.append(Case("vless", "tcp", "reality", mux))
    # Trojan: TLS always.
    for transport in ("tcp", "ws", "grpc", "httpupgrade"):
        for mux in mux_list:
            out.append(Case("trojan", transport, "tls", mux))
    out.append(Case("trojan", "tcp", "ech"))
    out.append(Case("trojan", "tcp", "reality"))
    # QUIC protocols.
    out.append(Case("hysteria2", "quic", "tls"))
    out.append(Case("hysteria2", "quic", "tls", obfs="salamander", variant="salamander"))
    for relay in ("native", "quic"):
        out.append(Case("tuic", "quic", "tls", relay=relay, variant=f"udp-{relay}"))
    out.append(Case("tuic", "quic", "tls", relay="native", cc="cubic", variant="cubic"))
    out.append(Case("tuic", "quic", "ech", relay="native"))
    out.append(Case("hysteria2", "quic", "ech"))
    out.append(Case("anytls", "tcp", "tls"))
    out.append(Case("anytls", "tcp", "ech"))
    out.append(Case("shadowtls", "tcp", "tls", udp=False, method="2022-blake3-aes-128-gcm",
                    variant="v3+ss2022"))
    out.append(Case("shadowtls", "tcp", "tls", udp=False, method="aes-256-gcm",
                    variant="v3+aes-256-gcm"))
    # Plain proxies, with a user.
    out.append(Case("socks"))
    out.append(Case("http", udp=False))
    out.append(Case("http", "tcp", "tls", udp=False))
    out.append(Case("mixed", variant="socks"))
    out.append(Case("mixed", udp=False, via="http", variant="http"))
    out.append(Case("wireguard", "udp"))
    return out


# What each implementation lacks, as a reason, or None.
def unsupported(case, role, impl):
    p, t = case.proto, case.transport
    if impl in ("sail", "sailY"):
        if role == "server" and case.tls == "ech":
            return ("sail has no ECH on inbounds (docs/compat/sing-box.md: "
                    "Encrypted Client Hello on an inbound is an error)")
        if role == "server" and case.opt.get("obfs") and p == "ss":
            return "sail's Shadowsocks inbound has no simple-obfs"
    if impl == "sailY":
        if role == "server" and p not in ("ss", "socks", "http", "mixed"):
            return (f"sail's Clash front-end has no {p} listeners "
                    "(docs/compat/clash.md, listeners[...])")
        if role == "server" and (case.opt.get("obfs") or case.mux):
            return "sail's Clash Shadowsocks listener: no obfs or mux options"
        if role == "server" and case.tls != "off":
            return ("sail's Clash listeners take no certificate "
                    "(docs/compat/clash.md: listeners[http].certificate is an error)")
    if impl == "sb":
        if p == "ss" and case.opt.get("obfs") and role == "server":
            return "sing-box's Shadowsocks inbound has no simple-obfs"
        if p == "ss" and case.opt.get("obfs") and role == "client":
            return "needs the obfs-local plugin binary, which sing-box runs as a process"
    if impl == "mh":
        if p == "wireguard" and role == "server":
            return "Mihomo has no WireGuard listener"
        if p == "mixed" and role == "client":
            return "Mihomo has no mixed proxy type (socks5 and http rows cover it)"
        if p == "http" and case.tls == "tls" and role == "server":
            return None
        if p == "trojan" and case.tls == "reality" and role == "server":
            return None
    return None


def dir_skip(case, client, server):
    """A skip that comes from the pair, not one side."""
    if case.opt.get("obfs") and case.proto == "ss" and client in ("sail", "sailY") \
            and server != "mh":
        return "only Mihomo serves simple-obfs"
    return None


# ------------------------------------------------------------- materials
class Materials:
    """Certificates and keys, made once per work directory."""

    def __init__(self, work, sing_box):
        self.dir = os.path.join(work, "materials")
        os.makedirs(self.dir, exist_ok=True)
        self.cert = os.path.join(self.dir, "cert.pem")
        self.key = os.path.join(self.dir, "key.pem")
        if not os.path.exists(self.cert):
            subprocess.run(
                ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
                 "ec_paramgen_curve:prime256v1", "-nodes", "-subj", f"/CN={SERVER_NAME}",
                 "-addext", f"subjectAltName=DNS:{SERVER_NAME},IP:127.0.0.1",
                 "-days", "30", "-keyout", self.key, "-out", self.cert],
                check=True, capture_output=True)
        self.cert_pem = open(self.cert).read()
        self.key_pem = open(self.key).read()
        path = os.path.join(self.dir, "keys.json")
        if os.path.exists(path):
            keys = json.load(open(path))
        else:
            def gen(*args):
                return subprocess.run([sing_box, "generate", *args], check=True,
                                      capture_output=True, text=True).stdout
            reality = dict(line.split(": ", 1) for line in gen("reality-keypair").splitlines()
                           if ": " in line)
            ech = gen("ech-keypair", ECH_PUBLIC_NAME)
            wg = [dict(line.split(": ", 1) for line in gen("wg-keypair").splitlines()
                       if ": " in line) for _ in range(2)]
            keys = {
                "reality_private": reality["PrivateKey"].strip(),
                "reality_public": reality["PublicKey"].strip(),
                "reality_short_id": gen("rand", "--hex", "8").strip(),
                "ech": ech,
                "wg_server": {k.strip(): v.strip() for k, v in wg[0].items()},
                "wg_client": {k.strip(): v.strip() for k, v in wg[1].items()},
            }
            json.dump(keys, open(path, "w"), indent=1)
        self.k = keys
        blocks = re.findall(r"(-----BEGIN ([A-Z ]+)-----.*?-----END \2-----)", keys["ech"], re.S)
        self.ech = {name: block for block, name in blocks}
        self.ech_config_lines = self.ech["ECH CONFIGS"].splitlines()
        self.ech_key_lines = self.ech["ECH KEYS"].splitlines()
        self.ech_config_b64 = "".join(self.ech_config_lines[1:-1])


# ------------------------------------------------------------- sing-box JSON
def sb_tls_server(case, m, alpn=None):
    if case.tls == "off":
        return None
    if case.tls == "reality":
        return {"enabled": True, "server_name": SERVER_NAME,
                "reality": {"enabled": True,
                            "handshake": {"server": LOCAL, "server_port": HS_PORT},
                            "private_key": m.k["reality_private"],
                            "short_id": [m.k["reality_short_id"]]}}
    tls = {"enabled": True, "server_name": SERVER_NAME,
           "certificate_path": m.cert, "key_path": m.key}
    if alpn:
        tls["alpn"] = alpn
    if case.tls == "ech":
        tls["ech"] = {"enabled": True, "key": m.ech_key_lines}
    return tls


def sb_tls_client(case, m, alpn=None):
    if case.tls == "off":
        return None
    if case.tls == "reality":
        return {"enabled": True, "server_name": SERVER_NAME,
                "utls": {"enabled": True, "fingerprint": "chrome"},
                "reality": {"enabled": True, "public_key": m.k["reality_public"],
                            "short_id": m.k["reality_short_id"]}}
    tls = {"enabled": True, "server_name": SERVER_NAME, "insecure": True}
    if alpn:
        tls["alpn"] = alpn
    if case.tls == "ech":
        tls["ech"] = {"enabled": True, "config": m.ech_config_lines}
    return tls


def sb_transport(case):
    t = case.transport
    if t == "ws":
        return {"type": "ws", "path": WS_PATH, "headers": {"Host": SERVER_NAME}}
    if t == "ws-ed":
        return {"type": "ws", "path": WS_PATH, "headers": {"Host": SERVER_NAME},
                "max_early_data": 2048, "early_data_header_name": "Sec-WebSocket-Protocol"}
    if t == "grpc":
        return {"type": "grpc", "service_name": GRPC_SERVICE}
    if t == "httpupgrade":
        return {"type": "httpupgrade", "path": UP_PATH, "host": SERVER_NAME}
    return None


def sb_transport_server(case):
    tr = sb_transport(case)
    if tr and tr["type"] == "ws":
        tr.pop("headers")
    return tr


def compact(d):
    return {k: v for k, v in d.items() if v is not None}


def sb_server(case, m, port):
    """The server's sing-box configuration: what sail and sing-box serve."""
    p = case.proto
    base = {"tag": "in", "listen": LOCAL, "listen_port": port}
    inbounds = []
    endpoints = []
    mux = {"enabled": True} if case.mux else None
    if p == "ss":
        inbounds.append(compact(dict(base, type="shadowsocks", method=case.opt["method"],
                                     password=SS_KEYS.get(case.opt["method"], PASSWORD),
                                     multiplex=mux)))
    elif p == "vmess":
        inbounds.append(compact(dict(base, type="vmess",
                                     users=[{"name": USER, "uuid": UUID, "alterId": 0}],
                                     tls=sb_tls_server(case, m), transport=sb_transport_server(case),
                                     multiplex=mux)))
    elif p == "vless":
        inbounds.append(compact(dict(base, type="vless",
                                     users=[{"name": USER, "uuid": UUID,
                                             "flow": case.opt.get("flow", "")}],
                                     tls=sb_tls_server(case, m), transport=sb_transport_server(case),
                                     multiplex=mux)))
    elif p == "trojan":
        inbounds.append(compact(dict(base, type="trojan",
                                     users=[{"name": USER, "password": PASSWORD}],
                                     tls=sb_tls_server(case, m), transport=sb_transport_server(case),
                                     multiplex=mux)))
    elif p == "hysteria2":
        ib = dict(base, type="hysteria2", users=[{"name": USER, "password": PASSWORD}],
                  tls=sb_tls_server(case, m, alpn=["h3"]))
        if case.opt.get("obfs"):
            ib["obfs"] = {"type": "salamander", "password": PASSWORD}
        inbounds.append(ib)
    elif p == "tuic":
        inbounds.append(dict(base, type="tuic",
                             users=[{"name": USER, "uuid": UUID, "password": PASSWORD}],
                             congestion_control=case.opt.get("cc", "bbr"),
                             tls=sb_tls_server(case, m, alpn=["h3"])))
    elif p == "anytls":
        inbounds.append(dict(base, type="anytls", users=[{"name": USER, "password": PASSWORD}],
                             tls=sb_tls_server(case, m)))
    elif p == "shadowtls":
        inbounds.append(dict(base, type="shadowtls", version=3,
                             users=[{"name": USER, "password": PASSWORD}],
                             handshake={"server": LOCAL, "server_port": HS_PORT},
                             strict_mode=True, detour="ss-in"))
        inbounds.append({"type": "shadowsocks", "tag": "ss-in", "method": case.opt["method"],
                         "password": SS_KEYS.get(case.opt["method"], PASSWORD)})
    elif p in ("socks", "http", "mixed"):
        ib = dict(base, type=p, users=[{"username": USER, "password": PASSWORD}])
        tls = sb_tls_server(case, m)
        if tls:
            ib["tls"] = tls
        inbounds.append(ib)
    elif p == "wireguard":
        endpoints.append({"type": "wireguard", "tag": "in", "address": ["10.77.0.1/24"],
                          "private_key": m.k["wg_server"]["PrivateKey"], "listen_port": port,
                          "peers": [{"public_key": m.k["wg_client"]["PublicKey"],
                                     "allowed_ips": ["10.77.0.2/32"]}]})
    cfg = {"log": {"level": LOG_LEVEL, "timestamp": True}}
    if inbounds:
        cfg["inbounds"] = inbounds
    if endpoints:
        cfg["endpoints"] = endpoints
    cfg["outbounds"] = [{"type": "direct", "tag": "direct"}]
    cfg["route"] = {"final": "direct"}
    return cfg


def sb_client(case, m, port, socks_port):
    """The client's sing-box configuration: what sail and sing-box run."""
    p = case.proto
    base = {"tag": "proxy", "server": LOCAL, "server_port": port}
    outbounds = []
    endpoints = []
    mux = {"enabled": True, "protocol": case.mux} if case.mux else None
    if p == "ss":
        ob = dict(base, type="shadowsocks", method=case.opt["method"],
                  password=SS_KEYS.get(case.opt["method"], PASSWORD))
        if mux:
            ob["multiplex"] = mux
        if case.opt.get("uot"):
            ob["udp_over_tcp"] = {"enabled": True, "version": 2}
        if case.opt.get("obfs"):
            ob["plugin"] = "obfs-local"
            ob["plugin_opts"] = f"obfs={case.opt['obfs']};obfs-host={SERVER_NAME}"
        outbounds.append(ob)
    elif p == "vmess":
        outbounds.append(compact(dict(base, type="vmess", uuid=UUID, alter_id=0,
                                      security=case.opt.get("security", "aes-128-gcm"),
                                      tls=sb_tls_client(case, m), transport=sb_transport(case),
                                      multiplex=mux)))
    elif p == "vless":
        outbounds.append(compact(dict(base, type="vless", uuid=UUID,
                                      flow=case.opt.get("flow") or None,
                                      tls=sb_tls_client(case, m), transport=sb_transport(case),
                                      multiplex=mux)))
    elif p == "trojan":
        outbounds.append(compact(dict(base, type="trojan", password=PASSWORD,
                                      tls=sb_tls_client(case, m), transport=sb_transport(case),
                                      multiplex=mux)))
    elif p == "hysteria2":
        ob = dict(base, type="hysteria2", password=PASSWORD,
                  tls=sb_tls_client(case, m, alpn=["h3"]))
        if case.opt.get("obfs"):
            ob["obfs"] = {"type": "salamander", "password": PASSWORD}
        outbounds.append(ob)
    elif p == "tuic":
        outbounds.append(dict(base, type="tuic", uuid=UUID, password=PASSWORD,
                              congestion_control=case.opt.get("cc", "bbr"),
                              udp_relay_mode=case.opt.get("relay", "native"),
                              tls=sb_tls_client(case, m, alpn=["h3"])))
    elif p == "anytls":
        tls = sb_tls_client(case, m)
        tls["utls"] = {"enabled": True, "fingerprint": "chrome"}
        outbounds.append(dict(base, type="anytls", password=PASSWORD, tls=tls))
    elif p == "shadowtls":
        outbounds.append({"type": "shadowsocks", "tag": "proxy", "method": case.opt["method"],
                          "password": SS_KEYS.get(case.opt["method"], PASSWORD),
                          "detour": "stls"})
        outbounds.append(dict(base, tag="stls", type="shadowtls", version=3, password=PASSWORD,
                              tls={"enabled": True, "server_name": SERVER_NAME, "insecure": True,
                                   "utls": {"enabled": True, "fingerprint": "chrome"}}))
    elif p in ("socks", "mixed") and case.opt.get("via") != "http":
        outbounds.append(dict(base, type="socks", version="5", username=USER, password=PASSWORD))
    elif p in ("http", "mixed"):
        ob = dict(base, type="http", username=USER, password=PASSWORD)
        tls = sb_tls_client(case, m)
        if tls:
            ob["tls"] = tls
        outbounds.append(ob)
    elif p == "wireguard":
        endpoints.append({"type": "wireguard", "tag": "proxy", "address": ["10.77.0.2/32"],
                          "private_key": m.k["wg_client"]["PrivateKey"], "mtu": 1408,
                          "peers": [{"address": LOCAL, "port": port,
                                     "public_key": m.k["wg_server"]["PublicKey"],
                                     "allowed_ips": ["0.0.0.0/0"]}]})
    outbounds.append({"type": "direct", "tag": "direct"})
    cfg = {"log": {"level": LOG_LEVEL, "timestamp": True},
           "inbounds": [{"type": "socks", "tag": "socks-in", "listen": LOCAL,
                         "listen_port": socks_port}]}
    if endpoints:
        cfg["endpoints"] = endpoints
    cfg["outbounds"] = outbounds
    cfg["route"] = {"final": "proxy"}
    return cfg


# ------------------------------------------------------------- Clash YAML
def mh_tls_listener(case, m, listener):
    if case.tls == "off":
        return
    if case.tls == "reality":
        listener["reality-config"] = {"dest": f"{LOCAL}:{HS_PORT}",
                                      "private-key": m.k["reality_private"],
                                      "short-id": [m.k["reality_short_id"]],
                                      "server-names": [SERVER_NAME]}
        return
    listener["certificate"] = m.cert_pem
    listener["private-key"] = m.key_pem
    if case.tls == "ech":
        listener["ech-key"] = m.ech["ECH KEYS"] + "\n"


def mh_transport_listener(case, listener):
    if case.transport in ("ws", "ws-ed", "httpupgrade"):
        listener["ws-path"] = WS_PATH if case.transport != "httpupgrade" else UP_PATH
    elif case.transport == "grpc":
        listener["grpc-service-name"] = GRPC_SERVICE


def mh_server(case, m, port):
    """Mihomo's listener for the case (and sail's, where it reads one)."""
    p = case.proto
    li = {"name": "in", "listen": LOCAL, "port": port}
    if p == "ss":
        li.update(type="shadowsocks", cipher=case.opt["method"],
                  password=SS_KEYS.get(case.opt["method"], PASSWORD), udp=True)
        if case.opt.get("obfs"):
            li["simple-obfs"] = {"enable": True, "mode": case.opt["obfs"]}
    elif p == "vmess":
        li.update(type="vmess", users=[{"username": USER, "uuid": UUID, "alterId": 0}])
        mh_tls_listener(case, m, li)
        mh_transport_listener(case, li)
    elif p == "vless":
        li.update(type="vless", users=[{"username": USER, "uuid": UUID,
                                        "flow": case.opt.get("flow", "")}])
        if case.tls == "off":
            # Mihomo refuses a VLESS listener without TLS unless told.
            li["allow-insecure"] = True
        mh_tls_listener(case, m, li)
        mh_transport_listener(case, li)
    elif p == "trojan":
        li.update(type="trojan", users=[{"username": USER, "password": PASSWORD}])
        mh_tls_listener(case, m, li)
        mh_transport_listener(case, li)
    elif p == "hysteria2":
        li.update(type="hysteria2", users={USER: PASSWORD}, alpn=["h3"])
        mh_tls_listener(case, m, li)
        if case.opt.get("obfs"):
            li.update(obfs="salamander", **{"obfs-password": PASSWORD})
    elif p == "tuic":
        li.update(type="tuic", users={UUID: PASSWORD}, alpn=["h3"],
                  **{"congestion-controller": case.opt.get("cc", "bbr")})
        mh_tls_listener(case, m, li)
    elif p == "anytls":
        li.update(type="anytls", users={USER: PASSWORD})
        mh_tls_listener(case, m, li)
    elif p == "shadowtls":
        li.update(type="shadowsocks", cipher=case.opt["method"],
                  password=SS_KEYS.get(case.opt["method"], PASSWORD), udp=False,
                  **{"shadow-tls": {"enable": True, "version": 3,
                                    "users": [{"name": USER, "password": PASSWORD}],
                                    "handshake": {"dest": f"{LOCAL}:{HS_PORT}"},
                                    "strict-mode": True}})
    elif p in ("socks", "http", "mixed"):
        li.update(type=p, users=[{"username": USER, "password": PASSWORD}])
        if p != "http":
            li["udp"] = True
        mh_tls_listener(case, m, li)
    else:
        return None
    return {"log-level": LOG_LEVEL, "allow-lan": False, "ipv6": False, "mode": "rule",
            "find-process-mode": "off", "geo-auto-update": False,
            "dns": {"enable": False}, "listeners": [li], "proxies": [],
            "rules": ["MATCH,DIRECT"]}


def mh_client(case, m, port, socks_port):
    """Mihomo's proxy for the case, as Mihomo and sail (sailY) read it."""
    p = case.proto
    pr = {"name": "proxy", "server": LOCAL, "port": port, "udp": True}

    def tls(pr, sni_key="servername"):
        if case.tls == "off":
            return
        pr["tls"] = True
        pr[sni_key] = SERVER_NAME
        if case.tls == "reality":
            pr["reality-opts"] = {"public-key": m.k["reality_public"],
                                  "short-id": m.k["reality_short_id"]}
            pr["client-fingerprint"] = "chrome"
            return
        pr["skip-cert-verify"] = True
        if case.tls == "ech":
            pr["ech-opts"] = {"enable": True, "config": m.ech_config_b64}

    def transport(pr):
        t = case.transport
        if t in ("ws", "ws-ed", "httpupgrade"):
            pr["network"] = "ws"
            ws = {"path": WS_PATH if t != "httpupgrade" else UP_PATH,
                  "headers": {"Host": SERVER_NAME}}
            if t == "ws-ed":
                ws.update({"max-early-data": 2048,
                           "early-data-header-name": "Sec-WebSocket-Protocol"})
            if t == "httpupgrade":
                ws["v2ray-http-upgrade"] = True
            pr["ws-opts"] = ws
        elif t == "grpc":
            pr["network"] = "grpc"
            pr["grpc-opts"] = {"grpc-service-name": GRPC_SERVICE}

    if p == "ss":
        pr.update(type="ss", cipher=case.opt["method"],
                  password=SS_KEYS.get(case.opt["method"], PASSWORD))
        if case.opt.get("uot"):
            pr.update({"udp-over-tcp": True, "udp-over-tcp-version": 2})
        if case.opt.get("obfs"):
            pr.update(plugin="obfs", **{"plugin-opts": {"mode": case.opt["obfs"],
                                                        "host": SERVER_NAME}})
    elif p == "vmess":
        pr.update(type="vmess", uuid=UUID, alterId=0,
                  cipher=case.opt.get("security", "aes-128-gcm"))
        tls(pr)
        transport(pr)
    elif p == "vless":
        pr.update(type="vless", uuid=UUID)
        if case.opt.get("flow"):
            pr["flow"] = case.opt["flow"]
        tls(pr)
        transport(pr)
    elif p == "trojan":
        pr.update(type="trojan", password=PASSWORD)
        tls(pr, "sni")
        pr.pop("tls", None)
        transport(pr)
    elif p == "hysteria2":
        pr.update(type="hysteria2", password=PASSWORD, alpn=["h3"])
        tls(pr, "sni")
        pr.pop("tls", None)
        if case.opt.get("obfs"):
            pr.update(obfs="salamander", **{"obfs-password": PASSWORD})
    elif p == "tuic":
        pr.update(type="tuic", uuid=UUID, password=PASSWORD, alpn=["h3"],
                  **{"congestion-controller": case.opt.get("cc", "bbr"),
                     "udp-relay-mode": case.opt.get("relay", "native")})
        tls(pr, "sni")
        pr.pop("tls", None)
    elif p == "anytls":
        pr.update(type="anytls", password=PASSWORD, **{"client-fingerprint": "chrome"})
        tls(pr, "sni")
        pr.pop("tls", None)
    elif p == "shadowtls":
        pr.update(type="ss", cipher=case.opt["method"], udp=False,
                  password=SS_KEYS.get(case.opt["method"], PASSWORD), plugin="shadow-tls",
                  **{"client-fingerprint": "chrome",
                     "plugin-opts": {"host": SERVER_NAME, "password": PASSWORD, "version": 3,
                                     "skip-cert-verify": True}})
    elif p == "socks" or (p == "mixed" and case.opt.get("via") != "http"):
        pr.update(type="socks5", username=USER, password=PASSWORD)
    elif p in ("http", "mixed"):
        pr.update(type="http", username=USER, password=PASSWORD)
        pr.pop("udp")
        tls(pr, "sni")
    elif p == "wireguard":
        pr.update(type="wireguard", ip="10.77.0.2", mtu=1408,
                  **{"private-key": m.k["wg_client"]["PrivateKey"],
                     "public-key": m.k["wg_server"]["PublicKey"],
                     "allowed-ips": ["0.0.0.0/0"]})
    if case.mux:
        pr["smux"] = {"enabled": True, "protocol": case.mux}
    return {"socks-port": socks_port, "bind-address": LOCAL, "allow-lan": False,
            "mode": "rule", "log-level": LOG_LEVEL, "ipv6": False,
            "find-process-mode": "off", "geo-auto-update": False,
            "dns": {"enable": False}, "proxies": [pr], "rules": ["MATCH,proxy"]}


def to_yaml(value, indent=0):
    """Block-style YAML of dicts, lists, strings, numbers and booleans.
    Strings are JSON-quoted, which YAML reads as double-quoted scalars."""
    pad = "  " * indent
    lines = []
    if isinstance(value, dict):
        for k, v in value.items():
            if isinstance(v, (dict, list)) and v:
                lines.append(f"{pad}{k}:")
                lines.append(to_yaml(v, indent + 1))
            else:
                lines.append(f"{pad}{k}: {scalar(v)}")
    elif isinstance(value, list):
        for v in value:
            if isinstance(v, dict) and v:
                inner = to_yaml(v, indent + 1).split("\n")
                lines.append(f"{pad}- {inner[0].lstrip()}")
                lines.extend(inner[1:])
            elif isinstance(v, list) and v:
                lines.append(f"{pad}-")
                lines.append(to_yaml(v, indent + 1))
            else:
                lines.append(f"{pad}- {scalar(v)}")
    return "\n".join(lines)


def scalar(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, dict):
        return "{}"
    if isinstance(v, list):
        return "[]"
    return json.dumps(v)


# ------------------------------------------------------------- targets
def stream_block(seed):
    return random.Random(seed).randbytes(1 << 20)


def stream_chunks(seed, total):
    """The bulk stream: 1 MiB blocks, each with its index in front, so that
    a block repeated, dropped or out of order differs."""
    block = stream_block(seed)
    i, left = 0, total
    while left > 0:
        chunk = struct.pack(">Q", i) + block[8:]
        yield chunk[:left]
        left -= len(chunk)
        i += 1


def stream_digest(seed, total):
    h = hashlib.sha256()
    for c in stream_chunks(seed, total):
        h.update(c)
    return h.digest()


def recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        b = sock.recv(min(n - len(buf), 1 << 20))
        if not b:
            raise EOFError(f"closed after {len(buf)} of {n} bytes")
        buf += b
    return bytes(buf)


class Targets:
    """TCP and UDP echo on ECHO_PORT, bulk on BULK_PORT, a TLS 1.3 server
    for handshakes on HS_PORT."""

    def __init__(self, m, log_path=None):
        self.m = m
        self.socks = []
        # Each bulk connection's end: what reached the target, for telling
        # which leg lost bytes when a transfer fails.
        self.log = open(log_path, "a") if log_path else None
        self.log_lock = threading.Lock()

    def note(self, text):
        if self.log:
            with self.log_lock:
                self.log.write(f"{time.strftime('%H:%M:%S')} {text}\n")
                self.log.flush()

    def start(self):
        for target, fn in ((ECHO_PORT, self.tcp_echo), (BULK_PORT, self.bulk)):
            s = socket.socket()
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((TARGET, target))
            s.listen(256)
            self.socks.append(s)
            threading.Thread(target=self.accept, args=(s, fn), daemon=True).start()
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.bind((TARGET, ECHO_PORT))
        self.socks.append(u)
        threading.Thread(target=self.udp_echo, args=(u,), daemon=True).start()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.load_cert_chain(self.m.cert, self.m.key)
        h = socket.socket()
        h.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        h.bind((LOCAL, HS_PORT))
        h.listen(256)
        self.socks.append(h)
        threading.Thread(target=self.accept, args=(h, lambda c: self.tls(ctx, c)),
                         daemon=True).start()

    def accept(self, s, fn):
        while True:
            try:
                c, _ = s.accept()
            except OSError:
                return
            threading.Thread(target=self.guard, args=(fn, c), daemon=True).start()

    @staticmethod
    def guard(fn, c):
        try:
            c.settimeout(150)
            fn(c)
        except Exception:
            pass
        finally:
            c.close()

    @staticmethod
    def tcp_echo(c):
        while True:
            b = c.recv(65536)
            if not b:
                return
            c.sendall(b)

    @staticmethod
    def udp_echo(u):
        while True:
            try:
                b, addr = u.recvfrom(65536)
                u.sendto(b, addr)
            except OSError:
                return

    def bulk(self, c):
        peer = c.getpeername()[1]
        cmd, total, seed = struct.unpack(">cQQ", recv_exact(c, 17))
        if cmd == b"D":
            sent = 0
            try:
                for chunk in stream_chunks(seed, total):
                    c.sendall(chunk)
                    sent += len(chunk)
            finally:
                self.note(f"bulk D seed={seed} from :{peer}: sent {sent} of {total}")
            # Wait for the client to close, so that the last bytes are not
            # cut by a reset.
            c.recv(1)
        elif cmd == b"U":
            h, left = hashlib.sha256(), total
            try:
                while left:
                    b = c.recv(min(left, 1 << 20))
                    if not b:
                        raise EOFError
                    h.update(b)
                    left -= len(b)
            except Exception as e:
                self.note(f"bulk U seed={seed} from :{peer}: got {total - left} of {total}, "
                          f"{type(e).__name__}")
                raise
            ok = h.digest() == stream_digest(seed, total)
            self.note(f"bulk U seed={seed} from :{peer}: got all {total}, "
                      f"{'intact' if ok else 'CORRUPT'}, digest sent")
            c.sendall(h.digest())
            c.recv(1)

    @staticmethod
    def tls(ctx, c):
        t = ctx.wrap_socket(c, server_side=True)
        try:
            t.recv(4096)
            t.sendall(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok")
        finally:
            t.close()

    def stop(self):
        for s in self.socks:
            try:
                s.close()
            except OSError:
                pass


# ------------------------------------------------------------- SOCKS5 client
def socks_connect(port, host, dport, timeout=10):
    s = socket.create_connection((LOCAL, port), timeout=timeout)
    s.sendall(b"\x05\x01\x00")
    if recv_exact(s, 2) != b"\x05\x00":
        raise RuntimeError("SOCKS: no auth method accepted")
    s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(host) + struct.pack(">H", dport))
    rep = recv_exact(s, 4)
    if rep[1] != 0:
        raise RuntimeError(f"SOCKS: CONNECT refused, reply {rep[1]}")
    atyp = rep[3]
    recv_exact(s, {1: 4, 4: 16}.get(atyp, 0) or recv_exact(s, 1)[0])
    recv_exact(s, 2)
    return s


def socks_udp(port, timeout=10):
    """A UDP association: the TCP control connection and the relay's address."""
    s = socket.create_connection((LOCAL, port), timeout=timeout)
    s.sendall(b"\x05\x01\x00")
    if recv_exact(s, 2) != b"\x05\x00":
        raise RuntimeError("SOCKS: no auth method accepted")
    s.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
    rep = recv_exact(s, 4)
    if rep[1] != 0:
        raise RuntimeError(f"SOCKS: UDP ASSOCIATE refused, reply {rep[1]}")
    if rep[3] == 1:
        addr = socket.inet_ntoa(recv_exact(s, 4))
    elif rep[3] == 4:
        addr = socket.inet_ntop(socket.AF_INET6, recv_exact(s, 16))
    else:
        addr = recv_exact(s, recv_exact(s, 1)[0]).decode()
    rport = struct.unpack(">H", recv_exact(s, 2))[0]
    if addr in ("0.0.0.0", "::"):
        addr = LOCAL
    return s, (addr, rport)


# ------------------------------------------------------------- checks
TCP_SIZES = [1, 7, 1000, 16384, 65536, 200000]
UDP_SIZES = [16, 200, 512, 1000, 1200]


def check_tcp(socks_port):
    s = socks_connect(socks_port, TARGET, ECHO_PORT)
    try:
        s.settimeout(15)
        for i, n in enumerate(TCP_SIZES):
            msg = random.Random(i).randbytes(n)
            s.sendall(msg)
            got = recv_exact(s, n)
            if got != msg:
                raise RuntimeError(f"echo of {n} bytes differs")
    finally:
        s.close()


def warm_up(socks_port, procs, deadline=10):
    """Seconds until one byte is echoed through the chain, at most deadline."""
    t0 = time.time()
    while time.time() - t0 < deadline:
        try:
            s = socks_connect(socks_port, TARGET, ECHO_PORT, timeout=2)
            try:
                s.settimeout(2)
                s.sendall(b"w")
                if recv_exact(s, 1) == b"w":
                    return round(time.time() - t0, 2)
            finally:
                s.close()
        except Exception:
            pass
        if any(not p.alive() for p in procs):
            break
        time.sleep(0.2)
    return None


def check_udp(socks_port):
    ctl, relay = socks_udp(socks_port)
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.settimeout(1.5)
    head = b"\x00\x00\x00\x01" + socket.inet_aton(TARGET) + struct.pack(">H", ECHO_PORT)
    try:
        for i, n in enumerate(UDP_SIZES):
            msg = random.Random(100 + i).randbytes(n)
            for attempt in range(4):
                u.sendto(head + msg, relay)
                try:
                    while True:
                        b, _ = u.recvfrom(65536)
                        if len(b) >= 10 and b[3] == 1 and b[10:] == msg:
                            break
                except socket.timeout:
                    continue
                break
            else:
                raise RuntimeError(f"no echo of a {n}-byte datagram (4 tries)")
    finally:
        u.close()
        ctl.close()


def check_bulk(socks_port, way, total, timeout):
    seed = random.getrandbits(32)
    s = socks_connect(socks_port, TARGET, BULK_PORT)
    t0 = time.time()
    try:
        s.settimeout(30)
        s.sendall(struct.pack(">cQQ", way, total, seed))
        if way == b"D":
            h, left = hashlib.sha256(), total
            while left:
                if time.time() - t0 > timeout:
                    raise RuntimeError(f"download: {total - left} of {total} bytes in {timeout}s")
                try:
                    b = s.recv(min(left, 1 << 20))
                except OSError as e:
                    raise RuntimeError(f"download: {type(e).__name__} after {total - left} of "
                                       f"{total} bytes") from None
                if not b:
                    raise EOFError(f"download: closed after {total - left} of {total} bytes")
                h.update(b)
                left -= len(b)
            if h.digest() != stream_digest(seed, total):
                raise RuntimeError("download: checksum differs")
        else:
            sent = 0
            for chunk in stream_chunks(seed, total):
                if time.time() - t0 > timeout:
                    raise RuntimeError(f"upload: {sent} of {total} bytes sent in {timeout}s")
                for i in range(0, len(chunk), 1 << 16):
                    try:
                        s.sendall(chunk[i:i + (1 << 16)])
                    except OSError as e:
                        raise RuntimeError(f"upload: {type(e).__name__} after {sent} of "
                                           f"{total} bytes sent: {e}") from None
                    sent += len(chunk[i:i + (1 << 16)])
            try:
                got = recv_exact(s, 32)
            except OSError as e:
                raise RuntimeError(f"upload: all sent, no checksum back: "
                                   f"{type(e).__name__}: {e}") from None
            if got != stream_digest(seed, total):
                raise RuntimeError("upload: the server's checksum differs")
    finally:
        s.close()
    secs = time.time() - t0
    return round(total / secs / 1e6, 1)


# ------------------------------------------------------------- processes
class Proc:
    def __init__(self, cmd, log, cwd):
        self.log_path = log
        self.log = open(log, "ab")
        self.p = subprocess.Popen(cmd, stdout=self.log, stderr=subprocess.STDOUT, cwd=cwd,
                                  start_new_session=True)

    def alive(self):
        return self.p.poll() is None

    def stop(self):
        if self.p.poll() is None:
            try:
                os.killpg(self.p.pid, signal.SIGTERM)
                self.p.wait(timeout=3)
            except (subprocess.TimeoutExpired, ProcessLookupError):
                try:
                    os.killpg(self.p.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                self.p.wait()
        self.log.close()


def listening(port, proto):
    """Whether something in this namespace listens on 127.0.0.1:port."""
    want = f"0100007F:{port:04X}"
    for path in (f"/proc/net/{proto}", f"/proc/net/{proto}6"):
        try:
            for line in open(path).read().splitlines()[1:]:
                f = line.split()
                if proto == "tcp" and f[3] != "0A":
                    continue
                local = f[1]
                if local == want or local.endswith(f":{port:04X}") and set(local.split(":")[0]) == {"0"}:
                    return True
        except OSError:
            pass
    return False


def wait_listening(port, proto, procs, deadline=10):
    t0 = time.time()
    while time.time() - t0 < deadline:
        if listening(port, proto):
            return True
        if any(not p.alive() for p in procs):
            return False
        time.sleep(0.05)
    return False


def tail(path, n=12):
    try:
        lines = open(path, errors="replace").read().splitlines()
    except OSError:
        return []
    return [line[:400] for line in lines[-n:]]


def command(impl, binary, cfg_path, cell_dir, role):
    # A data directory per side: Mihomo and sail each lock a cache.db in
    # theirs, and two in one directory refuse or wait for each other.
    cell_dir = os.path.join(cell_dir, role)
    os.makedirs(cell_dir, exist_ok=True)
    if impl in ("sail", "sailY"):
        cmd = [binary, "-c", cfg_path, "--no-run-dir", "-D", cell_dir]
        if role == "server":
            cmd += ["--profile", "server"]
        return cmd
    if impl == "sb":
        return [binary, "run", "-c", cfg_path, "-D", cell_dir]
    return [binary, "-d", cell_dir, "-f", cfg_path]


# ------------------------------------------------------------- cells
def server_proto(case):
    return "udp" if case.proto in ("hysteria2", "tuic", "wireguard") else "tcp"


def run_cell(args, m, case, client, server, worker, out, nth=0):
    port = PORT_BASE + 100 * worker
    socks_port = port + 1
    cid = f"{case.id}@{client}>{server}" + (f"#{nth}" if args.repeat > 1 else "")
    cell_dir = os.path.join(out, "cells", re.sub(r"[^A-Za-z0-9_.+-]+", "_", cid))
    os.makedirs(cell_dir, exist_ok=True)
    res = {"case": case.id, "client": client, "server": server, "checks": {}}
    procs = []
    t0 = time.time()
    try:
        if server in ("mh", "sailY"):
            cfg = mh_server(case, m, port)
            spath = os.path.join(cell_dir, "server.yaml")
            open(spath, "w").write(to_yaml(cfg) + "\n")
        else:
            spath = os.path.join(cell_dir, "server.json")
            json.dump(sb_server(case, m, port), open(spath, "w"), indent=1)
        if client in ("mh", "sailY"):
            cpath = os.path.join(cell_dir, "client.yaml")
            open(cpath, "w").write(to_yaml(mh_client(case, m, port, socks_port)) + "\n")
        else:
            cpath = os.path.join(cell_dir, "client.json")
            json.dump(sb_client(case, m, port, socks_port), open(cpath, "w"), indent=1)
        sp = Proc(command(server, args.bins[server], spath, cell_dir, "server"),
                  os.path.join(cell_dir, "server.log"), cell_dir)
        procs.append(sp)
        if not wait_listening(port, server_proto(case), procs):
            raise CellError("server", "the server did not start listening")
        cp = Proc(command(client, args.bins[client], cpath, cell_dir, "client"),
                  os.path.join(cell_dir, "client.log"), cell_dir)
        procs.append(cp)
        if not wait_listening(socks_port, "tcp", procs):
            raise CellError("client", "the client's SOCKS inbound did not start listening")
        time.sleep(0.3)
        if "mh" in (client, server):
            # Mihomo opens its listeners before its tunnel runs, and drops
            # what arrives in between (hub/executor/executor.go: listeners,
            # then providers, then tunnel.OnRunning; tunnel/tunnel.go,
            # isHandle): wait until a byte goes through and back.
            res["warmup_s"] = warm_up(socks_port, procs)
        checks = [("tcp", lambda: check_tcp(socks_port))]
        if case.udp:
            checks.append(("udp", lambda: check_udp(socks_port)))
        total = args.bulk_mib << 20
        checks.append(("up", lambda: check_bulk(socks_port, b"U", total, args.bulk_timeout)))
        checks.append(("down", lambda: check_bulk(socks_port, b"D", total, args.bulk_timeout)))
        for name, fn in checks:
            try:
                r = fn()
                res["checks"][name] = {"ok": True, **({"MBps": r} if r else {})}
            except Exception as e:
                res["checks"][name] = {"ok": False, "error": f"{type(e).__name__}: {e}"}
            for who, p in (("server", sp), ("client", cp)):
                if not p.alive():
                    res["checks"][name].setdefault("error", "")
                    res["checks"][name]["ok"] = False
                    res["checks"][name]["error"] += f" [{who} exited {p.p.returncode}]"
            if any(not p.alive() for p in procs):
                break
        res["ok"] = all(c["ok"] for c in res["checks"].values()) and len(res["checks"]) == len(checks)
        # The traffic went through the server under test, not around it:
        # each server logs the destinations it connects to at info.
        sp.log.flush()
        if res["ok"] and TARGET not in open(sp.log_path, errors="replace").read():
            res["ok"] = False
            res["error"] = f"harness: the server's log never names {TARGET}"
    except CellError as e:
        res["ok"] = False
        res["error"] = f"{e.side}: {e.msg}"
    except Exception as e:
        res["ok"] = False
        res["error"] = "harness: " + "".join(traceback.format_exception_only(type(e), e)).strip()
    finally:
        for p in reversed(procs):
            p.stop()
    res["seconds"] = round(time.time() - t0, 1)
    if not res["ok"]:
        res["server_log"] = tail(os.path.join(cell_dir, "server.log"))
        res["client_log"] = tail(os.path.join(cell_dir, "client.log"))
    elif not args.keep_logs:
        for f in ("server.log", "client.log"):
            try:
                os.remove(os.path.join(cell_dir, f))
            except OSError:
                pass
    json.dump(res, open(os.path.join(cell_dir, "result.json"), "w"), indent=1)
    return res


class CellError(Exception):
    def __init__(self, side, msg):
        self.side, self.msg = side, msg


def plan(args):
    """Every (case, client, server) with its skip reason, or None to run."""
    dirs = [d.split(">") for d in args.dirs.split(",")]
    for c, s in dirs:
        if c not in IMPLS or s not in IMPLS:
            sys.exit(f"--dirs: {c}>{s}: each side is one of {', '.join(IMPLS)}")
    rows = []
    only = re.compile(args.only) if args.only else None
    skip = re.compile(args.skip) if args.skip else None
    for case in cases():
        if only and not only.search(case.id):
            continue
        if skip and skip.search(case.id):
            continue
        for client, server in dirs:
            reason = (unsupported(case, "client", client) or unsupported(case, "server", server)
                      or dir_skip(case, client, server))
            rows.append((case, client, server, reason))
    return rows


def mark(v):
    """P, F, or for repeated cells F with the passes out of the runs."""
    if not isinstance(v, list):
        return v
    ok, n = v
    if ok == n:
        return "P" if n == 1 else f"P({n})"
    return "F" if n == 1 else f"F({ok}/{n})"


def summarize(out, results, skips, dirs, meta):
    by_case = {}
    order = []
    for r in results + skips:
        if r["case"] not in by_case:
            by_case[r["case"]] = {}
            order.append(r["case"])
        key = f"{r['client']}>{r['server']}"
        if "skip" in r:
            by_case[r["case"]][key] = "skip"
        else:
            runs = by_case[r["case"]].setdefault(key, [0, 0])
            runs[0] += r["ok"]
            runs[1] += 1
    lines = ["| case | " + " | ".join(dirs) + " |", "|---" * (len(dirs) + 1) + "|"]
    for c in order:
        lines.append(f"| {c} | " + " | ".join(mark(by_case[c].get(d, "")) for d in dirs) + " |")
    fails = [r for r in results if not r["ok"]]
    lines.append("")
    lines.append(f"{sum(r['ok'] for r in results)} passed, {len(fails)} failed, "
                 f"{len(skips)} skipped")
    for r in fails:
        bad = {k: v.get("error") for k, v in r["checks"].items() if not v["ok"]}
        lines.append(f"- F {r['case']} {r['client']}>{r['server']}: "
                     f"{r.get('error') or json.dumps(bad)}")
    skip_reasons = {}
    for r in skips:
        skip_reasons.setdefault(r["skip"], []).append(f"{r['case']} {r['client']}>{r['server']}")
    lines.append("")
    lines.append("Skips:")
    for reason, which in skip_reasons.items():
        lines.append(f"- {reason}: {len(which)} cells")
    open(os.path.join(out, "summary.md"), "w").write("\n".join(lines) + "\n")
    json.dump({"schema": 1, "meta": meta, "results": results, "skips": skips},
              open(os.path.join(out, "summary.json"), "w"), indent=1)
    return "\n".join(lines)


# ------------------------------------------------------------- netns
def netns_up(name):
    existing = subprocess.run(["ip", "netns", "list"], capture_output=True,
                              text=True).stdout.split()
    if name in existing:
        sys.exit(f"netns {name} exists: pick another --netns, or remove it if it is yours")
    for cmd in (["ip", "netns", "add", name],
                ["ip", "-n", name, "link", "set", "lo", "up"],
                ["ip", "-n", name, "link", "add", "tgt0", "type", "dummy"],
                ["ip", "-n", name, "addr", "add", f"{TARGET}/32", "dev", "tgt0"],
                ["ip", "-n", name, "link", "set", "tgt0", "up"],
                # A default route, into the dummy (where packets end): sing-box
                # takes its WireGuard device down while there is no default
                # interface ("missing default interface").
                ["ip", "-n", name, "route", "add", "default", "dev", "tgt0"]):
        subprocess.run(cmd, check=True)


def netns_down(name):
    # Whatever still runs in it, ours alone, then the namespace.
    pids = subprocess.run(["ip", "netns", "pids", name], capture_output=True,
                          text=True).stdout.split()
    for pid in pids:
        if int(pid) != os.getpid():
            try:
                os.kill(int(pid), signal.SIGKILL)
            except ProcessLookupError:
                pass
    subprocess.run(["ip", "netns", "del", name], check=False)


def version(impl, binary):
    try:
        if impl in ("sail", "sailY"):
            out = subprocess.run([binary, "-V"], capture_output=True, text=True, timeout=10).stdout
        elif impl == "sb":
            out = subprocess.run([binary, "version"], capture_output=True, text=True,
                                 timeout=10).stdout
        else:
            out = subprocess.run([binary, "-v"], capture_output=True, text=True,
                                 timeout=10).stdout
        return out.strip().splitlines()[0] if out.strip() else "?"
    except Exception as e:
        return f"? ({e})"


# ------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--work", help="where materials and results go")
    ap.add_argument("--sail", help="the sail binary")
    ap.add_argument("--sing-box", dest="sing_box", help="the sing-box binary")
    ap.add_argument("--mihomo", help="the Mihomo binary")
    ap.add_argument("--dirs", default=DEFAULT_DIRS,
                    help=f"client>server pairs, comma-separated, of {', '.join(IMPLS)} "
                         f"(sailY: sail reading Mihomo's YAML); default {DEFAULT_DIRS}")
    ap.add_argument("--only", help="run the cases whose id matches this regex")
    ap.add_argument("--skip", help="leave out the cases whose id matches this regex")
    ap.add_argument("--part", help="K/N: the K-th of N equal slices of the cells to run")
    ap.add_argument("--jobs", type=int, default=2, help="cells run side by side")
    ap.add_argument("--netns", default="iop1", help="the namespace to create and use")
    ap.add_argument("--bulk-mib", type=int, default=64, help="bulk bytes each way, in MiB")
    ap.add_argument("--bulk-timeout", type=int, default=120, help="seconds per bulk transfer")
    ap.add_argument("--repeat", type=int, default=1,
                    help="run each cell this many times (for a flaky one)")
    ap.add_argument("--log-level", default="info", choices=["info", "debug"],
                    help="the log level of every process")
    ap.add_argument("--keep-logs", action="store_true", help="keep the logs of passing cells too")
    ap.add_argument("--list", action="store_true", help="print the plan and exit")
    ap.add_argument("--in-netns", action="store_true", help=argparse.SUPPRESS)
    args = ap.parse_args()

    global LOG_LEVEL
    LOG_LEVEL = args.log_level
    rows = plan(args)
    if args.part:
        # Whole cases to each part, so that a part's table has whole rows.
        k, n = map(int, args.part.split("/"))
        ids = list(dict.fromkeys(r[0].id for r in rows))
        mine = set(ids[(k - 1) * len(ids) // n:k * len(ids) // n])
        rows = [r for r in rows if r[0].id in mine]
    if args.repeat > 1:
        rows = [r for r in rows for _ in range(args.repeat)]
    if args.list:
        for case, client, server, reason in rows:
            print(f"{case.id:48} {client}>{server:6} {('skip: ' + reason) if reason else 'run'}")
        print(f"{sum(r[3] is None for r in rows)} to run, {sum(r[3] is not None for r in rows)} "
              "skipped")
        return

    for name in ("work", "sail", "sing_box", "mihomo"):
        if not getattr(args, name):
            sys.exit(f"--{name.replace('_', '-')} is needed")
    args.work = os.path.abspath(args.work)
    args.bins = {"sail": os.path.abspath(args.sail), "sailY": os.path.abspath(args.sail),
                 "sb": os.path.abspath(args.sing_box), "mh": os.path.abspath(args.mihomo)}

    if not args.in_netns:
        if os.geteuid() != 0:
            sys.exit("needs root, for the network namespace")
        os.makedirs(args.work, exist_ok=True)
        netns_up(args.netns)
        try:
            argv = [a for a in sys.argv[1:]]
            rc = subprocess.run(["ip", "netns", "exec", args.netns, sys.executable,
                                 os.path.abspath(__file__), "--in-netns", *argv]).returncode
        finally:
            netns_down(args.netns)
        sys.exit(rc)

    m = Materials(args.work, args.bins["sb"])
    run_id = time.strftime("%Y%m%dT%H%M%S") + (f"-part{args.part.replace('/', 'of')}"
                                               if args.part else "")
    out = os.path.join(args.work, "results", run_id)
    os.makedirs(out, exist_ok=True)
    targets = Targets(m, os.path.join(out, "targets.log"))
    targets.start()
    meta = {"versions": {IMPL_NAMES[i]: version(i, args.bins[i]) for i in ("sail", "sb", "mh")},
            "dirs": args.dirs, "only": args.only, "part": args.part,
            "bulk_mib": args.bulk_mib, "started": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                                                time.gmtime())}
    print(json.dumps(meta), flush=True)
    todo = [(c, cl, sv, i) for i, (c, cl, sv, reason) in enumerate(rows) if reason is None]
    skips = [{"case": c, "client": cl, "server": sv, "skip": reason}
             for c, cl, sv, reason in dict.fromkeys((c.id, cl, sv, reason)
                                                    for c, cl, sv, reason in rows
                                                    if reason is not None)]
    results = []
    lock = threading.Lock()
    queue = list(todo)

    def worker(k):
        while True:
            with lock:
                if not queue:
                    return
                case, client, server, nth = queue.pop(0)
            r = run_cell(args, m, case, client, server, k, out, nth)
            with lock:
                results.append(r)
                mark = "P" if r["ok"] else "F"
                detail = "" if r["ok"] else " " + (r.get("error") or json.dumps(
                    {k2: v.get("error") for k2, v in r["checks"].items() if not v["ok"]}))
                speeds = " ".join(f"{k2}={v['MBps']}" for k2, v in r["checks"].items()
                                  if v.get("MBps"))
                print(f"[{len(results)}/{len(todo)}] {mark} {case.id} {client}>{server} "
                      f"{r['seconds']}s {speeds}{detail}", flush=True)

    threads = [threading.Thread(target=worker, args=(k,)) for k in range(max(1, args.jobs))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    targets.stop()
    meta["finished"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    order = {(c.id, cl, sv): i for i, (c, cl, sv, _) in enumerate(rows)}
    results.sort(key=lambda r: order[(r["case"], r["client"], r["server"])])
    print(summarize(out, results, skips, [d for d in args.dirs.split(",")], meta))
    print(f"results: {out}")
    sys.exit(0 if all(r["ok"] for r in results) else 1)


if __name__ == "__main__":
    main()
