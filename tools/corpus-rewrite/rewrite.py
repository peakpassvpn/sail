#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Rewrites a proxy configuration into a synthetic one of the same structure.

sail's config corpus (sail/tests/corpus) is made of public sing-box JSON,
Clash / Mihomo YAML and Surge profiles run through this: sections, keys,
rule, group and protocol types, enum values, numbers, list lengths and
order stay; every name, server, credential, URL, rule payload and other
free value becomes a synthetic one, the same original value the same
synthetic one within a file, so that references still meet. Comments go.

What a value becomes is decided by its key, then by its shape; a string
neither says to keep is replaced. `kept` and `replaced` record, per file,
what stayed and what went, for review and for the leak check.

Usage: rewrite.py {sing-box|clash|surge} IN OUT
YAML needs ruamel.yaml (pip install ruamel.yaml).
"""

import base64
import hashlib
import ipaddress
import json
import re
import sys
from collections import Counter
from urllib.parse import parse_qsl, quote, urlsplit

# Policies every format has built in.
BUILTIN = {
    "DIRECT", "REJECT", "REJECT-DROP", "REJECT-NO-DROP", "REJECT-TINYGIF",
    "REJECT-200", "PASS", "GLOBAL", "COMPATIBLE", "PROXY", "SYSTEM", "LAN",
    "any", "CELLULAR", "CELLULAR-ONLY", "HYBRID",
}

# Words that are values of some enum: protocols, ciphers, modes, levels.
VOCAB = set("""
true false yes no on off none null auto default always never enable disable
enabled disabled
ss ssr shadowsocks shadowsocksr vmess vless trojan snell socks socks4 socks5
socks5-tls http https http2 h2 h3 grpc ws wss websocket httpupgrade quic tcp
udp tls xtls reality hysteria hysteria2 hy2 tuic wireguard wg anytls mieru ssh
direct reject block dns selector select urltest url-test fallback
load-balance relay smart tor naive shadowtls shadow-tls mixed redirect tproxy
tun tunnel sudoku masque juicity mtproto ponte external subscribe
aes-128-gcm aes-192-gcm aes-256-gcm chacha20-ietf-poly1305 chacha20-poly1305
xchacha20-ietf-poly1305 xchacha20-poly1305 2022-blake3-aes-128-gcm
2022-blake3-aes-256-gcm 2022-blake3-chacha20-poly1305 aes-128-cfb aes-192-cfb
aes-256-cfb aes-128-ctr aes-192-ctr aes-256-ctr rc4-md5 rc4 chacha20
chacha20-ietf xchacha20 salsa20 bf-cfb camellia-128-cfb camellia-256-cfb
plain aead zero aes-128-ccm lea-128-gcm
origin auth_sha1_v4 auth_aes128_md5 auth_aes128_sha1 auth_chain_a auth_chain_b
http_simple http_post tls1.2_ticket_auth tls1.2_ticket_fastauth plain
simple_obfs obfs obfs-local v2ray-plugin gost-plugin shadow-tls restls
xtls-rprx-vision xtls-rprx-vision-udp443 xtls-rprx-direct xtls-rprx-origin
chrome firefox safari ios android edge 360 qq random randomized randomizedalpn
randomizednoalpn chrome_psk chrome_pq
http/1.1 http/1.0 h2c
rule global script info warning warn error debug silent trace fatal panic
notify verbose
ipv4 ipv6 ipv4-only ipv6-only prefer-ipv4 prefer-ipv6 dual prefer_ipv4
prefer_ipv6 ipv4_only ipv6_only
fake-ip redir-host normal mapping fakeip fake_ip system gvisor lwip
consistent-hashing round-robin sticky-sessions
domain ipcidr classical yaml text mrs binary source srs json remote local
inline file
sniff sniff-override route hijack-dns reject-drop resolve route-options predefined
rdp ssh ntp dtls bittorrent stun
bypass drop reply
cubic bbr new_reno reno brutal
native quic-rs
strict loose
xudp packetaddr
smux yamux h2mux
tcp-udp tcp_udp udp_over_tcp
geoip geosite mmdb dat memconservative standard
always-on
dhcp localhost
ALL WIFI CELLULAR WIRED
A AAAA CNAME HTTPS SVCB MX TXT NS PTR SRV SOA ANY
NOERROR NXDOMAIN SERVFAIL REFUSED FORMERR NOTIMP
mozilla chrome wireformat syslib
CN LAN private geolocation-!cn geolocation-cn
""".split())

# Enum values that are uppercase or case-insensitive in some format.
VOCAB_CI = {v.lower() for v in VOCAB}

# Keys whose values are enum words, kept when they look like one.
ENUM_KEYS = set("""
type cipher method network mode protocol obfs plugin flow version strategy
level log-level loglevel stack client-fingerprint behavior format
lazy udp tfo find-process-mode geodata-loader enhanced-mode
fake-ip-filter-mode domain-strategy sniff action packet-encoding
congestion-control congestion-controller udp-relay-mode multiplexing security
encryption transport padding cache-algorithm global-client-fingerprint
default-mode clash-mode ip-version query-type rcode network-type
interface-name-type tls-version min-version max-version cipher-suites
curve-preferences ech-mode heartbeat udp-over-tcp-version
network-strategy fallback-network-type protocol-param-type
engine style exclude-type include-type sub-rule
brutal-opts http-method request-method geodata-mode
udp-fragment strict-route auto-route auto-detect-interface
""".split())

# Keys whose values are secrets, always replaced.
SECRET_KEYS = set("""
password passwd pass psk obfs-password auth auth-str auth-str-base64 token
secret private-key public-key pre-shared-key preshared-key short-id uuid
id username user ca-passphrase ca-p12 passphrase key certificate cert ca
ca-str certificate-str private-key-passphrase api-key access-token
fingerprint server-cert-fingerprint-sha256 protocol-param obfs-param
auth-user authentication users user-id reserved config ech-config
key-pem cert-pem client-cert client-key certificate-path key-path
cache-id external-controller-access http-api http-api-tls private-key-path
""".split())

# Keys whose values are regular expressions.
REGEX_KEYS = {
    "filter", "exclude-filter", "policy-regex-filter", "regex", "pattern",
    "domain-regex", "process-path-regex", "process-name-regex", "url-regex",
    "keyword-filter",
}

# URL extensions that tell a format.
EXTS = set(
    "list yaml yml mrs srs txt json conf sgmodule js dat db mmdb metadb ruleset "
    "plugin snippet png ico ini toml gz tar zip dconf module mitm p12 pem crt "
    "svg jpg jpeg webp sh xml".split()
)

# URL paths that are protocol constants, not names.
KEEP_PATHS = {"/dns-query", "/generate_204", "/resolve", "/"}

# URL query keys whose short values are kept.
QUERY_ENUM_KEYS = {
    "target", "flag", "list", "type", "ver", "udp", "emoji", "tfo", "scv",
    "sort", "expand", "fdn", "append_type", "insert", "new_name", "classic",
    "include_insert", "exclude_insert", "tls13", "surge_ver", "h3",
}

# Addresses and ranges that name nothing: unspecified, loopback, private.
KEEP_NETS = {
    "0.0.0.0", "::", "127.0.0.1", "::1", "0.0.0.0/0", "::/0", "0.0.0.0/8",
    "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15",
    "198.18.0.0/16", "198.18.0.1/16", "224.0.0.0/4", "224.0.0.0/3",
    "240.0.0.0/4", "255.255.255.255/32", "255.255.255.255", "28.0.0.1/8",
    "fc00::/7", "fe80::/10", "ff00::/8", "::1/128", "::/128", "fd00::/8",
    "fdfe:dcba:9876::1/126", "64:ff9b::/96", "::ffff:0:0/96", "2001:db8::/32",
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
}

# HTTP header names, kept as keys.
HEADERS = {
    "host", "user-agent", "accept", "accept-encoding", "accept-language",
    "connection", "cookie", "referer", "origin", "content-type", "pragma",
    "cache-control", "upgrade", "authorization", "x-forwarded-for",
}

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
DOMAIN_RE = re.compile(r"^(?:[A-Za-z0-9_*?-]+\.)+[A-Za-z0-9_*?-]*[A-Za-z*][A-Za-z0-9_*?-]*\.?$")
NUM_RE = re.compile(
    r"^[+-]?(\d+(\.\d+)?|\d+(\.\d+)?\s*[kKmMgG]?(bps|Bps|ps|b|B)?|0x[0-9a-fA-F]+"
    r"|\d+(-\d+)?(,\d+(-\d+)?)*|\d+(ms|s|m|h|d)|\d+\s*[kKmMgGtT]?(bps|Bps|b|B|bit)?"
    r"|\d+(\.\d+)?\s*[kKmMgGtT]bps|(\d+(\.\d+)?(ns|us|ms|s|m|h|d))+)$"
)
MAC_RE = re.compile(r"^[0-9a-fA-F]{2}([:-][0-9a-fA-F]{2}){5}$")
HEX_RE = re.compile(r"^[0-9a-fA-F]{8,}$")
B64_RE = re.compile(r"^[A-Za-z0-9+/_-]{16,}={0,2}$")
PEM_RE = re.compile(r"-----BEGIN ([A-Z0-9 ]+)-----")
CRON_RE = re.compile(r"^[0-9*/,\- ]+$")
WORD_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+/-]{0,31}$")

DUMMY_B64_LINE = "MIIBszCCAVmgAwIBAgIUZHVtbXktY2VydGlmaWNhdGUtZm9yLWEtdGVzdA=="


def norm(key):
    return str(key).lower().replace("_", "-")


def pem(label):
    return "-----BEGIN %s-----\n%s\n-----END %s-----\n" % (label, DUMMY_B64_LINE, label)


class Synth:
    """The synthetic values of one file."""

    def __init__(self):
        self.maps = {}
        self.counts = Counter()
        self.replaced = set()
        self.kept = Counter()

    def _one(self, kind, orig, make):
        m = self.maps.setdefault(kind, {})
        if orig not in m:
            self.counts[kind] += 1
            m[orig] = make(self.counts[kind])
        if m[orig] != orig:
            self.replaced.add(orig)
        return m[orig]

    def keep(self, s):
        if isinstance(s, str) and not NUM_RE.match(s):
            self.kept[s] += 1
        return s

    def _bytes(self, kind, n, length):
        out = b""
        i = 0
        while len(out) < length:
            out += hashlib.sha256(("sail-corpus-%s-%d-%d" % (kind, n, i)).encode()).digest()
            i += 1
        return out[:length]

    # Names: `ns` is the namespace references are resolved in.
    def define(self, ns, orig, label):
        orig = str(orig)
        if orig in BUILTIN:
            return orig
        m = self.maps.setdefault("name:" + ns, {})
        if orig not in m:
            self.counts["label:%s:%s" % (ns, label)] += 1
            sep = " " if label[0].isupper() else "-"
            m[orig] = "%s%s%d" % (label, sep, self.counts["label:%s:%s" % (ns, label)])
            self.replaced.add(orig)
        return m[orig]

    def name(self, ns, orig, label):
        orig = str(orig)
        if orig in BUILTIN or orig == "":
            return orig
        m = self.maps.get("name:" + ns, {})
        if orig in m:
            return m[orig]
        return self.define(ns, orig, label)

    def uuid(self, orig):
        return self._one("uuid", orig, lambda n: "%08x-0000-4000-8000-%012x" % (0x5a11, n))

    def hex(self, orig):
        return self._one("hex", orig, lambda n: self._bytes("hex", n, len(orig)).hex()[: len(orig)].lower())

    def b64(self, orig, nbytes=None):
        def make(n):
            if nbytes is not None:
                return base64.b64encode(self._bytes("b64", n, nbytes)).decode()
            url = "-" in orig or "_" in orig
            try:
                pad = "=" * (-len(orig.rstrip("=")) % 4)
                size = len((base64.urlsafe_b64decode if url else base64.b64decode)(orig.rstrip("=") + pad))
                out = (base64.urlsafe_b64encode if url else base64.b64encode)(self._bytes("b64", n, size)).decode()
                return out if orig.endswith("=") else out.rstrip("=")
            except ValueError:
                pass
            body = orig.rstrip("=")
            raw = base64.b64encode(self._bytes("b64", n, len(body))).decode()[: len(body)]
            if "-" in orig or "_" in orig:
                raw = raw.replace("+", "-").replace("/", "_")
            return raw + "=" * (len(orig) - len(body))
        return self._one("b64:%s" % nbytes, orig, make)

    def secret(self, orig, word="password"):
        return self._one("secret:" + word, orig, lambda n: "%s%d" % (word, n))

    def string(self, orig):
        return self._one("str", orig, lambda n: "str%d" % n)

    def keyword(self, orig):
        return self._one("kw", orig, lambda n: "kw%d" % n)

    def regex(self, orig, kind="name"):
        if kind == "name":
            return self._one("re", orig, lambda n: "Proxy [0-9]+|Group %d" % n)
        return self._one("re:" + kind, orig, lambda n: r"^https?://r%d\.example\.com/" % n)

    def path(self, orig):
        ext = ""
        m = re.search(r"\.([A-Za-z0-9]{1,8})$", orig)
        if m and m.group(1).lower() in EXTS:
            ext = "." + m.group(1)
        return self._one("path", orig, lambda n: "./path-%d%s" % (n, ext))

    def process(self, orig):
        ext = ".exe" if orig.lower().endswith(".exe") else ""
        if "/" in orig or "\\" in orig:
            if "\\" in orig:
                return self._one("proc", orig, lambda n: "C:\\Apps\\app%d%s" % (n, ext))
            return self._one("proc", orig, lambda n: "/opt/app%d/app%d%s" % (n, n, ext))
        return self._one("proc", orig, lambda n: "app%d%s" % (n, ext))

    def package(self, orig):
        return self._one("pkg", orig, lambda n: "com.example.app%d" % n)

    def ssid(self, orig):
        return self._one("ssid", orig, lambda n: "ssid-%d" % n)

    def mac(self, orig):
        return self._one("mac", orig, lambda n: "02:00:00:00:%02x:%02x" % (n // 256 % 256, n % 256))

    def iface(self, orig):
        return self._one("if", orig, lambda n: "if%d" % n)

    def agent(self, orig):
        pre = "*" if orig.startswith("*") else ""
        post = "*" if orig.endswith("*") and len(orig) > 1 else ""
        return self._one("ua", orig, lambda n: "%sAgent%d%s" % (pre, n, post))

    # Hosts.
    def domain(self, orig, role="rule"):
        m = re.match(r"^(-?)(\+\.|\*\.|\.)?(.*?)$", orig)
        neg, pre, base = m.group(1), m.group(2) or "", m.group(3)
        if base.lower() == "localhost":
            return self.keep(orig)
        trail = "." if base.endswith(".") else ""
        base = base.rstrip(".").lower()
        if "*" in base or "?" in base:
            # The wildcards stay where they were, a whole label or part of
            # one: Mihomo takes `*` as a whole label only.
            labels = base.split(".")
            shape = ".".join(
                l if l in ("*", "?") else re.sub(r"[^*?]+", "w", l) for l in labels[:-1]
            )
            new = self._one(
                "dom", base, lambda n: "d%d%s.example" % (n, ("." + shape) if shape else "")
            )
        else:
            fmt = {"server": "s%d.example.net", "sni": "sni%d.example.org"}.get(role, "d%d.example")
            new = self._one("dom", base, lambda n: fmt % n)
        self.replaced.add(orig)
        return neg + pre + new + trail

    def urlhost(self, host):
        if host in ("sub.store", "localhost", "any", "*") or host == "":
            return self.keep(host)
        if self.is_ip(host.strip("[]")):
            h = self.ip(host.strip("[]"))
            return "[%s]" % h if host.startswith("[") else h
        return self._one("urlhost", host.lower(), lambda n: "h%d.example.com" % n)

    @staticmethod
    def is_ip(s):
        try:
            ipaddress.ip_address(s)
            return True
        except ValueError:
            return False

    @staticmethod
    def is_net(s):
        if "/" not in s:
            return False
        try:
            ipaddress.ip_network(s, strict=False)
            return True
        except ValueError:
            return False

    def ip(self, orig):
        if orig in KEEP_NETS:
            return self.keep(orig)
        a = ipaddress.ip_address(orig)
        if a.is_loopback or a.is_unspecified:
            return self.keep(orig)
        if a.version == 4:
            def make(n):
                pools = ["192.0.2.", "198.51.100.", "203.0.113."]
                i = (n - 1) % (253 * 3)
                return pools[i // 253] + str(i % 253 + 1)
            return self._one("ip4", orig, make)
        return self._one("ip6", orig, lambda n: "2001:db8::%x" % n)

    def net(self, orig):
        if orig in KEEP_NETS:
            return self.keep(orig)
        addr, plen = orig.split("/", 1)
        plen_i = int(plen)
        v6 = ":" in addr
        if (not v6 and plen_i < 4) or (v6 and plen_i < 8):
            return self.keep(orig)
        if not v6 and plen_i == 32:
            return self.ip(addr) + "/32"
        if v6 and plen_i == 128:
            return self.ip(addr) + "/128"

        def make(n):
            if v6:
                pool = ipaddress.ip_network("2001:db8::/32" if plen_i >= 32 else "3fff::/20" if plen_i >= 20 else "3f00::/8")
            elif plen_i >= 24:
                pool = ipaddress.ip_network(["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"][(n - 1) % 3])
                n = (n - 1) // 3 + 1
            elif plen_i >= 15:
                pool = ipaddress.ip_network("198.18.0.0/15")
            else:
                pool = ipaddress.ip_network("240.0.0.0/4")
            if plen_i < pool.prefixlen:
                pool = ipaddress.ip_network((pool.network_address, plen_i), strict=False)
            count = 2 ** (plen_i - pool.prefixlen)
            step = 2 ** ((128 if v6 else 32) - plen_i)
            start = int(pool.network_address) + ((n - 1) % count) * step
            return "%s/%d" % (ipaddress.ip_address(start), plen_i)
        # The host part stays: an interface address is not its network's.
        network = self._one("net%s/%d" % ("6" if v6 else "4", plen_i), str(ipaddress.ip_network(orig, strict=False)), make)
        host = int(ipaddress.ip_address(addr)) - int(ipaddress.ip_network(orig, strict=False).network_address)
        self.replaced.add(orig)
        if host == 0:
            return network
        naddr, _ = network.split("/")
        return "%s/%d" % (ipaddress.ip_address(int(ipaddress.ip_address(naddr)) + host), plen_i)

    def url(self, orig, fragment=None):
        if re.match(r"^(rcode|dhcp)://[A-Za-z0-9_-]*$", orig):
            scheme, _, rest = orig.partition("://")
            if scheme == "rcode" or rest in ("auto", "system", ""):
                return self.keep(orig)
            return "dhcp://" + self.iface(rest)
        try:
            u = urlsplit(orig)
            host, port = u.hostname or "", u.port
        except ValueError:
            return self.string(orig)
        netloc = ""
        if u.username is not None:
            netloc = self.secret(u.username, "user")
            if u.password is not None:
                netloc += ":" + self.secret(u.password)
            netloc += "@"
        raw_host = u.netloc.rsplit("@", 1)[-1]
        if raw_host.startswith("["):
            netloc += "[%s]" % self.urlhost(host)
        else:
            netloc += self.urlhost(host)
        if port is not None:
            netloc += ":%d" % port
        path = u.path
        if path and path not in KEEP_PATHS:
            ext = ""
            m = re.search(r"\.([A-Za-z0-9]{1,8})$", path)
            if m and m.group(1).lower() in EXTS:
                ext = "." + m.group(1)
            path = self._one("urlpath", path, lambda n: "/p%d%s" % (n, ext))
        query = ""
        if u.query:
            parts = []
            for k, v in parse_qsl(u.query, keep_blank_values=True):
                nk = k if re.match(r"^[A-Za-z0-9_-]{1,20}$", k) else self._one("qk", k, lambda n: "k%d" % n)
                if v == "" or re.match(r"^\d{1,4}$", v) or v.lower() in ("true", "false"):
                    nv = v
                elif k in QUERY_ENUM_KEYS and re.match(r"^[A-Za-z0-9._-]{1,20}$", v):
                    nv = self.keep(v)
                else:
                    nv = self._one("qv", v, lambda n: "v%d" % n)
                parts.append("%s=%s" % (nk, quote(nv, safe="")) if "=" in u.query else nk)
            query = "?" + "&".join(parts)
        frag = ""
        if u.fragment:
            frag = "#" + (fragment(u.fragment) if fragment else self._one("frag", u.fragment, lambda n: "f%d" % n))
        self.replaced.add(orig)
        return "%s://%s%s%s%s" % (u.scheme, netloc, path, query, frag)

    def hostport(self, s):
        """host:port, [v6]:port, or None."""
        m = re.match(r"^\[([0-9a-fA-F:.]+)\]:(\d+)$", s)
        if m:
            return "[%s]:%s" % (self.ip(m.group(1)), m.group(2))
        if re.match(r"^:\d{1,5}$", s):
            return self.keep(s)
        m = re.match(r"^([^:\s/]+):(\d{1,5})$", s)
        if m:
            h = m.group(1)
            if self.is_ip(h):
                return "%s:%s" % (self.ip(h), m.group(2))
            if h in ("*", "any", "localhost", ""):
                return self.keep(s)
            if DOMAIN_RE.match(h):
                return "%s:%s" % (self.domain(h, "server"), m.group(2))
        return None

    def shape(self, s, role="rule"):
        """A synthetic value of the shape of `s`, or `s` where nothing names."""
        if not isinstance(s, str):
            return s
        t = s.strip()
        if t == "":
            return s
        if NUM_RE.match(t) or t.lower() in VOCAB_CI or re.match(r"^%[A-Z]+%$", t) or t in ("*", "any"):
            return self.keep(s)
        if PEM_RE.search(t):
            return pem(PEM_RE.search(t).group(1))
        if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", t):
            return self.url(t)
        if self.is_ip(t):
            return self.ip(t)
        if self.is_net(t):
            return self.net(t)
        hp = self.hostport(t)
        if hp:
            return hp
        if UUID_RE.match(t):
            return self.uuid(t)
        if MAC_RE.match(t):
            return self.mac(t)
        if re.match(r"^[^@\s]+@[^@\s]+$", t):
            user, rest = t.split("@", 1)
            return self.secret(user, "user") + "@" + self.shape(rest, "server")
        if re.match(r"^(geosite|geoip|rule-set|ruleset):", t, re.I):
            k, v = t.split(":", 1)
            if k.lower() in ("rule-set", "ruleset"):
                return k + ":" + ",".join(self.name("set", x, "set") for x in v.split(","))
            return self.keep(s)
        if re.match(r"^[-+*.]", t) or DOMAIN_RE.match(t):
            base = re.sub(r"^-?(\+\.|\*\.|\.)?", "", t)
            if DOMAIN_RE.match(base) or base.replace("*", "a").replace("?", "a").isalnum():
                return self.domain(t, role)
        if t.startswith(("./", "../", "/", "~/")) or re.match(r"^[A-Za-z]:\\", t):
            return self.path(t)
        if HEX_RE.match(t) and len(t) % 2 == 0:
            return self.hex(t)
        if B64_RE.match(t) and re.search(r"[0-9]", t) and re.search(r"[A-Z]", t):
            return self.b64(t)
        return self.string(t)


def key_rule(k):
    """How the value under key `k` is rewritten: a category."""
    nk = norm(k)
    if nk in SECRET_KEYS or nk.endswith(("-password", "-secret", "-token", "-key", "-psk", "-auth")):
        return "secret"
    if nk in REGEX_KEYS or nk.endswith(("-regex", "-filter")):
        return "regex"
    if nk in ENUM_KEYS or nk.endswith(("-mode", "-type", "-strategy", "-level", "-version")):
        return "enum"
    return "shape"


def secret_value(syn, key, v, siblings):
    """A synthetic secret of the form the key and its siblings want."""
    if not isinstance(v, str):
        return v
    nk = norm(key)
    if v == "" or v.lower() in ("true", "false"):
        return v
    if PEM_RE.search(v):
        return pem(PEM_RE.search(v).group(1))
    if nk in ("uuid", "id", "user-id") or UUID_RE.match(v):
        return syn.uuid(v)
    if nk in ("short-id",) or (nk == "fingerprint" and HEX_RE.match(v.replace(":", ""))):
        if ":" in v:
            return ":".join(syn.hex(x) for x in v.split(":"))
        return syn.hex(v) if re.match(r"^[0-9a-fA-F]+$", v) else syn.string(v)
    if nk == "fingerprint" and v.lower() in VOCAB_CI:
        return syn.keep(v)
    if nk in ("certificate", "cert", "ca", "key", "certificate-path", "key-path", "private-key-path") and (
        v.startswith(("/", "./", "~")) or re.search(r"\.(pem|crt|key|cer|p12)$", v)
    ):
        return syn.path(v)
    method = ""
    for mk in ("cipher", "method", "encrypt-method"):
        for sk, sv in siblings:
            if norm(sk) == mk and isinstance(sv, str):
                method = sv
    if method.startswith("2022-") and nk in ("password", "psk"):
        n = 16 if "128" in method else 32
        return ":".join(syn.b64(p, n) for p in v.split(":"))
    if nk in ("reserved",) and re.match(r"^[0-9, ]+$", v):
        return syn.keep(v)
    if B64_RE.match(v) and len(v) in (43, 44) and nk in ("private-key", "public-key", "pre-shared-key", "preshared-key", "psk"):
        return syn.b64(v)
    if nk in ("username", "user", "auth-user", "users"):
        return syn.secret(v, "user")
    if (nk in ("authentication",) or nk.endswith("-auth")) and ":" in v:
        u, p = v.split(":", 1)
        return syn.secret(u, "user") + ":" + syn.secret(p)
    if nk in ("config", "ech-config") and B64_RE.match(v):
        return syn.b64(v)
    if nk in ("private-key", "public-key") and B64_RE.match(v):
        return syn.b64(v)
    if nk in ("external-controller-access", "http-api", "http-api-tls") and "@" in v:
        p, rest = v.rsplit("@", 1)
        return syn.secret(p) + "@" + syn.shape(rest)
    return syn.secret(v, "token" if "token" in nk else "password")


def regex_value(syn, key, v):
    if not isinstance(v, str) or v == "":
        return v
    nk = norm(key)
    if nk in ("pattern", "url-regex", "regex"):
        return syn.regex(v, "url")
    if nk in ("domain-regex",):
        return syn._one("re:dom", v, lambda n: r"^d%d\.example$" % n)
    if "process" in nk:
        return syn._one("re:proc", v, lambda n: r"^app%d.*$" % n)
    return syn.regex(v)


def enum_value(syn, v):
    if isinstance(v, str) and (HEX_RE.match(v) or UUID_RE.match(v) or B64_RE.match(v) and re.search(r"[0-9]", v) and re.search(r"[A-Z]", v)):
        return syn.shape(v)
    if isinstance(v, str) and (WORD_RE.match(v) or v.lower() in VOCAB_CI) and not DOMAIN_RE.match(v) or (
        isinstance(v, str) and v.lower() in VOCAB_CI
    ):
        return syn.keep(v)
    if isinstance(v, str) and re.match(r"^[A-Za-z0-9|,.+ _-]{1,40}$", v) and not DOMAIN_RE.match(v):
        return syn.keep(v)
    return syn.shape(v)


# ---------------------------------------------------------------- rules

RULE_TYPE_RE = re.compile(r"^[A-Z][A-Z0-9-]*$")
LOGICAL = {"AND", "OR", "NOT"}
CODE_RULES = {
    "GEOIP", "SRC-GEOIP", "GEOSITE", "IP-ASN", "SRC-IP-ASN", "DEST-PORT",
    "DST-PORT", "SRC-PORT", "IN-PORT", "PROTOCOL", "NETWORK", "IN-TYPE", "DSCP",
    "UID", "FINAL", "MATCH", "DEVICE-NAME-TYPE", "CELLULAR-RADIO", "HOSTNAME-TYPE",
    "DEST-PORT-RANGE",
}
DOMAIN_RULES = {"DOMAIN", "DOMAIN-SUFFIX", "HOST", "HOST-SUFFIX", "DOMAIN-WILDCARD", "HOST-WILDCARD"}
KEYWORD_RULES = {"DOMAIN-KEYWORD", "HOST-KEYWORD"}
CIDR_RULES = {"IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR", "SRC-IP", "IP-SUFFIX", "SRC-IP-SUFFIX", "DEST-IP", "IP"}
REGEX_RULES = {"DOMAIN-REGEX", "URL-REGEX", "PROCESS-NAME-REGEX", "PROCESS-PATH-REGEX", "HOST-REGEX"}
PROCESS_RULES = {"PROCESS-NAME", "PROCESS-PATH", "PROCESS-NAME-WILDCARD", "PROCESS-PATH-WILDCARD"}
NAME_RULES = {"IN-NAME": "listener", "IN-USER": "user", "SCRIPT": "script", "SUB-RULE": "sub"}
SET_RULES = {"RULE-SET", "DOMAIN-SET", "IP-SET"}
RULE_OPTS = {
    "no-resolve", "extended-matching", "dns-failed", "pre-matching", "src",
    "notification", "no-alert",
}


def split_top(s, sep=","):
    """Splits at `sep` outside parentheses and quotes."""
    out, depth, cur, q = [], 0, "", None
    for c in s:
        if q:
            cur += c
            if c == q:
                q = None
            continue
        if c in "\"'":
            q = c
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        if c == sep and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += c
    out.append(cur)
    return out


class Rules:
    """Rewrites rule lines of Clash and Surge; `target` rewrites a policy."""

    def __init__(self, syn, target, sets_are_urls):
        self.syn = syn
        self.target = target
        self.sets_are_urls = sets_are_urls

    def payload(self, kind, p):
        syn = self.syn
        t = p.strip()
        pad = p[: len(p) - len(p.lstrip())]
        if t == "":
            return p
        if kind in DOMAIN_RULES:
            return pad + syn.domain(t)
        if kind in KEYWORD_RULES:
            return pad + syn.keyword(t)
        if kind in CIDR_RULES:
            if syn.is_net(t):
                return pad + syn.net(t)
            if syn.is_ip(t):
                return pad + syn.ip(t)
            return pad + syn.shape(t)
        if kind in REGEX_RULES:
            return pad + regex_value(syn, kind.lower(), t)
        if kind == "USER-AGENT":
            return pad + syn.agent(t)
        if kind in PROCESS_RULES:
            return pad + syn.process(t)
        if kind in NAME_RULES:
            return pad + syn.name(NAME_RULES[kind], t, NAME_RULES[kind])
        if kind in SET_RULES:
            if re.match(r"^[a-z]+://", t):
                return pad + syn.url(t)
            if t in BUILTIN:
                return pad + t
            if self.sets_are_urls and ("/" in t or "." in t):
                return pad + syn.path(t)
            return pad + syn.name("set", t, "set")
        if kind == "SUBNET":
            m = re.match(r"^(SSID|BSSID|ROUTER|TYPE|MCCMNC):(.*)$", t)
            if m:
                k, v = m.groups()
                if k == "SSID":
                    return pad + "SSID:" + syn.ssid(v)
                if k == "BSSID":
                    return pad + "BSSID:" + syn.mac(v)
                if k == "ROUTER":
                    return pad + "ROUTER:" + syn.shape(v)
                if k == "MCCMNC":
                    return pad + "MCCMNC:" + syn._one("mccmnc", v, lambda n: "001-%02d" % n)
                return pad + syn.keep(t)
            return pad + syn.shape(t)
        if kind in ("DEVICE-NAME",):
            return pad + syn._one("dev", t, lambda n: "device-%d" % n)
        if kind in CODE_RULES or kind in ("SRC-IP-ASN",):
            if re.match(r"^[A-Za-z0-9_!@:.+/-]{1,40}$", t) and not syn.is_ip(t):
                return pad + syn.keep(t)
            return pad + syn.shape(t)
        return pad + syn.shape(t)

    def sub(self, s):
        """A parenthesized sub-rule: `(TYPE,payload)`."""
        t = s.strip()
        if t.startswith("(") and t.endswith(")"):
            return "(" + self.line(t[1:-1], has_target=False) + ")"
        return self.syn.shape(s)

    def line(self, s, has_target=True):
        parts = split_top(s)
        kind = parts[0].strip()
        if not RULE_TYPE_RE.match(kind):
            return self.syn.shape(s) if not has_target else self.syn.string(s)
        out = [parts[0]]
        rest = parts[1:]
        if kind in LOGICAL:
            if rest:
                inner = rest[0].strip()
                if inner.startswith("(") and inner.endswith(")"):
                    subs = split_top(inner[1:-1])
                    rest[0] = "(" + ",".join(self.sub(x) for x in subs) + ")"
                out.append(rest[0])
                rest = rest[1:]
        elif kind in ("FINAL", "MATCH"):
            pass
        elif rest:
            out.append(self.payload(kind, rest[0]))
            rest = rest[1:]
        if has_target and rest:
            out.append(self.target(rest[0]))
            rest = rest[1:]
        for o in rest:
            ot = o.strip()
            if ot.lower() in RULE_OPTS or ot.lower() in VOCAB_CI or NUM_RE.match(ot):
                out.append(o)
                self.syn.keep(ot)
            elif re.match(r"^[a-z-]+=", ot):
                k, v = ot.split("=", 1)
                if k == "notification-text":
                    out.append('%s="%s"' % (k, self.syn.string(v.strip('"'))))
                else:
                    out.append("%s=%s" % (k, v if NUM_RE.match(v) or v.lower() in VOCAB_CI else self.syn.shape(v)))
            elif kind in LOGICAL or not has_target:
                out.append(self.target(o))
            else:
                out.append(self.syn.shape(o))
        return ",".join(out)


def is_rule(s):
    return isinstance(s, str) and re.match(r"^\s*[A-Z][A-Z0-9-]+\s*,", s) is not None


# ---------------------------------------------------------------- trees

class Tree:
    """Rewrites a parsed JSON or YAML document in place."""

    def __init__(self, syn, fmt):
        self.syn = syn
        self.fmt = fmt
        self.memo = {}
        self.anchors = 0
        self.holders = set()
        self.rules = Rules(syn, lambda t: self.policy(t.strip(), t), sets_are_urls=False)

    def policy(self, name, raw=None):
        new = self.syn.name("policy", name, "Proxy")
        if raw is not None:
            return raw[: len(raw) - len(raw.lstrip())] + new
        return new

    # Clash: definitions first, so that references meet them.
    def clash_defs(self, doc):
        syn = self.syn
        if not isinstance(doc, dict):
            return
        for p in doc.get("proxies") or []:
            if isinstance(p, dict) and "name" in p:
                syn.define("policy", p["name"], "Proxy")
        for g in doc.get("proxy-groups") or []:
            if isinstance(g, dict) and "name" in g:
                syn.define("policy", g["name"], "Group")
        for k in doc.get("rule-providers") or {}:
            syn.define("set", k, "set")
        for k in doc.get("proxy-providers") or {}:
            syn.define("provider", k, "provider")
        for k in doc.get("sub-rules") or {}:
            syn.define("sub", k, "sub")
        for li in doc.get("listeners") or []:
            if isinstance(li, dict) and "name" in li:
                syn.define("listener", li["name"], "listener")

    def singbox_defs(self, doc):
        syn = self.syn
        if not isinstance(doc, dict):
            return
        for sec in ("outbounds", "endpoints"):
            for o in doc.get(sec) or []:
                if isinstance(o, dict) and isinstance(o.get("tag"), str):
                    label = "Group" if o.get("type") in ("selector", "urltest") else "Proxy"
                    syn.define("out", o["tag"], label)
        for i in doc.get("inbounds") or []:
            if isinstance(i, dict) and isinstance(i.get("tag"), str):
                syn.define("in", i["tag"], "in")
        dns = doc.get("dns") or {}
        if isinstance(dns, dict):
            for s in dns.get("servers") or []:
                if isinstance(s, dict) and isinstance(s.get("tag"), str):
                    syn.define("dns", s["tag"], "dns")
        route = doc.get("route") or {}
        if isinstance(route, dict):
            for s in route.get("rule_set") or []:
                if isinstance(s, dict) and isinstance(s.get("tag"), str):
                    syn.define("set", s["tag"], "set")

    def new_key(self, k, path):
        syn = self.syn
        if not isinstance(k, str):
            return k
        parent = norm(path[-1]) if path else ""
        top = norm(path[0]) if path else ""
        if self.fmt == "clash":
            # A key of its own holding an anchor, as templates have: its
            # name is the author's.
            if not path and k not in CLASH_SECTIONS and self.holds_anchor(k):
                return syn._one("holder", k, lambda n: "anchor-%d" % n)
            if path == ["rule-providers"]:
                return syn.name("set", k, "set")
            if path == ["proxy-providers"]:
                return syn.name("provider", k, "provider")
            if path == ["sub-rules"]:
                return syn.name("sub", k, "sub")
            if parent in ("hosts",) or (top == "dns" and parent in ("nameserver-policy", "proxy-server-nameserver-policy")):
                out, prefix = [], ""
                for x in k.split(","):
                    m = re.match(r"^(geosite|geoip|rule-set):", x)
                    if m:
                        prefix = m.group(1)
                    if prefix == "rule-set":
                        name = x.split(":", 1)[1] if m else x
                        out.append(("rule-set:" if m else "") + syn.name("set", name.strip(), "set"))
                    elif prefix:
                        out.append(syn.keep(x))
                    else:
                        out.append(syn.shape(x))
                return ",".join(out)
        if parent in ("headers", "header", "ws-headers", "http-headers") or (parent == "headers" and path):
            return k if k.lower() in HEADERS else syn._one("hdr", k, lambda n: "X-Header-%d" % n)
        if parent in ("hosts", "predefined", "mapping"):
            return syn.shape(k)
        if re.match(r"^\$?[A-Za-z_][A-Za-z0-9_-]*$", k) and len(k) <= 48:
            return k
        if k in ("<<",):
            return k
        return syn.shape(k)

    def holds_anchor(self, k):
        return k in self.holders

    def walk(self, obj, path, siblings=()):
        from_memo = self.memo.get(id(obj))
        if from_memo is not None:
            return from_memo[0]
        if isinstance(obj, dict):
            self.memo[id(obj)] = (obj,)
            self.anchor(obj)
            # A merged map is read where it is merged: walk it here first.
            for merged in getattr(obj, "_yaml_merge", None) or []:
                self.walk(merged[1] if isinstance(merged, tuple) else merged, path, siblings)
            items = list(obj.non_merged_items()) if hasattr(obj, "non_merged_items") else list(obj.items())
            if not path:
                # Sections before whatever holds anchors, so that an alias is
                # read in the section it is used in.
                known = ("proxies", "proxy-groups", "proxy-providers", "rule-providers", "rules",
                         "sub-rules", "listeners", "dns", "tun", "sniffer", "tunnels", "hosts",
                         "outbounds", "endpoints", "inbounds", "route")
                order = sorted(range(len(items)), key=lambda i: items[i][0] not in known)
                for i in order:
                    self.walk(items[i][1], [items[i][0]], items)
            new = []
            for k, v in items:
                nk = self.new_key(k, path)
                nv = self.walk(v, path + [k], items)
                new.append((nk, nv))
            if any(a[0] != b[0] for a, b in zip(items, new)) and hasattr(obj, "insert"):
                for k, _ in items:
                    del obj[k]
                for i, (k, v) in enumerate(new):
                    obj.insert(i, k, v)
            else:
                if any(a[0] != b[0] for a, b in zip(items, new)):
                    obj.clear()
                for k, v in new:
                    obj[k] = v
            return obj
        if isinstance(obj, list):
            self.memo[id(obj)] = (obj,)
            self.anchor(obj)
            for i, v in enumerate(obj):
                obj[i] = self.walk(v, path + [i], siblings)
            return obj
        if isinstance(obj, str):
            new = self.value(obj, path, siblings)
            anchor = getattr(obj, "anchor", None)
            if type(obj) is not str:
                a = anchor.value if anchor is not None and anchor.value else None
                if a:
                    self.anchors += 1
                    a = "a%d" % self.anchors
                new = type(obj)(new, anchor=a) if a else type(obj)(new)
            self.memo[id(obj)] = (new,)
            return new
        return obj

    def anchor(self, obj):
        a = getattr(obj, "anchor", None)
        if a is not None and a.value:
            self.anchors += 1
            obj.yaml_set_anchor("a%d" % self.anchors, always_dump=True)

    def value(self, v, path, siblings):
        syn = self.syn
        keys = [norm(p) for p in path if isinstance(p, str)]
        key = keys[-1] if keys else ""
        in_list = bool(path) and isinstance(path[-1], int)
        top = keys[0] if keys else ""
        if self.fmt == "clash":
            r = self.clash_value(v, keys, key, in_list, top, siblings)
        else:
            r = self.singbox_value(v, keys, key, in_list, top, siblings)
        if r is not None:
            return r
        return self.generic(v, key, siblings)

    def generic(self, v, key, siblings):
        syn = self.syn
        if is_rule(v):
            return self.rules.line(v, has_target=False) if key == "payload" else self.rules.line(v)
        rule = key_rule(key)
        if rule == "secret":
            return secret_value(syn, key, v, siblings)
        if rule == "regex":
            return regex_value(syn, key, v)
        if rule == "enum":
            return enum_value(syn, v)
        if key == "alpn":
            return syn.keep(v) if v.lower() in VOCAB_CI or re.match(r"^(h[123]|http/1\.[01]|spdy/\d|hq-\d+)$", v) else syn._one("alpn", v, lambda n: "alpn%d" % n)
        if key in ("server-name", "servername", "sni", "server-name", "host", "obfs-host", "peer"):
            if DOMAIN_RE.match(v):
                return syn.domain(v, "sni")
        if key in ("server", "address", "ip", "ipv6") and DOMAIN_RE.match(v):
            return syn.domain(v, "server")
        if key in ("process-name", "process-path", "process"):
            return syn.process(v)
        if key in ("package-name", "include-package", "exclude-package", "package"):
            return syn.package(v)
        if key in ("wifi-ssid", "ssid"):
            return syn.ssid(v)
        if key in ("wifi-bssid", "bssid"):
            return syn.mac(v)
        if key in ("interface-name", "default-interface", "bind-interface", "device", "include-interface", "exclude-interface", "interface", "outbound-interface"):
            return v if v.lower() in VOCAB_CI else syn.iface(v)
        if key in ("domain-keyword", "keyword"):
            return syn.keyword(v)
        if key in ("user-agent", "ua"):
            return syn.agent(v)
        if key in ("path", "external-ui", "cache-path", "working-dir", "certificate-path", "key-path"):
            if not re.match(r"^[a-z]+://", v):
                fileish = v.startswith(("./", "../", "~")) or re.search(r"\.[A-Za-z0-9]{1,8}$", v)
                if key == "path" and not fileish:
                    if v.startswith("/"):
                        return syn._one("urlpath", v, lambda n: "/p%d" % n)
                    return syn.string(v)
                return syn.path(v)
        if key in ("name", "title", "content", "description", "desc", "remark", "remarks", "tag", "label"):
            return syn.string(v)
        return syn.shape(v)

    def clash_value(self, v, keys, key, in_list, top, siblings):
        syn = self.syn
        depth = len(keys)
        if top == "proxies" and key == "name" and depth == 2:
            return syn.name("policy", v, "Proxy")
        if top == "proxy-groups":
            if key == "name" and depth == 2:
                return syn.name("policy", v, "Group")
            if key == "proxies":
                return syn.name("policy", v, "Proxy")
            if key == "use":
                return syn.name("provider", v, "provider")
        if key in ("dialer-proxy", "proxy", "detour") and top != "tunnels":
            return syn.name("policy", v, "Proxy")
        if top == "listeners" and key == "name":
            return syn.name("listener", v, "listener")
        if top == "listeners" and key == "rule":
            return syn.name("sub", v, "sub")
        if top in ("rules",) or (top == "sub-rules" and depth >= 2):
            return self.rules.line(v)
        if top == "tunnels" and depth == 1 and "," in v:
            parts = v.split(",")
            out = [syn.keep(parts[0])] + [syn.shape(p.strip()) for p in parts[1:-1]] + [syn.name("policy", parts[-1].strip(), "Proxy")]
            return ",".join(out)
        if top == "tunnels" and key == "proxy":
            return syn.name("policy", v, "Proxy")
        if top == "dns" or key in ("nameserver", "default-nameserver", "fallback", "proxy-server-nameserver", "direct-nameserver", "nameserver-policy"):
            if re.match(r"^[a-z0-9+.-]+://", v) or "#" in v:
                base, _, frag = v.partition("#")
                out = syn.url(base) if "://" in base else syn.shape(base)
                if frag:
                    if "=" in frag:
                        out += "#" + "&".join(
                            "%s=%s" % (a, b if NUM_RE.match(b) or b.lower() in VOCAB_CI else syn.shape(b))
                            if eq else syn.name("policy", a, "Proxy")
                            for a, eq, b in (x.partition("=") for x in frag.split("&"))
                        )
                    else:
                        out += "#" + syn.name("policy", frag, "Proxy")
                return out
            if key in ("fake-ip-filter", "domain", "fallback-filter"):
                return syn.shape(v)
        if key == "authentication":
            return secret_value(syn, key, v, siblings)
        if key in ("exclude-type", "include-type"):
            return enum_value(syn, v)
        return None

    def singbox_value(self, v, keys, key, in_list, top, siblings):
        syn = self.syn
        depth = len(keys)
        in_rules = "rules" in keys
        if key == "tag" and depth == 2:
            if top in ("outbounds", "endpoints"):
                return syn.name("out", v, "Proxy")
            if top == "inbounds":
                return syn.name("in", v, "in")
        if top == "dns" and keys[1:2] == ["servers"] and key == "tag":
            return syn.name("dns", v, "dns")
        if top == "route" and keys[1:2] == ["rule-set"] and key == "tag":
            return syn.name("set", v, "set")
        if key in ("outbounds", "default", "detour", "download-detour", "external-ui-download-detour"):
            if key == "detour" and top == "inbounds":
                return syn.name("in", v, "in")
            return syn.name("out", v, "Proxy")
        if key == "outbound":
            return syn.name("out", v, "Proxy")
        if key == "final":
            return syn.name("dns", v, "dns") if top == "dns" else syn.name("out", v, "Proxy")
        if key in ("address-resolver", "domain-resolver", "default-domain-resolver") or (
            key == "server" and keys[-2:-1] in (["domain-resolver"], ["default-domain-resolver"])
        ):
            return syn.name("dns", v, "dns")
        if key == "server" and in_rules:
            return syn.name("dns", v, "dns")
        if key == "inbound":
            return syn.name("in", v, "in")
        if key == "rule-set" and top in ("route", "dns") and in_rules:
            return syn.name("set", v, "set")
        if key == "rule-set" and keys[1:2] == ["rules"]:
            return syn.name("set", v, "set")
        if top == "dns" and key == "address":
            if re.match(r"^[a-z0-9]+://", v):
                if v.startswith(("rcode://", "dhcp://")):
                    return syn.keep(v)
                return syn.url(v)
            if v.lower() in ("local", "fakeip", "dhcp"):
                return syn.keep(v)
        if key in ("domain", "domain-suffix") and in_list:
            return syn.domain(v)
        if key == "clash-mode":
            return syn.keep(v) if WORD_RE.match(v) else syn.string(v)
        if key in ("geosite", "geoip", "source-geoip"):
            return syn.keep(v) if re.match(r"^[A-Za-z0-9_!@:.-]{1,40}$", v) else syn.string(v)
        if key in ("ip-cidr", "source-ip-cidr", "inet4-address", "inet6-address", "address", "allowed-ips", "route-address", "route-exclude-address", "inet4-route-address", "inet6-route-address", "inet4-route-exclude-address", "inet6-route-exclude-address", "local-address") and (syn.is_net(v) or syn.is_ip(v)):
            return syn.net(v) if "/" in v else syn.ip(v)
        if key in ("user", "auth-user", "name") and top == "inbounds":
            return syn.secret(v, "user")
        if key == "certificate" and in_list:
            if v.startswith("-----"):
                return syn.keep(v)
            return DUMMY_B64_LINE
        return None


# ---------------------------------------------------------------- formats

CLASH_SECTIONS = {
    "proxies", "proxy-groups", "proxy-providers", "rule-providers", "rules", "sub-rules",
    "dns", "tun", "sniffer", "listeners", "tunnels", "hosts", "profile", "experimental",
    "geox-url", "ntp", "tls", "clash-for-android", "iptables", "ebpf", "authentication",
}


def has_anchor(o, seen=None):
    """Whether `o` or anything in it holds an anchor."""
    seen = seen if seen is not None else set()
    if id(o) in seen:
        return False
    seen.add(id(o))
    a = getattr(o, "anchor", None)
    if a is not None and a.value:
        return True
    if isinstance(o, dict):
        return any(has_anchor(v, seen) for v in o.values())
    if isinstance(o, list):
        return any(has_anchor(v, seen) for v in o)
    return False


def strip_comments(o, seen=None):
    seen = seen if seen is not None else set()
    if id(o) in seen:
        return
    seen.add(id(o))
    ca = getattr(o, "ca", None)
    if ca is not None:
        ca.items.clear()
        ca.comment = None
        if hasattr(ca, "end"):
            ca.end = []
    if isinstance(o, dict):
        for v in o.values():
            strip_comments(v, seen)
    elif isinstance(o, list):
        for v in o:
            strip_comments(v, seen)


def jsonc_strip(s):
    """JSON with // and /* */ comments and trailing commas, as JSON."""
    out, i, n, q = [], 0, len(s), False
    while i < n:
        c = s[i]
        if q:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(s[i + 1])
                i += 2
                continue
            if c == '"':
                q = False
            i += 1
            continue
        if c == '"':
            q = True
            out.append(c)
            i += 1
        elif s.startswith("//", i):
            while i < n and s[i] != "\n":
                i += 1
        elif s.startswith("/*", i):
            j = s.find("*/", i + 2)
            i = n if j < 0 else j + 2
        else:
            out.append(c)
            i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


def rewrite_singbox(text, syn):
    doc = json.loads(jsonc_strip(text))
    if not isinstance(doc, dict) or "outbounds" not in doc and "endpoints" not in doc:
        raise ValueError("not a sing-box configuration")
    t = Tree(syn, "sing-box")
    t.singbox_defs(doc)
    t.walk(doc, [])
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def rewrite_clash(text, syn):
    from io import StringIO

    from ruamel.yaml import YAML

    y = YAML()
    y.preserve_quotes = True
    y.allow_duplicate_keys = True
    y.width = 4096
    y.indent(mapping=2, sequence=4, offset=2)
    doc = y.load(text)
    if not isinstance(doc, dict) or not ("proxy-groups" in doc or "rules" in doc):
        raise ValueError("not a Clash configuration")
    strip_comments(doc)
    t = Tree(syn, "clash")
    t.holders = {k for k, v in doc.non_merged_items() if has_anchor(v)}
    t.clash_defs(doc)
    t.walk(doc, [])
    out = StringIO()
    y.dump(doc, out)
    lines = [l for l in out.getvalue().splitlines() if not l.lstrip().startswith("#") and l.strip()]
    return "\n".join(lines) + "\n"


# Surge

SURGE_NAMED = {"Proxy": ("policy", "Proxy"), "Proxy Group": ("policy", "Group"),
               "Script": ("script", "script"), "Panel": ("panel", "panel"),
               "Keystore": ("key", "key")}
SURGE_SECTION_NAMES = {"WireGuard": "wg", "Ruleset": "set", "Tailscale": "ts"}
SURGE_KEEP_DIRECTIVES = ("#!MANAGED-CONFIG", "#!include", "#!REQUIREMENT")


class Surge:
    def __init__(self, syn):
        self.syn = syn
        self.rules = Rules(syn, self.target, sets_are_urls=True)

    def target(self, t):
        s = t.strip()
        pad = t[: len(t) - len(t.lstrip())]
        if s.startswith('"') and s.endswith('"'):
            return pad + '"' + self.syn.name("policy", s[1:-1], "Proxy") + '"'
        return pad + self.syn.name("policy", s, "Proxy")

    def defs(self, sections):
        for name, lines in sections:
            if name in ("Proxy", "Proxy Group", "Script", "Panel", "Keystore"):
                ns, label = SURGE_NAMED[name]
                for l in lines:
                    kv = self.key_value(l)
                    if kv:
                        self.syn.define(ns, kv[0].strip(), label)
            head = name.split(" ", 1)
            if len(head) == 2 and head[0] in SURGE_SECTION_NAMES:
                self.syn.define(SURGE_SECTION_NAMES[head[0]], head[1], SURGE_SECTION_NAMES[head[0]])

    @staticmethod
    def key_value(l):
        m = re.match(r"^([^=]+?)\s*=\s*(.*)$", l)
        return (m.group(1), m.group(2)) if m else None

    def section_name(self, name):
        head = name.split(" ", 1)
        if len(head) == 2 and head[0] in SURGE_SECTION_NAMES:
            ns = SURGE_SECTION_NAMES[head[0]]
            return head[0] + " " + self.syn.name(ns, head[1], ns)
        if re.match(r"^[A-Za-z][A-Za-z ]*$", name):
            return name
        return self.syn.string(name)

    def param(self, k, v, siblings, positional_kind=None):
        """One `key=value` parameter."""
        syn = self.syn
        nk = norm(k)
        q = ""
        if len(v) >= 2 and v[0] == v[-1] == '"':
            q, v = '"', v[1:-1]
        if nk in ("underlying-proxy", "policy", "include-other-group", "detour", "policy-select-name"):
            nv = ",".join(self.target(x) for x in v.split(","))
        elif nk in ("section-name",):
            nv = syn.name("wg", v, "wg")
        elif nk in ("script-name",):
            nv = syn.name("script", v, "script")
        elif nk == "policy-priority":
            nv = ";".join(
                "%s:%s" % (syn.regex(a), b if NUM_RE.match(b) else "1")
                for a, _, b in (x.rpartition(":") for x in v.split(";"))
            )
        elif nk == "policy-path":
            nv = syn.url(v) if "://" in v else syn.path(v)
        elif nk == "ws-headers" or nk == "headers":
            hs = []
            for h in v.split("|"):
                hn, _, hv = h.partition(":")
                hq = ""
                if len(hv) >= 2 and hv[0] == hv[-1] == '"':
                    hq, hv = '"', hv[1:-1]
                hn2 = hn if hn.strip().lower() in HEADERS else syn._one("hdr", hn, lambda n: "X-Header-%d" % n)
                hv2 = syn.domain(hv, "sni") if DOMAIN_RE.match(hv) else syn.shape(hv)
                hs.append("%s:%s%s%s" % (hn2, hq, hv2, hq))
            nv = "|".join(hs)
        elif nk == "private-key" and v in syn.maps.get("name:key", {}):
            nv = syn.name("key", v, "key")
        elif nk in ("sni", "obfs-host", "server-name", "host", "peer-id") and DOMAIN_RE.match(v):
            nv = syn.domain(v, "sni")
        elif nk in ("ws-path", "path", "grpc-service-name"):
            nv = syn._one("urlpath", v, lambda n: "/p%d" % n) if v.startswith("/") else syn.string(v)
        elif nk in ("interface", "interface-name"):
            nv = syn.iface(v)
        elif nk == "base64":
            nv = syn.b64(v[:64] if len(v) > 64 else v)
        elif nk in ("cronexp", "cron") and CRON_RE.match(v):
            nv = syn.keep(v)
        elif nk in ("argument", "title", "content", "exec", "args", "icon", "icon-color", "notification-text"):
            nv = syn.url(v) if "://" in v else syn.string(v) if v else v
        elif nk in ("dns-server", "allowed-ips", "self-ip", "self-ip-v6", "endpoint", "server", "address"):
            nv = ",".join(syn.shape(x.strip()) for x in v.split(","))
        else:
            rule = key_rule(k)
            if rule == "secret":
                nv = secret_value(syn, k, v, siblings)
            elif rule == "regex":
                nv = regex_value(syn, k, v)
            elif rule == "enum":
                nv = enum_value(syn, v)
            else:
                nv = syn.shape(v)
        return "%s=%s%s%s" % (k, q, nv, q)

    def items(self, value, kind=None):
        """A comma list of positional values and `key=value` parameters."""
        syn = self.syn
        parts = split_top(value)
        pairs = []
        for p in parts:
            m = re.match(r"^\s*([A-Za-z0-9_-]+)\s*=\s*(.*?)\s*$", p)
            if m:
                pairs.append((m.group(1), m.group(2).strip('"')))
        out = []
        for i, p in enumerate(parts):
            t = p.strip()
            m = re.match(r"^([A-Za-z0-9_-]+)\s*=\s*(.*)$", t)
            if m and not (kind == "group" and i == 0):
                k, v = m.group(1), m.group(2)
                if v.startswith("(") and v.endswith(")"):
                    out.append("%s=(%s)" % (k, ", ".join(self.items(v[1:-1]))))
                else:
                    out.append(self.param(k, v, pairs))
            elif kind == "proxy":
                if i == 0:
                    out.append(syn.keep(t))
                elif i == 1:
                    out.append(syn.shape(t, "server"))
                elif NUM_RE.match(t) or t.lower() in VOCAB_CI:
                    out.append(syn.keep(t))
                else:
                    out.append(syn.secret(t))
            elif kind == "group":
                if i == 0:
                    out.append(syn.keep(t))
                else:
                    out.append(self.target(t))
            else:
                out.append(syn.shape(t) if t else t)
        return out

    def line(self, section, l):
        syn = self.syn
        base = section.split(" ", 1)[0]
        if section == "Rule":
            return self.rules.line(l)
        if section in ("Proxy", "Proxy Group", "Script", "Panel", "Keystore"):
            kv = self.key_value(l)
            if not kv:
                return syn.string(l)
            ns, label = SURGE_NAMED[section]
            name = syn.name(ns, kv[0].strip(), label)
            kind = {"Proxy": "proxy", "Proxy Group": "group"}.get(section)
            return "%s = %s" % (name, ", ".join(self.items(kv[1], kind)))
        if section == "Host":
            kv = self.key_value(l)
            if not kv:
                return syn.string(l)
            k, v = kv
            if v.startswith("server:"):
                nv = "server:" + ",".join(syn.shape(x.strip()) for x in v[7:].split(","))
            else:
                nv = syn.shape(v, "server")
            return "%s = %s" % (syn.shape(k), nv)
        if section in ("URL Rewrite", "Header Rewrite", "Body Rewrite", "Map Local", "Port Forwarding", "SSID Setting"):
            return " ".join(self.word(section, w, i) for i, w in enumerate(self.words(l)))
        if base == "WireGuard" or section in ("General", "MITM", "Replica", "Snell Server", "Ponte", "DHCP", "Testing", "Proxy Chain") or base in ("Tailscale", "Ruleset"):
            if base == "Ruleset":
                return self.rules.line(l, has_target=False) if is_rule(l) else syn.shape(l)
            kv = self.key_value(l)
            if not kv:
                return syn.shape(l)
            k, v = kv
            nk = k if re.match(r"^[a-z0-9-]+$", k) else syn.string(k)
            return "%s = %s" % (nk, self.general_value(k, v))
        kv = self.key_value(l)
        if kv and re.match(r"^[a-z0-9-]+$", kv[0]):
            return "%s = %s" % (kv[0], self.general_value(kv[0], kv[1]))
        return syn.string(l)

    def general_value(self, k, v):
        syn = self.syn
        nk = norm(k)
        if nk in ("hostname", "hostname-disabled", "skip-proxy", "always-real-ip", "tun-excluded-routes", "tun-included-routes", "always-raw-tcp-hosts", "exclude-simple-hostnames-list", "keyword-filter"):
            if nk == "keyword-filter":
                return ", ".join(syn.keyword(x.strip()) for x in v.split(","))
            return ", ".join(syn.shape(x.strip()) for x in v.split(","))
        if nk in ("ca-p12",):
            return base64.b64encode(b"sail corpus dummy p12").decode()
        if nk == "peer" and v.startswith("("):
            return "(" + ", ".join(self.items(v[1:-1])) + ")"
        if nk in ("external-controller-access", "http-api", "http-api-tls", "ca-passphrase", "private-key", "psk"):
            return secret_value(syn, k, v, [])
        if nk in ("interface", "outbound-interface"):
            return syn.shape(v) if syn.is_ip(v.strip()) else syn.iface(v)
        if key_rule(k) == "enum" or re.match(r"^[a-z]+(-[a-z]+)*$", v.strip()) and len(v) <= 24:
            return enum_value(syn, v)
        if key_rule(k) == "secret":
            return secret_value(syn, k, v, [])
        if key_rule(k) == "regex":
            return regex_value(syn, k, v)
        return ", ".join(self.items(v))

    @staticmethod
    def words(l):
        return re.findall(r'"[^"]*"|\S+', l)

    def word(self, section, w, i):
        syn = self.syn
        q = w.startswith('"') and w.endswith('"') and len(w) >= 2
        t = w[1:-1] if q else w
        if section == "SSID Setting" and i == 0:
            if re.match(r"^[A-Z]+:", t):
                k, v = t.split(":", 1)
                nt = k + ":" + (syn.keep(v) if v.isupper() else syn.ssid(v))
            else:
                nt = syn.ssid(t)
        elif re.match(r"^[a-z0-9-]+=", t):
            k, v = t.split("=", 1)
            nt = self.param(k, v, [])
        elif NUM_RE.match(t) or t.lower() in VOCAB_CI or t.lower() in HEADERS or t in ("http-request", "http-response") or re.match(r"^[a-z][a-z0-9-]{1,24}$", t) and i > 0:
            nt = syn.keep(t)
        elif re.search(r"[\^$\\()|\[\]]", t) and "://" not in t[:10]:
            nt = syn.regex(t, "url")
        elif re.search(r"[\^$\\()|\[\]]", t):
            nt = syn.regex(t, "url")
        else:
            nt = syn.shape(t)
        return '"%s"' % nt if q else nt

    def directive(self, l):
        syn = self.syn
        if l.startswith("#!MANAGED-CONFIG"):
            parts = l.split()
            return " ".join([parts[0]] + [syn.url(p) if "://" in p else p if re.match(r"^[a-z-]+=[a-z0-9]+$", p) else syn.string(p) for p in parts[1:]])
        if l.startswith("#!include"):
            rest = l[len("#!include"):]
            return "#!include " + ", ".join(syn.url(x.strip()) if "://" in x else syn.path(x.strip()) for x in rest.split(","))
        if l.startswith("#!REQUIREMENT"):
            return l if re.match(r"^#!REQUIREMENT[A-Za-z0-9_ <>=!&|'\".()]*$", l) else "#!REQUIREMENT"
        return None

    @staticmethod
    def comment_start(l):
        """Where a comment after a line starts, as Surge reads it."""
        quoted = escaped = False
        for i, c in enumerate(l):
            if escaped:
                escaped = False
                continue
            if c == "\\" and quoted:
                escaped = True
            elif c == '"':
                quoted = not quoted
            elif c in "#;/" and not quoted and i > 0 and l[i - 1].isspace() and (c != "/" or l[i + 1 : i + 2] == "/"):
                return i
        return None

    @staticmethod
    def requirement(expr):
        """A requirement's expression, if it is made of enum words only."""
        if re.match(r"^[A-Za-z0-9_<>=!&|'.() ]*$", expr) and not re.search(r"[A-Za-z0-9-]+\.[A-Za-z]{2,}", expr):
            return expr
        return "CORE_VERSION>=1"

    def split_line(self, l):
        """(requirement ahead, content, directive after) of a line."""
        req = ""
        m = re.match(r"^#!REQUIREMENT\s+", l)
        if m:
            rest = l[m.end():]
            if rest.startswith('"') and '"' in rest[1:]:
                end = rest.index('"', 1)
                expr, rest = rest[1:end], rest[end + 1:]
                req = '#!REQUIREMENT "%s" ' % self.requirement(expr)
            else:
                expr, _, rest = rest.partition(" ")
                req = "#!REQUIREMENT %s " % self.requirement(expr)
            l = rest.strip()
        suffix = ""
        at = self.comment_start(l)
        if at is not None:
            comment = l[at:]
            l = l[:at].rstrip()
            d = comment[2:] if comment.startswith("#!") else comment[3:] if comment.startswith("//!") else None
            if d is not None:
                word = (d.split() or [""])[0]
                if word in ("IOS-ONLY", "MACOS-ONLY", "TVOS-ONLY"):
                    suffix = " #!" + word
                elif word == "REQUIREMENT":
                    expr = d[len("REQUIREMENT"):].strip().strip('"')
                    suffix = ' #!REQUIREMENT "%s"' % self.requirement(expr)
        return req, l, suffix

    def rewrite(self, text):
        sections, cur, pre = [], None, []
        for raw in text.splitlines():
            l = raw.strip().lstrip("\ufeff")
            if not l:
                continue
            if l.startswith(("#!include", "#!MANAGED-CONFIG")):
                (cur[2] if cur else pre).append(("", l, ""))
                if cur:
                    cur[1].append(None)
                continue
            if l.startswith(("#", ";", "//")) and not l.startswith("#!REQUIREMENT"):
                continue
            req, content, suffix = self.split_line(l)
            if not content:
                continue
            m = re.match(r"^\[([^\]]+)\]$", content)
            if m:
                cur = (m.group(1).strip(), [], [])
                sections.append(cur)
                continue
            if cur is None:
                continue
            cur[1].append(content)
            cur[2].append((req, content, suffix))
        names = {s[0] for s in sections}
        if "Proxy Group" not in names or "Rule" not in names:
            raise ValueError("not a Surge profile")
        self.defs([(n, [x for x in ls if x is not None]) for n, ls, _ in sections])
        out = []
        for _, l, _ in pre:
            d = self.directive(l)
            if d:
                out.append(d)
        for name, _, lines in sections:
            out.append("[%s]" % self.section_name(name))
            for req, l, suffix in lines:
                if not req and l.startswith("#!"):
                    d = self.directive(l)
                    if d:
                        out.append(d)
                    continue
                out.append(req + self.line(name, l) + suffix)
        return "\n".join(out) + "\n"


def rewrite(fmt, text):
    """(rewritten text, Synth) for `text` in `fmt`."""
    syn = Synth()
    if fmt == "sing-box":
        out = rewrite_singbox(text, syn)
    elif fmt == "clash":
        out = rewrite_clash(text, syn)
    elif fmt == "surge":
        out = Surge(syn).rewrite(text)
    else:
        raise ValueError(fmt)
    return out, syn


def main(argv):
    if len(argv) != 4:
        sys.exit(__doc__)
    fmt, src, dst = argv[1:]
    with open(src, encoding="utf-8", errors="replace") as f:
        out, _ = rewrite(fmt, f.read())
    with open(dst, "w", encoding="utf-8") as f:
        f.write(out)


if __name__ == "__main__":
    main(sys.argv)
