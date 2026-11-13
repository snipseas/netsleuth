"""Generate the bundled sample captures and test fixtures.

    python -m netsleuth.devtools.gen_samples

Everything is synthetic and deterministic (seeded). External addresses come
from the RFC 5737 documentation ranges and names use reserved example
domains, so no real third party appears in the data.
"""

from __future__ import annotations

import base64
import hashlib
import os
import random
import struct

from .pcapgen import (SYN, CaptureBuilder, tls_appdata, tls_client_hello,
                      tls_server_hello)

BASE_TS = 1_763_020_800.0     # 2025-11-13 08:00:00 UTC
RESOLVER = "10.0.5.2"
WORKSTATIONS = ["10.0.5.21", "10.0.5.22", "10.0.5.23", "10.0.5.31", "10.0.5.42",
                "10.0.5.55", "10.0.5.60", "10.0.5.77"]
SITES = [
    ("www.example.com", "203.0.113.10"), ("cdn.example.net", "203.0.113.11"),
    ("mail.example.org", "198.51.100.25"), ("api.example.com", "203.0.113.12"),
    ("docs.example.org", "198.51.100.30"), ("static.example.net", "203.0.113.14"),
    ("updates.example.com", "198.51.100.40"), ("intranet-sso.example.org", "198.51.100.41"),
]


class Ports:
    def __init__(self, start=49152):
        self.n = start

    def __call__(self) -> int:
        self.n += 1
        if self.n > 65000:
            self.n = 49152
        return self.n


def build_incident(seed: int = 7) -> CaptureBuilder:
    """One hour of office traffic with several overlapping suspicious behaviours."""
    rnd = random.Random(seed)
    b = CaptureBuilder()
    port = Ports()
    T = BASE_TS

    # --- ARP chatter, including one address claimed by two MACs ------------
    for i, ws in enumerate(WORKSTATIONS):
        b.arp_request(T + i * 0.3, ws, RESOLVER)
        b.arp_reply(T + i * 0.3 + 0.001, RESOLVER, ws)
    b.arp_reply(T + 1500.0, "10.0.5.1", "10.0.5.21", src_mac="02:de:ad:be:ef:01")
    b.arp_reply(T + 1500.5, "10.0.5.1", "10.0.5.21", src_mac="02:00:00:00:00:01")
    b.arp_reply(T + 1530.0, "10.0.5.1", "10.0.5.22", src_mac="02:de:ad:be:ef:01")

    # --- background: ordinary browsing -----------------------------------
    for ws in WORKSTATIONS[:7]:
        t = T + rnd.uniform(5, 60)
        while t < T + 3500:
            name, ip = rnd.choice(SITES)
            b.dns(t, ws, RESOLVER, name, "A", [("A", ip)])
            if rnd.random() < 0.25:
                b.http(t + 0.05, ws, ip, port(), name, path=rnd.choice(
                    ["/", "/index.html", "/news", "/assets/app.js", "/api/v1/status"]),
                    body=b"x" * rnd.randint(400, 9000))
            else:
                b.tls(t + 0.05, ws, ip, port(), sni=name, sent=rnd.randint(300, 2500),
                      received=rnd.randint(3000, 14000), seed=rnd.randint(1, 9999),
                      grease=True)
            t += rnd.expovariate(1 / 75.0)
        for k in range(4):
            b.ping(T + 100 + k * 900 + rnd.uniform(0, 5), ws, "10.0.5.1", seq=k)
    # NTP from everyone (periodic by design; must not be reported)
    for ws in WORKSTATIONS:
        for k in range(55):
            ts = T + 20 + k * 64 + rnd.uniform(0, 0.2)
            b.udp(ts, ws, "198.51.100.123", 123, 123, b"\x23" + b"\x00" * 47)
            b.udp(ts + 0.03, "198.51.100.123", ws, 123, 123, b"\x24" + b"\x00" * 47)

    # --- 1. beaconing: 10.0.5.23 -> 203.0.113.50:443 every ~60 s -----------
    t = T + 42.0
    for k in range(55):
        b.tls(t, "10.0.5.23", "203.0.113.50", port(), sni="telemetry-sync.example.net",
              sent=312, received=96, seed=4242)
        t += 60.0 + rnd.uniform(-1.5, 1.5)

    # --- 2. DNS tunnelling: long encoded TXT lookups under one domain ------
    t = T + 600.0
    blob = hashlib.sha512(b"netsleuth-sample-exfil").digest() * 200
    off = 0
    for k in range(240):
        chunk = base64.b32encode(blob[off:off + 30]).decode().rstrip("=").lower()
        off += 30
        name = f"{chunk[:24]}.{chunk[24:48]}.{k:04x}.t.cache-metrics.example"
        b.dns(t, "10.0.5.23", RESOLVER, name, "TXT",
              [("TXT", base64.b64encode(blob[off:off + 60]).decode())])
        t += rnd.uniform(0.4, 1.6)

    # --- 3. port scan + sweep from 10.0.5.77 ---------------------------------
    t = T + 1200.0
    open_ports = {22, 80, 443, 445, 3306}
    scan_ports = list(range(1, 1025)) + [1433, 3306, 3389, 5432, 5900, 8080, 8443]
    rnd.shuffle(scan_ports)
    for p in scan_ports:
        b.syn_probe(t, "10.0.5.77", "10.0.5.10", 61000 + (p % 400), p,
                    "open" if p in open_ports else ("filtered" if p % 97 == 0 else "closed"))
        t += rnd.uniform(0.004, 0.012)
    t = T + 1300.0
    for last in range(100, 141):
        target = f"10.0.5.{last}"
        result = "open" if last in (104, 117, 131) else ("closed" if last % 3 else "filtered")
        b.syn_probe(t, "10.0.5.77", target, port(), 445, result)
        t += rnd.uniform(0.02, 0.08)
    # follow-up SMB sessions to the hosts that answered
    t = T + 1400.0
    for last in (104, 117, 131):
        b.tcp_session(t, "10.0.5.77", f"10.0.5.{last}", port(), 445,
                      [("c", b"\x00\x00\x00\x54\xfeSMB" + b"\x00" * 80, 0.01),
                       ("s", b"\x00\x00\x00\x94\xfeSMB" + b"\x00" * 144, 0.01),
                       ("c", b"\x00\x00\x02\x00\xfeSMB" + b"\x01" * 508, 0.05),
                       ("s", b"\x00\x00\x08\x00\xfeSMB" + b"\x02" * 2044, 0.05)])
        t += 20.0

    # --- 4. rapid repeated SSH sessions (password guessing shape) ------------
    t = T + 1700.0
    for k in range(40):
        b.tcp_session(t, "10.0.5.77", "10.0.5.10", port(), 22,
                      [("s", b"SSH-2.0-OpenSSH_9.6\r\n", 0.01),
                       ("c", b"SSH-2.0-libssh_0.10.5\r\n", 0.01),
                       ("c", bytes(rnd.getrandbits(8) for _ in range(560)), 0.02),
                       ("s", bytes(rnd.getrandbits(8) for _ in range(820)), 0.02),
                       ("c", bytes(rnd.getrandbits(8) for _ in range(140)), 0.4),
                       ("s", bytes(rnd.getrandbits(8) for _ in range(84)), 0.9)],
                      close="rst_server")
        t += rnd.uniform(1.8, 3.2)

    # --- 5. DGA-like NXDOMAIN burst + external resolver use -----------------
    t = T + 2100.0
    alphabet = "bcdfghjklmnpqrstvwxz0123456789aeiou"
    for k in range(34):
        label = "".join(rnd.choice(alphabet[:28]) for _ in range(rnd.randint(12, 18)))
        b.dns(t, "10.0.5.42", RESOLVER, f"{label}.{rnd.choice(['com', 'net', 'info'])}",
              "A", rcode=3)
        t += rnd.uniform(0.2, 1.1)
    for k, name in enumerate(["cfg.update-node.example.top", "a1.update-node.example.top",
                              "www.example.com"]):
        b.dns(T + 2150 + k, "10.0.5.42", "8.8.8.8", name, "A", [("A", "192.0.2.99")])

    # --- 6. unusual outbound: port 4444 + scripted HTTP to a bare IP --------
    b.tcp_session(T + 2200.0, "10.0.5.42", "192.0.2.99", port(), 4444,
                  [("c", b"\x00\x00\x00\x10READY\x00" + b"\x7f" * 10, 0.02),
                   ("s", b"\x00\x00\x01\x00" + b"\x90" * 256, 0.5),
                   ("c", b"\x00\x00\x04\x00" + b"\x41" * 1024, 2.0),
                   ("s", b"\x00\x00\x00\x08ACK\x00\x00\x00\x00\x00", 1.0)])
    for k, path in enumerate(["/stage/loader.bin", "/stage/cfg.dat", "/gate.php?id=10052342"]):
        b.http(T + 2260.0 + k * 4, "10.0.5.42", "192.0.2.99", port(), "192.0.2.99", path=path,
               user_agent="curl/8.5.0", body=bytes(rnd.getrandbits(8) for _ in range(3000)),
               content_type="application/octet-stream")
    b.tls(T + 2300.0, "10.0.5.42", "192.0.2.120", port(), sni=None, dport=8443,
          sent=900, received=1800, seed=99)

    # --- 7. large upload (exfiltration shape) ---------------------------------
    payload = tls_appdata(1_300_000, seed=31337)
    b.tcp_session(T + 2500.0, "10.0.5.23", "198.51.100.77", port(), 443,
                  [("c", tls_client_hello("files.bulk-storage.example.org", seed=5), 0.001),
                   ("s", tls_server_hello(seed=5), 0.02),
                   ("c", payload, 0.05),
                   ("s", tls_appdata(900, 6), 0.05)])

    # --- 8. cleartext FTP login and HTTP Basic -------------------------------
    b.tcp_session(T + 2800.0, "10.0.5.31", "203.0.113.80", port(), 21,
                  [("s", b"220 ProFTPD Server ready.\r\n", 0.02),
                   ("c", b"USER backup\r\n", 0.3), ("s", b"331 Password required\r\n", 0.02),
                   ("c", b"PASS not-a-real-password\r\n", 0.4),
                   ("s", b"230 User backup logged in\r\n", 0.05),
                   ("c", b"QUIT\r\n", 1.0), ("s", b"221 Goodbye.\r\n", 0.02)])
    b.http(T + 2850.0, "10.0.5.31", "203.0.113.81", port(), "legacy-admin.example.org",
           path="/admin/", extra_headers="Authorization: Basic bm90OnJlYWw=\r\n")

    # --- 9. long-lived interactive session -----------------------------------
    ex = [("s", b"SSH-2.0-OpenSSH_9.3\r\n", 0.01), ("c", b"SSH-2.0-OpenSSH_9.6\r\n", 0.01)]
    for k in range(60):
        ex.append(("c", bytes(rnd.getrandbits(8) for _ in range(rnd.randint(36, 120))),
                   rnd.uniform(20, 55)))
        ex.append(("s", bytes(rnd.getrandbits(8) for _ in range(rnd.randint(36, 400))), 0.03))
    b.tcp_session(T + 300.0, "10.0.5.31", "198.51.100.20", port(), 22, ex)

    # --- 10. a dead destination retried over and over -------------------------
    t = T + 900.0
    for k in range(18):
        seq = 900000 + k * 1000
        for retry, gap in enumerate((0.0, 1.0, 3.0)):
            b.tcp(t + gap, "10.0.5.55", "203.0.113.200", 50500 + k, 8081, seq, 0, SYN)
        t += 45.0

    # --- a little IPv6 and a hostile-looking Host header ---------------------
    b.dns(T + 3000.0, "fd00:5::21", "fd00:5::2", "www.example.com", "AAAA",
          [("AAAA", "2001:db8::10")])
    b.tls(T + 3000.2, "fd00:5::21", "2001:db8::10", port(), sni="www.example.com", seed=77)
    b.http(T + 3100.0, "10.0.5.21", "203.0.113.10", port(),
           '<script>alert("xss")</script>.example.com', path='/"><img src=x onerror=alert(1)>',
           user_agent="<b>ua</b>")
    return b


def build_basic() -> CaptureBuilder:
    """Tiny capture: one DNS lookup, one HTTP exchange, one TLS session, a ping."""
    b = CaptureBuilder()
    T = BASE_TS
    b.arp_request(T, "192.168.1.10", "192.168.1.1")
    b.arp_reply(T + 0.001, "192.168.1.1", "192.168.1.10")
    b.dns(T + 0.1, "192.168.1.10", "192.168.1.1", "www.example.com", "A",
          [("CNAME", "web.example.com"), ("A", "203.0.113.10")], txid=0x1A2B, sport=40001)
    b.http(T + 0.2, "192.168.1.10", "203.0.113.10", 40002, "www.example.com",
           path="/index.html", body=b"<html>hello</html>")
    b.tls(T + 1.0, "192.168.1.10", "203.0.113.11", 40003, sni="secure.example.com",
          sent=500, received=3000, seed=3, grease=True)
    b.ping(T + 2.0, "192.168.1.10", "192.168.1.1")
    b.dns(T + 2.5, "192.168.1.10", "192.168.1.1", "nope.example.com", "A", rcode=3,
          txid=0x2B3C, sport=40004)
    return b


def build_ipv6_vlan() -> CaptureBuilder:
    b = CaptureBuilder(vlan=42)
    T = BASE_TS
    b.dns(T, "fd00::10", "fd00::1", "v6.example.com", "AAAA", [("AAAA", "2001:db8::beef")],
          txid=0x0606, sport=41000)
    b.http(T + 0.1, "fd00::10", "2001:db8::beef", 41001, "v6.example.com", path="/v6")
    return b


def write_malformed(directory: str) -> None:
    """Deliberately damaged files used by the robustness tests."""
    good = os.path.join(directory, "basic.pcap")
    data = open(good, "rb").read()
    # truncated in the middle of a packet record
    open(os.path.join(directory, "truncated.pcap"), "wb").write(data[:len(data) - 37])
    # a record header that claims an absurd captured length
    bad = bytearray(data)
    struct.pack_into("<I", bad, 24 + 8, 0x7FFFFFF0)
    open(os.path.join(directory, "corrupt-length.pcap"), "wb").write(bytes(bad))
    # valid file header followed by random bytes inside each frame
    rnd = random.Random(1)
    b = CaptureBuilder()
    for i in range(200):
        b.raw(BASE_TS + i * 0.01, bytes(rnd.getrandbits(8) for _ in range(rnd.randint(0, 120))))
    # frames with valid Ethernet/IP starts but truncated or lying headers
    liar = bytes.fromhex("020000000001020000000002" "0800" "4f00ffff000040000006") + b"\x00" * 6
    b.raw(BASE_TS + 3.0, liar)
    b.raw(BASE_TS + 3.1, bytes.fromhex("020000000001020000000002" "86dd" "60000000ffff2c40"))
    b.raw(BASE_TS + 3.2, bytes.fromhex("020000000001020000000002" "8100"))
    b.write_pcap(os.path.join(directory, "garbage-frames.pcap"))
    # not a capture at all
    open(os.path.join(directory, "not-a-capture.pcap"), "wb").write(b"GIF89a" + b"\x00" * 64)
    # DNS with a compression-pointer loop
    b = CaptureBuilder()
    loop = struct.pack("!HHHHHH", 0x6666, 0x0100, 1, 0, 0, 0) + b"\xc0\x0c" + b"\x00\x01\x00\x01"
    b.udp(BASE_TS, "192.168.1.10", "192.168.1.1", 40000, 53, loop)
    b.write_pcap(os.path.join(directory, "dns-pointer-loop.pcap"))


def main() -> None:
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    samples = os.path.join(root, "netsleuth", "samples")
    fixtures = os.path.join(root, "tests", "fixtures")
    os.makedirs(samples, exist_ok=True)
    os.makedirs(fixtures, exist_ok=True)

    build_incident().write_pcapng(os.path.join(samples, "demo-incident.pcapng"))
    basic = build_basic()
    basic.write_pcap(os.path.join(samples, "demo-basic.pcap"))
    basic.write_pcap(os.path.join(fixtures, "basic.pcap"))
    basic.write_pcap(os.path.join(fixtures, "basic-nanos-be.pcap"), nanos=True, big_endian=True)
    basic.write_pcapng(os.path.join(fixtures, "basic.pcapng"))
    basic.write_pcapng(os.path.join(fixtures, "basic-be.pcapng"), big_endian=True, tsresol=9)
    build_ipv6_vlan().write_pcapng(os.path.join(fixtures, "ipv6-vlan.pcapng"))
    write_malformed(fixtures)
    for d in (samples, fixtures):
        for name in sorted(os.listdir(d)):
            print(f"{os.path.getsize(os.path.join(d, name)):>10,}  {os.path.relpath(os.path.join(d, name), root)}")


if __name__ == "__main__":
    main()
