"""A small, dependency-free packet and capture-file builder.

Used to generate the bundled sample captures and the test fixtures. It is
written independently of the NetSleuth parsers (it only *writes* bytes), and
its output is cross-checked against tshark in the test-suite, so the parsers
are not merely tested against their own assumptions.
"""

from __future__ import annotations

import hashlib
import ipaddress
import socket
import struct

FIN, SYN, RST, PSH, ACK, URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20
MSS = 1460
GATEWAY_MAC = "02:00:00:00:00:01"


def _mac(s: str) -> bytes:
    return bytes(int(x, 16) for x in s.split(":"))


def mac_for(ip: str) -> str:
    """Deterministic locally-administered MAC for an address."""
    d = hashlib.md5(ip.encode()).digest()
    return "02:" + ":".join(f"{b:02x}" for b in d[:5])


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def _is_v6(ip: str) -> bool:
    return ":" in ip


def _addr(ip: str) -> bytes:
    return socket.inet_pton(socket.AF_INET6 if _is_v6(ip) else socket.AF_INET, ip)


def _is_local(ip: str) -> bool:
    a = ipaddress.ip_address(ip)
    return a.is_private and not a.is_loopback and not str(a).startswith(("192.0.2.", "198.51.100.", "203.0.113.")) \
        and not (a.version == 6 and str(a).startswith("2001:db8"))


# ---------------------------------------------------------------- layers ---
def ether(src_mac: str, dst_mac: str, etype: int, payload: bytes, vlan: int | None = None) -> bytes:
    head = _mac(dst_mac) + _mac(src_mac)
    if vlan is not None:
        head += struct.pack("!HH", 0x8100, vlan & 0x0FFF)
    return head + struct.pack("!H", etype) + payload


def ipv4(src: str, dst: str, proto: int, payload: bytes, ttl: int = 64, ident: int = 0,
         flags_frag: int = 0x4000) -> bytes:
    head = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident & 0xFFFF,
                       flags_frag, ttl, proto, 0, _addr(src), _addr(dst))
    return head[:10] + struct.pack("!H", checksum(head)) + head[12:] + payload


def ipv6(src: str, dst: str, nxt: int, payload: bytes, hlim: int = 64) -> bytes:
    return struct.pack("!IHBB", 0x60000000, len(payload), nxt, hlim) + _addr(src) + _addr(dst) + payload


def _pseudo(src: str, dst: str, proto: int, length: int) -> bytes:
    if _is_v6(src):
        return _addr(src) + _addr(dst) + struct.pack("!IHBB", length, 0, 0, proto)
    return _addr(src) + _addr(dst) + struct.pack("!BBH", 0, proto, length)


def tcp_segment(src: str, dst: str, sport: int, dport: int, seq: int, ack: int,
                flags: int, payload: bytes = b"", window: int = 64240,
                options: bytes = b"") -> bytes:
    options += b"\x00" * (-len(options) % 4)
    off = (20 + len(options)) // 4
    head = struct.pack("!HHIIHHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
                       (off << 12) | flags, window, 0, 0) + options
    csum = checksum(_pseudo(src, dst, 6, len(head) + len(payload)) + head + payload)
    return head[:16] + struct.pack("!H", csum) + head[18:] + payload


def udp_datagram(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    head = struct.pack("!HHHH", sport, dport, length, 0)
    csum = checksum(_pseudo(src, dst, 17, length) + head + payload) or 0xFFFF
    return head[:6] + struct.pack("!H", csum) + payload


def icmp_echo(ident: int, seq: int, reply: bool = False, data: bytes = b"netsleuth-ping") -> bytes:
    head = struct.pack("!BBHHH", 0 if reply else 8, 0, 0, ident, seq)
    return head[:2] + struct.pack("!H", checksum(head + data)) + head[4:] + data


def icmp_port_unreachable(original_ip_packet: bytes) -> bytes:
    body = b"\x00" * 4 + original_ip_packet[:28]
    head = struct.pack("!BBH", 3, 3, 0)
    return head[:2] + struct.pack("!H", checksum(head + body)) + body


def arp(op: int, sha: str, spa: str, tha: str, tpa: str) -> bytes:
    return struct.pack("!HHBBH", 1, 0x0800, 6, 4, op) + _mac(sha) + _addr(spa) + _mac(tha) + _addr(tpa)


# ------------------------------------------------------------------- DNS ---
QTYPE = {"A": 1, "NS": 2, "CNAME": 5, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28, "NULL": 10}


def dns_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        if label:
            raw = label.encode("latin-1")
            out += bytes([len(raw)]) + raw
    return out + b"\x00"


def dns_query(txid: int, name: str, qtype: str = "A") -> bytes:
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + dns_name(name) + \
        struct.pack("!HH", QTYPE[qtype], 1)


def dns_response(txid: int, name: str, qtype: str = "A", answers=(), rcode: int = 0) -> bytes:
    """answers: iterable of (type, value); the owner name is compressed."""
    out = struct.pack("!HHHHHH", txid, 0x8180 | rcode, 1, len(answers), 0, 0)
    out += dns_name(name) + struct.pack("!HH", QTYPE[qtype], 1)
    for rtype, value in answers:
        if rtype == "A":
            rdata = socket.inet_aton(value)
        elif rtype == "AAAA":
            rdata = socket.inet_pton(socket.AF_INET6, value)
        elif rtype == "TXT":
            raw = value.encode("latin-1")[:255]
            rdata = bytes([len(raw)]) + raw
        else:
            rdata = dns_name(value)
        out += b"\xc0\x0c" + struct.pack("!HHIH", QTYPE[rtype], 1, 300, len(rdata)) + rdata
    return out


# ------------------------------------------------------------------- TLS ---
def _ext(etype: int, data: bytes) -> bytes:
    return struct.pack("!HH", etype, len(data)) + data


def tls_client_hello(sni: str | None = "example.com",
                     ciphers=(0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8),
                     alpn=("h2", "http/1.1"), grease: bool = False, seed: int = 1) -> bytes:
    rnd = hashlib.sha256(f"ch{seed}".encode()).digest()
    cs = list(ciphers)
    if grease:
        cs = [0x0A0A] + cs
    exts = b""
    if grease:
        exts += _ext(0x1A1A, b"")
    if sni:
        raw = sni.encode()
        exts += _ext(0, struct.pack("!HBH", len(raw) + 3, 0, len(raw)) + raw)
    exts += _ext(23, b"")                                             # extended_master_secret
    exts += _ext(65281, b"\x00")                                      # renegotiation_info
    groups = ([0x2A2A] if grease else []) + [29, 23, 24]
    exts += _ext(10, struct.pack("!H", len(groups) * 2) + b"".join(struct.pack("!H", g) for g in groups))
    exts += _ext(11, b"\x01\x00")                                     # ec_point_formats
    if alpn:
        body = b"".join(bytes([len(a)]) + a.encode() for a in alpn)
        exts += _ext(16, struct.pack("!H", len(body)) + body)
    exts += _ext(13, struct.pack("!H", 8) + bytes.fromhex("0403080404010805"))   # sig algs
    exts += _ext(43, b"\x04\x03\x04\x03\x03")                         # supported_versions
    exts += _ext(51, struct.pack("!HHH", 36, 29, 32) + rnd)           # key_share x25519
    body = (b"\x03\x03" + rnd + b"\x20" + rnd[::-1]
            + struct.pack("!H", len(cs) * 2) + b"".join(struct.pack("!H", c) for c in cs)
            + b"\x01\x00" + struct.pack("!H", len(exts)) + exts)
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def tls_server_hello(cipher: int = 0x1301, tls13: bool = True, seed: int = 1) -> bytes:
    rnd = hashlib.sha256(f"sh{seed}".encode()).digest()
    exts = b""
    if tls13:
        exts += _ext(43, b"\x03\x04") + _ext(51, struct.pack("!HH", 29, 32) + rnd)
    else:
        exts += _ext(65281, b"\x00") + _ext(23, b"")
    body = (b"\x03\x03" + rnd + b"\x20" + rnd[::-1] + struct.pack("!H", cipher) + b"\x00"
            + struct.pack("!H", len(exts)) + exts)
    hs = b"\x02" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x03" + struct.pack("!H", len(hs)) + hs + b"\x14\x03\x03\x00\x01\x01"


def tls_appdata(n: int, seed: int = 0) -> bytes:
    """n bytes of pseudo-random 'encrypted' application data, as TLS records."""
    out = b""
    block = hashlib.sha256(f"ad{seed}".encode()).digest()
    while n > 0:
        size = min(n, 16384)
        data = (block * (size // 32 + 1))[:size]
        out += b"\x17\x03\x03" + struct.pack("!H", size) + data
        n -= size
    return out


# --------------------------------------------------------------- builder ---
class CaptureBuilder:
    """Accumulates timestamped Ethernet frames and writes capture files."""

    def __init__(self, vlan: int | None = None):
        self.frames: list[tuple[float, bytes]] = []
        self.vlan = vlan
        self._ident = 1
        self._isn = 1000

    # -- frame helpers ------------------------------------------------------
    def _macs(self, src: str, dst: str) -> tuple[str, str]:
        s = mac_for(src) if _is_local(src) else GATEWAY_MAC
        if dst.endswith(".255") or dst.startswith(("224.", "239.", "ff0")):
            d = "ff:ff:ff:ff:ff:ff"
        else:
            d = mac_for(dst) if (_is_local(dst) and _is_local(src)) else \
                (GATEWAY_MAC if _is_local(src) else mac_for(dst))
        return s, d

    def ip(self, ts: float, src: str, dst: str, proto: int, l4: bytes, ttl: int = 64) -> bytes:
        self._ident += 1
        if _is_v6(src):
            pkt, etype = ipv6(src, dst, proto, l4, ttl), 0x86DD
        else:
            pkt, etype = ipv4(src, dst, proto, l4, ttl, self._ident), 0x0800
        s, d = self._macs(src, dst)
        self.frames.append((ts, ether(s, d, etype, pkt, self.vlan)))
        return pkt

    def raw(self, ts: float, frame: bytes) -> None:
        self.frames.append((ts, frame))

    def tcp(self, ts, src, dst, sport, dport, seq, ack, flags, payload=b"", ttl=64, options=b""):
        return self.ip(ts, src, dst, 6,
                       tcp_segment(src, dst, sport, dport, seq, ack, flags, payload, options=options), ttl)

    def udp(self, ts, src, dst, sport, dport, payload, ttl=64):
        return self.ip(ts, src, dst, 17, udp_datagram(src, dst, sport, dport, payload), ttl)

    def arp_request(self, ts, src_ip, target_ip, src_mac=None):
        mac = src_mac or mac_for(src_ip)
        self.raw(ts, ether(mac, "ff:ff:ff:ff:ff:ff", 0x0806,
                           arp(1, mac, src_ip, "00:00:00:00:00:00", target_ip)))

    def arp_reply(self, ts, src_ip, dst_ip, src_mac=None):
        mac = src_mac or mac_for(src_ip)
        self.raw(ts, ether(mac, mac_for(dst_ip), 0x0806, arp(2, mac, src_ip, mac_for(dst_ip), dst_ip)))

    def ping(self, ts, src, dst, seq=1, rtt=0.004):
        self.ip(ts, src, dst, 1, icmp_echo(0x1234, seq))
        self.ip(ts + rtt, dst, src, 1, icmp_echo(0x1234, seq, reply=True))

    # -- conversations ------------------------------------------------------
    def dns(self, ts, client, resolver, name, qtype="A", answers=(), rcode=0, sport=None,
            txid=None, rtt=0.012, answer=True) -> float:
        self._ident += 1
        txid = txid if txid is not None else (self._ident * 7919) & 0xFFFF
        sport = sport or 20000 + (self._ident * 31) % 40000
        self.udp(ts, client, resolver, sport, 53, dns_query(txid, name, qtype))
        if answer:
            self.udp(ts + rtt, resolver, client, 53, sport,
                     dns_response(txid, name, qtype, answers, rcode))
        return ts + rtt

    def tcp_session(self, ts, client, server, sport, dport, exchanges=(), close="fin",
                    rtt=0.02, handshake=True) -> float:
        """Emit a full TCP conversation.

        exchanges: sequence of (direction, payload, delay_before) where
        direction is 'c' (client->server) or 's'. Payloads are segmented at
        the MSS and acknowledged. close: 'fin', 'rst', 'rst_server' or None.
        Returns the timestamp of the last packet.
        """
        self._isn += 7919
        cseq, sseq = self._isn, self._isn * 3 + 11
        t = ts
        if handshake:
            self.tcp(t, client, server, sport, dport, cseq, 0, SYN, options=b"\x02\x04\x05\xb4")
            t += rtt
            self.tcp(t, server, client, dport, sport, sseq, cseq + 1, SYN | ACK, options=b"\x02\x04\x05\xb4")
            t += rtt / 10
            self.tcp(t, client, server, sport, dport, cseq + 1, sseq + 1, ACK)
        cseq += 1
        sseq += 1
        for direction, payload, delay in exchanges:
            t += delay
            for i in range(0, len(payload), MSS):
                chunk = payload[i:i + MSS]
                last = i + MSS >= len(payload)
                flags = ACK | (PSH if last else 0)
                if direction == "c":
                    self.tcp(t, client, server, sport, dport, cseq, sseq, flags, chunk)
                    cseq += len(chunk)
                else:
                    self.tcp(t, server, client, dport, sport, sseq, cseq, flags, chunk)
                    sseq += len(chunk)
                t += 0.0004
                # acknowledge every second segment and the final one
                if last or (i // MSS) % 2:
                    if direction == "c":
                        self.tcp(t + rtt / 4, server, client, dport, sport, sseq, cseq, ACK)
                    else:
                        self.tcp(t + rtt / 4, client, server, sport, dport, cseq, sseq, ACK)
            t += rtt / 4
        if close == "fin":
            t += 0.001
            self.tcp(t, client, server, sport, dport, cseq, sseq, FIN | ACK)
            t += rtt
            self.tcp(t, server, client, dport, sport, sseq, cseq + 1, FIN | ACK)
            t += rtt / 10
            self.tcp(t, client, server, sport, dport, cseq + 1, sseq + 1, ACK)
        elif close == "rst":
            t += 0.001
            self.tcp(t, client, server, sport, dport, cseq, sseq, RST | ACK)
        elif close == "rst_server":
            t += 0.001
            self.tcp(t, server, client, dport, sport, sseq, cseq, RST | ACK)
        return t

    def syn_probe(self, ts, src, dst, sport, dport, result="closed", rtt=0.001) -> None:
        """One SYN-scan probe. result: 'open', 'closed' or 'filtered'."""
        self._isn += 104729
        seq = self._isn
        self.tcp(ts, src, dst, sport, dport, seq, 0, SYN)
        if result == "closed":
            self.tcp(ts + rtt, dst, src, dport, sport, 0, seq + 1, RST | ACK)
        elif result == "open":
            self.tcp(ts + rtt, dst, src, dport, sport, seq * 5, seq + 1, SYN | ACK)
            self.tcp(ts + rtt * 1.5, src, dst, sport, dport, seq + 1, 0, RST)

    def http(self, ts, client, server, sport, host, path="/", method="GET", status=200,
             body=b"<html>ok</html>", user_agent="Mozilla/5.0 (X11; Linux x86_64)",
             dport=80, req_body=b"", extra_headers="", content_type="text/html", **kw) -> float:
        req = (f"{method} {path} HTTP/1.1\r\nHost: {host}\r\n"
               + (f"User-Agent: {user_agent}\r\n" if user_agent else "")
               + "Accept: */*\r\n" + extra_headers
               + (f"Content-Length: {len(req_body)}\r\n" if req_body else "")
               + "\r\n").encode("latin-1") + req_body
        resp = (f"HTTP/1.1 {status} {'OK' if status == 200 else 'Status'}\r\nServer: nginx\r\n"
                f"Content-Type: {content_type}\r\nContent-Length: {len(body)}\r\n\r\n").encode() + body
        return self.tcp_session(ts, client, server, sport, dport,
                                [("c", req, 0.001), ("s", resp, 0.03)], **kw)

    def tls(self, ts, client, server, sport, sni="example.com", dport=443, sent=600,
            received=4000, seed=1, tls13=True, grease=False, **kw) -> float:
        ex = [("c", tls_client_hello(sni, grease=grease, seed=seed), 0.001),
              ("s", tls_server_hello(tls13=tls13, seed=seed) + tls_appdata(2400, seed), 0.02)]
        if sent:
            ex.append(("c", tls_appdata(sent, seed + 1), 0.01))
        if received:
            ex.append(("s", tls_appdata(received, seed + 2), 0.03))
        return self.tcp_session(ts, client, server, sport, dport, ex, **kw)

    # -- output -------------------------------------------------------------
    def sorted_frames(self) -> list[tuple[float, bytes]]:
        return sorted(self.frames, key=lambda f: f[0])

    def write_pcap(self, path, nanos: bool = False, big_endian: bool = False,
                   linktype: int = 1, snaplen: int = 262144) -> None:
        e = ">" if big_endian else "<"
        magic = 0xA1B23C4D if nanos else 0xA1B2C3D4
        scale = 1_000_000_000 if nanos else 1_000_000
        with open(path, "wb") as f:
            f.write(struct.pack(e + "IHHiIII", magic, 2, 4, 0, 0, snaplen, linktype))
            for ts, frame in self.sorted_frames():
                sec = int(ts)
                frac = int(round((ts - sec) * scale))
                if frac >= scale:
                    sec, frac = sec + 1, frac - scale
                data = frame[:snaplen]
                f.write(struct.pack(e + "IIII", sec, frac, len(data), len(frame)) + data)

    def write_pcapng(self, path, big_endian: bool = False, linktype: int = 1,
                     tsresol: int = 6) -> None:
        e = ">" if big_endian else "<"

        def block(btype: int, body: bytes) -> bytes:
            body += b"\x00" * (-len(body) % 4)
            total = 12 + len(body)
            return struct.pack(e + "II", btype, total) + body + struct.pack(e + "I", total)

        def option(code: int, value: bytes) -> bytes:
            return struct.pack(e + "HH", code, len(value)) + value + b"\x00" * (-len(value) % 4)

        with open(path, "wb") as f:
            shb = struct.pack(e + "IHHq", 0x1A2B3C4D, 1, 0, -1) + \
                option(4, b"NetSleuth pcapgen") + option(0, b"")
            f.write(block(0x0A0D0D0A, shb))
            idb = struct.pack(e + "HHI", linktype, 0, 262144) + option(2, b"eth0") + \
                option(9, bytes([tsresol])) + option(0, b"")
            f.write(block(1, idb))
            units = 10 ** tsresol
            for ts, frame in self.sorted_frames():
                t = int(round(ts * units))
                body = struct.pack(e + "IIIII", 0, t >> 32, t & 0xFFFFFFFF, len(frame), len(frame)) + frame
                f.write(block(6, body))
