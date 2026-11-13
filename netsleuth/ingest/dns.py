"""DNS message parsing (RFC 1035) with bounded name decompression."""

from __future__ import annotations

import socket
import struct

QTYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 10: "NULL", 12: "PTR", 13: "HINFO",
    15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 35: "NAPTR", 41: "OPT",
    43: "DS", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 52: "TLSA", 64: "SVCB",
    65: "HTTPS", 99: "SPF", 251: "IXFR", 252: "AXFR", 255: "ANY", 257: "CAA",
}
RCODES = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP",
    5: "REFUSED", 6: "YXDOMAIN", 7: "YXRRSET", 8: "NXRRSET", 9: "NOTAUTH",
    10: "NOTZONE",
}

MAX_NAME_LEN = 255
MAX_POINTER_HOPS = 16
MAX_ANSWERS = 32

_HDR = struct.Struct("!HHHHHH")
_RR = struct.Struct("!HHIH")

# Printable label characters are kept; anything else is hex-escaped so that a
# hostile name cannot smuggle control characters into logs or the UI.
_SAFE = frozenset(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_=+/*~!$&'(),;:@")


def _label(raw: bytes) -> str:
    if all(c in _SAFE for c in raw):
        return raw.decode("ascii")
    return "".join(chr(c) if c in _SAFE else f"\\x{c:02x}" for c in raw)


def read_name(data: bytes, off: int) -> tuple[str, int]:
    """Decode a (possibly compressed) domain name.

    Returns (name, offset just past the name in the original position).
    Raises ValueError on malformed input.
    """
    labels: list[str] = []
    n = len(data)
    end = -1
    hops = 0
    total = 0
    while True:
        if off >= n:
            raise ValueError("name runs past message")
        length = data[off]
        if length == 0:
            off += 1
            break
        kind = length & 0xC0
        if kind == 0xC0:
            if off + 1 >= n:
                raise ValueError("truncated compression pointer")
            hops += 1
            if hops > MAX_POINTER_HOPS:
                raise ValueError("compression pointer loop")
            if end < 0:
                end = off + 2
            off = ((length & 0x3F) << 8) | data[off + 1]
            continue
        if kind:
            raise ValueError("unsupported label type")
        off += 1
        if off + length > n:
            raise ValueError("label runs past message")
        total += length + 1
        if total > MAX_NAME_LEN:
            raise ValueError("name too long")
        labels.append(_label(data[off:off + length]))
        off += length
    return ".".join(labels), (end if end >= 0 else off)


class DnsMessage:
    __slots__ = ("txid", "is_response", "opcode", "rcode", "flags", "questions",
                 "answers", "ancount", "nscount", "arcount", "truncated", "size")

    def __init__(self):
        self.questions: list[tuple[str, str]] = []
        self.answers: list[tuple[str, str, int, str]] = []
        self.truncated = False

    @property
    def qname(self) -> str:
        return self.questions[0][0] if self.questions else ""

    @property
    def qtype(self) -> str:
        return self.questions[0][1] if self.questions else ""

    @property
    def rcode_name(self) -> str:
        return RCODES.get(self.rcode) or f"RCODE{self.rcode}"


def qtype_name(t: int) -> str:
    return QTYPES.get(t) or f"TYPE{t}"


def parse_dns(data: bytes) -> DnsMessage | None:
    """Parse a DNS message; return None when the bytes are not plausible DNS."""
    n = len(data)
    if n < 12:
        return None
    txid, flags, qd, an, ns, ar = _HDR.unpack_from(data, 0)
    opcode = (flags >> 11) & 0xF
    if opcode > 5 or qd > 8 or (qd == 0 and an == 0 and ns == 0 and ar == 0):
        return None
    msg = DnsMessage()
    msg.txid = txid
    msg.flags = flags
    msg.is_response = bool(flags & 0x8000)
    msg.opcode = opcode
    msg.rcode = flags & 0xF
    msg.ancount, msg.nscount, msg.arcount = an, ns, ar
    msg.size = n
    off = 12
    try:
        for _ in range(qd):
            name, off = read_name(data, off)
            if off + 4 > n:
                return None
            qtype, _qclass = struct.unpack_from("!HH", data, off)
            off += 4
            msg.questions.append((name, qtype_name(qtype)))
    except ValueError:
        return None
    # Answer section: tolerate damage, keep what parsed cleanly.
    try:
        for _ in range(min(an, MAX_ANSWERS)):
            name, off = read_name(data, off)
            if off + 10 > n:
                raise ValueError("truncated RR")
            rtype, _rclass, ttl, rdlen = _RR.unpack_from(data, off)
            off += 10
            if off + rdlen > n:
                raise ValueError("truncated RDATA")
            msg.answers.append((name, qtype_name(rtype), ttl,
                                _rdata(data, off, rdlen, rtype)))
            off += rdlen
    except ValueError:
        msg.truncated = True
    return msg


def _rdata(data: bytes, off: int, rdlen: int, rtype: int) -> str:
    try:
        if rtype == 1 and rdlen == 4:
            return socket.inet_ntoa(data[off:off + 4])
        if rtype == 28 and rdlen == 16:
            return socket.inet_ntop(socket.AF_INET6, data[off:off + 16])
        if rtype in (2, 5, 12):
            return read_name(data, off)[0]
        if rtype == 15 and rdlen >= 3:
            return read_name(data, off + 2)[0]
        if rtype == 33 and rdlen >= 7:
            port = (data[off + 4] << 8) | data[off + 5]
            return f"{read_name(data, off + 6)[0]}:{port}"
        if rtype == 6:
            return read_name(data, off)[0]
        if rtype == 16:
            parts = []
            pos, end = off, off + rdlen
            while pos < end and len(parts) < 4:
                ln = data[pos]
                parts.append(_label(data[pos + 1:min(pos + 1 + ln, end)]))
                pos += 1 + ln
            return " ".join(parts)[:200]
    except (ValueError, IndexError):
        pass
    return f"<{rdlen} bytes>"
