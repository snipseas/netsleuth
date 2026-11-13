"""Link, network and transport layer decoding.

`decode_packet` is the hot path: it is called once per captured frame and
extracts only what the analysis stages need. It never raises on hostile
input; structural problems are reported through `Packet.malformed`.
"""

from __future__ import annotations

import socket
import struct

# TCP flag bits
FIN, SYN, RST, PSH, ACK, URG, ECE, CWR = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80

# link types (https://www.tcpdump.org/linktypes.html)
DLT_NULL = 0
DLT_EN10MB = 1
DLT_RAW_BSD = 12
DLT_RAW = 101
DLT_LOOP = 108
DLT_LINUX_SLL = 113
DLT_IPV4 = 228
DLT_IPV6 = 229
DLT_LINUX_SLL2 = 276

LINKTYPE_NAMES = {
    DLT_NULL: "BSD loopback", DLT_EN10MB: "Ethernet", DLT_RAW_BSD: "Raw IP",
    DLT_RAW: "Raw IP", DLT_LOOP: "OpenBSD loopback", DLT_LINUX_SLL: "Linux cooked v1",
    DLT_IPV4: "Raw IPv4", DLT_IPV6: "Raw IPv6", DLT_LINUX_SLL2: "Linux cooked v2",
    105: "IEEE 802.11", 127: "IEEE 802.11 radiotap",
}
SUPPORTED_LINKTYPES = frozenset(
    (DLT_NULL, DLT_EN10MB, DLT_RAW_BSD, DLT_RAW, DLT_LOOP, DLT_LINUX_SLL,
     DLT_IPV4, DLT_IPV6, DLT_LINUX_SLL2))

ETHERTYPE_NAMES = {
    0x0800: "IPv4", 0x86DD: "IPv6", 0x0806: "ARP", 0x8035: "RARP",
    0x88CC: "LLDP", 0x888E: "EAPOL", 0x8847: "MPLS", 0x8848: "MPLS",
    0x8863: "PPPoE-D", 0x8864: "PPPoE", 0x88E5: "MACsec", 0x9000: "LOOP",
}
IP_PROTO_NAMES = {
    1: "ICMP", 2: "IGMP", 4: "IPIP", 6: "TCP", 17: "UDP", 41: "IPv6-in-IP",
    47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6", 89: "OSPF", 103: "PIM",
    112: "VRRP", 132: "SCTP",
}

_ETH = struct.Struct("!6s6sH")
_IP4 = struct.Struct("!BBHHHBBH4s4s")
_IP6 = struct.Struct("!IHBB16s16s")
_TCP = struct.Struct("!HHIIHHHH")
_UDP = struct.Struct("!HHHH")
_ARP = struct.Struct("!HHBBH6s4s6s4s")

_inet_ntoa = socket.inet_ntoa
_inet_ntop = socket.inet_ntop
_AF_INET6 = socket.AF_INET6

_v4_cache: dict[bytes, str] = {}
_v6_cache: dict[bytes, str] = {}
_mac_cache: dict[bytes, str] = {}
_CACHE_MAX = 200_000


def ip4_str(raw: bytes) -> str:
    s = _v4_cache.get(raw)
    if s is None:
        if len(_v4_cache) >= _CACHE_MAX:
            _v4_cache.clear()
        s = _v4_cache[raw] = _inet_ntoa(raw)
    return s


def ip6_str(raw: bytes) -> str:
    s = _v6_cache.get(raw)
    if s is None:
        if len(_v6_cache) >= _CACHE_MAX:
            _v6_cache.clear()
        s = _v6_cache[raw] = _inet_ntop(_AF_INET6, raw)
    return s


def mac_str(raw: bytes) -> str:
    s = _mac_cache.get(raw)
    if s is None:
        if len(_mac_cache) >= _CACHE_MAX:
            _mac_cache.clear()
        s = _mac_cache[raw] = raw.hex(":")
    return s


class Packet:
    """Decoded view of one frame (layers 2-4)."""

    __slots__ = (
        "no", "ts", "caplen", "wirelen", "offset",
        "src_mac", "dst_mac", "vlan",
        "net", "src", "dst", "ttl", "ip_proto", "frag",
        "proto", "sport", "dport", "flags", "seq", "ack", "win",
        "payload", "icmp_type", "icmp_code", "arp_op", "arp_sha",
        "malformed", "info",
    )

    def __init__(self, no: int, ts: float, caplen: int, wirelen: int, offset: int):
        self.no = no
        self.ts = ts
        self.caplen = caplen
        self.wirelen = wirelen
        self.offset = offset
        self.src_mac = None
        self.dst_mac = None
        self.vlan = None
        self.net = None        # IPv4 / IPv6 / ARP / other ethertype name
        self.src = None
        self.dst = None
        self.ttl = None
        self.ip_proto = None
        self.frag = False      # non-first IP fragment: no transport header
        self.proto = None      # TCP / UDP / ICMP / ... highest decoded L3/L4
        self.sport = None
        self.dport = None
        self.flags = None
        self.seq = 0
        self.ack = 0
        self.win = 0
        self.payload = b""
        self.icmp_type = None
        self.icmp_code = None
        self.arp_op = None
        self.arp_sha = None
        self.malformed = None
        self.info = ""


def decode_packet(no: int, ts: float, data: bytes, wirelen: int,
                  linktype: int, offset: int = 0) -> Packet:
    pkt = Packet(no, ts, len(data), wirelen, offset)
    try:
        _decode_link(pkt, data, linktype)
    except (struct.error, IndexError, ValueError):
        # Safety net: the explicit length checks below should make this
        # unreachable, but a decoder must never take the pipeline down.
        pkt.malformed = pkt.malformed or "decode error"
    if pkt.proto is None:
        pkt.proto = pkt.net or "UNKNOWN"
    return pkt


def _decode_link(pkt: Packet, data: bytes, linktype: int) -> None:
    n = len(data)
    if linktype == DLT_EN10MB:
        if n < 14:
            pkt.malformed = "truncated Ethernet header"
            pkt.net = "Ethernet"
            return
        dst, src, etype = _ETH.unpack_from(data, 0)
        pkt.dst_mac = mac_str(dst)
        pkt.src_mac = mac_str(src)
        _decode_ethertype(pkt, data, 14, etype)
    elif linktype == DLT_LINUX_SLL:
        if n < 16:
            pkt.malformed = "truncated SLL header"
            pkt.net = "SLL"
            return
        alen = (data[4] << 8) | data[5]
        if alen == 6:
            pkt.src_mac = mac_str(data[6:12])
        _decode_ethertype(pkt, data, 16, (data[14] << 8) | data[15])
    elif linktype == DLT_LINUX_SLL2:
        if n < 20:
            pkt.malformed = "truncated SLL2 header"
            pkt.net = "SLL2"
            return
        if data[11] == 6:
            pkt.src_mac = mac_str(data[12:18])
        _decode_ethertype(pkt, data, 20, (data[0] << 8) | data[1])
    elif linktype in (DLT_RAW, DLT_RAW_BSD, DLT_IPV4, DLT_IPV6):
        _decode_ip_auto(pkt, data, 0)
    elif linktype in (DLT_NULL, DLT_LOOP):
        if n < 4:
            pkt.malformed = "truncated loopback header"
            pkt.net = "Loopback"
            return
        _decode_ip_auto(pkt, data, 4)
    else:
        pkt.net = "UNSUPPORTED-LINK"


def _decode_ip_auto(pkt: Packet, data: bytes, off: int) -> None:
    if len(data) <= off:
        pkt.malformed = "empty frame"
        pkt.net = "Raw"
        return
    version = data[off] >> 4
    if version == 4:
        _decode_ipv4(pkt, data, off)
    elif version == 6:
        _decode_ipv6(pkt, data, off)
    else:
        pkt.net = "Raw"
        pkt.malformed = f"unknown IP version {version}"


def _decode_ethertype(pkt: Packet, data: bytes, off: int, etype: int) -> None:
    n = len(data)
    # 802.1Q / 802.1ad / legacy QinQ tags, possibly stacked
    depth = 0
    while etype in (0x8100, 0x88A8, 0x9100) and depth < 4:
        if n < off + 4:
            pkt.malformed = "truncated VLAN tag"
            pkt.net = "VLAN"
            return
        if pkt.vlan is None:
            pkt.vlan = ((data[off] << 8) | data[off + 1]) & 0x0FFF
        etype = (data[off + 2] << 8) | data[off + 3]
        off += 4
        depth += 1
    if etype == 0x8864:  # PPPoE session
        if n < off + 8:
            pkt.malformed = "truncated PPPoE header"
            pkt.net = "PPPoE"
            return
        ppp = (data[off + 6] << 8) | data[off + 7]
        off += 8
        etype = 0x0800 if ppp == 0x0021 else 0x86DD if ppp == 0x0057 else -1
        if etype < 0:
            pkt.net = "PPPoE"
            return
    if etype == 0x0800:
        _decode_ipv4(pkt, data, off)
    elif etype == 0x86DD:
        _decode_ipv6(pkt, data, off)
    elif etype == 0x0806:
        _decode_arp(pkt, data, off)
    elif etype < 0x0600:
        pkt.net = "LLC"      # 802.3 length field: STP, CDP and friends
    else:
        pkt.net = ETHERTYPE_NAMES.get(etype) or f"ETH-0x{etype:04x}"


def _decode_arp(pkt: Packet, data: bytes, off: int) -> None:
    pkt.net = pkt.proto = "ARP"
    if len(data) < off + 28:
        pkt.malformed = "truncated ARP"
        return
    htype, ptype, hlen, plen, op, sha, spa, tha, tpa = _ARP.unpack_from(data, off)
    if hlen != 6 or plen != 4:
        return
    pkt.arp_op = op
    pkt.arp_sha = mac_str(sha)
    pkt.src = ip4_str(spa)
    pkt.dst = ip4_str(tpa)


def _decode_ipv4(pkt: Packet, data: bytes, off: int) -> None:
    pkt.net = "IPv4"
    n = len(data)
    if n < off + 20:
        pkt.malformed = "truncated IPv4 header"
        return
    vhl, _tos, total, _ident, fragfield, ttl, proto, _csum, src, dst = _IP4.unpack_from(data, off)
    ihl = (vhl & 0x0F) * 4
    if (vhl >> 4) != 4 or ihl < 20:
        pkt.malformed = "invalid IPv4 header"
        return
    pkt.src = ip4_str(src)
    pkt.dst = ip4_str(dst)
    pkt.ttl = ttl
    pkt.ip_proto = proto
    if n < off + ihl:
        pkt.malformed = "truncated IPv4 options"
        return
    # total length trims link-layer padding; a bogus value never extends
    # past what was actually captured
    end = off + total if ihl <= total <= n - off else n
    if fragfield & 0x1FFF:
        pkt.frag = True
        pkt.proto = IP_PROTO_NAMES.get(proto) or f"IP-{proto}"
        return
    _decode_transport(pkt, data, off + ihl, end, proto)


def _decode_ipv6(pkt: Packet, data: bytes, off: int) -> None:
    pkt.net = "IPv6"
    n = len(data)
    if n < off + 40:
        pkt.malformed = "truncated IPv6 header"
        return
    vtf, plen, nxt, hlim, src, dst = _IP6.unpack_from(data, off)
    if (vtf >> 28) != 6:
        pkt.malformed = "invalid IPv6 header"
        return
    pkt.src = ip6_str(src)
    pkt.dst = ip6_str(dst)
    pkt.ttl = hlim
    pos = off + 40
    end = pos + plen if 0 < plen <= n - pos else n
    # walk the extension header chain (bounded)
    for _ in range(8):
        if nxt in (0, 43, 60):          # hop-by-hop, routing, destination opts
            if end < pos + 8:
                pkt.malformed = "truncated IPv6 extension header"
                pkt.ip_proto = nxt
                return
            nxt, hlen = data[pos], (data[pos + 1] + 1) * 8
            pos += hlen
        elif nxt == 44:                 # fragment
            if end < pos + 8:
                pkt.malformed = "truncated IPv6 fragment header"
                pkt.ip_proto = nxt
                return
            fragoff = ((data[pos + 2] << 8) | data[pos + 3]) >> 3
            nxt = data[pos]
            pos += 8
            if fragoff:
                pkt.frag = True
                pkt.ip_proto = nxt
                pkt.proto = IP_PROTO_NAMES.get(nxt) or f"IP-{nxt}"
                return
        elif nxt == 51:                 # authentication header
            if end < pos + 8:
                pkt.malformed = "truncated IPv6 AH"
                pkt.ip_proto = nxt
                return
            nxt, hlen = data[pos], (data[pos + 1] + 2) * 4
            pos += hlen
        else:
            break
    pkt.ip_proto = nxt
    if pos > end:
        pkt.malformed = "IPv6 extension headers exceed packet"
        return
    _decode_transport(pkt, data, pos, end, nxt)


def _decode_transport(pkt: Packet, data: bytes, off: int, end: int, proto: int) -> None:
    if proto == 6:
        pkt.proto = "TCP"
        if end < off + 20:
            pkt.malformed = "truncated TCP header"
            return
        sport, dport, seq, ack, offflags, win, _csum, _urg = _TCP.unpack_from(data, off)
        hlen = (offflags >> 12) * 4
        pkt.sport = sport
        pkt.dport = dport
        pkt.seq = seq
        pkt.ack = ack
        pkt.flags = offflags & 0xFF
        pkt.win = win
        if hlen < 20 or off + hlen > end:
            pkt.malformed = "invalid TCP data offset"
            return
        pkt.payload = data[off + hlen:end]
    elif proto == 17:
        pkt.proto = "UDP"
        if end < off + 8:
            pkt.malformed = "truncated UDP header"
            return
        sport, dport, ulen, _csum = _UDP.unpack_from(data, off)
        pkt.sport = sport
        pkt.dport = dport
        if 8 <= ulen <= end - off:
            end = off + ulen
        pkt.payload = data[off + 8:end]
    elif proto == 1 or proto == 58:
        pkt.proto = "ICMP" if proto == 1 else "ICMPv6"
        if end < off + 4:
            pkt.malformed = "truncated ICMP header"
            return
        pkt.icmp_type = data[off]
        pkt.icmp_code = data[off + 1]
        pkt.payload = data[off + 4:end]
    else:
        pkt.proto = IP_PROTO_NAMES.get(proto) or f"IP-{proto}"


def flags_str(flags: int | None) -> str:
    if flags is None:
        return ""
    out = []
    if flags & SYN: out.append("SYN")
    if flags & FIN: out.append("FIN")
    if flags & RST: out.append("RST")
    if flags & PSH: out.append("PSH")
    if flags & ACK: out.append("ACK")
    if flags & URG: out.append("URG")
    if flags & ECE: out.append("ECE")
    if flags & CWR: out.append("CWR")
    return ", ".join(out) if out else "<none>"
