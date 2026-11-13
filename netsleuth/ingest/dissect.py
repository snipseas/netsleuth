"""Verbose single-packet dissection for the packet detail view.

Unlike `decode_packet` (the hot path) this builds a layer-by-layer field
tree. It is only ever run for one packet at a time, on demand.
"""

from __future__ import annotations

import struct

from . import tls as tlsmod
from .decode import (ETHERTYPE_NAMES, IP_PROTO_NAMES, LINKTYPE_NAMES, flags_str,
                     ip4_str, ip6_str, mac_str)
from .dns import parse_dns
from .http import parse_request_head, parse_response_head

MAX_HEX_BYTES = 4096


def _layer(name: str, summary: str, fields: list) -> dict:
    return {"name": name, "summary": summary,
            "fields": [{"name": k, "value": str(v)} for k, v in fields]}


def dissect(data: bytes, linktype: int) -> list[dict]:
    layers: list[dict] = []
    try:
        _link(data, linktype, layers)
    except (struct.error, IndexError, ValueError):
        layers.append(_layer("Malformed", "packet could not be fully dissected", []))
    return layers


def _link(data: bytes, linktype: int, layers: list) -> None:
    if linktype == 1:
        if len(data) < 14:
            layers.append(_layer("Ethernet", "truncated", []))
            return
        dst, src, etype = struct.unpack_from("!6s6sH", data, 0)
        fields = [("Destination", mac_str(dst)), ("Source", mac_str(src))]
        off = 14
        while etype in (0x8100, 0x88A8, 0x9100) and len(data) >= off + 4:
            tci, etype = struct.unpack_from("!HH", data, off)
            fields.append(("VLAN ID", tci & 0x0FFF))
            fields.append(("VLAN priority", tci >> 13))
            off += 4
        fields.append(("EtherType", f"0x{etype:04x} ({ETHERTYPE_NAMES.get(etype, 'unknown')})"))
        layers.append(_layer("Ethernet", f"{mac_str(src)} → {mac_str(dst)}", fields))
        _ether_payload(data, off, etype, layers)
    elif linktype == 113 and len(data) >= 16:
        etype = (data[14] << 8) | data[15]
        layers.append(_layer("Linux cooked capture", "SLL v1",
                             [("Packet type", (data[0] << 8) | data[1]),
                              ("Protocol", f"0x{etype:04x}")]))
        _ether_payload(data, 16, etype, layers)
    elif linktype == 276 and len(data) >= 20:
        etype = (data[0] << 8) | data[1]
        layers.append(_layer("Linux cooked capture", "SLL v2", [("Protocol", f"0x{etype:04x}")]))
        _ether_payload(data, 20, etype, layers)
    elif linktype in (101, 12, 228, 229):
        _ip_auto(data, 0, layers)
    elif linktype in (0, 108) and len(data) >= 4:
        layers.append(_layer("Loopback", "null/loopback header", []))
        _ip_auto(data, 4, layers)
    else:
        layers.append(_layer(LINKTYPE_NAMES.get(linktype, f"Link type {linktype}"),
                             "unsupported link layer - not decoded", []))


def _ip_auto(data, off, layers):
    if len(data) > off:
        v = data[off] >> 4
        if v == 4:
            _ipv4(data, off, layers)
        elif v == 6:
            _ipv6(data, off, layers)


def _ether_payload(data, off, etype, layers):
    if etype == 0x0800:
        _ipv4(data, off, layers)
    elif etype == 0x86DD:
        _ipv6(data, off, layers)
    elif etype == 0x0806 and len(data) >= off + 28:
        _h, _p, _hl, _pl, op, sha, spa, tha, tpa = struct.unpack_from("!HHBBH6s4s6s4s", data, off)
        layers.append(_layer("ARP", {1: "request", 2: "reply"}.get(op, f"opcode {op}"), [
            ("Opcode", op), ("Sender MAC", mac_str(sha)), ("Sender IP", ip4_str(spa)),
            ("Target MAC", mac_str(tha)), ("Target IP", ip4_str(tpa))]))


def _ipv4(data, off, layers):
    if len(data) < off + 20:
        layers.append(_layer("IPv4", "truncated header", []))
        return
    vhl, tos, total, ident, frag, ttl, proto, csum, src, dst = struct.unpack_from(
        "!BBHHHBBH4s4s", data, off)
    ihl = (vhl & 0xF) * 4
    flags = []
    if frag & 0x4000: flags.append("DF")
    if frag & 0x2000: flags.append("MF")
    layers.append(_layer("IPv4", f"{ip4_str(src)} → {ip4_str(dst)}", [
        ("Source", ip4_str(src)), ("Destination", ip4_str(dst)),
        ("Header length", f"{ihl} bytes"), ("Total length", total),
        ("DSCP/ECN", f"0x{tos:02x}"), ("Identification", f"0x{ident:04x}"),
        ("Flags", ", ".join(flags) or "none"), ("Fragment offset", (frag & 0x1FFF) * 8),
        ("TTL", ttl), ("Protocol", f"{proto} ({IP_PROTO_NAMES.get(proto, 'unknown')})"),
        ("Header checksum", f"0x{csum:04x}")]))
    if ihl < 20 or frag & 0x1FFF:
        return
    end = off + total if ihl <= total <= len(data) - off else len(data)
    _transport(data, off + ihl, end, proto, layers)


def _ipv6(data, off, layers):
    if len(data) < off + 40:
        layers.append(_layer("IPv6", "truncated header", []))
        return
    vtf, plen, nxt, hlim, src, dst = struct.unpack_from("!IHBB16s16s", data, off)
    fields = [("Source", ip6_str(src)), ("Destination", ip6_str(dst)),
              ("Payload length", plen), ("Hop limit", hlim),
              ("Traffic class", (vtf >> 20) & 0xFF), ("Flow label", f"0x{vtf & 0xFFFFF:05x}")]
    pos = off + 40
    end = pos + plen if 0 < plen <= len(data) - pos else len(data)
    for _ in range(8):
        if nxt in (0, 43, 60) and end >= pos + 8:
            fields.append(("Extension header", {0: "Hop-by-hop", 43: "Routing", 60: "Destination options"}[nxt]))
            nxt, pos = data[pos], pos + (data[pos + 1] + 1) * 8
        elif nxt == 44 and end >= pos + 8:
            fields.append(("Extension header", "Fragment"))
            fragoff = ((data[pos + 2] << 8) | data[pos + 3]) >> 3
            nxt, pos = data[pos], pos + 8
            if fragoff:
                nxt = -1
                break
        else:
            break
    fields.append(("Next header", f"{nxt} ({IP_PROTO_NAMES.get(nxt, 'unknown')})"))
    layers.append(_layer("IPv6", f"{ip6_str(src)} → {ip6_str(dst)}", fields))
    if nxt >= 0 and pos <= end:
        _transport(data, pos, end, nxt, layers)


def _tcp_options(opts: bytes) -> str:
    out, i = [], 0
    while i < len(opts) and len(out) < 12:
        kind = opts[i]
        if kind == 0:
            break
        if kind == 1:
            i += 1
            continue
        if i + 1 >= len(opts) or opts[i + 1] < 2:
            break
        ln = opts[i + 1]
        val = opts[i + 2:i + ln]
        if kind == 2 and len(val) == 2:
            out.append(f"MSS={int.from_bytes(val, 'big')}")
        elif kind == 3 and len(val) == 1:
            out.append(f"WScale={val[0]}")
        elif kind == 4:
            out.append("SACK permitted")
        elif kind == 5:
            out.append("SACK")
        elif kind == 8 and len(val) == 8:
            out.append(f"TSval={int.from_bytes(val[:4], 'big')}")
        else:
            out.append(f"kind {kind}")
        i += ln
    return ", ".join(out) or "none"


def _transport(data, off, end, proto, layers):
    if proto == 6:
        if end < off + 20:
            layers.append(_layer("TCP", "truncated header", []))
            return
        sport, dport, seq, ack, offflags, win, csum, urg = struct.unpack_from("!HHIIHHHH", data, off)
        hlen = (offflags >> 12) * 4
        flags = offflags & 0xFF
        payload = data[off + hlen:end] if 20 <= hlen <= end - off else b""
        layers.append(_layer("TCP", f"{sport} → {dport} [{flags_str(flags)}]", [
            ("Source port", sport), ("Destination port", dport),
            ("Sequence number (raw)", seq), ("Acknowledgment number (raw)", ack),
            ("Header length", f"{hlen} bytes"), ("Flags", f"0x{flags:02x} ({flags_str(flags)})"),
            ("Window", win), ("Checksum", f"0x{csum:04x}"), ("Urgent pointer", urg),
            ("Options", _tcp_options(data[off + 20:off + hlen]) if hlen > 20 else "none"),
            ("Payload length", len(payload))]))
        _application(payload, sport, dport, True, layers)
    elif proto == 17:
        if end < off + 8:
            layers.append(_layer("UDP", "truncated header", []))
            return
        sport, dport, ulen, csum = struct.unpack_from("!HHHH", data, off)
        payload = data[off + 8:min(end, off + ulen) if ulen >= 8 else end]
        layers.append(_layer("UDP", f"{sport} → {dport}", [
            ("Source port", sport), ("Destination port", dport), ("Length", ulen),
            ("Checksum", f"0x{csum:04x}"), ("Payload length", len(payload))]))
        _application(payload, sport, dport, False, layers)
    elif proto in (1, 58) and end >= off + 4:
        layers.append(_layer("ICMP" if proto == 1 else "ICMPv6",
                             f"type {data[off]}, code {data[off + 1]}", [
            ("Type", data[off]), ("Code", data[off + 1]),
            ("Checksum", f"0x{(data[off + 2] << 8) | data[off + 3]:04x}")]))


def _application(payload: bytes, sport: int, dport: int, tcp: bool, layers: list) -> None:
    if not payload:
        return
    ports = (sport, dport)
    if 53 in ports or 5353 in ports or 5355 in ports:
        body = payload[2:] if tcp and len(payload) > 14 else payload
        msg = parse_dns(body)
        if msg is not None:
            fields = [("Transaction ID", f"0x{msg.txid:04x}"),
                      ("Type", "response" if msg.is_response else "query"),
                      ("Opcode", msg.opcode)]
            if msg.is_response:
                fields.append(("Response code", msg.rcode_name))
            for name, qtype in msg.questions:
                fields.append(("Question", f"{qtype} {name or '<root>'}"))
            for name, rtype, ttl, rdata in msg.answers:
                fields.append(("Answer", f"{name} {rtype} ttl={ttl} {rdata}"))
            layers.append(_layer("DNS", f"{'response' if msg.is_response else 'query'} {msg.qname}", fields))
            return
    if tcp:
        head_end = payload.find(b"\r\n\r\n")
        head = payload[:head_end if head_end >= 0 else min(len(payload), 4096)]
        if payload[:5] == b"HTTP/":
            m = parse_response_head(head)
            if m:
                layers.append(_layer("HTTP", f"response {m['status']}", [
                    ("Status", m["status"]), ("Version", m["version"]), ("Server", m["server"]),
                    ("Content-Type", m["content_type"]), ("Content-Length", m["content_length"])]))
                return
        m = parse_request_head(head) if head_end >= 0 else None
        if m:
            layers.append(_layer("HTTP", f"{m['method']} {m['uri'][:80]}", [
                ("Method", m["method"]), ("URI", m["uri"]), ("Version", m["version"]),
                ("Host", m["host"]), ("User-Agent", m["user_agent"]), ("Referer", m["referer"]),
                ("Content-Type", m["content_type"]), ("Content-Length", m["content_length"]),
                ("Authorization scheme", m["auth_scheme"] or "none")]))
            return
        if tlsmod.looks_like_tls(payload) or (len(payload) >= 5 and payload[0] in (0x14, 0x15, 0x17) and payload[1] == 3):
            names = {0x14: "Change Cipher Spec", 0x15: "Alert", 0x16: "Handshake", 0x17: "Application Data"}
            fields = [("Record type", names.get(payload[0], payload[0])),
                      ("Record version", tlsmod.version_name((payload[1] << 8) | payload[2])),
                      ("Record length", (payload[3] << 8) | payload[4])]
            summary = names.get(payload[0], "record")
            if payload[0] == 0x16:
                res = tlsmod.extract_handshake(payload)
                if isinstance(res, tuple):
                    hs_type, body = res
                    if hs_type == 1:
                        ch = tlsmod.parse_client_hello(body)
                        if ch:
                            summary = "Client Hello"
                            fields += [("Handshake", "Client Hello"), ("SNI", ch["sni"] or "<none>"),
                                       ("Max version offered", tlsmod.version_name(ch["max_version"])),
                                       ("Cipher suites offered", ch["ciphers"]),
                                       ("ALPN", ", ".join(ch["alpn"]) or "<none>"),
                                       ("JA3", ch["ja3"]), ("JA3 string", ch["ja3_string"])]
                    elif hs_type == 2:
                        sh = tlsmod.parse_server_hello(body)
                        if sh:
                            summary = "Server Hello"
                            fields += [("Handshake", "Server Hello"),
                                       ("Version", tlsmod.version_name(sh["version"])),
                                       ("Cipher suite", tlsmod.cipher_name(sh["cipher"])),
                                       ("JA3S", sh["ja3s"])]
            layers.append(_layer("TLS", summary, fields))
            return
    layers.append(_layer("Payload", f"{len(payload)} bytes", [("Length", len(payload))]))


def hexdump(data: bytes) -> dict:
    """Hex + ASCII rows for display; long packets are truncated."""
    shown = data[:MAX_HEX_BYTES]
    rows = []
    for i in range(0, len(shown), 16):
        chunk = shown[i:i + 16]
        rows.append({
            "offset": f"{i:04x}",
            "hex": " ".join(f"{b:02x}" for b in chunk),
            "ascii": "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk),
        })
    return {"rows": rows, "bytes": len(data), "truncated": len(data) > MAX_HEX_BYTES}
