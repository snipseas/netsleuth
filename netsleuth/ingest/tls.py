"""TLS handshake metadata extraction (ClientHello / ServerHello).

No decryption is attempted. The parser extracts what is visible in clear text:
versions, cipher suites, SNI, ALPN and the JA3 / JA3S fingerprints.
"""

from __future__ import annotations

import hashlib
import struct

NEED_MORE = "need_more"
INVALID = "invalid"

VERSIONS = {
    0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1",
    0x0303: "TLS 1.2", 0x0304: "TLS 1.3",
}
CIPHERS = {
    0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0xC02B: "ECDHE-ECDSA-AES128-GCM-SHA256", 0xC02C: "ECDHE-ECDSA-AES256-GCM-SHA384",
    0xC02F: "ECDHE-RSA-AES128-GCM-SHA256", 0xC030: "ECDHE-RSA-AES256-GCM-SHA384",
    0xCCA8: "ECDHE-RSA-CHACHA20-POLY1305", 0xCCA9: "ECDHE-ECDSA-CHACHA20-POLY1305",
    0xC013: "ECDHE-RSA-AES128-SHA", 0xC014: "ECDHE-RSA-AES256-SHA",
    0x009C: "RSA-AES128-GCM-SHA256", 0x009D: "RSA-AES256-GCM-SHA384",
    0x002F: "RSA-AES128-SHA", 0x0035: "RSA-AES256-SHA", 0x000A: "RSA-3DES-EDE-SHA",
    0x0005: "RSA-RC4-128-SHA", 0x0004: "RSA-RC4-128-MD5",
}

MAX_RECORD = 16_384 + 2_048
MAX_HANDSHAKE = 65_536


def version_name(v: int | None) -> str:
    if v is None:
        return ""
    return VERSIONS.get(v) or f"0x{v:04x}"


def cipher_name(c: int | None) -> str:
    if c is None:
        return ""
    return CIPHERS.get(c) or f"0x{c:04x}"


def _is_grease(v: int) -> bool:
    return (v & 0x0F0F) == 0x0A0A and (v >> 8) == (v & 0xFF)


def looks_like_tls(buf) -> bool | None:
    """True/False once decidable, None while more bytes are needed."""
    if len(buf) < 3:
        return None if (not buf or buf[0] == 0x16) else False
    return buf[0] == 0x16 and buf[1] == 0x03 and buf[2] <= 0x04


def extract_handshake(buf):
    """Reassemble the first handshake message from a TLS record stream.

    Returns (hs_type, body) on success, or NEED_MORE / INVALID.
    """
    pos = 0
    n = len(buf)
    hs = bytearray()
    while True:
        if len(hs) >= 4:
            hlen = (hs[1] << 16) | (hs[2] << 8) | hs[3]
            if hlen > MAX_HANDSHAKE:
                return INVALID
            if len(hs) >= 4 + hlen:
                return hs[0], bytes(hs[4:4 + hlen])
        if pos + 5 > n:
            return NEED_MORE
        ctype, major, _minor, rlen = buf[pos], buf[pos + 1], buf[pos + 2], (buf[pos + 3] << 8) | buf[pos + 4]
        if ctype != 0x16 or major != 0x03 or rlen == 0 or rlen > MAX_RECORD:
            return INVALID
        if pos + 5 + rlen > n:
            return NEED_MORE
        hs += buf[pos + 5:pos + 5 + rlen]
        pos += 5 + rlen


def _u16_list(data: bytes) -> list[int]:
    return [(data[i] << 8) | data[i + 1] for i in range(0, len(data) - 1, 2)]


def parse_client_hello(body: bytes) -> dict | None:
    try:
        return _client_hello(body)
    except (IndexError, struct.error, ValueError):
        return None


def _client_hello(b: bytes) -> dict | None:
    n = len(b)
    if n < 38:
        return None
    version = (b[0] << 8) | b[1]
    pos = 34
    pos += 1 + b[pos]                         # session id
    clen = (b[pos] << 8) | b[pos + 1]
    pos += 2
    if pos + clen > n:
        return None
    ciphers = _u16_list(b[pos:pos + clen])
    pos += clen
    pos += 1 + b[pos]                         # compression methods
    exts: list[int] = []
    curves: list[int] = []
    point_formats: list[int] = []
    sni = ""
    alpn: list[str] = []
    supported: list[int] = []
    if pos + 2 <= n:
        elen = (b[pos] << 8) | b[pos + 1]
        pos += 2
        end = min(pos + elen, n)
        while pos + 4 <= end:
            etype = (b[pos] << 8) | b[pos + 1]
            ln = (b[pos + 2] << 8) | b[pos + 3]
            pos += 4
            if pos + ln > end:
                break
            data = b[pos:pos + ln]
            pos += ln
            exts.append(etype)
            if etype == 0 and ln >= 5:        # server_name
                nlen = (data[3] << 8) | data[4]
                if data[2] == 0:
                    raw = data[5:5 + nlen]
                    sni = "".join(chr(c) if 0x20 < c < 0x7F else f"\\x{c:02x}"
                                  for c in raw[:255])
            elif etype == 10 and ln >= 2:     # supported_groups
                curves = _u16_list(data[2:])
            elif etype == 11 and ln >= 1:     # ec_point_formats
                point_formats = list(data[1:1 + data[0]])
            elif etype == 16 and ln >= 2:     # ALPN
                p = 2
                while p < ln and len(alpn) < 8:
                    l2 = data[p]
                    alpn.append(data[p + 1:p + 1 + l2].decode("ascii", "replace")[:32])
                    p += 1 + l2
            elif etype == 43 and ln >= 1:     # supported_versions
                supported = [v for v in _u16_list(data[1:1 + data[0]]) if not _is_grease(v)]
    ja3_str = ",".join((
        str(version),
        "-".join(str(c) for c in ciphers if not _is_grease(c)),
        "-".join(str(e) for e in exts if not _is_grease(e)),
        "-".join(str(c) for c in curves if not _is_grease(c)),
        "-".join(str(p) for p in point_formats),
    ))
    return {
        "version": version,
        "max_version": max(supported) if supported else version,
        "ciphers": len(ciphers),
        "sni": sni,
        "alpn": alpn,
        "ja3": hashlib.md5(ja3_str.encode()).hexdigest(),
        "ja3_string": ja3_str,
    }


def parse_server_hello(body: bytes) -> dict | None:
    try:
        return _server_hello(body)
    except (IndexError, struct.error, ValueError):
        return None


def _server_hello(b: bytes) -> dict | None:
    n = len(b)
    if n < 38:
        return None
    version = (b[0] << 8) | b[1]
    pos = 34
    pos += 1 + b[pos]
    cipher = (b[pos] << 8) | b[pos + 1]
    pos += 3                                  # cipher + compression method
    exts: list[int] = []
    selected = version
    alpn = ""
    if pos + 2 <= n:
        elen = (b[pos] << 8) | b[pos + 1]
        pos += 2
        end = min(pos + elen, n)
        while pos + 4 <= end:
            etype = (b[pos] << 8) | b[pos + 1]
            ln = (b[pos + 2] << 8) | b[pos + 3]
            pos += 4
            if pos + ln > end:
                break
            data = b[pos:pos + ln]
            pos += ln
            exts.append(etype)
            if etype == 43 and ln == 2:
                selected = (data[0] << 8) | data[1]
            elif etype == 16 and ln >= 4:
                alpn = data[3:3 + data[2]].decode("ascii", "replace")[:32]
    ja3s_str = f"{version},{cipher},{'-'.join(str(e) for e in exts if not _is_grease(e))}"
    return {
        "version": selected,
        "cipher": cipher,
        "alpn": alpn,
        "ja3s": hashlib.md5(ja3s_str.encode()).hexdigest(),
    }
