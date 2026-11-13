import hashlib
import random
import struct
from collections import deque

import pytest

from netsleuth.analysis.flows import Stream
from netsleuth.devtools import pcapgen as g
from netsleuth.ingest import tls
from netsleuth.ingest.dns import parse_dns, read_name
from netsleuth.ingest.http import HttpDirection, looks_like_request


# ------------------------------------------------------------------ DNS ---
def test_dns_query_and_compressed_response():
    q = parse_dns(g.dns_query(0x1234, "www.example.com", "A"))
    assert (q.txid, q.is_response, q.qname, q.qtype) == (0x1234, False, "www.example.com", "A")
    r = parse_dns(g.dns_response(0x1234, "www.example.com", "A",
                                 [("CNAME", "web.example.com"), ("A", "203.0.113.10"),
                                  ("AAAA", "2001:db8::1"), ("TXT", "hello world")]))
    assert r.is_response and r.rcode_name == "NOERROR"
    assert [(a[0], a[1], a[3]) for a in r.answers] == [
        ("www.example.com", "CNAME", "web.example.com"), ("www.example.com", "A", "203.0.113.10"),
        ("www.example.com", "AAAA", "2001:db8::1"), ("www.example.com", "TXT", "hello\\x20world")]
    assert parse_dns(g.dns_response(1, "x.example", "A", rcode=3)).rcode_name == "NXDOMAIN"


def test_dns_pointer_loop_and_bounds():
    loop = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\xc0\x0c\x00\x01\x00\x01"
    assert parse_dns(loop) is None
    with pytest.raises(ValueError):
        read_name(b"\x00" * 12 + b"\xc0\x0c", 12)
    with pytest.raises(ValueError):
        read_name(b"\x3fabc", 0)                       # label runs past the message
    long_name = b"".join(b"\x3f" + b"a" * 63 for _ in range(5)) + b"\x00"
    with pytest.raises(ValueError):
        read_name(long_name, 0)                        # exceeds 255 octets
    assert parse_dns(b"") is None and parse_dns(b"\x00" * 11) is None


def test_dns_hostile_label_bytes_are_escaped():
    msg = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\x0b<script>\x00\n." + b"\x03com\x00" + b"\x00\x01\x00\x01"
    q = parse_dns(msg)
    assert "<" not in q.qname and "\n" not in q.qname and "\\x3c" in q.qname


def test_dns_truncated_answers_keep_question():
    full = g.dns_response(7, "a.example.com", "A", [("A", "1.2.3.4"), ("A", "5.6.7.8")])
    msg = parse_dns(full[:-3])
    assert msg.qname == "a.example.com" and msg.truncated and len(msg.answers) == 1


def test_dns_parser_never_raises_on_garbage():
    rnd = random.Random(5)
    base = g.dns_response(7, "a.b.example.com", "TXT", [("TXT", "x" * 40), ("CNAME", "c.example.com")])
    for _ in range(5000):
        b = bytearray(base)
        for _ in range(rnd.randint(1, 5)):
            b[rnd.randrange(len(b))] = rnd.getrandbits(8)
        parse_dns(bytes(b[:rnd.randint(0, len(b))]))


# ------------------------------------------------------------------ TLS ---
def test_client_hello_fields_and_ja3():
    rec = g.tls_client_hello("secure.example.com", grease=True, seed=3)
    hs_type, body = tls.extract_handshake(rec)
    ch = tls.parse_client_hello(body)
    assert hs_type == 1 and ch["sni"] == "secure.example.com"
    assert ch["alpn"] == ["h2", "http/1.1"] and ch["max_version"] == 0x0304
    # JA3 computed by hand from the generator's parameters; GREASE excluded
    expected = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392,0-23-65281-10-11-16-13-43-51,29-23-24,0"
    assert ch["ja3_string"] == expected
    assert ch["ja3"] == hashlib.md5(expected.encode()).hexdigest()
    # GREASE must not change the fingerprint
    plain = tls.parse_client_hello(tls.extract_handshake(g.tls_client_hello("secure.example.com", seed=3))[1])
    assert plain["ja3"] == ch["ja3"]


def test_server_hello_and_missing_sni():
    hs_type, body = tls.extract_handshake(g.tls_server_hello(cipher=0x1302, tls13=True))
    sh = tls.parse_server_hello(body)
    assert hs_type == 2 and tls.version_name(sh["version"]) == "TLS 1.3"
    assert tls.cipher_name(sh["cipher"]) == "TLS_AES_256_GCM_SHA384"
    sh12 = tls.parse_server_hello(tls.extract_handshake(g.tls_server_hello(cipher=0xC02F, tls13=False))[1])
    assert tls.version_name(sh12["version"]) == "TLS 1.2"
    ch = tls.parse_client_hello(tls.extract_handshake(g.tls_client_hello(None))[1])
    assert ch["sni"] == ""


def test_tls_incremental_and_invalid():
    rec = g.tls_client_hello("a.example.com")
    for cut in (0, 3, 5, 40, len(rec) - 1):
        assert tls.extract_handshake(rec[:cut]) == tls.NEED_MORE
    assert tls.extract_handshake(b"GET / HTTP/1.1\r\n") == tls.INVALID
    assert tls.extract_handshake(b"\x16\x03\x01\xff\xff" + b"\x00" * 10) == tls.INVALID
    assert tls.looks_like_tls(b"\x16\x03\x01") and tls.looks_like_tls(b"GET") is False
    rnd = random.Random(9)
    for _ in range(3000):
        b = bytearray(rec)
        for _ in range(rnd.randint(1, 6)):
            b[rnd.randrange(len(b))] = rnd.getrandbits(8)
        res = tls.extract_handshake(bytes(b))
        if isinstance(res, tuple):
            tls.parse_client_hello(res[1])
            tls.parse_server_hello(res[1])


# ----------------------------------------------------------- reassembly ---
def test_stream_reassembly_reorder_overlap_retransmit():
    data = bytes(range(256)) * 4
    segs = [(1000 + i, data[i:i + 100]) for i in range(0, len(data), 100)]
    rnd = random.Random(3)
    for _ in range(50):
        order = segs[:] + rnd.sample(segs, 4)             # duplicates = retransmissions
        rnd.shuffle(order)
        order.append((1000 + 50, data[50:230]))           # overlapping segment
        s = Stream(1000)
        for seq, chunk in order:
            s.add(seq, chunk)
        assert bytes(s.buf) == data
    s = Stream(0xFFFFFFF0)                                # sequence wrap-around
    s.add(0xFFFFFFF0, b"a" * 16)
    assert s.add(0, b"b" * 4) and bytes(s.buf) == b"a" * 16 + b"b" * 4
    assert not s.add(0xFFFFFF00, b"old")                  # before stream start


def test_stream_skip_and_bounds():
    s = Stream(0)
    s.add(0, b"HEAD")
    s.skip_ahead(10)                                      # 4 buffered + 6 to come
    s.add(4, b"123456TAIL")
    assert bytes(s.buf) == b"TAIL"
    s = Stream(0)
    for i in range(1, 500):                               # only gaps: pending must stay bounded
        s.add(i * 10, b"x")
    assert len(s.pending) <= Stream.MAX_PENDING
    assert not s.add(5_000_000, b"far")                   # beyond the gap window: ignored


# ----------------------------------------------------------------- HTTP ---
def feed_all(direction, payload, methods=None, step=None):
    s = Stream(0)
    methods = deque() if methods is None else methods
    out = []
    step = step or len(payload)
    for i in range(0, len(payload), step):
        s.add(i, payload[i:i + step])
        out += direction.feed(s, methods)
    return out, methods


def test_http_keepalive_pipeline_with_bodies():
    reqs = (b"POST /a HTTP/1.1\r\nHost: h.example\r\nContent-Length: 5\r\nUser-Agent: t/1\r\n\r\nhello"
            b"GET /b?x=1 HTTP/1.1\r\nHost: h.example\r\nAuthorization: Basic c2VjcmV0\r\n\r\n"
            b"HEAD /c HTTP/1.1\r\nHost: h.example\r\n\r\n")
    for step in (None, 1, 7, 64):
        msgs, methods = feed_all(HttpDirection(True), reqs, step=step)
        assert [(m["method"], m["uri"]) for m in msgs] == [("POST", "/a"), ("GET", "/b?x=1"), ("HEAD", "/c")]
        assert msgs[0]["content_length"] == 5 and msgs[0]["user_agent"] == "t/1"
        assert msgs[1]["auth_scheme"] == "Basic" and "c2VjcmV0" not in str(msgs[1])
        resp = (b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc"
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nwxyz\r\n3;ext=1\r\nabc\r\n0\r\n\r\n"
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 999\r\n\r\n")
        rmsgs, _ = feed_all(HttpDirection(False), resp, methods=methods, step=step)
        assert [m["status"] for m in rmsgs] == [200, 200, 404]
        assert rmsgs[2]["request_method"] == "HEAD"


def test_http_rejects_non_http_and_oversized_heads():
    d = HttpDirection(True)
    msgs, _ = feed_all(d, b"NOTHTTP garbage\r\n\r\n")
    assert msgs == [] and d.done
    d = HttpDirection(True)
    msgs, _ = feed_all(d, b"GET / HTTP/1.1\r\nX: " + b"a" * 40000, step=1000)
    assert msgs == [] and d.done
    assert looks_like_request(b"GET / HTTP/1.1") is True
    assert looks_like_request(b"\x16\x03\x01\x02\x00") is False
    assert looks_like_request(b"GE") is None


def test_http_control_characters_are_neutralised():
    msgs, _ = feed_all(HttpDirection(True), b"GET /a\x1b[31m HTTP/1.1\r\nHost: evil\x00host\r\n\r\n")
    assert "\x1b" not in msgs[0]["uri"] and "\x00" not in msgs[0]["host"]


def test_http_request_target_with_spaces_is_kept():
    msgs, _ = feed_all(HttpDirection(True), b'GET /a b"><x> HTTP/1.1\r\nHost: h\r\n\r\n')
    assert msgs[0]["uri"] == '/a b"><x>' and msgs[0]["version"] == "HTTP/1.1"
