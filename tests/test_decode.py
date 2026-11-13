import random

from netsleuth.ingest.decode import ACK, SYN, SUPPORTED_LINKTYPES, decode_packet
from netsleuth.ingest.dissect import dissect, hexdump
from netsleuth.ingest.reader import CaptureReader
from netsleuth.devtools import pcapgen as g
from tests.conftest import fixture_path


def decode_file(name):
    with CaptureReader(fixture_path(name)) as r:
        return [decode_packet(p.no, p.ts, p.data, p.wirelen, p.linktype, p.offset) for p in r]


def test_basic_capture_layers():
    pkts = decode_file("basic.pcap")
    assert pkts[0].proto == "ARP" and pkts[0].arp_op == 1
    assert pkts[0].src == "192.168.1.10" and pkts[0].dst == "192.168.1.1"
    dns = pkts[2]
    assert (dns.net, dns.proto, dns.sport, dns.dport) == ("IPv4", "UDP", 40001, 53)
    syn = next(p for p in pkts if p.proto == "TCP")
    assert syn.flags == SYN and syn.dport == 80 and syn.ttl == 64 and syn.payload == b""
    synack = next(p for p in pkts if p.proto == "TCP" and p.flags == SYN | ACK)
    assert synack.src == "203.0.113.10" and synack.ack == syn.seq + 1
    assert any(p.proto == "ICMP" and p.icmp_type == 8 for p in pkts)
    assert all(p.malformed is None for p in pkts)
    assert all(p.src_mac and len(p.src_mac) == 17 for p in pkts)


def test_ipv6_and_vlan():
    pkts = decode_file("ipv6-vlan.pcapng")
    assert all(p.vlan == 42 and p.net == "IPv6" for p in pkts)
    assert pkts[0].src == "fd00::10" and pkts[0].dst == "fd00::1" and pkts[0].proto == "UDP"
    assert any(p.proto == "TCP" and p.payload.startswith(b"GET /v6") for p in pkts)


def test_ethernet_padding_is_not_payload():
    seg = g.tcp_segment("10.0.0.1", "10.0.0.2", 1234, 80, 1, 0, g.ACK, b"")
    frame = g.ether("02:00:00:00:00:01", "02:00:00:00:00:02", 0x0800,
                    g.ipv4("10.0.0.1", "10.0.0.2", 6, seg)) + b"\x00" * 6
    p = decode_packet(1, 0.0, frame, len(frame), 1)
    assert p.proto == "TCP" and p.payload == b""


def test_fragments_and_extension_headers():
    frag = g.ipv4("10.0.0.1", "10.0.0.2", 17, b"\x00" * 24, flags_frag=0x00B9)
    p = decode_packet(1, 0.0, g.ether("02:00:00:00:00:01", "02:00:00:00:00:02", 0x0800, frag), 60, 1)
    assert p.frag and p.sport is None and p.proto == "UDP"
    udp = g.udp_datagram("fd00::1", "fd00::2", 5000, 53, b"hi")
    hop = bytes([17, 0]) + b"\x00" * 6
    v6 = g.ipv6("fd00::1", "fd00::2", 0, hop + udp)
    p = decode_packet(1, 0.0, v6, len(v6), 229)
    assert p.proto == "UDP" and p.dport == 53 and p.payload == b"hi"


def test_other_link_types():
    seg = g.udp_datagram("10.0.0.1", "10.0.0.2", 1000, 2000, b"abc")
    ip = g.ipv4("10.0.0.1", "10.0.0.2", 17, seg)
    for linktype, prefix in ((101, b""), (228, b""), (0, b"\x02\x00\x00\x00"),
                             (113, b"\x00\x00\x00\x01\x00\x06" + b"\xaa" * 6 + b"\x00\x00\x08\x00"),
                             (276, b"\x08\x00\x00\x00" + b"\x00" * 16)):
        p = decode_packet(1, 0.0, prefix + ip, len(prefix + ip), linktype)
        assert (p.proto, p.src, p.dport, p.payload) == ("UDP", "10.0.0.1", 2000, b"abc"), linktype
    p = decode_packet(1, 0.0, b"\x00" * 64, 64, 127)
    assert p.net == "UNSUPPORTED-LINK"


def test_decoder_never_raises_on_garbage():
    rnd = random.Random(1234)
    valid = [p.data for p in CaptureReader(fixture_path("basic.pcap"))]
    for i in range(6000):
        if i % 3 == 0:
            data = bytes(rnd.getrandbits(8) for _ in range(rnd.randint(0, 100)))
        else:
            # mutate a valid frame: flip bytes and truncate
            b = bytearray(rnd.choice(valid))
            for _ in range(rnd.randint(1, 6)):
                if b:
                    b[rnd.randrange(len(b))] = rnd.getrandbits(8)
            data = bytes(b[:rnd.randint(0, len(b))])
        for lt in (1, 0, 101, 113, 276, 999):
            p = decode_packet(i, 0.0, data, len(data), lt)
            assert p.proto
            layers = dissect(data, lt)
            assert isinstance(layers, list)
    assert 1 in SUPPORTED_LINKTYPES


def test_garbage_fixture_decodes_with_malformed_flags():
    pkts = decode_file("garbage-frames.pcap")
    assert len(pkts) == 203
    assert sum(1 for p in pkts if p.malformed) > 0


def test_dissect_and_hexdump():
    with CaptureReader(fixture_path("basic.pcap")) as r:
        raws = list(r)
    names = [[l["name"] for l in dissect(p.data, p.linktype)] for p in raws]
    assert ["Ethernet", "ARP"] in names
    assert ["Ethernet", "IPv4", "UDP", "DNS"] in names
    assert ["Ethernet", "IPv4", "TCP", "HTTP"] in names
    assert ["Ethernet", "IPv4", "TCP", "TLS"] in names
    hello = next(l for p in raws for l in dissect(p.data, p.linktype) if l["summary"] == "Client Hello")
    assert {"name": "SNI", "value": "secure.example.com"} in hello["fields"]
    h = hexdump(raws[0].data)
    assert h["bytes"] == raws[0].caplen and h["rows"][0]["offset"] == "0000"
    assert hexdump(b"\x00" * 10000)["truncated"]
