import struct

import pytest

from netsleuth.ingest.reader import CaptureFormatError, CaptureReader, ReaderLimits, sniff_format
from tests.conftest import fixture_path


def read_all(name, **kw):
    with CaptureReader(fixture_path(name), **kw) as r:
        pkts = list(r)
    return r, pkts


@pytest.mark.parametrize("name", ["basic.pcap", "basic-nanos-be.pcap", "basic.pcapng", "basic-be.pcapng"])
def test_all_format_variants_yield_identical_packets(name):
    _, ref = read_all("basic.pcap")
    r, pkts = read_all(name)
    assert r.warnings == []
    assert len(pkts) == len(ref) > 20
    for a, b in zip(ref, pkts):
        assert a.data == b.data
        assert a.wirelen == b.wirelen
        assert a.linktype == b.linktype == 1
        assert abs(a.ts - b.ts) < 2e-6


def test_packet_offsets_point_at_frame_data():
    for name in ("basic.pcap", "basic.pcapng", "basic-be.pcapng"):
        raw = open(fixture_path(name), "rb").read()
        _, pkts = read_all(name)
        for p in pkts:
            assert raw[p.offset:p.offset + p.caplen] == p.data


def test_format_sniffing():
    assert sniff_format(fixture_path("basic.pcap")) == "pcap"
    assert sniff_format(fixture_path("basic.pcapng")) == "pcapng"
    with pytest.raises(CaptureFormatError):
        sniff_format(fixture_path("not-a-capture.pcap"))


def test_not_a_capture_is_rejected():
    with pytest.raises(CaptureFormatError):
        CaptureReader(fixture_path("not-a-capture.pcap"))


def test_gzip_gets_a_helpful_error(tmp_path):
    p = tmp_path / "x.pcap.gz"
    p.write_bytes(b"\x1f\x8b\x08\x00" + b"\x00" * 32)
    with pytest.raises(CaptureFormatError, match="gzip"):
        CaptureReader(str(p))


def test_truncated_file_keeps_readable_packets():
    _, ref = read_all("basic.pcap")
    r, pkts = read_all("truncated.pcap")
    assert len(pkts) == len(ref) - 1
    assert any("truncated" in w for w in r.warnings)


def test_corrupt_length_stops_without_allocating():
    r, pkts = read_all("corrupt-length.pcap")
    assert pkts == []
    assert any("corrupt" in w for w in r.warnings)


def test_packet_size_limit_is_enforced():
    r, pkts = read_all("basic.pcap", limits=ReaderLimits(max_packet_bytes=60))
    assert len(pkts) < 10 and r.warnings


def test_empty_and_header_only_files(tmp_path):
    p = tmp_path / "empty.pcap"
    p.write_bytes(b"")
    with pytest.raises(CaptureFormatError):
        CaptureReader(str(p))
    p.write_bytes(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    with CaptureReader(str(p)) as r:
        assert list(r) == []
    p.write_bytes(struct.pack("<IHH", 0xA1B2C3D4, 2, 4))
    with pytest.raises(CaptureFormatError):
        CaptureReader(str(p))


def test_pcapng_damage_is_contained(tmp_path):
    good = open(fixture_path("basic.pcapng"), "rb").read()
    # absurd block length in the 3rd block
    first = struct.unpack_from("<I", good, 4)[0]
    second = struct.unpack_from("<I", good, first + 4)[0]
    bad = bytearray(good)
    third_block = first + second
    struct.pack_into("<I", bad, third_block + 4, 0xFFFFFFF0)
    p = tmp_path / "bad.pcapng"
    p.write_bytes(bytes(bad))
    with CaptureReader(str(p)) as r:
        assert list(r) == []
        assert r.warnings
    # packet block referencing an interface that was never defined
    bad = bytearray(good)
    struct.pack_into("<I", bad, third_block + 8, 7)
    p.write_bytes(bytes(bad))
    with CaptureReader(str(p)) as r:
        pkts = list(r)
    assert any("undefined interface" in w for w in r.warnings)
    # truncated mid-block
    p.write_bytes(good[:len(good) - 21])
    with CaptureReader(str(p)) as r:
        n = len(list(r))
    assert n == len(pkts) and r.warnings
    # garbage after a valid section header must not raise
    p.write_bytes(good[:first] + bytes(range(256)) * 4)
    with CaptureReader(str(p)) as r:
        assert list(r) == []
