"""Cross-validation against Wireshark's tshark.

The fixtures are produced by our own generator, so agreeing with our own
parser proves little. These tests compare NetSleuth's output with an
independent implementation on the same files. Skipped when tshark is absent.
"""
import os
import shutil
import subprocess

import pytest

from tests.conftest import SAMPLES, fixture_path

pytestmark = pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed")


def tshark(path, fields, display_filter=None):
    cmd = ["tshark", "-n", "-r", path, "-T", "fields", "-E", "separator=|", "-E", "occurrence=f"]
    for f in fields:
        cmd += ["-e", f]
    if display_filter:
        cmd += ["-Y", display_filter]
    env = dict(os.environ, HOME=os.environ.get("TMPDIR", "/tmp"))
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=120, env=env)
    assert out.returncode == 0, out.stderr
    return [line.split("|") for line in out.stdout.splitlines()]


@pytest.mark.parametrize("name", ["basic.pcap", "basic-be.pcapng", "ipv6-vlan.pcapng"])
def test_per_packet_fields_match(analyze, name):
    path = fixture_path(name)
    _, store = analyze(path)
    ours = store.packets(limit=1000)["items"]
    theirs = tshark(path, ["frame.number", "frame.len", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst",
                           "tcp.srcport", "udp.srcport", "tcp.dstport", "udp.dstport", "tcp.flags"])
    assert len(ours) == len(theirs)
    for p, t in zip(ours, theirs):
        assert p["no"] == int(t[0]) and p["len"] == int(t[1])
        if p["proto"] in ("TCP", "UDP", "ICMP"):
            assert p["src"] == (t[2] or t[3]) and p["dst"] == (t[4] or t[5])
        if p["proto"] in ("TCP", "UDP"):
            assert p["sport"] == int(t[6] or t[7]) and p["dport"] == int(t[8] or t[9])
        if p["proto"] == "TCP":
            assert p["flags"] == int(t[10], 16) & 0xFF


def test_generated_packets_are_valid_per_tshark():
    """tshark must find no malformed packets or bad checksums in our fixtures."""
    for path in (fixture_path("basic.pcap"), fixture_path("ipv6-vlan.pcapng")):
        bad = tshark(path, ["frame.number"],
                     "_ws.malformed || ip.checksum.status == 0 || tcp.checksum.status == 0 || udp.checksum.status == 0")
        assert bad == []


def test_incident_totals_match(incident):
    summary, store = incident
    path = os.path.join(SAMPLES, "demo-incident.pcapng")
    frames = tshark(path, ["frame.len"])
    assert summary["packets"] == len(frames)
    assert summary["bytes"] == sum(int(f[0]) for f in frames)
    # TCP connections: tshark numbers streams per 5-tuple + new SYN, as we do
    streams = {s[0] for s in tshark(path, ["tcp.stream"], "tcp")}
    assert summary["flows_by_proto"]["TCP"] == len(streams)


def test_dns_http_tls_metadata_match(incident):
    _, store = incident
    path = os.path.join(SAMPLES, "demo-incident.pcapng")
    their_q = sorted(r[0].lower() for r in tshark(path, ["dns.qry.name"], "dns.flags.response == 0"))
    our_q = sorted(r[0] for r in store.db.execute("SELECT qname FROM dns WHERE proto = 'DNS'"))
    assert our_q == their_q
    their_nx = len(tshark(path, ["frame.number"], "dns.flags.rcode == 3"))
    assert store.db.execute("SELECT COUNT(*) FROM dns WHERE rcode = 'NXDOMAIN'").fetchone()[0] == their_nx

    their_http = sorted((r[0], r[1]) for r in tshark(path, ["http.request.method", "http.request.uri"], "http.request"))
    # tshark cuts the request target at the first space; we keep it whole
    our_http = sorted((m, u.split(" ")[0]) for m, u in
                      store.db.execute("SELECT method, uri FROM http WHERE method != ''"))
    assert our_http == their_http
    their_status = sorted(int(r[0]) for r in tshark(path, ["http.response.code"], "http.response"))
    our_status = sorted(r[0] for r in store.db.execute("SELECT status FROM http WHERE status IS NOT NULL"))
    assert our_status == their_status

    hello = tshark(path, ["tls.handshake.extensions_server_name", "tls.handshake.ja3"], "tls.handshake.type == 1")
    their_sni = sorted(r[0] for r in hello)
    our = store.db.execute("SELECT sni, ja3 FROM tls WHERE ja3 != ''").fetchall()
    assert sorted(r[0] for r in our) == their_sni
    if hello and len(hello[0]) > 1 and hello[0][1]:
        assert sorted(r[1] for r in our) == sorted(r[1] for r in hello)   # JA3 agrees with Wireshark
