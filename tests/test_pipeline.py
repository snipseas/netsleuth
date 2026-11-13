from netsleuth.config import Config, Limits
from netsleuth.devtools import pcapgen as g
from netsleuth.devtools.pcapgen import ACK, FIN, PSH, SYN, CaptureBuilder
from tests.conftest import fixture_path

T = 1_700_000_000.0


def test_basic_capture_end_to_end(analyze):
    s, store = analyze(fixture_path("basic.pcap"))
    assert s["packets"] == 36 and s["format"] == "pcap" and s["warnings"] == []
    assert len(s["sha256"]) == 64 and s["link_types"] == ["Ethernet"]
    flows = store.flows(sort="id")["items"]
    by = {(f["proto"], f["dport"]): f for f in flows}
    http, tls_flow = by[("TCP", 80)], by[("TCP", 443)]
    assert (http["src"], http["dst"], http["state"], http["app"], http["app_by"]) == (
        "192.168.1.10", "203.0.113.10", "SF", "HTTP", "payload")
    assert http["http_host"] == "www.example.com" and http["retrans"] == 0
    assert tls_flow["sni"] == "secure.example.com" and tls_flow["app"] == "TLS"
    assert (http["src_scope"], http["dst_scope"]) == ("internal", "external")
    # byte accounting: both directions add up to what the flow's packets carry
    pk = store.packets(q=f"flow:{http['id']}")["items"]
    assert sum(p["len"] for p in pk) == http["bytes_fwd"] + http["bytes_rev"]
    assert len(pk) == http["pkts_fwd"] + http["pkts_rev"]

    dns = store.dns()["items"]
    assert [(d["qname"], d["rcode"], d["answered"]) for d in dns] == [
        ("www.example.com", "NOERROR", 1), ("nope.example.com", "NXDOMAIN", 1)]
    assert dns[0]["answers"] == ["CNAME web.example.com", "A 203.0.113.10"]
    assert 0.011 < dns[0]["rtt"] < 0.013

    h = store.http()["items"]
    assert len(h) == 1 and (h[0]["method"], h[0]["uri"], h[0]["status"]) == ("GET", "/index.html", 200)
    t = store.tls()["items"][0]
    assert (t["sni"], t["version"], t["client_version"]) == ("secure.example.com", "TLS 1.3", "TLS 1.3")
    assert len(t["ja3"]) == 32 and len(t["ja3s"]) == 32

    host = store.host("203.0.113.10")
    assert host["scope"] == "external" and "www.example.com" in host["names"]
    assert "80/tcp HTTP" in host["services"]
    assert store.host("192.168.1.10")["mac"] == g.mac_for("192.168.1.10")
    assert store.host("192.168.1.10")["peers"] == 3


def test_all_formats_give_identical_analysis(analyze):
    ref, _ = analyze(fixture_path("basic.pcap"))
    for name in ("basic-nanos-be.pcap", "basic.pcapng", "basic-be.pcapng"):
        s, _ = analyze(fixture_path(name))
        for k in ("packets", "bytes", "flows", "hosts", "dns_records", "http_records", "tls_records", "findings"):
            assert s[k] == ref[k], (name, k)
        assert abs(s["duration"] - ref["duration"]) < 1e-5


def test_timeline_and_protocol_totals_match_packet_count(analyze):
    s, store = analyze(fixture_path("basic.pcap"))
    tl = store.timeline(buckets=10)
    assert sum(sum(v["packets"]) for v in tl["series"].values()) == s["packets"]
    assert sum(sum(v["bytes"]) for v in tl["series"].values()) == s["bytes"]
    protos = store.meta("protocols")
    assert sum(p["packets"] for p in protos) == s["packets"]
    labels = {p["app"] or p["transport"] or p["net"] for p in protos}
    assert {"ARP", "DNS", "HTTP", "TLS", "ICMP"} <= labels


def test_tcp_states(analyze):
    b = CaptureBuilder()
    c, srv = "10.0.0.5", "10.0.0.9"
    b.tcp(T, c, srv, 5001, 81, 100, 0, SYN)                                    # S0
    b.syn_probe(T + 1, c, srv, 5002, 82, "closed")                            # REJ
    b.syn_probe(T + 2, c, srv, 5003, 83, "open")                              # RSTO, never established
    b.tcp_session(T + 3, c, srv, 5004, 84, [("c", b"hi", 0.01), ("s", b"yo", 0.01)])           # SF
    b.tcp_session(T + 4, c, srv, 5005, 85, [("c", b"hi", 0.01)], close=None)                   # S1
    b.tcp_session(T + 5, c, srv, 5006, 86, [("c", b"hi", 0.01)], close="rst_server")           # RSTR
    b.tcp_session(T + 6, c, srv, 5007, 87, [("c", b"hi", 0.01), ("s", b"yo", 0.01)],
                  close=None, handshake=False)                                                  # OTH
    _, store = analyze(b)
    states = {f["dport"]: f["state"] for f in store.flows()["items"]}
    assert states == {81: "S0", 82: "REJ", 83: "RSTO", 84: "SF", 85: "S1", 86: "RSTR", 87: "OTH"}
    mid = store.flows(q="dport:87")["items"][0]
    assert (mid["src"], mid["dst"]) == (c, srv)        # lower port taken as the server


def test_retransmission_reordering_and_port_reuse(analyze):
    b = CaptureBuilder()
    c, srv = "10.0.0.5", "203.0.113.9"
    req = b"GET /one HTTP/1.1\r\nHost: reorder.example\r\n\r\n"
    b.tcp(T, c, srv, 6000, 80, 1000, 0, SYN)
    b.tcp(T + .01, srv, c, 80, 6000, 9000, 1001, SYN | ACK)
    b.tcp(T + .02, c, srv, 6000, 80, 1001, 9001, ACK)
    b.tcp(T + .04, c, srv, 6000, 80, 1001 + 20, 9001, ACK | PSH, req[20:])   # second half first
    b.tcp(T + .05, c, srv, 6000, 80, 1001, 9001, ACK, req[:20])
    b.tcp(T + .06, c, srv, 6000, 80, 1001, 9001, ACK, req[:20])               # retransmission
    b.tcp(T + .07, c, srv, 6000, 80, 1001 + len(req), 9001, FIN | ACK)
    b.tcp(T + .08, srv, c, 80, 6000, 9001, 1002 + len(req), FIN | ACK)
    # same 5-tuple reused by a new connection
    b.http(T + 5, c, srv, 6000, "second.example", path="/two")
    _, store = analyze(b)
    flows = store.flows(sort="id")["items"]
    assert len(flows) == 2
    assert flows[0]["retrans"] == 1 and flows[0]["ooo"] == 1 and flows[0]["state"] == "SF"
    reqs = [(h["host"], h["uri"]) for h in store.http()["items"]]
    assert reqs == [("reorder.example", "/one"), ("second.example", "/two")]


def test_udp_flows_timeout_and_direction(analyze):
    b = CaptureBuilder()
    b.udp(T, "10.0.0.5", "10.0.0.9", 4000, 9999, b"a")
    b.udp(T + 1, "10.0.0.9", "10.0.0.5", 9999, 4000, b"b")
    b.udp(T + 200, "10.0.0.5", "10.0.0.9", 4000, 9999, b"c")      # after idle timeout: new flow
    b.udp(T + 300, "10.0.0.2", "10.0.0.5", 53, 4100,              # reply seen without its query
          g.dns_response(5, "late.example.com", "A", [("A", "203.0.113.5")]))
    _, store = analyze(b)
    flows = store.flows(sort="id")["items"]
    assert [(f["state"], f["pkts_fwd"], f["pkts_rev"]) for f in flows[:2]] == [("REPLIED", 1, 1), ("UNANSWERED", 1, 0)]
    assert (flows[2]["src"], flows[2]["dport"], flows[2]["app"]) == ("10.0.0.5", 53, "DNS")


def test_malformed_inputs_are_analysed_safely(analyze):
    s, store = analyze(fixture_path("garbage-frames.pcap"))
    assert s["packets"] == 203 and s["malformed_packets"] > 0
    assert store.packets(limit=1000)["total"] == 203
    s, _ = analyze(fixture_path("truncated.pcap"))
    assert s["packets"] == 35 and any("truncated" in w for w in s["warnings"])
    s, _ = analyze(fixture_path("corrupt-length.pcap"))
    assert s["packets"] == 0 and s["warnings"] and s["findings"] == 0
    s, store = analyze(fixture_path("dns-pointer-loop.pcap"))
    assert s["packets"] == 1 and s["dns_records"] == 0


def test_resource_limits_are_enforced(analyze):
    cfg = Config(limits=Limits(max_packets=20, max_flows=3, max_hosts=3, max_app_records=1))
    s, store = analyze(fixture_path("basic.pcap"), cfg)
    assert s["packets"] == 20 and any("limit" in w for w in s["warnings"])
    assert s["hosts"] <= 3 and s["flows"] <= 3 and s["dns_records"] <= 1
    cfg = Config(limits=Limits(max_flows=2))
    s, store = analyze(fixture_path("basic.pcap"), cfg)
    assert s["packets"] == 36 and s["flows"] == 2
    assert any("flow table limit" in w for w in s["warnings"])


def test_snaplen_truncation_is_reported(analyze, tmp_path):
    from netsleuth.devtools.gen_samples import build_basic
    p = str(tmp_path / "snap.pcap")
    build_basic().write_pcap(p, snaplen=80)
    s, _ = analyze(p)
    assert s["truncated_packets"] > 0 and any("snap length" in w for w in s["warnings"])
    assert s["bytes"] > 80 * s["truncated_packets"]


def test_search_and_filters(analyze):
    _, store = analyze(fixture_path("basic.pcap"))
    assert store.packets(q="proto:arp")["total"] == 2
    assert store.packets(q="app:dns")["total"] == 4
    assert store.packets(q="flag:syn -flag:ack")["total"] == 2
    assert store.packets(q='"Client Hello"')["total"] == 1
    assert store.packets(q="203.0.113.11")["total"] == store.packets(q="ip:203.0.113.11")["total"] > 5
    assert store.flows(q="app:tls")["total"] == 1 and store.flows(q="secure.example")["total"] == 1
    assert store.flows(q="state:SF bytes>600")["total"] == 2
    assert store.flows(q="state:SF bytes>5000")["total"] == 1
    assert store.hosts(q="example.com")["total"] == 2
    assert store.dns(q="nope")["total"] == 1
    page = store.packets(limit=10, offset=10)["items"]
    assert [p["no"] for p in page] == list(range(11, 21))
    topo = store.topology()
    assert len(topo["nodes"]) == 4 and not topo["truncated"]
