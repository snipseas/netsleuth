"""Each detector is exercised with traffic that should trigger it and with
similar-looking benign traffic that must not."""
import base64
import random

from netsleuth.detect.beacon import score_intervals
from netsleuth.detect.dns import dga_score
from netsleuth.devtools.pcapgen import SYN, CaptureBuilder

T = 1_700_000_000.0
RES = "10.0.0.2"


def findings(store, detector=None, title=None):
    out = store.findings(detector=detector or "")
    return [f for f in out if title is None or title in f["title"]]


def assert_well_formed(f):
    assert f["severity"] in ("info", "low", "medium", "high")
    assert 0.05 <= f["confidence"] <= 0.95
    assert f["summary"] and f["explanation"] and f["evidence"] and f["hosts"]
    assert f["caveats"], "every finding must list benign explanations"
    assert f["recommendations"]


def test_incident_sample_triggers_every_category(incident):
    summary, store = incident
    all_f = store.findings()
    for f in all_f:
        assert_well_formed(f)
    titles = [f["title"] for f in all_f]
    expected = [
        "Possible vertical port scan", "Possible horizontal sweep on TCP port 445",
        "DNS tunnelling indicators", "NXDOMAIN burst with algorithmic-looking names",
        "Direct use of an external DNS resolver", "Periodic connections consistent with beaconing",
        "Large upload to an external host", "Outbound session on port 4444",
        "HTTP requests to a bare IP address", "TLS to an external address without SNI",
        "Rapid repeated SSH sessions", "Internal fan-out over SMB",
        "Credentials sent in cleartext (FTP)", "Credentials sent in cleartext (HTTP Basic)",
        "Long-lived session to an external host", "Repeated failed connections to one service",
        "IP address claimed by multiple MAC addresses",
    ]
    for e in expected:
        assert any(e in t for t in titles), e
    assert {d["name"] for d in store.meta("detectors")} == {
        "port_scan", "dns_tunnel", "dns_suspicious", "unusual_outbound", "beaconing",
        "volume_anomaly", "connection_patterns"}
    assert all(d["error"] is None for d in store.meta("detectors"))
    assert summary["warnings"] == []


def test_incident_evidence_is_accurate(incident):
    _, store = incident
    scan = findings(store, "port_scan", "vertical")[0]
    ev = scan["evidence"]
    assert (ev["source"], ev["target"]) == ("10.0.5.77", "10.0.5.10")
    assert ev["ports_that_answered"] == [22, 80, 443, 445, 3306]     # exactly the generator's open ports
    assert ev["ports_probed_without_data"] == 1031 and ev["technique"] == "SYN (half-open)"
    beacon = findings(store, "beaconing", "consistent with beaconing")
    assert len(beacon) == 1, "NTP, browsing and the SSH burst must not be reported as beacons"
    ev = beacon[0]["evidence"]
    assert ev["destination"] == "203.0.113.50" and ev["connections"] == 55
    assert 59 < ev["median_interval_seconds"] < 61
    tunnel = findings(store, "dns_tunnel")
    assert len(tunnel) == 1 and tunnel[0]["evidence"]["domain"] == "cache-metrics.example"
    assert tunnel[0]["evidence"]["queries"] == 240
    upload = findings(store, "volume_anomaly", "Large upload")[0]["evidence"]
    assert upload["destination"] == "198.51.100.77" and 1_300_000 <= upload["payload_bytes_sent"] < 1_320_000
    ftp = findings(store, "connection_patterns", "FTP")[0]
    assert "user=backup" in ftp["evidence"]["detail"]
    # the password must never be stored anywhere
    dump = "\n".join(store.db.iterdump()) if not store.db.in_transaction else ""
    assert "not-a-real-password" not in dump and "bm90OnJlYWw=" not in dump


def test_normal_browsing_produces_no_findings(analyze):
    rnd = random.Random(2)
    b = CaptureBuilder()
    sites = [("www.example.com", "203.0.113.10"), ("news.example.org", "203.0.113.20"),
             ("mail.example.net", "203.0.113.30")]
    for ws in ("10.0.0.11", "10.0.0.12", "10.0.0.13"):
        t = T + rnd.uniform(0, 30)
        port = 50000
        for _ in range(40):
            name, ip = rnd.choice(sites)
            b.dns(t, ws, RES, name, "A", [("A", ip)])
            port += 1
            b.tls(t + 0.1, ws, ip, port, sni=name, sent=rnd.randint(300, 3000),
                  received=rnd.randint(4000, 30000), seed=port)
            t += rnd.expovariate(1 / 40)
    s, store = analyze(b)
    assert store.findings() == []
    assert s["findings"] == 0


def test_port_scan_variants_and_negatives(analyze):
    b = CaptureBuilder()
    # FIN scan (no SYN at all) and UDP scan with ICMP unreachable replies
    for p in range(1, 60):
        b.tcp(T + p * 0.01, "10.0.0.66", "10.0.0.9", 40000, p, 1, 0, 0x01)
        pkt = b.udp(T + 5 + p * 0.01, "10.0.0.66", "10.0.0.8", 40001, 1000 + p, b"\x00")
        if p % 2:
            from netsleuth.devtools.pcapgen import icmp_port_unreachable
            b.ip(T + 5 + p * 0.01 + 0.001, "10.0.0.8", "10.0.0.66", 1, icmp_port_unreachable(pkt))
    # a busy legitimate client: many ports on one server, but all sessions work
    for p in range(8000, 8030):
        b.http(T + 20 + p * 0.01, "10.0.0.20", "10.0.0.9", 45000 + p, "svc.example", dport=p)
    # a client that fails on a few ports only (below threshold)
    for p in range(7000, 7008):
        b.syn_probe(T + 30, "10.0.0.21", "10.0.0.9", 46000 + p, p, "closed")
    _, store = analyze(b)
    fs = findings(store, "port_scan")
    assert {f["hosts"][0] for f in fs} == {"10.0.0.66"}
    fin = next(f for f in fs if "vertical" in f["title"])
    assert fin["evidence"]["technique"] == "FIN" and fin["evidence"]["ports_probed_without_data"] == 59
    udp = next(f for f in fs if "UDP" in f["title"])
    assert udp["evidence"]["icmp_unreachable_replies"] == 30 and udp["evidence"]["distinct_ports"] == 59


def test_beacon_scoring():
    rnd = random.Random(1)
    regular = [i * 30 + rnd.uniform(-0.5, 0.5) for i in range(40)]
    human = sorted(rnd.uniform(0, 1200) for _ in range(40))
    assert score_intervals(regular)["timing_score"] > 0.9
    assert score_intervals(human)["timing_score"] < 0.6
    assert score_intervals([1, 2, 3]) is None


def test_beacon_detector_ignores_irregular_and_tolerates_jitter(analyze):
    rnd = random.Random(4)
    b = CaptureBuilder()
    t1 = t2 = T
    for i in range(30):
        b.tls(t1, "10.0.0.31", "203.0.113.66", 50000 + i, sni="c2.example", sent=200, received=150, seed=1)
        t1 += 120 * rnd.uniform(0.9, 1.1)                 # 10% jitter beacon
        b.tls(t2, "10.0.0.32", "203.0.113.67", 51000 + i, sni="web.example",
              sent=rnd.randint(200, 9000), received=5000, seed=i)
        t2 += rnd.expovariate(1 / 120)                    # human-like arrivals
    _, store = analyze(b)
    fs = findings(store, "beaconing", "beaconing")
    assert [f["evidence"]["source"] for f in fs] == ["10.0.0.31"]
    assert 100 < fs[0]["evidence"]["median_interval_seconds"] < 140


def test_dns_tunnel_vs_cdn_like_names(analyze):
    rnd = random.Random(3)
    b = CaptureBuilder()
    for i in range(80):
        data = base64.b32encode(bytes(rnd.getrandbits(8) for _ in range(35))).decode().rstrip("=").lower()
        b.dns(T + i, "10.0.0.40", RES, f"{data[:50]}.x.tunnel.example", "TXT", [("TXT", "ok")])
        # many lookups of a few short, repeated names on another domain
        b.dns(T + i, "10.0.0.41", RES, f"img{i % 6}.cdn.example.org", "A", [("A", "203.0.113.5")])
        # unique but short, low-entropy names (e.g. numbered hosts)
        b.dns(T + i, "10.0.0.42", RES, f"host{i}.corp.example.net", "A", [("A", "203.0.113.6")])
    _, store = analyze(b)
    fs = findings(store, "dns_tunnel")
    assert [f["evidence"]["client"] for f in fs] == ["10.0.0.40"]
    assert fs[0]["evidence"]["domain"] == "tunnel.example" and fs[0]["evidence"]["record_types"] == {"TXT": 80}


def test_dga_score_separates_random_from_words():
    words = ["google", "wikipedia", "microsoft", "stackoverflow", "cloudflare", "netsleuth", "example"]
    rnd = random.Random(8)
    randoms = ["".join(rnd.choice("bcdfghjklmnpqrstvwxz0123456789") for _ in range(14)) for _ in range(20)]
    assert max(dga_score(w) for w in words) < 0.45
    assert min(dga_score(r) for r in randoms) > 0.55


def test_nxdomain_typos_are_not_dga(analyze):
    b = CaptureBuilder()
    for i, name in enumerate(["gogle.com", "exmaple.org", "wikipdia.org", "printer.corp.example",
                              "intranet.example", "fileserver.example", "wpad.example", "proxy.example",
                              "mailhost.example", "updates.example", "timeserver.example", "backup.example"]):
        b.dns(T + i, "10.0.0.50", RES, name, "A", rcode=3)
    _, store = analyze(b)
    assert findings(store, "dns_suspicious", "NXDOMAIN") == []


def test_external_resolver_only_flagged_when_internal_exists(analyze):
    b = CaptureBuilder()
    for i in range(5):
        b.dns(T + i, "10.0.0.60", "8.8.8.8", f"s{i}.example.com", "A", [("A", "203.0.113.5")])
    _, store = analyze(b)
    assert findings(store, "dns_suspicious", "external DNS resolver") == []


def test_upload_requires_asymmetry(analyze):
    from netsleuth.devtools.pcapgen import tls_appdata
    b = CaptureBuilder()
    big = tls_appdata(1_200_000)
    b.tcp_session(T, "10.0.0.70", "203.0.113.70", 50000, 443, [("c", big, 0.01), ("s", b"ok", 0.01)])
    b.tcp_session(T + 10, "10.0.0.71", "203.0.113.71", 50001, 443, [("c", big, 0.01), ("s", big, 0.01)])
    b.tcp_session(T + 20, "10.0.0.72", "10.0.0.73", 50002, 445, [("c", big, 0.01), ("s", b"ok", 0.01)])
    _, store = analyze(b)
    fs = findings(store, "volume_anomaly", "Large upload")
    assert [f["evidence"]["source"] for f in fs] == ["10.0.0.70"]


def test_syn_flood_detection(analyze):
    b = CaptureBuilder()
    rnd = random.Random(6)
    for i in range(600):
        src = f"198.51.100.{rnd.randint(1, 250)}"
        b.tcp(T + i * 0.004, src, "10.0.0.80", 1024 + i, 443, i * 1000, 0, SYN)
    _, store = analyze(b)
    fs = findings(store, "volume_anomaly", "half-open")
    assert len(fs) == 1 and fs[0]["evidence"]["half_open_attempts"] == 600
    assert fs[0]["evidence"]["distinct_sources"] > 100


def test_admin_work_is_not_bruteforce(analyze):
    b = CaptureBuilder()
    # an administrator with a few long, large SSH sessions
    for i in range(14):
        b.tcp_session(T + i * 400, "10.0.0.90", "10.0.0.91", 52000 + i, 22,
                      [("s", b"SSH-2.0-OpenSSH_9.6\r\n", 0.01), ("c", b"SSH-2.0-OpenSSH_9.6\r\n", 0.01),
                       ("c", b"\x01" * 3000, 60), ("s", b"\x02" * 40000, 120)])
    _, store = analyze(b)
    assert findings(store, "connection_patterns", "password guessing") == []
    assert store.flows(q="app:ssh")["total"] == 14


def test_a_failing_detector_does_not_break_analysis(analyze, monkeypatch):
    from netsleuth.detect import engine
    from netsleuth.detect.base import Detector

    class Broken(Detector):
        name = "broken"

        def run(self, ctx):
            raise RuntimeError("boom")

    monkeypatch.setattr(engine, "ALL_DETECTORS", (Broken,) + engine.ALL_DETECTORS)
    monkeypatch.setattr(engine.run_detectors, "__defaults__", ((Broken,) + engine.ALL_DETECTORS[1:],))
    from tests.conftest import fixture_path
    s, store = analyze(fixture_path("basic.pcap"))
    assert any("broken" in w for w in s["warnings"])
    assert next(d for d in store.meta("detectors") if d["name"] == "broken")["error"]
