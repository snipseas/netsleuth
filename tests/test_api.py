import os
import time

import pytest
from fastapi.testclient import TestClient

from netsleuth.config import Config, Limits
from netsleuth.server.app import create_app, safe_filename
from tests.conftest import SAMPLES, fixture_path


def wait_done(client, cid, timeout=60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        row = client.get(f"/api/captures/{cid}").json()
        if row["status"] in ("done", "failed"):
            return row
        time.sleep(0.05)
    raise AssertionError("analysis did not finish")


def upload(client, path, name=None):
    with open(path, "rb") as f:
        r = client.post("/api/captures", params={"filename": name or os.path.basename(path)}, content=f.read())
    return r


@pytest.fixture
def client(tmp_path):
    app = create_app(str(tmp_path / "data"), workers=0)
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def incident_client(tmp_path_factory):
    app = create_app(str(tmp_path_factory.mktemp("api") / "data"), workers=0)
    with TestClient(app) as c:
        cid = c.post("/api/samples/demo-incident.pcapng").json()["id"]
        assert wait_done(c, cid)["status"] == "done"
        yield c, cid


def test_upload_analyse_and_browse(client):
    r = upload(client, fixture_path("basic.pcap"))
    assert r.status_code == 201
    cid = r.json()["id"]
    row = wait_done(client, cid)
    assert row["status"] == "done" and row["progress"] == 1.0 and row["summary"]["packets"] == 36
    assert [c["id"] for c in client.get("/api/captures").json()] == [cid]
    base = f"/api/captures/{cid}"
    ov = client.get(f"{base}/overview").json()
    assert ov["summary"]["flows"] == 5 and ov["protocols"] and len(ov["top_hosts"]) == 4
    assert client.get(f"{base}/timeline").json()["buckets"] >= 1
    assert len(client.get(f"{base}/topology").json()["nodes"]) == 4
    assert client.get(f"{base}/hosts").json()["total"] == 4
    host = client.get(f"{base}/hosts/192.168.1.10").json()
    assert host["peer_list"] and host["dns_queries"] and host["timeline"]["sent"]
    assert client.get(f"{base}/hosts/1.2.3.4").status_code == 404
    flows = client.get(f"{base}/flows", params={"q": "app:http"}).json()
    assert flows["total"] == 1
    flow = client.get(f"{base}/flows/{flows['items'][0]['id']}").json()
    assert flow["http"][0]["uri"] == "/index.html" and len(flow["packets"]) == 10
    assert client.get(f"{base}/flows/9999").status_code == 404
    pk = client.get(f"{base}/packets", params={"q": "proto:tcp flag:syn", "limit": 5}).json()
    assert pk["total"] == 4 and len(pk["items"]) == 4
    detail = client.get(f"{base}/packets/{pk['items'][0]['no']}").json()
    assert [l["name"] for l in detail["layers"]] == ["Ethernet", "IPv4", "TCP"]
    assert detail["hex"]["rows"][0]["hex"].startswith("02:"[:2])
    assert client.get(f"{base}/packets/0").status_code == 404
    assert client.get(f"{base}/dns").json()["total"] == 2
    assert client.get(f"{base}/http").json()["total"] == 1
    assert client.get(f"{base}/tls").json()["total"] == 1
    assert client.get(f"{base}/findings").json() == []
    assert client.delete(base).status_code == 204
    assert client.get(base).status_code == 404
    assert client.get("/api/captures").json() == []
    assert not os.listdir(client.app.state.catalog.captures_dir)


def test_invalid_requests(client):
    assert client.get("/api/captures/not-an-id").status_code == 404
    assert client.get("/api/captures/" + "0" * 32).status_code == 404
    assert client.get("/api/captures/..%2f..%2fetc/overview").status_code == 404
    assert client.get("/api/nope").status_code == 404
    assert client.post("/api/samples/..%2Fsecret").status_code == 404
    r = upload(client, fixture_path("not-a-capture.pcap"))
    assert r.status_code == 415
    assert client.post("/api/captures", content=b"").status_code == 400
    assert client.post("/api/captures", content=b"\xd4\xc3").status_code == 400
    assert client.get("/api/captures").json() == []
    incoming = os.path.join(client.app.state.catalog.data_dir, "incoming")
    assert not os.path.isdir(incoming) or os.listdir(incoming) == []
    cid = upload(client, fixture_path("basic.pcap")).json()["id"]
    wait_done(client, cid)
    base = f"/api/captures/{cid}"
    r = client.get(f"{base}/packets", params={"q": "bogus:1"})
    assert r.status_code == 400 and "unknown filter key" in r.json()["detail"]
    assert client.get(f"{base}/packets", params={"limit": 100000}).status_code == 422
    assert client.get(f"{base}/report", params={"format": "exe"}).status_code == 422
    assert client.get(f"{base}/packets", params={"q": "'; DROP TABLE packets;--"}).status_code == 400
    assert client.get(f"{base}/packets", params={"q": "x; DROP TABLE packets;--"}).json()["total"] == 0
    assert client.get(f"{base}/packets").json()["total"] == 36


def test_upload_size_limit(tmp_path):
    cfg = Config(limits=Limits(max_upload_bytes=4096))
    with TestClient(create_app(str(tmp_path / "d"), cfg, workers=0)) as c:
        assert upload(c, fixture_path("basic.pcap")).status_code == 413
        assert c.get("/api/captures").json() == []


def test_corrupt_capture_fails_cleanly(client, tmp_path):
    bad = tmp_path / "bad.pcapng"
    bad.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\xff" * 64)
    cid = upload(client, str(bad)).json()["id"]
    row = wait_done(client, cid)
    assert row["status"] == "failed" and "byte-order" in row["error"]
    assert client.get(f"/api/captures/{cid}/overview").status_code == 409
    # damaged-but-readable captures still complete, with warnings
    cid = upload(client, fixture_path("truncated.pcap")).json()["id"]
    row = wait_done(client, cid)
    assert row["status"] == "done" and row["summary"]["warnings"]


def test_filenames_are_sanitised(client):
    assert safe_filename("../../etc/passwd") == "passwd"
    assert safe_filename("C:\\x\\<script>.pcap") == "_script_.pcap"
    assert safe_filename("") == "capture.pcap"
    r = upload(client, fixture_path("basic.pcap"), name='../<img src=x onerror=alert(1)>.pcap')
    assert "<" not in r.json()["filename"] and "/" not in r.json()["filename"]


def test_security_headers_and_host_check(tmp_path):
    app = create_app(str(tmp_path / "d"), workers=0, allowed_hosts=["localhost", "127.0.0.1", "testserver"])
    with TestClient(app) as c:
        r = c.get("/api/health")
        assert r.headers["x-content-type-options"] == "nosniff"
        assert "default-src 'self'" in r.headers["content-security-policy"]
        assert c.get("/api/health", headers={"host": "evil.example"}).status_code == 400


def test_reports(incident_client):
    c, cid = incident_client
    base = f"/api/captures/{cid}/report"
    data = c.get(base, params={"format": "json"}).json()
    assert len(data["findings"]) >= 17 and data["recommendations"] and data["hosts"]
    assert len(data["capture"]["sha256"]) == 64
    assert "not confirmation" in " ".join(data["executive_summary"])
    md = c.get(base, params={"format": "md"}).text
    for section in ("Executive summary", "Identified hosts", "Communication patterns",
                    "Suspicious activity", "Technical recommendations", "limitations"):
        assert section in md
    r = c.get(base, params={"format": "html", "download": "true"})
    assert "attachment" in r.headers["content-disposition"]
    assert r.headers["content-security-policy"].startswith("default-src 'none'")
    html = r.text
    assert "Possible vertical port scan" in html and "10.0.5.77" in html


def test_capture_derived_strings_are_escaped(incident_client):
    """The sample contains HTML in an HTTP Host header, URI and User-Agent."""
    c, cid = incident_client
    rows = c.get(f"/api/captures/{cid}/http", params={"q": "script"}).json()["items"]
    assert rows and "<script>" in rows[0]["host"]          # raw data is preserved in JSON...
    html = c.get(f"/api/captures/{cid}/report").text
    assert "<script" not in html and "onerror=alert(1)>" not in html   # ...and escaped in HTML
    md = c.get(f"/api/captures/{cid}/report", params={"format": "md"}).text
    assert "<script>" not in md


def test_reanalyze_and_restart_resume(tmp_path):
    data = str(tmp_path / "data")
    with TestClient(create_app(data, workers=0)) as c:
        cid = upload(c, fixture_path("basic.pcap")).json()["id"]
        wait_done(c, cid)
        assert c.post(f"/api/captures/{cid}/reanalyze").status_code == 202
        assert wait_done(c, cid)["status"] == "done"
        # simulate a crash mid-analysis: job left in 'processing'
        c.app.state.catalog.update(cid, status="processing", progress=0.4)
    with TestClient(create_app(data, workers=0)) as c:
        assert wait_done(c, cid)["status"] == "done"       # re-queued on startup


def test_real_worker_process(tmp_path):
    """One run through the actual process pool (spawned worker)."""
    with TestClient(create_app(str(tmp_path / "data"), workers=1)) as c:
        cid = c.post("/api/samples/demo-basic.pcap").json()["id"]
        row = wait_done(c, cid)
        assert row["status"] == "done" and row["summary"]["packets"] == 36
        assert os.path.exists(os.path.join(SAMPLES, "demo-basic.pcap"))
