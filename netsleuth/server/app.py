"""HTTP API and static web interface.

The API is a thin presentation layer: it validates input, opens the relevant
capture store read-only and returns JSON. No analysis happens here.
"""

from __future__ import annotations

import os
import re
import shutil
from contextlib import asynccontextmanager, contextmanager

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .. import __version__
from ..config import Config
from ..detect.engine import ALL_DETECTORS
from ..ingest.dissect import dissect, hexdump
from ..ingest.reader import PCAP_MAGICS, PCAPNG_MAGIC
from ..report.builder import build_report, render_html, render_markdown
from ..storage.catalog import DONE, Catalog
from ..storage.query import FilterError
from ..storage.store import CaptureStore
from .jobs import JobManager

WEB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web")
SAMPLES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples")
_SAMPLE_INFO = {
    "demo-incident.pcapng": "Simulated office network, one hour: beaconing, DNS tunnelling, "
                            "port scanning, password guessing, a large upload and more.",
    "demo-basic.pcap": "A handful of packets: DNS, HTTP, TLS and ICMP. Good for a first look.",
}
_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": (
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "object-src 'none'; base-uri 'none'; frame-ancestors 'self'"),
}
# The report is previewed in a sandboxed iframe by the interface. Framing is
# governed by frame-ancestors (X-Frame-Options cannot express "same origin"
# for a sandboxed, opaque-origin frame).
_REPORT_CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; frame-ancestors 'self'"


def safe_filename(name: str) -> str:
    name = os.path.basename((name or "").replace("\\", "/"))
    name = re.sub(r"[^\w.\- ()\[\]]", "_", name)[:120].strip(" .")
    return name or "capture.pcap"


def create_app(data_dir: str, config: Config | None = None, workers: int = 2,
               allowed_hosts: list[str] | None = None) -> FastAPI:
    config = config or Config()
    catalog = Catalog(data_dir)
    jobs = JobManager(data_dir, config, workers)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        jobs.resume_pending()
        yield
        jobs.shutdown()

    app = FastAPI(title="NetSleuth", version=__version__, lifespan=lifespan,
                  docs_url="/api/docs", redoc_url=None, openapi_url="/api/openapi.json")
    app.state.catalog = catalog
    app.state.jobs = jobs
    if allowed_hosts:
        # blocks DNS-rebinding access to a loopback-bound instance
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        for k, v in _SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        if request.url.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    @app.exception_handler(FilterError)
    async def filter_error(_request: Request, exc: FilterError):
        return JSONResponse({"detail": f"invalid filter: {exc}"}, status_code=400)

    # -- helpers -------------------------------------------------------------
    def capture_or_404(cid: str) -> dict:
        try:
            row = catalog.get(cid) if re.fullmatch(r"[0-9a-f]{32}", cid) else None
        except KeyError:
            row = None
        if row is None:
            raise HTTPException(404, "capture not found")
        return row

    @contextmanager
    def open_store(cid: str):
        row = capture_or_404(cid)
        if row["status"] != DONE:
            raise HTTPException(409, f"capture analysis is {row['status']}")
        store = CaptureStore(catalog.db_file(cid), readonly=True)
        try:
            yield store
        finally:
            store.close()

    def ingest_file(src_path: str, filename: str, move: bool) -> dict:
        cid = catalog.new_id()
        dst = catalog.capture_file(cid)
        if move:
            os.replace(src_path, dst)
        else:
            shutil.copyfile(src_path, dst)
        row = catalog.register(cid, filename, os.path.getsize(dst))
        jobs.submit(cid)
        return row

    # -- meta ------------------------------------------------------------------
    @app.get("/api/health")
    def health():
        return {"status": "ok", "version": __version__}

    @app.get("/api/config")
    def get_config():
        return {
            "version": __version__,
            "max_upload_bytes": config.limits.max_upload_bytes,
            "max_packets": config.limits.max_packets,
            "detectors": [{"name": d.name, "category": d.category, "description": d.description}
                          for d in ALL_DETECTORS],
        }

    @app.get("/api/samples")
    def samples():
        out = []
        for name, desc in _SAMPLE_INFO.items():
            path = os.path.join(SAMPLES_DIR, name)
            if os.path.exists(path):
                out.append({"name": name, "description": desc, "size": os.path.getsize(path)})
        return out

    @app.post("/api/samples/{name}", status_code=201)
    def load_sample(name: str):
        if name not in _SAMPLE_INFO:
            raise HTTPException(404, "unknown sample")
        path = os.path.join(SAMPLES_DIR, name)
        if not os.path.exists(path):
            raise HTTPException(404, "sample file is not installed")
        return ingest_file(path, name, move=False)

    # -- captures ----------------------------------------------------------------
    @app.get("/api/captures")
    def list_captures():
        return catalog.list()

    @app.post("/api/captures", status_code=201)
    async def upload_capture(request: Request, filename: str = Query("capture.pcap", max_length=300)):
        """Upload a capture as the raw request body (streamed to disk)."""
        limit = config.limits.max_upload_bytes
        declared = request.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > limit:
            raise HTTPException(413, f"capture exceeds the upload limit of {limit // (1024 * 1024)} MB")
        tmp_dir = os.path.join(catalog.data_dir, "incoming")
        os.makedirs(tmp_dir, exist_ok=True)
        tmp_path = os.path.join(tmp_dir, os.urandom(12).hex())
        size = 0
        checked = False
        try:
            with open(tmp_path, "wb") as f:
                async for chunk in request.stream():
                    if not chunk:
                        continue
                    if not checked and size + len(chunk) >= 4:
                        # reject non-captures before accepting gigabytes
                        f.write(chunk)
                        f.flush()
                        with open(tmp_path, "rb") as probe:
                            magic = probe.read(4)
                        if magic not in PCAP_MAGICS and magic != PCAPNG_MAGIC:
                            raise HTTPException(
                                415, "not a PCAP or PCAPNG file (unrecognised magic number)")
                        checked = True
                        size += len(chunk)
                        continue
                    size += len(chunk)
                    if size > limit:
                        raise HTTPException(
                            413, f"capture exceeds the upload limit of {limit // (1024 * 1024)} MB")
                    f.write(chunk)
            if not checked:
                raise HTTPException(400, "empty or truncated upload")
            return ingest_file(tmp_path, safe_filename(filename), move=True)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    @app.get("/api/captures/{cid}")
    def get_capture(cid: str):
        return capture_or_404(cid)

    @app.delete("/api/captures/{cid}", status_code=204)
    def delete_capture(cid: str):
        capture_or_404(cid)
        catalog.delete(cid)
        return Response(status_code=204)

    @app.post("/api/captures/{cid}/reanalyze", status_code=202)
    def reanalyze(cid: str):
        row = capture_or_404(cid)
        if row["status"] in ("queued", "processing"):
            raise HTTPException(409, "analysis already in progress")
        catalog.update(cid, status="queued", progress=0.0, stage="", error="")
        jobs.submit(cid)
        return catalog.get(cid)

    # -- analysis views ------------------------------------------------------------
    @app.get("/api/captures/{cid}/overview")
    def overview(cid: str):
        with open_store(cid) as s:
            return {
                "summary": s.summary(),
                "protocols": s.meta("protocols", []),
                "detectors": s.meta("detectors", []),
                "state_descriptions": s.meta("state_descriptions", {}),
                "top_hosts": s.hosts(sort="bytes", limit=10)["items"],
                "top_conversations": s.top_conversations(10),
                "top_services": s.top_services(10),
                "top_domains": s.top_domains(10),
                "findings": [{k: f[k] for k in ("id", "title", "severity", "confidence",
                                                "category", "summary", "hosts", "first_ts",
                                                "last_ts", "detector")}
                             for f in s.findings()],
            }

    @app.get("/api/captures/{cid}/timeline")
    def timeline(cid: str, buckets: int = Query(240, ge=10, le=2000),
                 t0: float | None = None, t1: float | None = None):
        with open_store(cid) as s:
            return s.timeline(buckets, t0, t1)

    @app.get("/api/captures/{cid}/topology")
    def topology(cid: str, max_edges: int = Query(300, ge=10, le=2000)):
        with open_store(cid) as s:
            return s.topology(max_edges)

    @app.get("/api/captures/{cid}/hosts")
    def hosts(cid: str, q: str = Query("", max_length=200), scope: str = Query("", max_length=20),
              sort: str = "bytes", order: str = "desc",
              limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
        with open_store(cid) as s:
            return s.hosts(q, scope, sort, order, limit, offset)

    @app.get("/api/captures/{cid}/hosts/{ip}")
    def host(cid: str, ip: str):
        with open_store(cid) as s:
            h = s.host(ip)
            if h is None:
                raise HTTPException(404, "host not found in this capture")
            h["timeline"] = s.host_timeline(ip)
            return h

    @app.get("/api/captures/{cid}/flows")
    def flows(cid: str, q: str = Query("", max_length=500), sort: str = "first_ts",
              order: str = "asc", limit: int = Query(100, ge=1, le=500),
              offset: int = Query(0, ge=0), t0: float | None = None, t1: float | None = None):
        with open_store(cid) as s:
            return s.flows(q, sort, order, limit, offset, t0, t1)

    @app.get("/api/captures/{cid}/flows/{flow_id}")
    def flow(cid: str, flow_id: int):
        with open_store(cid) as s:
            f = s.flow(flow_id)
            if f is None:
                raise HTTPException(404, "connection not found")
            return f

    @app.get("/api/captures/{cid}/packets")
    def packets(cid: str, q: str = Query("", max_length=500),
                limit: int = Query(200, ge=1, le=1000), offset: int = Query(0, ge=0),
                t0: float | None = None, t1: float | None = None):
        with open_store(cid) as s:
            return s.packets(q, limit, offset, t0, t1)

    @app.get("/api/captures/{cid}/packets/{no}")
    def packet(cid: str, no: int):
        with open_store(cid) as s:
            p = s.packet(no)
        if p is None:
            raise HTTPException(404, "packet not found")
        path = catalog.capture_file(cid)
        size = os.path.getsize(path)
        off, caplen = p["off"], min(p["caplen"], config.limits.max_packet_bytes)
        if off < 0 or off + caplen > size:
            raise HTTPException(500, "packet offset is outside the capture file")
        with open(path, "rb") as f:
            f.seek(off)
            data = f.read(caplen)
        p["layers"] = dissect(data, p["linktype"])
        p["hex"] = hexdump(data)
        return p

    @app.get("/api/captures/{cid}/dns")
    def dns(cid: str, q: str = Query("", max_length=200), host: str = Query("", max_length=64),
            limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
        with open_store(cid) as s:
            return s.dns(q, host, limit, offset)

    @app.get("/api/captures/{cid}/http")
    def http(cid: str, q: str = Query("", max_length=200), host: str = Query("", max_length=64),
             limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
        with open_store(cid) as s:
            return s.http(q, host, limit, offset)

    @app.get("/api/captures/{cid}/tls")
    def tls(cid: str, q: str = Query("", max_length=200), host: str = Query("", max_length=64),
            limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
        with open_store(cid) as s:
            return s.tls(q, host, limit, offset)

    @app.get("/api/captures/{cid}/findings")
    def findings(cid: str, severity: str = Query("", max_length=16),
                 detector: str = Query("", max_length=40), host: str = Query("", max_length=64)):
        with open_store(cid) as s:
            return s.findings(severity, detector, host)

    @app.get("/api/captures/{cid}/findings/{fid}")
    def finding(cid: str, fid: int):
        with open_store(cid) as s:
            f = s.finding(fid)
            if f is None:
                raise HTTPException(404, "finding not found")
            return f

    @app.get("/api/captures/{cid}/report")
    def report(cid: str, format: str = Query("html", pattern="^(html|md|json)$"),
               download: bool = False):
        row = capture_or_404(cid)
        with open_store(cid) as s:
            data = build_report(s)
        base = re.sub(r"[^\w.\-]", "_", os.path.splitext(row["filename"])[0])[:80] or "capture"
        headers = {}
        if download:
            headers["Content-Disposition"] = f'attachment; filename="netsleuth-report-{base}.{format}"'
        if format == "json":
            return JSONResponse(data, headers=headers)
        if format == "md":
            return PlainTextResponse(render_markdown(data), headers=headers,
                                     media_type="text/markdown; charset=utf-8")
        headers["Content-Security-Policy"] = _REPORT_CSP
        return HTMLResponse(render_html(data), headers=headers)

    @app.api_route("/api/{rest:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
                   include_in_schema=False)
    def api_not_found(rest: str):
        raise HTTPException(404, "unknown API endpoint")

    if os.path.isdir(WEB_DIR) and os.path.exists(os.path.join(WEB_DIR, "index.html")):
        app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")
    return app
