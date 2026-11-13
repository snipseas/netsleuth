"""Per-capture SQLite store.

One database file holds everything derived from one capture. The analysis
worker writes it once; afterwards it is only read, which keeps concurrency
trivial (many readers, no writers).
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any, Iterable

from .query import parse_filter

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS packets (
    no INTEGER PRIMARY KEY, ts REAL NOT NULL, len INTEGER NOT NULL,
    caplen INTEGER NOT NULL, off INTEGER NOT NULL, linktype INTEGER NOT NULL,
    net TEXT, proto TEXT NOT NULL, src TEXT, dst TEXT, sport INTEGER,
    dport INTEGER, flags INTEGER, flow_id INTEGER, info TEXT);
CREATE TABLE IF NOT EXISTS flows (
    id INTEGER PRIMARY KEY, proto TEXT NOT NULL, src TEXT NOT NULL, sport INTEGER,
    dst TEXT NOT NULL, dport INTEGER, first_ts REAL, last_ts REAL, duration REAL,
    pkts_fwd INTEGER, pkts_rev INTEGER, bytes_fwd INTEGER, bytes_rev INTEGER,
    payload_fwd INTEGER, payload_rev INTEGER, state TEXT, app TEXT, app_by TEXT,
    sni TEXT, http_host TEXT, detail TEXT, retrans INTEGER, ooo INTEGER,
    syn_count INTEGER, flags_fwd INTEGER, flags_rev INTEGER,
    src_scope TEXT, dst_scope TEXT);
CREATE TABLE IF NOT EXISTS hosts (
    ip TEXT PRIMARY KEY, scope TEXT, mac TEXT, names TEXT,
    pkts_out INTEGER, pkts_in INTEGER, bytes_out INTEGER, bytes_in INTEGER,
    first_ts REAL, last_ts REAL, flows_out INTEGER, flows_in INTEGER,
    peers INTEGER, services TEXT, findings INTEGER DEFAULT 0, max_severity TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS dns (
    id INTEGER PRIMARY KEY, ts REAL, flow_id INTEGER, client TEXT, server TEXT,
    proto TEXT, transport TEXT, txid INTEGER, qname TEXT, qtype TEXT, rcode TEXT,
    answers TEXT, rtt REAL, qsize INTEGER, rsize INTEGER, answered INTEGER);
CREATE TABLE IF NOT EXISTS http (
    id INTEGER PRIMARY KEY, ts REAL, flow_id INTEGER, src TEXT, dst TEXT, dport INTEGER,
    method TEXT, host TEXT, uri TEXT, version TEXT, user_agent TEXT, referer TEXT,
    req_content_type TEXT, req_len INTEGER, auth_scheme TEXT, status INTEGER,
    resp_content_type TEXT, resp_len INTEGER, server TEXT);
CREATE TABLE IF NOT EXISTS tls (
    id INTEGER PRIMARY KEY, ts REAL, flow_id INTEGER, src TEXT, dst TEXT, dport INTEGER,
    sni TEXT, client_version TEXT, version TEXT, cipher TEXT, alpn TEXT,
    ja3 TEXT, ja3s TEXT);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY, detector TEXT, category TEXT, title TEXT,
    severity TEXT, sev_rank INTEGER, confidence REAL, summary TEXT,
    explanation TEXT, evidence TEXT, hosts TEXT, first_ts REAL, last_ts REAL,
    caveats TEXT, recommendations TEXT, mitre TEXT);
CREATE TABLE IF NOT EXISTS finding_hosts (finding_id INTEGER, ip TEXT);
CREATE TABLE IF NOT EXISTS timeline (
    ts INTEGER NOT NULL, proto TEXT NOT NULL, packets INTEGER, bytes INTEGER,
    PRIMARY KEY (ts, proto)) WITHOUT ROWID;
"""

INDEXES = """
CREATE INDEX IF NOT EXISTS ix_packets_flow ON packets(flow_id);
CREATE INDEX IF NOT EXISTS ix_packets_src ON packets(src);
CREATE INDEX IF NOT EXISTS ix_packets_dst ON packets(dst);
CREATE INDEX IF NOT EXISTS ix_packets_ts ON packets(ts);
CREATE INDEX IF NOT EXISTS ix_flows_src ON flows(src);
CREATE INDEX IF NOT EXISTS ix_flows_dst ON flows(dst);
CREATE INDEX IF NOT EXISTS ix_flows_ts ON flows(first_ts);
CREATE INDEX IF NOT EXISTS ix_dns_client ON dns(client);
CREATE INDEX IF NOT EXISTS ix_dns_flow ON dns(flow_id);
CREATE INDEX IF NOT EXISTS ix_http_src ON http(src);
CREATE INDEX IF NOT EXISTS ix_http_flow ON http(flow_id);
CREATE INDEX IF NOT EXISTS ix_tls_src ON tls(src);
CREATE INDEX IF NOT EXISTS ix_tls_flow ON tls(flow_id);
CREATE INDEX IF NOT EXISTS ix_fh_ip ON finding_hosts(ip);
"""

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

_FLOW_SORT = {
    "id": "f.id", "first_ts": "f.first_ts", "duration": "f.duration",
    "bytes": "(f.bytes_fwd + f.bytes_rev)", "packets": "(f.pkts_fwd + f.pkts_rev)",
    "src": "f.src", "dst": "f.dst", "dport": "f.dport", "app": "f.app",
    "state": "f.state", "bytes_fwd": "f.bytes_fwd", "bytes_rev": "f.bytes_rev",
}
_HOST_SORT = {
    "ip": "ip", "bytes": "(bytes_out + bytes_in)", "bytes_out": "bytes_out",
    "bytes_in": "bytes_in", "packets": "(pkts_out + pkts_in)", "peers": "peers",
    "flows": "(flows_out + flows_in)", "findings": "findings", "first_ts": "first_ts",
    "severity": "max_severity",
}
_JSON_COLS = ("evidence", "hosts", "caveats", "recommendations", "mitre",
              "answers", "names", "services")


def _rows(cur) -> list[dict]:
    cols = [c[0] for c in cur.description]
    out = []
    for row in cur.fetchall():
        d = dict(zip(cols, row))
        for k in _JSON_COLS:
            v = d.get(k)
            if isinstance(v, str) and v[:1] in "[{":
                try:
                    d[k] = json.loads(v)
                except ValueError:
                    pass
        out.append(d)
    return out


def _page(limit: int, offset: int, cap: int = 500) -> tuple[int, int]:
    return max(1, min(int(limit), cap)), max(0, int(offset))


class CaptureStore:
    def __init__(self, path: str, readonly: bool = False):
        self.path = path
        if readonly:
            self.db = sqlite3.connect(f"file:{path}?mode=ro", uri=True,
                                      check_same_thread=False)
            self.db.execute("PRAGMA query_only = ON")
        else:
            self.db = sqlite3.connect(path)
            self.db.executescript(
                "PRAGMA journal_mode = OFF; PRAGMA synchronous = OFF;"
                "PRAGMA temp_store = MEMORY; PRAGMA cache_size = -65536;")
            self.db.executescript(SCHEMA)

    def close(self) -> None:
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # ======================================================================
    # write side (analysis worker)
    # ======================================================================
    def add_packets(self, rows: list[tuple]) -> None:
        self.db.executemany(
            "INSERT INTO packets VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)

    def add_flows(self, rows: Iterable[tuple]) -> None:
        self.db.executemany(
            "INSERT INTO flows VALUES (" + ",".join("?" * 28) + ")", rows)

    def add_hosts(self, rows: Iterable[tuple]) -> None:
        self.db.executemany(
            "INSERT INTO hosts (ip, scope, mac, names, pkts_out, pkts_in, bytes_out,"
            " bytes_in, first_ts, last_ts, flows_out, flows_in, peers, services)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)

    def add_dns(self, rows: Iterable[tuple]) -> None:
        self.db.executemany(
            "INSERT INTO dns (ts, flow_id, client, server, proto, transport, txid, qname,"
            " qtype, rcode, answers, rtt, qsize, rsize, answered)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)

    def add_http(self, rows: Iterable[tuple]) -> None:
        self.db.executemany(
            "INSERT INTO http (ts, flow_id, src, dst, dport, method, host, uri, version,"
            " user_agent, referer, req_content_type, req_len, auth_scheme, status,"
            " resp_content_type, resp_len, server)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)

    def add_tls(self, rows: Iterable[tuple]) -> None:
        self.db.executemany(
            "INSERT INTO tls (ts, flow_id, src, dst, dport, sni, client_version, version,"
            " cipher, alpn, ja3, ja3s) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", rows)

    def add_findings(self, findings: list[dict]) -> None:
        for f in findings:
            cur = self.db.execute(
                "INSERT INTO findings (detector, category, title, severity, sev_rank,"
                " confidence, summary, explanation, evidence, hosts, first_ts, last_ts,"
                " caveats, recommendations, mitre) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (f["detector"], f["category"], f["title"], f["severity"],
                 SEVERITY_RANK.get(f["severity"], 0), f["confidence"], f["summary"],
                 f["explanation"], json.dumps(f["evidence"]), json.dumps(f["hosts"]),
                 f["first_ts"], f["last_ts"], json.dumps(f["caveats"]),
                 json.dumps(f["recommendations"]), json.dumps(f["mitre"])))
            fid = cur.lastrowid
            self.db.executemany("INSERT INTO finding_hosts VALUES (?, ?)",
                                [(fid, ip) for ip in f["hosts"]])
        self.db.execute(
            "UPDATE hosts SET findings = (SELECT COUNT(*) FROM finding_hosts fh WHERE fh.ip = hosts.ip),"
            " max_severity = COALESCE((SELECT f.severity FROM findings f JOIN finding_hosts fh"
            "   ON fh.finding_id = f.id WHERE fh.ip = hosts.ip ORDER BY f.sev_rank DESC LIMIT 1), '')")

    def build_indexes(self) -> None:
        self.db.executescript(INDEXES)

    def build_timeline(self) -> None:
        """Aggregate packets into 1-second buckets labelled by protocol.

        The label is the flow's application protocol when one was identified
        or inferred, otherwise the transport/network protocol of the packet.
        """
        self.db.execute("DELETE FROM timeline")
        self.db.execute(
            "INSERT INTO timeline (ts, proto, packets, bytes) "
            "SELECT CAST(p.ts AS INTEGER), COALESCE(NULLIF(f.app, ''), p.proto),"
            " COUNT(*), SUM(p.len) FROM packets p LEFT JOIN flows f ON f.id = p.flow_id"
            " GROUP BY 1, 2")

    def protocol_hierarchy(self) -> list[dict]:
        cur = self.db.execute(
            "SELECT COALESCE(p.net, 'unknown') AS net,"
            " CASE WHEN p.proto = p.net THEN '' ELSE p.proto END AS transport,"
            " COALESCE(f.app, '') AS app, COALESCE(f.app_by, '') AS app_by,"
            " COUNT(*) AS packets, SUM(p.len) AS bytes"
            " FROM packets p LEFT JOIN flows f ON f.id = p.flow_id GROUP BY 1, 2, 3, 4")
        return _rows(cur)

    def set_meta(self, key: str, value: Any) -> None:
        self.db.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)",
                        (key, json.dumps(value)))

    def commit(self) -> None:
        self.db.commit()

    # ======================================================================
    # read side (API, reports)
    # ======================================================================
    def meta(self, key: str, default: Any = None) -> Any:
        row = self.db.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def summary(self) -> dict:
        return self.meta("summary", {})

    def timeline(self, buckets: int = 240, t0: float | None = None,
                 t1: float | None = None) -> dict:
        buckets = max(10, min(int(buckets), 2000))
        lo, hi = self.db.execute("SELECT MIN(ts), MAX(ts) FROM timeline").fetchone()
        if lo is None:
            return {"start": 0, "width": 1, "buckets": 0, "series": {}}
        start = max(lo, int(t0)) if t0 is not None else lo
        end = min(hi, int(t1)) if t1 is not None else hi
        if end < start:
            end = start
        span = end - start + 1
        width = max(1, -(-span // buckets))
        n = -(-span // width)
        cur = self.db.execute(
            "SELECT (ts - ?) / ? AS b, proto, SUM(packets), SUM(bytes) FROM timeline"
            " WHERE ts BETWEEN ? AND ? GROUP BY b, proto", (start, width, start, end))
        series: dict[str, dict] = {}
        for b, proto, pk, by in cur:
            s = series.get(proto)
            if s is None:
                s = series[proto] = {"packets": [0] * n, "bytes": [0] * n}
            s["packets"][b] = pk
            s["bytes"][b] = by
        return {"start": start, "width": width, "buckets": n, "series": series}

    def host_timeline(self, ip: str, buckets: int = 120) -> dict:
        s = self.summary()
        start, end = int(s.get("start_ts") or 0), int(s.get("end_ts") or 0)
        span = max(1, end - start + 1)
        buckets = max(10, min(int(buckets), 600))
        width = max(1, -(-span // buckets))
        n = -(-span // width)
        out = {"start": start, "width": width, "buckets": n,
               "sent": [0] * n, "received": [0] * n}
        for col, key in (("src", "sent"), ("dst", "received")):
            cur = self.db.execute(
                f"SELECT CAST((ts - ?) / ? AS INTEGER) AS b, SUM(len) FROM packets"
                f" WHERE {col} = ? GROUP BY b", (start, width, ip))
            for b, by in cur:
                if 0 <= b < n:
                    out[key][b] = by
        return out

    # -- hosts -------------------------------------------------------------
    def hosts(self, q: str = "", scope: str = "", sort: str = "bytes",
              order: str = "desc", limit: int = 100, offset: int = 0) -> dict:
        where, params = [], []
        if q:
            like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            where.append("(ip LIKE ? ESCAPE '\\' OR names LIKE ? ESCAPE '\\' OR mac LIKE ? ESCAPE '\\')")
            params += [like, like, like]
        if scope:
            where.append("scope = ?")
            params.append(scope)
        w = (" WHERE " + " AND ".join(where)) if where else ""
        col = _HOST_SORT.get(sort, _HOST_SORT["bytes"])
        if sort == "severity":
            col = ("CASE max_severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 "
                   "WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END")
        direction = "ASC" if order == "asc" else "DESC"
        limit, offset = _page(limit, offset)
        total = self.db.execute(f"SELECT COUNT(*) FROM hosts{w}", params).fetchone()[0]
        cur = self.db.execute(
            f"SELECT * FROM hosts{w} ORDER BY {col} {direction}, ip LIMIT ? OFFSET ?",
            params + [limit, offset])
        return {"total": total, "items": _rows(cur)}

    def host(self, ip: str) -> dict | None:
        rows = _rows(self.db.execute("SELECT * FROM hosts WHERE ip = ?", (ip,)))
        if not rows:
            return None
        h = rows[0]
        db = self.db
        h["peer_list"] = _rows(db.execute(
            "SELECT peer, SUM(sent) AS bytes_sent, SUM(recv) AS bytes_received,"
            " SUM(n) AS flows, (SELECT scope FROM hosts WHERE ip = peer) AS scope,"
            " (SELECT names FROM hosts WHERE ip = peer) AS names FROM ("
            "  SELECT dst AS peer, bytes_fwd AS sent, bytes_rev AS recv, 1 AS n FROM flows WHERE src = ?"
            "  UNION ALL"
            "  SELECT src AS peer, bytes_rev AS sent, bytes_fwd AS recv, 1 AS n FROM flows WHERE dst = ?)"
            " GROUP BY peer ORDER BY SUM(sent) + SUM(recv) DESC LIMIT 50", (ip, ip)))
        h["ports_contacted"] = _rows(db.execute(
            "SELECT proto, dport AS port, app, COUNT(*) AS flows, COUNT(DISTINCT dst) AS hosts,"
            " SUM(bytes_fwd + bytes_rev) AS bytes FROM flows WHERE src = ? AND proto IN ('TCP','UDP')"
            " GROUP BY proto, dport ORDER BY flows DESC LIMIT 40", (ip,)))
        h["ports_served"] = _rows(db.execute(
            "SELECT proto, dport AS port, app, COUNT(*) AS flows, COUNT(DISTINCT src) AS clients,"
            " SUM(bytes_fwd + bytes_rev) AS bytes FROM flows WHERE dst = ? AND proto IN ('TCP','UDP')"
            " AND (state IN ('SF','S1','S2','S3','RSTO','RSTR','REPLIED') OR payload_rev > 0)"
            " GROUP BY proto, dport ORDER BY flows DESC LIMIT 40", (ip,)))
        h["dns_queries"] = _rows(db.execute(
            "SELECT qname, qtype, COUNT(*) AS count, MAX(rcode) AS rcode FROM dns"
            " WHERE client = ? AND qname != '' GROUP BY qname, qtype ORDER BY count DESC LIMIT 50", (ip,)))
        h["http"] = _rows(db.execute(
            "SELECT host, method, COUNT(*) AS count, MAX(user_agent) AS user_agent FROM http"
            " WHERE src = ? GROUP BY host, method ORDER BY count DESC LIMIT 30", (ip,)))
        h["tls"] = _rows(db.execute(
            "SELECT sni, dst, dport, version, ja3, COUNT(*) AS count FROM tls"
            " WHERE src = ? GROUP BY sni, dst, dport, ja3 ORDER BY count DESC LIMIT 30", (ip,)))
        h["finding_list"] = _rows(db.execute(
            "SELECT f.id, f.title, f.severity, f.confidence, f.summary, f.category FROM findings f"
            " JOIN finding_hosts fh ON fh.finding_id = f.id WHERE fh.ip = ?"
            " ORDER BY f.sev_rank DESC, f.confidence DESC", (ip,)))
        h["states"] = _rows(db.execute(
            "SELECT state, COUNT(*) AS flows FROM flows WHERE src = ? AND proto = 'TCP'"
            " GROUP BY state ORDER BY flows DESC", (ip,)))
        return h

    # -- flows -------------------------------------------------------------
    def flows(self, q: str = "", sort: str = "first_ts", order: str = "asc",
              limit: int = 100, offset: int = 0, t0: float | None = None,
              t1: float | None = None) -> dict:
        where, params = parse_filter(q, "flows")
        clauses = [where] if where else []
        if t0 is not None:
            clauses.append("f.last_ts >= ?")
            params.append(float(t0))
        if t1 is not None:
            clauses.append("f.first_ts <= ?")
            params.append(float(t1))
        w = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        col = _FLOW_SORT.get(sort, "f.first_ts")
        direction = "DESC" if order == "desc" else "ASC"
        limit, offset = _page(limit, offset)
        total = self.db.execute(f"SELECT COUNT(*) FROM flows f{w}", params).fetchone()[0]
        cur = self.db.execute(
            f"SELECT f.* FROM flows f{w} ORDER BY {col} {direction}, f.id LIMIT ? OFFSET ?",
            params + [limit, offset])
        return {"total": total, "items": _rows(cur)}

    def flow(self, flow_id: int) -> dict | None:
        rows = _rows(self.db.execute("SELECT * FROM flows WHERE id = ?", (flow_id,)))
        if not rows:
            return None
        f = rows[0]
        f["http"] = _rows(self.db.execute("SELECT * FROM http WHERE flow_id = ? LIMIT 100", (flow_id,)))
        f["tls"] = _rows(self.db.execute("SELECT * FROM tls WHERE flow_id = ? LIMIT 5", (flow_id,)))
        f["dns"] = _rows(self.db.execute("SELECT * FROM dns WHERE flow_id = ? LIMIT 100", (flow_id,)))
        f["packets"] = _rows(self.db.execute(
            "SELECT no, ts, len, src, dst, sport, dport, flags, proto, info FROM packets"
            " WHERE flow_id = ? ORDER BY no LIMIT 200", (flow_id,)))
        return f

    # -- packets -----------------------------------------------------------
    def packets(self, q: str = "", limit: int = 200, offset: int = 0,
                t0: float | None = None, t1: float | None = None,
                count: bool = True) -> dict:
        where, params = parse_filter(q, "packets")
        clauses = [where] if where else []
        if t0 is not None:
            clauses.append("p.ts >= ?")
            params.append(float(t0))
        if t1 is not None:
            clauses.append("p.ts <= ?")
            params.append(float(t1))
        w = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        limit, offset = _page(limit, offset, cap=1000)
        total = None
        if count:
            if not clauses:
                total = self.summary().get("packets")
            if total is None:
                total = self.db.execute(f"SELECT COUNT(*) FROM packets p{w}", params).fetchone()[0]
        cur = self.db.execute(
            "SELECT p.no, p.ts, p.len, p.caplen, p.net, p.proto, p.src, p.dst, p.sport,"
            " p.dport, p.flags, p.flow_id, p.info,"
            " (SELECT app FROM flows WHERE id = p.flow_id) AS app"
            f" FROM packets p{w} ORDER BY p.no LIMIT ? OFFSET ?", params + [limit, offset])
        return {"total": total, "items": _rows(cur)}

    def packet(self, no: int) -> dict | None:
        rows = _rows(self.db.execute("SELECT * FROM packets WHERE no = ?", (no,)))
        return rows[0] if rows else None

    # -- application records -------------------------------------------------
    def _records(self, table: str, cols: tuple[str, ...], q: str, order: str,
                 limit: int, offset: int, host: str = "", host_cols=("src", "dst")) -> dict:
        where, params = [], []
        if q:
            like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            where.append("(" + " OR ".join(f"{c} LIKE ? ESCAPE '\\'" for c in cols) + ")")
            params += [like] * len(cols)
        if host:
            where.append("(" + " OR ".join(f"{c} = ?" for c in host_cols) + ")")
            params += [host] * len(host_cols)
        w = (" WHERE " + " AND ".join(where)) if where else ""
        limit, offset = _page(limit, offset)
        total = self.db.execute(f"SELECT COUNT(*) FROM {table}{w}", params).fetchone()[0]
        cur = self.db.execute(
            f"SELECT * FROM {table}{w} ORDER BY {order} LIMIT ? OFFSET ?", params + [limit, offset])
        return {"total": total, "items": _rows(cur)}

    def dns(self, q="", host="", limit=100, offset=0) -> dict:
        return self._records("dns", ("qname", "client", "server", "answers", "rcode", "qtype"),
                             q, "ts, id", limit, offset, host, ("client", "server"))

    def http(self, q="", host="", limit=100, offset=0) -> dict:
        return self._records("http", ("host", "uri", "user_agent", "src", "dst", "method"),
                             q, "ts, id", limit, offset, host)

    def tls(self, q="", host="", limit=100, offset=0) -> dict:
        return self._records("tls", ("sni", "src", "dst", "ja3", "ja3s", "version"),
                             q, "ts, id", limit, offset, host)

    # -- findings ----------------------------------------------------------
    def findings(self, severity: str = "", detector: str = "", host: str = "") -> list[dict]:
        where, params = [], []
        if severity:
            where.append("f.severity = ?")
            params.append(severity)
        if detector:
            where.append("f.detector = ?")
            params.append(detector)
        if host:
            where.append("f.id IN (SELECT finding_id FROM finding_hosts WHERE ip = ?)")
            params.append(host)
        w = (" WHERE " + " AND ".join(where)) if where else ""
        return _rows(self.db.execute(
            f"SELECT f.* FROM findings f{w} ORDER BY f.sev_rank DESC, f.confidence DESC, f.id",
            params))

    def finding(self, fid: int) -> dict | None:
        rows = _rows(self.db.execute("SELECT * FROM findings WHERE id = ?", (fid,)))
        return rows[0] if rows else None

    # -- topology ----------------------------------------------------------
    def topology(self, max_edges: int = 300) -> dict:
        max_edges = max(10, min(int(max_edges), 2000))
        edges = _rows(self.db.execute(
            "SELECT MIN(src, dst) AS a, MAX(src, dst) AS b, COUNT(*) AS flows,"
            " SUM(bytes_fwd + bytes_rev) AS bytes, SUM(pkts_fwd + pkts_rev) AS packets,"
            " GROUP_CONCAT(DISTINCT CASE WHEN app != '' THEN app ELSE proto END) AS protos"
            " FROM flows GROUP BY a, b ORDER BY bytes DESC LIMIT ?", (max_edges,)))
        total_edges = self.db.execute(
            "SELECT COUNT(*) FROM (SELECT 1 FROM flows GROUP BY MIN(src, dst), MAX(src, dst))"
        ).fetchone()[0]
        ips = sorted({e["a"] for e in edges} | {e["b"] for e in edges})
        nodes: list[dict] = []
        for i in range(0, len(ips), 500):
            chunk = ips[i:i + 500]
            nodes += _rows(self.db.execute(
                "SELECT ip, scope, names, bytes_out, bytes_in, peers, findings, max_severity"
                f" FROM hosts WHERE ip IN ({','.join('?' * len(chunk))})", chunk))
        known = {n["ip"] for n in nodes}
        for ip in ips:
            if ip not in known:
                nodes.append({"ip": ip, "scope": "other", "names": [], "bytes_out": 0,
                              "bytes_in": 0, "peers": 0, "findings": 0, "max_severity": ""})
        return {"nodes": nodes, "edges": edges, "total_edges": total_edges,
                "truncated": total_edges > len(edges)}

    # -- aggregates for overview / reports ---------------------------------
    def top_conversations(self, limit: int = 15) -> list[dict]:
        return _rows(self.db.execute(
            "SELECT MIN(src, dst) AS a, MAX(src, dst) AS b, COUNT(*) AS flows,"
            " SUM(bytes_fwd + bytes_rev) AS bytes, SUM(pkts_fwd + pkts_rev) AS packets,"
            " GROUP_CONCAT(DISTINCT CASE WHEN app != '' THEN app ELSE proto END) AS protos"
            " FROM flows GROUP BY a, b ORDER BY bytes DESC LIMIT ?", (limit,)))

    def top_services(self, limit: int = 15) -> list[dict]:
        return _rows(self.db.execute(
            "SELECT proto, dport AS port, MAX(app) AS app, COUNT(*) AS flows,"
            " COUNT(DISTINCT src) AS clients, COUNT(DISTINCT dst) AS servers,"
            " SUM(bytes_fwd + bytes_rev) AS bytes FROM flows WHERE proto IN ('TCP','UDP')"
            " GROUP BY proto, dport ORDER BY bytes DESC LIMIT ?", (limit,)))

    def top_domains(self, limit: int = 15) -> list[dict]:
        return _rows(self.db.execute(
            "SELECT qname, COUNT(*) AS queries, COUNT(DISTINCT client) AS clients FROM dns"
            " WHERE qname != '' AND proto = 'DNS' GROUP BY qname ORDER BY queries DESC LIMIT ?",
            (limit,)))

    def top_sources_in_window(self, t0: float, t1: float, limit: int = 5) -> list[tuple]:
        return self.db.execute(
            "SELECT src, SUM(len) AS b FROM packets WHERE ts >= ? AND ts < ? AND src IS NOT NULL"
            " GROUP BY src ORDER BY b DESC LIMIT ?", (t0, t1, limit)).fetchall()

    def second_series(self) -> list[tuple]:
        return self.db.execute(
            "SELECT ts, SUM(packets), SUM(bytes) FROM timeline GROUP BY ts ORDER BY ts").fetchall()
