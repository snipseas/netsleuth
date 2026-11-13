# NetSleuth architecture

## Layers

```
capture file
     │
     ▼
┌──────────┐  RawPacket   ┌──────────┐  Packet   ┌────────────────────┐
│ ingest   │ ───────────▶ │ ingest   │ ────────▶ │ analysis           │
│ reader   │              │ decode   │           │ FlowTracker, hosts │
└──────────┘              └──────────┘           └─────────┬──────────┘
                                                           │ flows, DNS/HTTP/TLS records
                    ┌──────────────────────────────────────┤
                    ▼                                      ▼
            ┌──────────────┐                       ┌──────────────┐
            │ storage      │ ◀──── findings ────── │ detect       │
            │ CaptureStore │                       │ 7 detectors  │
            └──────┬───────┘                       └──────────────┘
                   │ read-only
        ┌──────────┴──────────┐
        ▼                     ▼
┌──────────────┐      ┌──────────────┐
│ server (API) │      │ report       │
│ + web UI     │      │ HTML/MD/JSON │
└──────────────┘      └──────────────┘
```

Dependencies only point downwards/rightwards as drawn: `ingest` knows nothing
about flows, `detect` knows nothing about SQLite or HTTP, the API contains no
analysis logic.

| Package | Responsibility |
|---|---|
| `netsleuth/ingest` | `reader.py` (PCAP/PCAPNG framing), `decode.py` (L2-L4 hot path), `dns.py`, `http.py`, `tls.py` (application parsers), `dissect.py` (verbose single-packet field tree for the detail view) |
| `netsleuth/analysis` | `flows.py` (flow table, TCP state, stream reassembly, L7 identification), `addr.py` (internal/external classification, registered domains, service names), `pipeline.py` (orchestration) |
| `netsleuth/detect` | `base.py` (`Finding`, `AnalysisContext`, statistics helpers), one module per detector family, `engine.py` (registry and isolated execution) |
| `netsleuth/storage` | `store.py` (per-capture SQLite database: write side for the pipeline, query side for the API), `query.py` (filter language), `catalog.py` (capture list and job state) |
| `netsleuth/report` | report model and renderers |
| `netsleuth/server` | `app.py` (FastAPI routes, static UI), `jobs.py` (background workers) |
| `netsleuth/web` | the interface: plain ES modules, hand-written SVG charts and canvas topology |
| `netsleuth/devtools` | `pcapgen.py` (independent packet/capture writer), `gen_samples.py` (samples and fixtures) |

## Technology choices

- **Pure-Python parsers instead of scapy/pyshark.** Writing the decoders is
  the point of the project, it removes a large dependency from the trust
  boundary that handles hostile input, and it is fast enough (about 75k
  packets/s) because the hot path extracts only what later stages need.
  Correctness is checked against tshark rather than assumed.
- **SQLite, one database per capture.** Analysis is write-once/read-many, so
  a single-writer embedded database fits exactly: bulk inserts with the journal
  off during analysis, indexes built afterwards, read-only connections for the
  API. Deleting a capture is deleting a directory. Raw packet bytes are not
  copied into the database; each packet row stores its byte offset in the
  original file, and the detail view re-reads and dissects on demand.
- **FastAPI + uvicorn** for the API; the only runtime dependencies.
- **No frontend framework or build step.** The UI is ~1,500 lines of ES
  modules. A forensic tool should run offline and its supply chain should be
  small; this also means nothing can load from a CDN.

## Processing pipeline

`analysis/pipeline.py::analyze_capture` runs, in order:

1. **Hash** the file (SHA-256, recorded in the report).
2. **Ingest**: stream packets, decode, update the flow tracker and host table,
   and batch-insert packet rows. Only flows, hosts and extracted application
   records stay in memory.
3. **Persist** flows, DNS/HTTP/TLS records and hosts; build indexes; aggregate
   the per-second timeline and protocol hierarchy in SQL. Labelling packets by
   application is done by joining to the flow, so the first packets of a
   connection (before its protocol was identified) are attributed correctly.
4. **Detect**: build an `AnalysisContext` and run every detector.
5. **Summarise**: counters, warnings and detector statistics.

### Flow tracking

A flow is keyed by protocol and the unordered endpoint pair; `src` is always
the originator (SYN sender; for mid-stream captures the higher port, except
that a segment without ACK is always treated as an originator probe). A new
SYN with a different ISN, or a SYN after FIN/RST, starts a new flow on the same
5-tuple; UDP flows end after 60 s idle.

Each TCP direction has a `Stream`: an in-order reassembly buffer that handles
retransmission, overlap, bounded reordering and sequence wrap-around. Parsers
*consume* from it, and `skip_ahead()` lets the HTTP parser frame a body without
buffering it. Buffers are capped (64 KiB per direction, 64 pending segments)
and released as soon as a parser has what it needs or gives up.

## Detection engine

A detector is a class with `name`, `category`, `description` and
`run(ctx) -> Iterable[Finding]`. To add one, write the class and append it to
`ALL_DETECTORS` in `detect/engine.py`. Detectors see only the in-memory
`AnalysisContext`, which keeps them unit-testable without a database.

The engine runs each detector in isolation: an exception becomes an analysis
warning and the remaining detectors still run. Output per detector is capped.

A `Finding` must carry: `evidence` (structured measurements and samples),
`severity` (info/low/medium/high - there is deliberately no "critical", since
no traffic heuristic justifies it on its own), `confidence` (0.05-0.95, capped
below certainty), `explanation`, `caveats` (benign explanations) and
`recommendations`. The test-suite asserts these are present for every finding.

Statistics are robust by default (median, MAD, quantile skew) so that the
outliers being hunted do not distort the baseline they are compared against.

## Background processing

Uploads are streamed to disk and registered in the catalogue as `queued`.
`JobManager` runs each analysis in a **separate process** (spawned
`ProcessPoolExecutor`): parsing is CPU-bound, so the API stays responsive, and
a worker killed by a pathological capture cannot take the server down - the
job is marked failed instead. Progress and state live in the catalogue
database (WAL), so they are visible across processes and survive restarts;
jobs found `queued`/`processing` at startup are re-queued. Deleting a capture
during analysis makes the worker stop at its next cancellation check. The
analysis database is written to a `.partial` file and renamed on success, so
readers never see a half-written store.

## Handling hostile input

| Threat | Mitigation |
|---|---|
| Record/block lengths that lie | validated against hard limits before any read; damage ends iteration with a warning and keeps what was readable |
| Truncated or garbage frames | every decoder checks lengths; a decode problem marks the packet malformed and never raises (fuzz-tested) |
| DNS compression loops, oversized names | pointer-hop and name-length limits |
| Memory exhaustion | caps on packets, flows, hosts, application records, stream buffers, pending segments, upload size |
| Non-captures uploaded | magic number checked on the first bytes of the upload stream |
| Path traversal | capture ids are server-generated UUIDs and re-validated; original filenames are sanitised and only used for display |
| SQL injection through filters | whitelist of keys, all values parameterised, read-only connections |
| Stored XSS via capture contents | UI inserts text nodes only; reports escape; strict CSP |
| DNS rebinding against localhost | `Host` header allow-list when bound to loopback |
| Credential retention | passwords and Authorization values are never stored |

## API

All under `/api` (interactive documentation at `/api/docs`):

`GET/POST /captures`, `GET/DELETE /captures/{id}`, `POST /captures/{id}/reanalyze`,
`GET /captures/{id}/overview | timeline | topology | hosts | hosts/{ip} | flows |
flows/{id} | packets | packets/{no} | dns | http | tls | findings |
findings/{id} | report?format=html|md|json`, `GET/POST /samples`.

Uploads are a raw request body (`POST /api/captures?filename=...`), which lets
the server stream to disk and enforce the size limit without a multipart
parser.
