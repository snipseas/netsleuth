# NetSleuth

Network forensics and threat analysis for packet captures. NetSleuth ingests
PCAP / PCAPNG files, reconstructs what happened on the network (hosts,
connections, DNS, HTTP, TLS), runs a suite of behavioural detectors and
presents the result in an investigation interface and exportable reports.

It is built as a portfolio-grade security engineering project: the capture
parsers are written from scratch with hostile input in mind, every detection
carries evidence and caveats, and the parsers are cross-validated against
Wireshark's `tshark` in the test-suite.

> Findings are heuristic **indicators**, not verdicts. Each one states what was
> measured, how well it matches a known pattern (confidence), how much it would
> matter if true (severity) and which benign explanations fit the same data.

## Features

**Packet analysis engine**
- PCAP (micro/nanosecond, both byte orders) and PCAPNG (multiple sections and
  interfaces, per-interface timestamp resolution).
- Ethernet, 802.1Q/QinQ, PPPoE, Linux cooked (SLL/SLL2), raw IP and loopback
  link types; IPv4, IPv6 (extension headers), ARP, ICMP/ICMPv6, TCP, UDP.
- TCP session reconstruction: handshake/teardown state (Zeek-style `S0`, `SF`,
  `REJ`, `RSTO`, ...), retransmission and reordering detection, in-order stream
  reassembly for application parsing, 5-tuple reuse.
- DNS (UDP and TCP, query/response pairing, compression with loop protection),
  HTTP/1.x (keep-alive, pipelining, chunked bodies), TLS handshake metadata
  (SNI, ALPN, versions, cipher, JA3 / JA3S), SSH banners, FTP logins, QUIC
  recognition. Protocols identified from payload are distinguished from labels
  inferred from the port number.

**Threat detection** (modular; one class per detector)

| Detector | Looks for |
|---|---|
| `port_scan` | vertical scans, horizontal sweeps, UDP probing; names the technique (SYN, connect, FIN, NULL, Xmas) and lists the ports that answered |
| `dns_tunnel` | many unique, long, high-entropy subdomains under one domain, tunnel-friendly record types |
| `dns_suspicious` | NXDOMAIN bursts with algorithmic-looking names, bypass of the internal resolver, high-abuse TLDs |
| `unusual_outbound` | admin protocols leaving the network, ports tied to offensive tooling, uncommon ports, HTTP to bare IPs, TLS without SNI |
| `beaconing` | interval regularity (robust dispersion and skew), size consistency, coverage; periodic DNS lookups |
| `volume_anomaly` | lopsided uploads to external hosts, per-host volume outliers (median/MAD), bursts, half-open floods |
| `connection_patterns` | repeated failures, internal fan-out on admin ports, rapid repeated logins, cleartext credentials, long-lived sessions, conflicting ARP claims |

**Investigation interface** - capture library with background-analysis
progress, overview, detection centre, interactive force-directed topology,
zoomable traffic timeline with finding markers, host pages, connection explorer,
searchable packet table with per-layer dissection and hex view, report preview.
No third-party JavaScript; it works offline.

**Reports** - HTML (self-contained, prints to PDF), Markdown and JSON, with
executive summary, capture hash, hosts, communication patterns, findings with
evidence, recommendations and stated limitations.

## Install

Requires Python 3.10+.

```bash
python -m venv .venv
```

```bash
.venv/bin/pip install -e ".[dev]"
```

## Run

```bash
.venv/bin/netsleuth serve
```

Open <http://127.0.0.1:8600/>, then drop a capture on the page or load the
bundled sample `demo-incident.pcapng` (synthetic traffic containing every
behaviour the detectors look for).

Headless analysis, with an optional report:

```bash
.venv/bin/netsleuth analyze netsleuth/samples/demo-incident.pcapng --report report.html
```

`--report` accepts `.html`, `.md` or `.json`; `--json` prints summary and
findings to stdout for scripting. Exit status is 1 when the file is not a
capture.

### Try it on real captures

The bundled samples are synthetic. To test NetSleuth against real traffic,
the Wireshark project maintains a large public collection of captures covering
many protocols:

<https://wiki.wireshark.org/samplecaptures#dji-drones-control-protocol>

Download any `.pcap` / `.pcapng` file from that page and either drop it on the
web interface or run:

```bash
.venv/bin/netsleuth analyze path/to/capture.pcap --report report.html
```

Gzip-compressed captures (`.pcap.gz`) must be decompressed first. NetSleuth has
not yet been validated against this collection, so reports of captures that
are decoded incorrectly, crash the analysis or produce misleading findings are
especially welcome - please open an issue and name the capture file.

### Filter language (packets and connections)

Terms are AND-ed; prefix a term with `-` to negate it.

```
ip:10.0.5.23 port:443          proto:tcp flag:syn -flag:ack     app:dns
len>1400                       "Client Hello"                    -proto:arp
state:S0                       bytes>100000                      scope:external -dport:443
```

Values are always bound as SQL parameters and keys come from a whitelist.

### Configuration

| Variable | Default | Meaning |
|---|---|---|
| `NETSLEUTH_DATA_DIR` | `~/.local/share/netsleuth` | where captures and analysis databases are stored |
| `NETSLEUTH_MAX_UPLOAD_MB` | `2048` | largest accepted upload |
| `NETSLEUTH_MAX_PACKETS` | `5000000` | packets analysed per capture (the rest is skipped with a warning) |
| `NETSLEUTH_MAX_FLOWS` | `500000` | connection-table size |
| `NETSLEUTH_MAX_HOSTS` | `200000` | host-table size |
| `NETSLEUTH_INTERNAL_NETS` | *(empty)* | extra CIDR ranges to treat as internal, comma separated |

Detection thresholds live in `netsleuth/config.py` (`DetectionConfig`).

## Tests

```bash
.venv/bin/python -m pytest
```

93 tests covering the readers, decoders, protocol parsers (with mutation
fuzzing), stream reassembly, flow states, every detector (positive cases and
benign look-alikes), resource limits, the filter language (including SQL
injection attempts), the HTTP API and report escaping. If `tshark` is
installed, `tests/test_tshark.py` additionally checks that NetSleuth agrees
with Wireshark on per-packet fields, TCP stream count, DNS names and response
codes, HTTP requests, TLS SNI and JA3.

Fixtures are generated by `python -m netsleuth.devtools.gen_samples`
(deterministic; documentation address ranges and reserved example domains
only). `tests/fixtures/` also holds deliberately damaged captures.

## Security notes

- **No authentication.** The server binds to loopback by default and rejects
  requests with an unexpected `Host` header (DNS-rebinding protection). Do not
  expose it to a network without putting an authenticating proxy in front.
- Captures are untrusted input: all length fields are bounds-checked, analysis
  runs in a separate worker process, and resource use is capped.
- Strings taken from captures (hostnames, URIs, user agents) are only ever
  inserted as text in the interface and HTML-escaped in reports; a strict
  Content-Security-Policy is set as a second line of defence.
- Credentials are never stored: for FTP only the user name is kept, for HTTP
  only the authorization *scheme*.

## Known limitations

- Encrypted payloads are not decrypted; TLS analysis is handshake metadata
  only. TLS certificates are not parsed. QUIC is recognised but not dissected.
- IP fragments are not reassembled; tunnels (GRE, IP-in-IP, VXLAN, Teredo) are
  not decapsulated. 802.11 link types are counted but not decoded.
- HTTP/2 and HTTP/3 are not parsed (they are almost always inside TLS).
- Registered domains use a small built-in suffix list, not the full Public
  Suffix List.
- "Internal" means RFC 1918 / ULA / link-local plus configured ranges; an
  address ending in `.255` inside those ranges is assumed to be a broadcast.
- Beaconing inside one long-lived connection is not detected (the detector
  works on connection start times).
- Detection thresholds were tuned on synthetic traffic. Expect to adjust them
  for a real environment; there is no allow-list mechanism yet.
- Timestamps are stored as 64-bit floats (roughly 200 ns resolution).
- Throughput is about 75,000 packets per second on one core (measured: 505,015
  packets / 218 MB in 6.6 s, 260 MB peak memory). Multi-gigabyte captures work
  but take minutes.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the design.

## License

MIT
