"""The analysis pipeline: capture file in, populated CaptureStore out.

Stages, in order:
  1. ingest   - stream packets from the capture file and decode them
  2. analyse  - flow tracking / session reconstruction / host statistics
  3. persist  - write packets, flows, hosts and application records
  4. detect   - run the detector suite over the analysed data
  5. finalise - indexes, timeline aggregation and the capture summary

Packets are streamed; only flows, hosts and extracted application records
are held in memory, and those are bounded by `Limits`.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from typing import Callable

from .. import __version__
from ..config import Config
from ..detect.base import AnalysisContext
from ..detect.engine import run_detectors
from ..ingest.decode import (ACK, FIN, LINKTYPE_NAMES, PSH, RST, SUPPORTED_LINKTYPES,
                             SYN, URG, Packet, decode_packet)
from ..ingest.reader import CaptureReader, ReaderLimits
from ..storage.store import CaptureStore
from .addr import AddressClassifier
from .flows import STATE_DESCRIPTIONS, Flow, FlowTracker

Progress = Callable[[str, float], None]

_M32 = 0xFFFFFFFF
BATCH = 5000

_ICMP4 = {0: "Echo reply", 3: "Destination unreachable", 5: "Redirect", 8: "Echo request",
          11: "Time exceeded", 12: "Parameter problem"}
_ICMP4_UNREACH = {0: "network", 1: "host", 2: "protocol", 3: "port", 4: "fragmentation needed",
                  9: "network prohibited", 10: "host prohibited", 13: "admin prohibited"}
_ICMP6 = {1: "Destination unreachable", 2: "Packet too big", 3: "Time exceeded",
          128: "Echo request", 129: "Echo reply", 133: "Router solicitation",
          134: "Router advertisement", 135: "Neighbor solicitation",
          136: "Neighbor advertisement"}
_TLS_RECORDS = {0x14: "TLS Change Cipher Spec", 0x15: "TLS Alert", 0x16: "TLS Handshake",
                0x17: "TLS Application Data"}


class AnalysisCancelled(Exception):
    pass


class HostStat:
    __slots__ = ("ip", "scope", "mac", "pkts_out", "pkts_in", "bytes_out", "bytes_in",
                 "first_ts", "last_ts")

    def __init__(self, ip: str, scope: str, ts: float):
        self.ip = ip
        self.scope = scope
        self.mac = None
        self.pkts_out = self.pkts_in = 0
        self.bytes_out = self.bytes_in = 0
        self.first_ts = self.last_ts = ts


def _flag_letters(flags: int) -> str:
    out = []
    if flags & SYN: out.append("SYN")
    if flags & FIN: out.append("FIN")
    if flags & RST: out.append("RST")
    if flags & PSH: out.append("PSH")
    if flags & ACK: out.append("ACK")
    if flags & URG: out.append("URG")
    return ", ".join(out) or "none"


_flag_cache = {i: _flag_letters(i) for i in range(64)}


def describe(pkt: Packet, flow: Flow | None) -> str:
    """One-line human summary of a packet (the packet table's Info column)."""
    proto = pkt.proto
    if proto == "TCP" and pkt.flags is not None:
        plen = len(pkt.payload)
        seq, ack = pkt.seq, pkt.ack
        if flow is not None:
            fwd = flow.src == pkt.src and flow.sport == pkt.sport
            isn, peer = (flow.isn_fwd, flow.isn_rev) if fwd else (flow.isn_rev, flow.isn_fwd)
            if isn is not None:
                seq = (seq - isn) & _M32
            if peer is not None and pkt.flags & ACK:
                ack = (ack - peer) & _M32
            if plen and flow.app == "TLS":
                rec = _TLS_RECORDS.get(pkt.payload[0])
                if rec:
                    return f"{rec}  [{pkt.sport} → {pkt.dport}] Len={plen}"
        text = (f"{pkt.sport} → {pkt.dport} [{_flag_cache[pkt.flags & 0x3F]}] "
                f"Seq={seq} Ack={ack} Win={pkt.win} Len={plen}")
    elif proto == "UDP" and pkt.sport is not None:
        text = f"{pkt.sport} → {pkt.dport} Len={len(pkt.payload)}"
    elif proto == "ARP":
        if pkt.arp_op == 1:
            text = f"Who has {pkt.dst}? Tell {pkt.src}"
        elif pkt.arp_op == 2:
            text = f"{pkt.src} is at {pkt.arp_sha}"
        else:
            text = "ARP"
    elif proto == "ICMP" and pkt.icmp_type is not None:
        t = pkt.icmp_type
        text = _ICMP4.get(t) or f"Type {t}"
        if t == 3:
            text += f" ({_ICMP4_UNREACH.get(pkt.icmp_code, f'code {pkt.icmp_code}')})"
    elif proto == "ICMPv6" and pkt.icmp_type is not None:
        text = _ICMP6.get(pkt.icmp_type) or f"Type {pkt.icmp_type}"
    elif pkt.frag:
        text = f"Fragmented IP packet ({proto}), not reassembled"
    else:
        text = proto or ""
    if pkt.malformed:
        text = f"[malformed: {pkt.malformed}] {text}"
    return text


def file_sha256(path: str, progress: Progress | None = None) -> str:
    h = hashlib.sha256()
    size = os.path.getsize(path) or 1
    done = 0
    with open(path, "rb") as f:
        while True:
            chunk = f.read(4 * 1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
            done += len(chunk)
            if progress:
                progress("hashing", done / size)
    return h.hexdigest()


def analyze_capture(path: str, db_path: str, config: Config | None = None,
                    progress: Progress | None = None,
                    cancelled: Callable[[], bool] | None = None,
                    filename: str | None = None) -> dict:
    """Analyse `path` and write the results into a new store at `db_path`.

    Returns the capture summary. Raises CaptureFormatError when the file is
    not a capture at all and AnalysisCancelled when `cancelled()` turns true.
    """
    config = config or Config()
    limits = config.limits
    progress = progress or (lambda stage, frac: None)
    started = time.time()
    warnings: list[str] = []

    sha256 = file_sha256(path, progress)
    reader = CaptureReader(path, ReaderLimits(max_packet_bytes=limits.max_packet_bytes))
    file_size = reader.file_size or 1
    addr = AddressClassifier(config.detection.internal_networks)
    tracker = FlowTracker(limits)
    hosts: dict[str, HostStat] = {}
    arp: dict[str, set] = {}
    counters = {"malformed": 0, "fragments": 0, "truncated": 0, "unsupported_link": 0,
                "vlan": 0, "hosts_dropped": 0}
    total_bytes = 0
    first_ts = last_ts = None
    out_of_order_ts = 0
    n = 0

    store = CaptureStore(db_path)
    try:
        rows: list[tuple] = []
        add_packets = store.add_packets
        update = tracker.update
        scope = addr.scope
        max_hosts = limits.max_hosts
        max_packets = limits.max_packets
        with reader:
            for raw in reader:
                n += 1
                if n > max_packets:
                    n -= 1
                    warnings.append(
                        f"capture exceeds the configured limit of {max_packets:,} packets; "
                        "analysis covers the first part of the file only")
                    break
                ts = raw.ts
                pkt = decode_packet(raw.no, ts, raw.data, raw.wirelen, raw.linktype, raw.offset)
                if first_ts is None:
                    first_ts = last_ts = ts
                elif ts > last_ts:
                    last_ts = ts
                elif ts < first_ts:
                    first_ts = ts
                    out_of_order_ts += 1
                wirelen = raw.wirelen
                total_bytes += wirelen
                if pkt.malformed:
                    counters["malformed"] += 1
                if pkt.frag:
                    counters["fragments"] += 1
                if raw.caplen < wirelen:
                    counters["truncated"] += 1
                if pkt.vlan is not None:
                    counters["vlan"] += 1
                if pkt.net == "UNSUPPORTED-LINK":
                    counters["unsupported_link"] += 1

                flow = update(pkt)

                src, dst = pkt.src, pkt.dst
                if src is not None:
                    h = hosts.get(src)
                    if h is None:
                        if len(hosts) < max_hosts:
                            h = hosts[src] = HostStat(src, scope(src), ts)
                        else:
                            counters["hosts_dropped"] += 1
                    if h is not None:
                        h.pkts_out += 1
                        h.bytes_out += wirelen
                        h.last_ts = ts
                        if h.mac is None and pkt.src_mac and h.scope == "internal":
                            h.mac = pkt.src_mac
                if dst is not None:
                    h = hosts.get(dst)
                    if h is None:
                        if len(hosts) < max_hosts:
                            h = hosts[dst] = HostStat(dst, scope(dst), ts)
                    if h is not None:
                        h.pkts_in += 1
                        h.bytes_in += wirelen
                        h.last_ts = ts
                if pkt.arp_sha is not None and src and src != "0.0.0.0":
                    macs = arp.get(src)
                    if macs is None:
                        if len(arp) < max_hosts:
                            arp[src] = {pkt.arp_sha}
                    elif len(macs) < 8:
                        macs.add(pkt.arp_sha)

                rows.append((
                    raw.no, ts, wirelen, raw.caplen, raw.offset, raw.linktype,
                    pkt.net, pkt.proto, src, dst, pkt.sport, pkt.dport, pkt.flags,
                    flow.id if flow is not None else None,
                    pkt.info or describe(pkt, flow)))
                if len(rows) >= BATCH:
                    add_packets(rows)
                    rows = []
                    if cancelled is not None and cancelled():
                        raise AnalysisCancelled()
                    progress("parsing", min(1.0, reader.bytes_read / file_size))
            if rows:
                add_packets(rows)
        warnings.extend(reader.warnings)
        progress("parsing", 1.0)

        # ---- analysis results -------------------------------------------
        tracker.finalize()
        flows = tracker.flows
        progress("indexing", 0.0)
        store.add_flows(_flow_rows(flows, addr))
        store.add_dns((
            q.ts, q.flow_id, q.client, q.server, q.proto, q.transport, q.txid, q.qname,
            q.qtype, q.rcode, json.dumps(q.answers), q.rtt, q.qsize, q.rsize, int(q.answered))
            for q in tracker.dns)
        store.add_http((
            t.ts, t.flow_id, t.src, t.dst, t.dport, t.method, t.host, t.uri, t.version,
            t.user_agent, t.referer, t.req_content_type, t.req_len, t.auth_scheme, t.status,
            t.resp_content_type, t.resp_len, t.server) for t in tracker.http)
        store.add_tls((
            t.ts, t.flow_id, t.src, t.dst, t.dport, t.sni, t.client_version, t.version,
            t.cipher, t.alpn, t.ja3, t.ja3s) for t in tracker.tls)

        names = _merge_names(tracker, flows)
        store.add_hosts(_host_rows(hosts, flows, names))
        if cancelled is not None and cancelled():
            raise AnalysisCancelled()
        progress("indexing", 0.3)
        store.build_indexes()
        progress("indexing", 0.6)
        store.build_timeline()
        hierarchy = store.protocol_hierarchy()
        store.commit()
        progress("indexing", 1.0)

        # ---- detection ---------------------------------------------------
        progress("detecting", 0.0)
        ctx = AnalysisContext(
            flows=flows, dns=tracker.dns, http=tracker.http, tls=tracker.tls,
            hosts=hosts, names=names, arp=arp,
            icmp_unreachable=tracker.icmp_unreachable,
            series=store.second_series(),
            start_ts=first_ts or 0.0, end_ts=last_ts or 0.0,
            addr=addr, config=config.detection,
            top_sources=lambda t0, t1: store.top_sources_in_window(t0, t1))
        findings, detector_stats, det_warnings = run_detectors(ctx)
        warnings.extend(det_warnings)
        store.add_findings(findings)
        progress("detecting", 1.0)

        # ---- summary -------------------------------------------------------
        if tracker.flows_dropped:
            warnings.append(
                f"flow table limit ({limits.max_flows:,}) reached; "
                f"{tracker.flows_dropped:,} packets were not assigned to a connection")
        if tracker.records_dropped:
            warnings.append(
                f"{tracker.records_dropped:,} application records exceeded the per-table "
                "limit and were not stored")
        if counters["hosts_dropped"]:
            warnings.append(f"host table limit ({limits.max_hosts:,}) reached; "
                            "statistics for additional addresses were not kept")
        if counters["unsupported_link"]:
            unsupported = sorted(lt for lt in reader.linktypes if lt not in SUPPORTED_LINKTYPES)
            warnings.append(
                f"{counters['unsupported_link']:,} packets use an unsupported link type "
                f"({', '.join(LINKTYPE_NAMES.get(lt, str(lt)) for lt in unsupported)}) "
                "and were counted but not decoded")
        if counters["truncated"]:
            warnings.append(
                f"{counters['truncated']:,} packets were captured with a snap length shorter "
                "than the packet; payload-based analysis is incomplete for them")
        if counters["fragments"]:
            warnings.append(
                f"{counters['fragments']:,} IP fragments were seen; fragments are not "
                "reassembled, so their transport payload is not analysed")
        if out_of_order_ts:
            warnings.append(f"{out_of_order_ts:,} packets carry timestamps earlier than the "
                            "first packet (merged or re-ordered capture)")

        sev_counts = {s: 0 for s in ("high", "medium", "low", "info")}
        for f in findings:
            sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1
        scopes: dict[str, int] = {}
        for h in hosts.values():
            scopes[h.scope] = scopes.get(h.scope, 0) + 1
        proto_counts: dict[str, int] = {}
        for f in flows:
            proto_counts[f.proto] = proto_counts.get(f.proto, 0) + 1

        summary = {
            "filename": filename or os.path.basename(path),
            "file_size": reader.file_size,
            "sha256": sha256,
            "format": reader.format,
            "link_types": [LINKTYPE_NAMES.get(lt, f"DLT {lt}") for lt in sorted(reader.linktypes)],
            "packets": n,
            "bytes": total_bytes,
            "start_ts": first_ts,
            "end_ts": last_ts,
            "duration": (last_ts - first_ts) if first_ts is not None else 0.0,
            "flows": len(flows),
            "flows_by_proto": proto_counts,
            "hosts": len(hosts),
            "hosts_by_scope": scopes,
            "dns_records": len(tracker.dns),
            "http_records": len(tracker.http),
            "tls_records": len(tracker.tls),
            "findings": len(findings),
            "findings_by_severity": sev_counts,
            "malformed_packets": counters["malformed"],
            "fragments": counters["fragments"],
            "truncated_packets": counters["truncated"],
            "vlan_tagged_packets": counters["vlan"],
            "warnings": warnings,
            "analysis_seconds": round(time.time() - started, 2),
            "analyzed_at": time.time(),
            "netsleuth_version": __version__,
        }
        store.set_meta("summary", summary)
        store.set_meta("protocols", hierarchy)
        store.set_meta("detectors", detector_stats)
        store.set_meta("state_descriptions", STATE_DESCRIPTIONS)
        store.commit()
        progress("done", 1.0)
        return summary
    finally:
        store.close()


def _flow_rows(flows: list[Flow], addr: AddressClassifier):
    scope = addr.scope
    for f in flows:
        yield (f.id, f.proto, f.src, f.sport, f.dst, f.dport, f.first_ts, f.last_ts,
               f.last_ts - f.first_ts, f.pkts_fwd, f.pkts_rev, f.bytes_fwd, f.bytes_rev,
               f.payload_fwd, f.payload_rev, f.state, f.app, f.app_by, f.sni, f.http_host,
               f.detail, f.retrans, f.ooo, f.syn_count, f.flags_fwd, f.flags_rev,
               scope(f.src), scope(f.dst))


def _merge_names(tracker: FlowTracker, flows: list[Flow]) -> dict[str, set]:
    """ip -> names, from DNS answers plus TLS SNI and HTTP Host of servers."""
    names = {ip: set(v) for ip, v in tracker.names.items()}
    for f in flows:
        name = f.sni or f.http_host
        if name and not name.replace(".", "").replace(":", "").isdigit():
            s = names.get(f.dst)
            if s is None:
                if len(names) >= tracker.limits.max_hosts:
                    continue
                s = names[f.dst] = set()
            if len(s) < 8:
                s.add(name.split(":")[0].lower())
    return names


def _host_rows(hosts: dict[str, HostStat], flows: list[Flow], names: dict[str, set]):
    flows_out: dict[str, int] = {}
    flows_in: dict[str, int] = {}
    peers: dict[str, set] = {}
    services: dict[str, set] = {}
    for f in flows:
        flows_out[f.src] = flows_out.get(f.src, 0) + 1
        flows_in[f.dst] = flows_in.get(f.dst, 0) + 1
        p = peers.get(f.src)
        if p is None:
            p = peers[f.src] = set()
        if len(p) < 10_000:
            p.add(f.dst)
        p = peers.get(f.dst)
        if p is None:
            p = peers[f.dst] = set()
        if len(p) < 10_000:
            p.add(f.src)
        if f.proto in ("TCP", "UDP") and (
                (f.proto == "TCP" and f.synack) or (f.proto == "UDP" and f.pkts_rev)):
            s = services.get(f.dst)
            if s is None:
                s = services[f.dst] = set()
            if len(s) < 64:
                s.add(f"{f.dport}/{f.proto.lower()}" + (f" {f.app}" if f.app else ""))
    for h in hosts.values():
        yield (h.ip, h.scope, h.mac, json.dumps(sorted(names.get(h.ip, ()))),
               h.pkts_out, h.pkts_in, h.bytes_out, h.bytes_in, h.first_ts, h.last_ts,
               flows_out.get(h.ip, 0), flows_in.get(h.ip, 0), len(peers.get(h.ip, ())),
               json.dumps(sorted(services.get(h.ip, ()), key=_service_key)))


def _service_key(s: str):
    port = s.split("/", 1)[0]
    return (int(port) if port.isdigit() else 0, s)
