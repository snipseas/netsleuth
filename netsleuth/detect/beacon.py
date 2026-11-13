"""Beaconing detection from connection start-time regularity.

The scoring follows the approach popularised by RITA: periodic check-ins
show (a) low dispersion of inter-arrival times, (b) a symmetric interval
distribution and (c) near-constant request sizes. Each property is scored
0..1 with robust statistics so that a few missed or delayed check-ins do
not hide an otherwise regular pattern.
"""

from __future__ import annotations

from collections import defaultdict

from .base import (Detector, Finding, clamp, human_bytes, human_duration, mad,
                   median, mitre, quantile)

# Services that are periodic by design and not interesting as beacons.
_PERIODIC_BY_DESIGN = frozenset((("UDP", 123), ("UDP", 67), ("UDP", 68), ("UDP", 137),
                                 ("UDP", 138), ("UDP", 1900), ("UDP", 5353), ("UDP", 5355)))


def score_intervals(times: list[float]) -> dict | None:
    """Score how periodic a sorted list of event times is."""
    deltas = [b - a for a, b in zip(times, times[1:])]
    deltas = [d for d in deltas if d > 0]
    if len(deltas) < 4:
        return None
    s = sorted(deltas)
    med = median(s)
    if med <= 0:
        return None
    q1, q3 = quantile(s, 0.25), quantile(s, 0.75)
    # Bowley skewness: 0 for a symmetric distribution
    skew = ((q3 + q1 - 2 * med) / (q3 - q1)) if q3 > q1 else 0.0
    dispersion = mad(s, med)
    skew_score = 1.0 - abs(skew)
    disp_score = 1.0 - clamp(dispersion / med * 2.0)
    return {
        "median": med, "mad": dispersion, "jitter": dispersion / med,
        "skew_score": skew_score, "dispersion_score": disp_score,
        "timing_score": (skew_score + disp_score) / 2.0,
        "intervals": deltas,
    }


def score_sizes(sizes: list[int]) -> float:
    if not sizes:
        return 0.0
    med = median(sizes)
    if med <= 0:
        return 1.0 if max(sizes) == 0 else 0.0
    return 1.0 - clamp(mad(sizes, med) / med * 2.0)


class BeaconDetector(Detector):
    name = "beaconing"
    category = "Command and Control"
    description = ("Scores repeated connections between the same endpoints for "
                   "timing regularity and size consistency.")

    def run(self, ctx):
        cfg = ctx.config
        groups: dict[tuple, list] = defaultdict(list)
        for f in ctx.flows:
            if f.proto not in ("TCP", "UDP") or (f.proto, f.dport) in _PERIODIC_BY_DESIGN:
                continue
            if f.proto == "UDP" and f.dport == 53:
                continue        # per-name DNS periodicity is handled below
            if not ctx.addr.is_internal(f.src):
                continue
            if ctx.addr.scope(f.dst) in ("multicast", "broadcast"):
                continue
            if f.proto == "TCP" and f.failed and f.payload_fwd == 0:
                continue        # failed attempts are the connection-pattern detector's job
            groups[(f.src, f.dst, f.proto, f.dport)].append(f)

        for (src, dst, proto, dport), flows in groups.items():
            if len(flows) < cfg.beacon_min_connections:
                continue
            flows.sort(key=lambda f: f.first_ts)
            timing = score_intervals([f.first_ts for f in flows])
            if timing is None or timing["median"] < cfg.beacon_min_interval:
                continue
            size_score = score_sizes([f.payload_fwd for f in flows])
            span = flows[-1].first_ts - flows[0].first_ts
            coverage = clamp(span / ctx.duration) if ctx.duration > 0 else 0.0
            count_score = clamp(len(flows) / 20.0)
            score = (0.5 * timing["timing_score"] + 0.25 * size_score
                     + 0.15 * count_score + 0.10 * coverage)
            if score < cfg.beacon_min_score:
                continue
            external = ctx.addr.is_external(dst)
            name = flows[0].sni or flows[0].http_host or ctx.name_of(dst)
            severity = "medium" if external and score >= 0.85 else "low"
            yield Finding(
                detector=self.name, category=self.category,
                title="Periodic connections consistent with beaconing",
                severity=severity, confidence=clamp(score - 0.05),
                summary=(f"{src} connected to {dst}:{dport}/{proto.lower()}"
                         + (f" ({name})" if name else "")
                         + f" {len(flows)} times at a steady interval of about "
                         f"{human_duration(timing['median'])} "
                         f"(jitter {timing['jitter']:.1%})."),
                explanation=(
                    "Implants typically check in with their controller on a timer, which "
                    "produces connections that are evenly spaced and similar in size. This "
                    "pair scored highly on interval regularity "
                    f"({timing['timing_score']:.2f}) and request-size consistency "
                    f"({size_score:.2f}). Regularity alone does not indicate malice."),
                evidence={
                    "source": src, "destination": dst, "port": dport, "protocol": proto,
                    "destination_name": name or None,
                    "destination_scope": ctx.addr.scope(dst),
                    "connections": len(flows),
                    "median_interval_seconds": round(timing["median"], 2),
                    "interval_mad_seconds": round(timing["mad"], 3),
                    "jitter_ratio": round(timing["jitter"], 4),
                    "score": round(score, 2),
                    "score_components": {
                        "interval_dispersion": round(timing["dispersion_score"], 2),
                        "interval_symmetry": round(timing["skew_score"], 2),
                        "size_consistency": round(size_score, 2),
                        "connection_count": round(count_score, 2),
                        "capture_coverage": round(coverage, 2),
                    },
                    "median_bytes_sent": int(median([f.payload_fwd for f in flows])),
                    "median_bytes_received": int(median([f.payload_rev for f in flows])),
                    "first_intervals_seconds": [round(d, 2) for d in timing["intervals"][:15]],
                    "active_span_seconds": round(span, 1),
                    "application": flows[0].app or None,
                    "flow_ids": [f.id for f in flows[:20]],
                },
                hosts=[src, dst], first_ts=flows[0].first_ts, last_ts=flows[-1].last_ts,
                caveats=[
                    "Software update checks, telemetry, monitoring agents, mail polling and "
                    "keep-alives are all periodic by design.",
                    "Short captures contain few intervals; confidence grows with duration.",
                ],
                recommendations=[
                    f"Identify the process on {src} responsible and the owner of {dst}"
                    + (f" / {name}" if name else "") + ".",
                    "Compare against known-good periodic software in the environment; "
                    "allow-list what is expected.",
                    "If unexplained, capture the host's memory and process list before "
                    "containment so the implant can be analysed.",
                ],
                mitre=[mitre("T1071", "Application Layer Protocol"),
                       mitre("T1573", "Encrypted Channel")] if external else
                      [mitre("T1071", "Application Layer Protocol")])

        yield from self._dns_periodic(ctx)

    def _dns_periodic(self, ctx):
        cfg = ctx.config
        groups: dict[tuple, list] = defaultdict(list)
        for q in ctx.dns:
            if q.proto == "DNS" and q.qname and not q.qname.endswith((".arpa", ".local")):
                groups[(q.client, q.qname)].append(q.ts)
        for (client, qname), times in groups.items():
            if len(times) < max(cfg.beacon_min_connections, 10):
                continue
            times.sort()
            timing = score_intervals(times)
            if timing is None or timing["median"] < 5.0:
                continue
            score = 0.7 * timing["timing_score"] + 0.3 * clamp(len(times) / 30.0)
            if score < max(cfg.beacon_min_score, 0.85):
                continue
            yield Finding(
                detector=self.name, category=self.category,
                title="Periodic DNS lookups for a single name",
                severity="info", confidence=clamp(score - 0.25),
                summary=(f"{client} resolved {qname} {len(times)} times at a steady interval "
                         f"of about {human_duration(timing['median'])}."),
                explanation=(
                    "A name re-resolved on a fixed timer indicates software polling that "
                    "destination. It is listed as supporting context for connection-level "
                    "beaconing findings; on its own it is usually benign."),
                evidence={
                    "client": client, "name": qname, "lookups": len(times),
                    "median_interval_seconds": round(timing["median"], 2),
                    "jitter_ratio": round(timing["jitter"], 4),
                    "score": round(score, 2),
                },
                hosts=[client], first_ts=times[0], last_ts=times[-1],
                caveats=["Short DNS TTLs make any regularly used name appear periodic."],
                recommendations=["Correlate with connection findings for the same host."],
                mitre=[])
