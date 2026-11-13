"""Abnormal traffic volumes: lopsided uploads, per-host outliers, bursts and
half-open connection floods."""

from __future__ import annotations

from collections import defaultdict

from .base import (Detector, Finding, clamp, human_bytes, human_duration, mad,
                   median, mitre)


class VolumeAnomalyDetector(Detector):
    name = "volume_anomaly"
    category = "Abnormal Volume"
    description = ("Large one-directional uploads to external hosts, hosts whose "
                   "volume is a statistical outlier, short traffic bursts and "
                   "half-open connection floods.")

    def run(self, ctx):
        yield from self._uploads(ctx)
        yield from self._host_outliers(ctx)
        yield from self._bursts(ctx)
        yield from self._floods(ctx)

    def _uploads(self, ctx):
        cfg = ctx.config
        pairs: dict[tuple, list] = defaultdict(list)
        for f in ctx.flows:
            if ctx.addr.is_internal(f.src) and ctx.addr.is_external(f.dst):
                pairs[(f.src, f.dst)].append(f)
        for (src, dst), flows in pairs.items():
            sent = sum(f.payload_fwd for f in flows)
            recv = sum(f.payload_rev for f in flows)
            if sent < cfg.upload_min_bytes:
                continue
            ratio = sent / max(recv, 1)
            if ratio < cfg.upload_min_ratio:
                continue
            first = min(f.first_ts for f in flows)
            last = max(f.last_ts for f in flows)
            name = next((f.sni or f.http_host for f in flows if f.sni or f.http_host), "") \
                or ctx.name_of(dst)
            src_total = ctx.hosts[src].bytes_out if src in ctx.hosts else sent
            share = sent / max(src_total, 1)
            severity = ("high" if sent >= 500_000_000 else
                        "medium" if sent >= 20_000_000 else "low")
            conf = clamp(0.4 + 0.2 * min(1.0, ratio / 20) + 0.2 * min(1.0, share)
                         + (0.1 if not name else 0.0))
            yield Finding(
                detector=self.name, category=self.category,
                title="Large upload to an external host",
                severity=severity, confidence=conf,
                summary=(f"{src} sent {human_bytes(sent)} to {dst}"
                         + (f" ({name})" if name else "")
                         + f" and received {human_bytes(recv)} "
                         f"(upload/download ratio {ratio:.0f}:1)."),
                explanation=(
                    "Client traffic is normally download-heavy. A session that pushes far "
                    "more data out than it receives is what backups, uploads and data "
                    "exfiltration all look like on the wire; which one this is depends on "
                    "whether the destination and timing are expected."),
                evidence={
                    "source": src, "destination": dst, "destination_name": name or None,
                    "payload_bytes_sent": sent, "payload_bytes_received": recv,
                    "upload_download_ratio": round(ratio, 1),
                    "share_of_source_total_sent": round(share, 2),
                    "flows": len(flows),
                    "ports": sorted({f.dport for f in flows})[:10],
                    "applications": sorted({f.app for f in flows if f.app})[:5],
                    "duration_seconds": round(last - first, 1),
                    "flow_ids": [f.id for f in sorted(flows, key=lambda f: -f.payload_fwd)[:20]],
                },
                hosts=[src, dst], first_ts=first, last_ts=last,
                caveats=[
                    "Cloud backup, file sync, video conferencing and software publishing "
                    "produce the same asymmetry.",
                    "Payload bytes are counted from captured segments; retransmissions "
                    "slightly inflate the figure.",
                ],
                recommendations=[
                    f"Confirm whether {name or dst} is a sanctioned storage or collaboration "
                    "service for this host.",
                    "If not, determine what data was accessible to the host during the "
                    "transfer window and preserve the host for analysis.",
                ],
                mitre=[mitre("T1041", "Exfiltration Over C2 Channel"),
                       mitre("T1567", "Exfiltration Over Web Service")])

    def _host_outliers(self, ctx):
        internal = [h for h in ctx.hosts.values() if h.scope == "internal" and h.bytes_out > 0]
        if len(internal) < 8:
            return      # too few hosts for a meaningful population baseline
        values = [float(h.bytes_out) for h in internal]
        med = median(values)
        dev = mad(values, med)
        if dev <= 0:
            return
        for h in internal:
            z = 0.6745 * (h.bytes_out - med) / dev      # modified z-score
            if z < ctx.config.volume_outlier_z or h.bytes_out < 5_000_000:
                continue
            yield Finding(
                detector=self.name, category=self.category,
                title="Host is a traffic-volume outlier",
                severity="info", confidence=clamp(0.3 + 0.05 * min(z, 10)),
                summary=(f"{h.ip} sent {human_bytes(h.bytes_out)}, far above the internal "
                         f"host median of {human_bytes(med)} (modified z-score {z:.1f})."),
                explanation=(
                    "The host's transmitted volume was compared with all other internal "
                    "hosts in the capture using a median/MAD score, which is robust to the "
                    "outliers it is looking for. Servers and gateways are expected outliers."),
                evidence={
                    "host": h.ip, "bytes_sent": h.bytes_out, "bytes_received": h.bytes_in,
                    "population_median_sent": int(med), "population_mad": int(dev),
                    "modified_z_score": round(z, 1), "population_size": len(internal),
                },
                hosts=[h.ip], first_ts=h.first_ts, last_ts=h.last_ts,
                caveats=["File servers, proxies, gateways and backup sources are "
                         "legitimately the busiest hosts."],
                recommendations=["Check the host's role; investigate only if its role does "
                                 "not explain the volume."],
                mitre=[])

    def _bursts(self, ctx):
        series = ctx.series
        if len(series) < 30:
            return
        # fill gaps so that silent seconds count towards the baseline
        start, end = series[0][0], series[-1][0]
        if end - start > 7 * 86400:
            return
        per_sec = {s: b for s, _p, b in series}
        values = [float(per_sec.get(s, 0)) for s in range(start, end + 1)]
        med = median(values)
        dev = mad(values, med)
        scale = dev if dev > 0 else max(med * 0.1, 1.0)
        threshold = max(med + ctx.config.spike_z / 0.6745 * scale, 1_000_000.0)
        spikes = [(start + i, v) for i, v in enumerate(values) if v >= threshold]
        if not spikes:
            return
        # merge adjacent seconds into windows, report the largest few
        windows: list[list] = []
        for sec, v in spikes:
            if windows and sec - windows[-1][1] <= 2:
                windows[-1][1] = sec
                windows[-1][2] += v
                windows[-1][3] = max(windows[-1][3], v)
            else:
                windows.append([sec, sec, v, v])
        windows.sort(key=lambda w: -w[2])
        for t0, t1, total, peak in windows[:3]:
            top = []
            if ctx.top_sources is not None:
                top = [{"source": ip, "bytes": b} for ip, b in ctx.top_sources(t0, t1 + 1)]
            hosts = [t["source"] for t in top[:3]]
            yield Finding(
                detector=self.name, category=self.category,
                title="Traffic burst well above the capture baseline",
                severity="info", confidence=0.5,
                summary=(f"{human_bytes(total)} transferred within {t1 - t0 + 1}s "
                         f"(peak {human_bytes(peak)}/s against a median of "
                         f"{human_bytes(med)}/s)."),
                explanation=(
                    "Per-second byte counts were compared with the capture's own median "
                    "using a robust deviation estimate. Bursts mark moments worth looking "
                    "at - bulk transfers, floods, or scans - but are not suspicious in "
                    "themselves."),
                evidence={
                    "window_start": t0, "window_seconds": t1 - t0 + 1,
                    "bytes_in_window": int(total), "peak_bytes_per_second": int(peak),
                    "median_bytes_per_second": int(med),
                    "threshold_bytes_per_second": int(threshold),
                    "top_sources": top,
                },
                hosts=hosts, first_ts=float(t0), last_ts=float(t1 + 1),
                caveats=["Downloads, backups and streaming start-up all cause bursts."],
                recommendations=["Open the traffic timeline at this window and review the "
                                 "top sources."],
                mitre=[])

    def _floods(self, ctx):
        targets: dict[tuple, list] = defaultdict(list)
        for f in ctx.flows:
            if f.proto == "TCP" and f.state == "S0":
                targets[(f.dst, f.dport)].append(f)
        for (dst, port), flows in targets.items():
            if len(flows) < ctx.config.flood_min_half_open:
                continue
            first = min(f.first_ts for f in flows)
            last = max(f.last_ts for f in flows)
            window = max(last - first, 1e-6)
            rate = len(flows) / window
            if rate < 20:
                continue
            sources = {f.src for f in flows}
            yield Finding(
                detector=self.name, category=self.category,
                title="High rate of half-open connections to one service",
                severity="medium", confidence=clamp(0.4 + 0.3 * min(1.0, rate / 500)
                                                    + 0.2 * min(1.0, len(flows) / 5000)),
                summary=(f"{dst}:{port} received {len(flows)} unanswered connection attempts "
                         f"from {len(sources)} source address(es) in "
                         f"{human_duration(window)} ({rate:.0f}/s)."),
                explanation=(
                    "A large number of SYN segments to a single service with no completed "
                    "handshakes is the pattern of a SYN flood, which aims to exhaust the "
                    "server's connection table. It is also what a service outage looks like "
                    "from the client side."),
                evidence={
                    "target": dst, "port": port, "half_open_attempts": len(flows),
                    "distinct_sources": len(sources),
                    "attempts_per_second": round(rate, 1),
                    "window_seconds": round(window, 2),
                    "sample_sources": sorted(sources)[:15],
                },
                hosts=[dst] + sorted(sources)[:5], first_ts=first, last_ts=last,
                caveats=[
                    "If the service was down, legitimate clients retrying will produce "
                    "many unanswered SYNs.",
                    "A capture point that only sees one direction hides the replies.",
                ],
                recommendations=["Check service health during the window and whether "
                                 "source addresses are plausible or spoofed."],
                mitre=[mitre("T1499", "Endpoint Denial of Service")])
