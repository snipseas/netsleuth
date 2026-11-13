"""Port-scan detection: vertical scans, horizontal sweeps and UDP probing."""

from __future__ import annotations

from collections import defaultdict

from ..ingest.decode import ACK, FIN, PSH, RST, SYN, URG
from .base import Detector, Finding, clamp, mitre

_MITRE_SCAN = [mitre("T1046", "Network Service Discovery")]
_PROBE_STATES = frozenset(("S0", "REJ", "RSTOS0", "SH", "RSTO", "RSTR", "OTH"))


def _is_probe(f) -> bool:
    """A TCP flow that looks like a probe: no application payload exchanged
    and it never became a working session."""
    return (f.payload_fwd == 0 and f.payload_rev == 0
            and f.state in _PROBE_STATES and f.pkts_fwd <= 4)


def _technique(flows) -> str:
    """Name the scan technique from the flags the prober used."""
    kinds: dict[str, int] = defaultdict(int)
    for f in flows:
        ff = f.flags_fwd
        if ff & SYN:
            # full handshake then reset/close = connect() scan
            kinds["TCP connect" if (f.synack and f.est) else "SYN (half-open)"] += 1
        elif ff == 0:
            kinds["NULL"] += 1
        elif ff & (FIN | PSH | URG) == (FIN | PSH | URG):
            kinds["Xmas"] += 1
        elif ff & FIN and not ff & ACK:
            kinds["FIN"] += 1
        elif ff & ACK and not ff & (SYN | FIN | RST):
            kinds["ACK"] += 1
        else:
            kinds["other"] += 1
    return max(kinds, key=kinds.get) if kinds else "unknown"


def _port_sample(ports, limit: int = 30) -> list[int]:
    return sorted(ports)[:limit]


class PortScanDetector(Detector):
    name = "port_scan"
    category = "Reconnaissance"
    description = ("Flags sources that probe many ports on one host (vertical), "
                   "one port on many hosts (horizontal), or many UDP ports "
                   "without receiving replies.")

    def run(self, ctx):
        cfg = ctx.config
        by_pair: dict[tuple, list] = defaultdict(list)       # (src, dst) -> tcp flows
        by_port: dict[tuple, list] = defaultdict(list)       # (src, dport) -> tcp flows
        udp_pair: dict[tuple, list] = defaultdict(list)
        for f in ctx.flows:
            if f.proto == "TCP":
                if f.sport == 0 and f.dport == 0:
                    continue        # fragments without a transport header
                by_pair[(f.src, f.dst)].append(f)
                by_port[(f.src, f.dport)].append(f)
            elif f.proto == "UDP":
                udp_pair[(f.src, f.dst)].append(f)

        vertical_sources: dict[str, list] = defaultdict(list)
        for (src, dst), flows in by_pair.items():
            ports = {f.dport for f in flows}
            if len(ports) < cfg.scan_min_ports:
                continue
            probes = [f for f in flows if _is_probe(f)]
            probed_ports = {f.dport for f in probes}
            ratio = len(probed_ports) / len(ports)
            if len(probed_ports) < cfg.scan_min_ports or ratio < cfg.scan_min_failed_ratio:
                continue
            vertical_sources[src].append((dst, flows, probes, probed_ports, ratio))

        for src, targets in vertical_sources.items():
            targets.sort(key=lambda t: -len(t[3]))
            for dst, flows, probes, probed_ports, ratio in targets[:5]:
                yield self._vertical(ctx, src, dst, flows, probes, probed_ports, ratio)
            if len(targets) > 5:
                rest = targets[5:]
                yield Finding(
                    detector=self.name, category=self.category,
                    title="Possible port scanning of additional hosts",
                    severity="medium", confidence=0.7,
                    summary=(f"{src} probed {len(rest)} further hosts with the same pattern "
                             "(only the five most heavily probed are reported individually)."),
                    explanation="Aggregated to keep the alert list readable; see the "
                                "connection explorer for the individual probes.",
                    evidence={"source": src, "additional_targets": [t[0] for t in rest][:50],
                              "target_count": len(rest)},
                    hosts=[src] + [t[0] for t in rest][:20],
                    first_ts=min(f.first_ts for t in rest for f in t[2]),
                    last_ts=max(f.last_ts for t in rest for f in t[2]),
                    caveats=["Authorised vulnerability scanners and asset-discovery tools "
                             "produce identical traffic."],
                    recommendations=["Confirm whether the source is a sanctioned scanner."],
                    mitre=_MITRE_SCAN)

        # horizontal: one source, one port, many targets
        for (src, dport), flows in by_port.items():
            dsts = {f.dst for f in flows}
            if len(dsts) < cfg.scan_min_hosts:
                continue
            probes = [f for f in flows if _is_probe(f)]
            probed = {f.dst for f in probes}
            ratio = len(probed) / len(dsts)
            if len(probed) < cfg.scan_min_hosts or ratio < 0.5:
                continue
            responders = sorted({f.dst for f in flows if f.synack})
            first = min(f.first_ts for f in probes)
            last = max(f.last_ts for f in probes)
            conf = clamp(0.45 + 0.25 * min(1.0, len(probed) / 50) + 0.25 * ratio)
            yield Finding(
                detector=self.name, category=self.category,
                title=f"Possible horizontal sweep on TCP port {dport}",
                severity="medium" if len(probed) >= 25 else "low",
                confidence=conf,
                summary=(f"{src} attempted TCP port {dport} on {len(dsts)} distinct hosts; "
                         f"{len(probed)} attempts exchanged no data."),
                explanation=(
                    "One source contacting the same port on many hosts, with most attempts "
                    "unanswered or reset, is the signature of a service sweep: the source is "
                    "looking for hosts that expose this service rather than using it."),
                evidence={
                    "source": src, "port": dport, "targets_contacted": len(dsts),
                    "attempts_without_data": len(probed),
                    "probe_ratio": round(ratio, 2),
                    "technique": _technique(probes),
                    "hosts_that_answered": responders[:30],
                    "sample_targets": sorted(probed)[:30],
                    "window_seconds": round(last - first, 2),
                    "flow_ids": [f.id for f in probes[:20]],
                },
                hosts=[src] + responders[:10],
                first_ts=first, last_ts=last,
                caveats=[
                    "Inventory, monitoring and patch-management systems sweep ports by design.",
                    "A client retrying an unreachable service farm can look similar, though it "
                    "rarely touches this many distinct addresses.",
                ],
                recommendations=[
                    f"Identify what on {src} generated the sweep and whether it is authorised.",
                    f"Review the hosts that answered on port {dport} for subsequent sessions "
                    "from the same source.",
                ],
                mitre=_MITRE_SCAN)

        # UDP: many ports to one host, nothing coming back
        for (src, dst), flows in udp_pair.items():
            silent = [f for f in flows if f.pkts_rev == 0]
            ports = {f.dport for f in silent}
            if len(ports) < max(cfg.scan_min_ports, 20):
                continue
            if ctx.addr.scope(dst) in ("multicast", "broadcast"):
                continue
            unreach = ctx.icmp_unreachable.get((dst, src), 0)
            first = min(f.first_ts for f in silent)
            last = max(f.last_ts for f in silent)
            conf = clamp(0.4 + 0.2 * min(1.0, len(ports) / 100) + (0.25 if unreach else 0.0))
            yield Finding(
                detector=self.name, category=self.category,
                title="Possible UDP port scan",
                severity="low" if len(ports) < 100 else "medium",
                confidence=conf,
                summary=(f"{src} sent datagrams to {len(ports)} distinct UDP ports on {dst} "
                         "without receiving a UDP reply."),
                explanation=(
                    "Unanswered datagrams to many different ports on a single host are typical "
                    "of UDP service discovery. ICMP port-unreachable replies from the target, "
                    "when present, strengthen the interpretation."),
                evidence={
                    "source": src, "target": dst, "distinct_ports": len(ports),
                    "sample_ports": _port_sample(ports),
                    "icmp_unreachable_replies": unreach,
                    "window_seconds": round(last - first, 2),
                    "flow_ids": [f.id for f in silent[:20]],
                },
                hosts=[src, dst], first_ts=first, last_ts=last,
                caveats=[
                    "Media, VoIP and peer-to-peer applications legitimately spray UDP ports.",
                    "One-way capture points (asymmetric routing, SPAN misconfiguration) hide "
                    "replies and inflate the unanswered count.",
                ],
                recommendations=["Check the source process and whether replies were captured at all."],
                mitre=_MITRE_SCAN)

    def _vertical(self, ctx, src, dst, flows, probes, probed_ports, ratio) -> Finding:
        ports = {f.dport for f in flows}
        open_ports = sorted({f.dport for f in flows if f.synack})
        closed = len({f.dport for f in probes if f.state == "REJ"})
        silent = len({f.dport for f in probes if f.state == "S0"})
        first = min(f.first_ts for f in probes)
        last = max(f.last_ts for f in probes)
        window = max(last - first, 1e-6)
        technique = _technique(probes)
        n = len(probed_ports)
        conf = clamp(0.45 + 0.3 * min(1.0, n / 100) + 0.2 * ratio)
        severity = "high" if n >= 500 else "medium" if n >= 50 else "low"
        return Finding(
            detector=self.name, category=self.category,
            title="Possible vertical port scan",
            severity=severity, confidence=conf,
            summary=(f"{src} probed {n} distinct TCP ports on {dst} in "
                     f"{window:.1f}s; {len(open_ports)} port(s) answered."),
            explanation=(
                "A single source opened connections to many different ports on one host and "
                f"{ratio:.0%} of those ports saw no application data. Normal clients talk to a "
                "handful of known services; touching many ports without using them indicates "
                f"enumeration of listening services. Flag pattern is consistent with a "
                f"{technique} scan."),
            evidence={
                "source": src, "target": dst,
                "distinct_ports_contacted": len(ports),
                "ports_probed_without_data": n,
                "probe_ratio": round(ratio, 2),
                "technique": technique,
                "ports_that_answered": open_ports[:50],
                "ports_reset": closed, "ports_silent": silent,
                "sample_ports": _port_sample(probed_ports),
                "window_seconds": round(window, 2),
                "ports_per_second": round(n / window, 1),
                "flow_ids": [f.id for f in probes[:20]],
            },
            hosts=[src, dst], first_ts=first, last_ts=last,
            caveats=[
                "Authorised vulnerability scanners and penetration tests produce identical traffic.",
                "Ports listed as answering are those where a SYN-ACK was captured; filtered "
                "ports and capture loss can hide others.",
            ],
            recommendations=[
                f"Establish whether {src} is a sanctioned scanner; if not, treat the host as "
                "potentially compromised and review its recent process and login activity.",
                f"Review later connections from {src} to the ports that answered on {dst}.",
                "Restrict lateral reachability between segments so that hosts cannot enumerate "
                "each other's services.",
            ],
            mitre=_MITRE_SCAN)
