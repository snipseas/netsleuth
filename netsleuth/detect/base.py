"""Detection framework: the Finding model, the context handed to detectors
and small statistics helpers.

Design rule: detectors report *indicators*. Every finding states what was
measured (evidence), how strongly the measurements match the pattern
(confidence), how much it would matter if true (severity) and which benign
explanations fit the same data (caveats). Nothing here asserts that an attack
took place.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Callable, Iterable

from ..analysis.addr import AddressClassifier
from ..config import DetectionConfig

SEVERITIES = ("info", "low", "medium", "high")


@dataclass
class Finding:
    detector: str
    category: str
    title: str
    severity: str                 # info | low | medium | high
    confidence: float             # 0..1: how well the data matches the pattern
    summary: str                  # one sentence, specific to this instance
    explanation: str              # what the heuristic measures and why it fired
    evidence: dict                # structured measurements and samples
    hosts: list[str]              # addresses this finding is about
    first_ts: float | None = None
    last_ts: float | None = None
    caveats: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    mitre: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "detector": self.detector, "category": self.category, "title": self.title,
            "severity": self.severity if self.severity in SEVERITIES else "info",
            # heuristics never earn certainty: confidence is capped below 1
            "confidence": round(max(0.05, min(0.95, self.confidence)), 2),
            "summary": self.summary, "explanation": self.explanation,
            "evidence": self.evidence, "hosts": list(dict.fromkeys(self.hosts))[:50],
            "first_ts": self.first_ts, "last_ts": self.last_ts,
            "caveats": self.caveats, "recommendations": self.recommendations,
            "mitre": self.mitre,
        }


def mitre(tid: str, name: str) -> dict:
    return {"id": tid, "name": name}


@dataclass
class AnalysisContext:
    """Read-only view of the analysed capture given to every detector."""

    flows: list
    dns: list
    http: list
    tls: list
    hosts: dict                   # ip -> HostStat
    names: dict                   # ip -> set of names (DNS answers, SNI, Host)
    arp: dict                     # ip -> set of MACs seen in ARP
    icmp_unreachable: dict        # (reporter, prober) -> count
    series: list                  # [(second, packets, bytes)] ordered by time
    start_ts: float
    end_ts: float
    addr: AddressClassifier
    config: DetectionConfig
    top_sources: Callable | None = None   # (t0, t1) -> [(ip, bytes)]

    @property
    def duration(self) -> float:
        return max(0.0, self.end_ts - self.start_ts)

    def name_of(self, ip: str) -> str:
        names = self.names.get(ip)
        return sorted(names)[0] if names else ""

    def label(self, ip: str) -> str:
        n = self.name_of(ip)
        return f"{ip} ({n})" if n else ip


class Detector:
    """Base class. Subclasses set the class attributes and implement run()."""

    name = "detector"
    category = "General"
    description = ""

    def run(self, ctx: AnalysisContext) -> Iterable[Finding]:  # pragma: no cover
        raise NotImplementedError


# -- statistics helpers ------------------------------------------------------
def median(values: list[float]) -> float:
    n = len(values)
    if not n:
        return 0.0
    s = sorted(values)
    mid = n // 2
    return s[mid] if n % 2 else (s[mid - 1] + s[mid]) / 2.0


def mad(values: list[float], med: float | None = None) -> float:
    """Median absolute deviation."""
    if not values:
        return 0.0
    if med is None:
        med = median(values)
    return median([abs(v - med) for v in values])


def quantile(sorted_values: list[float], q: float) -> float:
    n = len(sorted_values)
    if not n:
        return 0.0
    pos = q * (n - 1)
    lo = int(pos)
    hi = min(lo + 1, n - 1)
    return sorted_values[lo] + (sorted_values[hi] - sorted_values[lo]) * (pos - lo)


def shannon_entropy(s: str) -> float:
    """Shannon entropy in bits per character."""
    n = len(s)
    if n < 2:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def clamp(x: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return lo if x < lo else hi if x > hi else x


def human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def human_duration(s: float) -> str:
    if s < 1:
        return f"{s * 1000:.0f} ms"
    if s < 120:
        return f"{s:.1f} s"
    if s < 7200:
        return f"{s / 60:.1f} min"
    return f"{s / 3600:.1f} h"
