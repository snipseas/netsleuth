"""Detector registry and runner."""

from __future__ import annotations

import logging
import time

from .base import AnalysisContext, Detector, SEVERITIES
from .beacon import BeaconDetector
from .dns import DnsTunnelDetector, SuspiciousDnsDetector
from .outbound import UnusualOutboundDetector
from .patterns import ConnectionPatternDetector
from .portscan import PortScanDetector
from .volume import VolumeAnomalyDetector

log = logging.getLogger("netsleuth.detect")

ALL_DETECTORS: tuple[type[Detector], ...] = (
    PortScanDetector,
    DnsTunnelDetector,
    SuspiciousDnsDetector,
    UnusualOutboundDetector,
    BeaconDetector,
    VolumeAnomalyDetector,
    ConnectionPatternDetector,
)

MAX_FINDINGS_PER_DETECTOR = 200
_SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}


def run_detectors(ctx: AnalysisContext,
                  detectors: tuple[type[Detector], ...] = ALL_DETECTORS
                  ) -> tuple[list[dict], list[dict], list[str]]:
    """Run every detector in isolation.

    Returns (findings, detector_stats, warnings). A detector that raises is
    reported as a warning and does not affect the others.
    """
    findings: list[dict] = []
    stats: list[dict] = []
    warnings: list[str] = []
    for cls in detectors:
        det = cls()
        started = time.perf_counter()
        produced: list[dict] = []
        error = None
        try:
            for f in det.run(ctx):
                produced.append(f.to_dict())
        except Exception as exc:  # noqa: BLE001 - isolation is the point
            log.exception("detector %s failed", det.name)
            error = f"{type(exc).__name__}: {exc}"
            warnings.append(f"detector '{det.name}' failed and was skipped ({error})")
        produced.sort(key=lambda d: (-_SEV_RANK.get(d["severity"], 0), -d["confidence"]))
        if len(produced) > MAX_FINDINGS_PER_DETECTOR:
            warnings.append(
                f"detector '{det.name}' produced {len(produced)} findings; only the "
                f"{MAX_FINDINGS_PER_DETECTOR} most severe were kept")
            produced = produced[:MAX_FINDINGS_PER_DETECTOR]
        findings.extend(produced)
        stats.append({
            "name": det.name, "category": det.category, "description": det.description,
            "findings": len(produced), "error": error,
            "seconds": round(time.perf_counter() - started, 3),
        })
    findings.sort(key=lambda d: (-_SEV_RANK.get(d["severity"], 0), -d["confidence"]))
    return findings, stats, warnings
