"""Central configuration: resource limits and detection thresholds.

Everything here has a conservative default and can be overridden through
environment variables (see README) or by constructing the dataclasses
directly, which is what the tests do.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


@dataclass
class Limits:
    """Hard resource ceilings applied while ingesting untrusted captures."""

    max_upload_bytes: int = field(
        default_factory=lambda: _env_int("NETSLEUTH_MAX_UPLOAD_MB", 2048) * 1024 * 1024)
    max_packets: int = field(
        default_factory=lambda: _env_int("NETSLEUTH_MAX_PACKETS", 5_000_000))
    max_flows: int = field(
        default_factory=lambda: _env_int("NETSLEUTH_MAX_FLOWS", 500_000))
    max_hosts: int = field(
        default_factory=lambda: _env_int("NETSLEUTH_MAX_HOSTS", 200_000))
    max_app_records: int = 500_000      # per table: DNS / HTTP / TLS rows
    stream_buffer_bytes: int = 65_536   # per direction, for L7 head parsing
    max_packet_bytes: int = 262_144
    tcp_idle_timeout: float = 3600.0
    udp_idle_timeout: float = 60.0


@dataclass
class DetectionConfig:
    """Thresholds for the heuristic detectors. Tuned to be conservative."""

    # port scanning
    scan_min_ports: int = 15            # distinct ports, one source -> one target
    scan_min_hosts: int = 12            # distinct targets, one source, one port
    scan_min_failed_ratio: float = 0.6

    # DNS tunnelling
    tunnel_min_queries: int = 25
    tunnel_min_unique_ratio: float = 0.8
    tunnel_min_avg_label_len: float = 24.0
    tunnel_min_entropy: float = 3.3

    # suspicious DNS
    dga_min_nxdomain: int = 10
    dga_min_score: float = 0.55

    # beaconing
    beacon_min_connections: int = 6
    beacon_min_interval: float = 10.0   # seconds; faster repetition is a burst
    beacon_min_score: float = 0.75

    # volume
    upload_min_bytes: int = 1_000_000
    upload_min_ratio: float = 4.0
    volume_outlier_z: float = 3.5
    spike_z: float = 6.0
    flood_min_half_open: int = 300

    # connection patterns
    failed_repeat_min: int = 10
    fanout_min_hosts: int = 5
    bruteforce_min_sessions: int = 12
    long_lived_seconds: float = 1800.0

    # extra CIDR ranges to treat as internal (besides RFC 1918 / ULA)
    internal_networks: tuple[str, ...] = field(
        default_factory=lambda: tuple(
            n.strip() for n in os.environ.get("NETSLEUTH_INTERNAL_NETS", "").split(",")
            if n.strip()))


@dataclass
class Config:
    limits: Limits = field(default_factory=Limits)
    detection: DetectionConfig = field(default_factory=DetectionConfig)
