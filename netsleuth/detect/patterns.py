"""Suspicious connection patterns: repeated failures, internal fan-out on
administrative ports, repeated short logins, cleartext credentials,
long-lived sessions and ARP inconsistencies."""

from __future__ import annotations

from collections import defaultdict

from .base import (Detector, Finding, clamp, human_bytes, human_duration,
                   median, mitre)

_ADMIN_PORTS = {22: "SSH", 23: "Telnet", 135: "MSRPC", 139: "NetBIOS", 445: "SMB",
                3389: "RDP", 5900: "VNC", 5985: "WinRM", 5986: "WinRM"}
_AUTH_PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 110: "POP3", 143: "IMAP",
               445: "SMB", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
               5900: "VNC"}


class ConnectionPatternDetector(Detector):
    name = "connection_patterns"
    category = "Suspicious Connections"
    description = ("Repeated failed connections, internal fan-out on admin ports, "
                   "rapid repeated logins, cleartext authentication, long-lived "
                   "sessions and conflicting ARP claims.")

    def run(self, ctx):
        yield from self._repeated_failures(ctx)
        yield from self._admin_fanout(ctx)
        yield from self._repeated_logins(ctx)
        yield from self._cleartext_auth(ctx)
        yield from self._long_lived(ctx)
        yield from self._arp_conflicts(ctx)

    def _repeated_failures(self, ctx):
        groups: dict[tuple, list] = defaultdict(list)
        for f in ctx.flows:
            if f.proto == "TCP" and f.failed:
                groups[(f.src, f.dst, f.dport)].append(f)
        for (src, dst, port), flows in groups.items():
            if len(flows) < ctx.config.failed_repeat_min:
                continue
            first = min(f.first_ts for f in flows)
            last = max(f.last_ts for f in flows)
            rejected = sum(f.state == "REJ" for f in flows)
            yield Finding(
                detector=self.name, category=self.category,
                title="Repeated failed connections to one service",
                severity="low", confidence=clamp(0.4 + 0.02 * len(flows), 0.4, 0.7),
                summary=(f"{src} tried {dst}:{port} {len(flows)} times over "
                         f"{human_duration(last - first)} without ever connecting."),
                explanation=(
                    "Software that keeps retrying a destination that never answers is often "
                    "misconfigured - but it is also what malware calling a dead or blocked "
                    "controller looks like. The destination and port help tell them apart."),
                evidence={
                    "source": src, "destination": dst, "port": port,
                    "destination_scope": ctx.addr.scope(dst),
                    "destination_name": ctx.name_of(dst) or None,
                    "attempts": len(flows), "rejected_with_rst": rejected,
                    "unanswered": len(flows) - rejected,
                    "span_seconds": round(last - first, 1),
                    "flow_ids": [f.id for f in flows[:20]],
                },
                hosts=[src, dst], first_ts=first, last_ts=last,
                caveats=["Decommissioned servers, stale configuration and firewalled "
                         "services cause persistent retries."],
                recommendations=[f"Identify what on {src} is trying to reach {dst}:{port}."],
                mitre=[mitre("T1008", "Fallback Channels")])

    def _admin_fanout(self, ctx):
        groups: dict[tuple, dict] = defaultdict(dict)
        for f in ctx.flows:
            if (f.proto == "TCP" and f.dport in _ADMIN_PORTS
                    and ctx.addr.is_internal(f.src) and ctx.addr.is_internal(f.dst)):
                groups[(f.src, f.dport)].setdefault(f.dst, []).append(f)
        for (src, port), by_dst in groups.items():
            if len(by_dst) < ctx.config.fanout_min_hosts:
                continue
            connected = sorted(d for d, fl in by_dst.items()
                               if any(f.est and (f.payload_fwd or f.payload_rev) for f in fl))
            if len(connected) < 2:
                continue    # pure probing is reported by the port-scan detector
            flows = [f for fl in by_dst.values() for f in fl]
            first = min(f.first_ts for f in flows)
            last = max(f.last_ts for f in flows)
            svc = _ADMIN_PORTS[port]
            yield Finding(
                detector=self.name, category=self.category,
                title=f"Internal fan-out over {svc}",
                severity="medium" if len(connected) >= 5 else "low",
                confidence=clamp(0.35 + 0.05 * min(len(connected), 6)
                                 + 0.01 * min(len(by_dst), 20)),
                summary=(f"{src} contacted {len(by_dst)} internal hosts on {svc} "
                         f"(TCP/{port}) and held working sessions with {len(connected)}."),
                explanation=(
                    f"One workstation opening {svc} sessions to many peers is unusual: "
                    "administrative protocols are normally used from a few management "
                    "hosts towards servers. The same pattern appears when an intruder or "
                    "worm moves laterally with harvested credentials."),
                evidence={
                    "source": src, "service": svc, "port": port,
                    "hosts_contacted": len(by_dst),
                    "hosts_with_sessions": connected[:30],
                    "span_seconds": round(last - first, 1),
                    "flow_ids": [f.id for f in flows[:20]],
                },
                hosts=[src] + connected[:10], first_ts=first, last_ts=last,
                caveats=["Jump hosts, configuration-management servers, backup servers and "
                         "administrators' workstations do this routinely."],
                recommendations=[
                    f"Confirm whether {src} is a management host.",
                    "If not, review authentication logs on the contacted hosts for the "
                    "account used.",
                ],
                mitre=[mitre("T1021", "Remote Services"),
                       mitre("T1570", "Lateral Tool Transfer")])

    def _repeated_logins(self, ctx):
        groups: dict[tuple, list] = defaultdict(list)
        for f in ctx.flows:
            if (f.proto == "TCP" and f.dport in _AUTH_PORTS and f.est
                    and f.payload_fwd and f.payload_rev):
                groups[(f.src, f.dst, f.dport)].append(f)
        for (src, dst, port), flows in groups.items():
            if len(flows) < ctx.config.bruteforce_min_sessions:
                continue
            durations = [f.duration for f in flows]
            sizes = [f.payload_fwd + f.payload_rev for f in flows]
            med_dur, med_size = median(durations), median(sizes)
            if med_dur > 30 or med_size > 20_000:
                continue    # real working sessions, not login attempts
            first = min(f.first_ts for f in flows)
            last = max(f.last_ts for f in flows)
            rate = len(flows) / max(last - first, 1.0) * 60
            if rate < 2:
                continue
            svc = _AUTH_PORTS[port]
            yield Finding(
                detector=self.name, category=self.category,
                title=f"Rapid repeated {svc} sessions (possible password guessing)",
                severity="medium", confidence=clamp(0.4 + 0.01 * len(flows)
                                                    + 0.15 * min(1.0, rate / 30)),
                summary=(f"{src} opened {len(flows)} short {svc} sessions to {dst}:{port} "
                         f"in {human_duration(last - first)} "
                         f"(median {human_duration(med_dur)}, {human_bytes(med_size)} each)."),
                explanation=(
                    "Many brief, similarly sized sessions to an authentication service in "
                    "quick succession match automated password guessing: each session "
                    "carries one or a few login attempts and is then closed. The capture "
                    "cannot show whether any attempt succeeded when the protocol is "
                    "encrypted."),
                evidence={
                    "source": src, "destination": dst, "service": svc, "port": port,
                    "sessions": len(flows),
                    "sessions_per_minute": round(rate, 1),
                    "median_duration_seconds": round(med_dur, 2),
                    "median_bytes_per_session": int(med_size),
                    "longest_session_seconds": round(max(durations), 1),
                    "largest_session_bytes": int(max(sizes)),
                    "flow_ids": [f.id for f in flows[:20]],
                },
                hosts=[src, dst], first_ts=first, last_ts=last,
                caveats=[
                    "Automation (Ansible, monitoring checks, scripted file transfers) opens "
                    "many short authenticated sessions legitimately.",
                    "A noticeably longer or larger final session may indicate a successful "
                    "login - compare the longest session above with the median.",
                ],
                recommendations=[
                    f"Review authentication logs on {dst} for failures from {src}.",
                    "Enforce lockout / rate limiting and key-based or multi-factor "
                    "authentication on the service.",
                ],
                mitre=[mitre("T1110", "Brute Force")])

    def _cleartext_auth(self, ctx):
        seen: dict[tuple, dict] = {}
        for f in ctx.flows:
            if f.proto != "TCP":
                continue
            if f.app == "FTP" and "cleartext login" in f.detail:
                key = (f.src, f.dst, "FTP")
            elif f.dport == 23 and f.est and f.payload_fwd and f.payload_rev:
                key = (f.src, f.dst, "Telnet")
            else:
                continue
            seen.setdefault(key, {"flows": [], "detail": f.detail})["flows"].append(f)
        for tx in ctx.http:
            if tx.auth_scheme.lower() == "basic":
                key = (tx.src, tx.dst, "HTTP Basic")
                seen.setdefault(key, {"flows": [], "detail": tx.host, "tx": 0})
                seen[key]["tx"] = seen[key].get("tx", 0) + 1
                seen[key].setdefault("ts", []).append(tx.ts)
                seen[key].setdefault("flow_ids", set()).add(tx.flow_id)
        for (src, dst, kind), info in seen.items():
            flows = info["flows"]
            if flows:
                first = min(f.first_ts for f in flows)
                last = max(f.last_ts for f in flows)
                ids = [f.id for f in flows[:20]]
                count = len(flows)
            else:
                first, last = min(info["ts"]), max(info["ts"])
                ids = sorted(info["flow_ids"])[:20]
                count = info["tx"]
            external = ctx.addr.is_external(dst)
            yield Finding(
                detector=self.name, category=self.category,
                title=f"Credentials sent in cleartext ({kind})",
                severity="medium" if external else "low", confidence=0.85,
                summary=(f"{src} authenticated to {dst} using {kind}, which transmits "
                         f"credentials unencrypted ({count} occurrence(s))."),
                explanation=(
                    "The protocol exchange was observed in the capture, so anyone on the "
                    "network path could read the credentials. This is a hygiene issue "
                    "rather than evidence of an attack. NetSleuth records that "
                    "authentication occurred but does not store passwords."),
                evidence={
                    "source": src, "destination": dst, "protocol": kind,
                    "destination_scope": ctx.addr.scope(dst),
                    "occurrences": count,
                    "detail": info.get("detail") or None,
                    "flow_ids": ids,
                },
                hosts=[src, dst], first_ts=first, last_ts=last,
                caveats=["For HTTP Basic the Authorization header was seen on an "
                         "unencrypted connection; the credentials themselves were not "
                         "validated."],
                recommendations=[
                    "Treat the credentials as exposed and rotate them.",
                    "Replace the service with an encrypted equivalent (SFTP/SSH/HTTPS).",
                ],
                mitre=[mitre("T1040", "Network Sniffing"),
                       mitre("T1552", "Unsecured Credentials")])

    def _long_lived(self, ctx):
        threshold = ctx.config.long_lived_seconds
        for f in ctx.flows:
            if f.proto != "TCP" or f.duration < threshold or not f.est:
                continue
            if not (ctx.addr.is_internal(f.src) and ctx.addr.is_external(f.dst)):
                continue
            name = f.sni or f.http_host or ctx.name_of(f.dst)
            rate = f.bytes / max(f.duration, 1.0)
            yield Finding(
                detector=self.name, category=self.category,
                title="Long-lived session to an external host",
                severity="info" if rate > 50_000 else "low", confidence=0.4,
                summary=(f"{f.src} held a {f.app or 'TCP'} session with {f.dst}:{f.dport}"
                         + (f" ({name})" if name else "")
                         + f" for {human_duration(f.duration)} "
                         f"({human_bytes(f.bytes)}, {human_bytes(rate)}/s average)."),
                explanation=(
                    "Sessions that stay open for a long time with little traffic can be "
                    "interactive remote access or a persistent command channel. They are "
                    "equally characteristic of VPNs, chat clients and push-notification "
                    "services."),
                evidence={
                    "source": f.src, "destination": f.dst, "port": f.dport,
                    "destination_name": name or None, "application": f.app or None,
                    "duration_seconds": round(f.duration, 1),
                    "bytes_sent": f.bytes_fwd, "bytes_received": f.bytes_rev,
                    "average_bytes_per_second": round(rate, 1),
                    "state": f.state, "flow_ids": [f.id],
                },
                hosts=[f.src, f.dst], first_ts=f.first_ts, last_ts=f.last_ts,
                caveats=["Capture boundaries truncate sessions; true duration may be longer."],
                recommendations=["Identify the application; allow-list expected "
                                 "persistent services."],
                mitre=[mitre("T1071", "Application Layer Protocol")])

    def _arp_conflicts(self, ctx):
        for ip, macs in ctx.arp.items():
            if len(macs) < 2 or ip in ("0.0.0.0",):
                continue
            yield Finding(
                detector=self.name, category=self.category,
                title="IP address claimed by multiple MAC addresses",
                severity="medium", confidence=0.5,
                summary=(f"ARP traffic advertised {ip} from {len(macs)} different hardware "
                         f"addresses: {', '.join(sorted(macs)[:4])}."),
                explanation=(
                    "ARP has no authentication, so an attacker on the local segment can "
                    "claim another host's IP address to intercept its traffic (ARP "
                    "spoofing). Two MAC addresses asserting the same IP within one capture "
                    "is the observable trace of that - and of several benign situations."),
                evidence={"ip": ip, "mac_addresses": sorted(macs)[:8]},
                hosts=[ip],
                caveats=["High-availability pairs (VRRP/HSRP/CARP), NIC teaming, DHCP "
                         "address reuse and device replacement cause the same observation."],
                recommendations=[
                    "Check switch CAM tables for the listed MAC addresses and enable "
                    "dynamic ARP inspection where supported.",
                ],
                mitre=[mitre("T1557.002", "Adversary-in-the-Middle: ARP Cache Poisoning")])
