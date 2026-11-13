"""Unusual outbound connections from internal hosts to external addresses."""

from __future__ import annotations

import ipaddress
from collections import defaultdict

from .base import Detector, Finding, clamp, human_bytes, mitre

# Destination ports that internal clients commonly use towards the internet.
_COMMON_OUT = frozenset((
    20, 21, 22, 25, 43, 53, 80, 110, 123, 143, 443, 465, 587, 853, 993, 995,
    1194, 3478, 3479, 3480, 3481, 4500, 500, 5222, 5223, 5228, 8080, 8443, 19302,
))
# Administrative / file-sharing services that should rarely cross the perimeter.
_ADMIN_OUT = {23: "Telnet", 135: "MSRPC", 139: "NetBIOS", 445: "SMB", 3389: "RDP",
              5900: "VNC", 5985: "WinRM", 5986: "WinRM", 1433: "MSSQL", 3306: "MySQL"}
# Ports that are defaults in common offensive tooling or anonymity networks.
# A port number is weak evidence; these findings carry low confidence.
_TOOLING_PORTS = {4444: "Metasploit default handler", 4445: "common reverse-shell port",
                  1337: "common backdoor port", 31337: "common backdoor port",
                  6666: "IRC / backdoor", 6667: "IRC", 6697: "IRC over TLS",
                  9001: "Tor relay (ORPort)", 9030: "Tor directory", 9050: "Tor SOCKS",
                  5555: "ADB / common backdoor port", 12345: "NetBus default"}
_SCRIPTED_UA = ("curl/", "wget/", "python-requests", "python-urllib", "go-http-client",
                "powershell", "winhttp", "libwww-perl", "java/", "okhttp", "aiohttp")


def _is_ip_literal(host: str) -> bool:
    h = host.strip("[]")
    if ":" in h and h.count(":") == 1:
        h = h.split(":")[0]
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


class UnusualOutboundDetector(Detector):
    name = "unusual_outbound"
    category = "Unusual Outbound"
    description = ("Internal-to-external sessions on administrative, tooling or "
                   "otherwise uncommon ports, HTTP to bare IP addresses and TLS "
                   "without SNI.")

    def run(self, ctx):
        admin: dict[tuple, list] = defaultdict(list)
        tooling: dict[tuple, list] = defaultdict(list)
        uncommon: dict[str, list] = defaultdict(list)
        for f in ctx.flows:
            if f.proto not in ("TCP", "UDP"):
                continue
            if not (ctx.addr.is_internal(f.src) and ctx.addr.is_external(f.dst)):
                continue
            # only sessions that actually worked are "connections"
            worked = (f.est and (f.payload_fwd or f.payload_rev)) if f.proto == "TCP" \
                else f.pkts_rev > 0
            if not worked:
                continue
            port = f.dport
            if f.proto == "TCP" and port in _ADMIN_OUT:
                admin[(f.src, port)].append(f)
            elif port in _TOOLING_PORTS:
                tooling[(f.src, f.dst, port)].append(f)
            elif port not in _COMMON_OUT and f.app_by != "payload":
                # payload-identified HTTP/TLS/SSH on odd ports is handled by
                # name; here we care about unidentified services
                uncommon[f.src].append(f)

        for (src, port), flows in admin.items():
            dsts = sorted({f.dst for f in flows})
            total = sum(f.bytes for f in flows)
            yield Finding(
                detector=self.name, category=self.category,
                title=f"Outbound {_ADMIN_OUT[port]} session to an external address",
                severity="medium", confidence=0.7,
                summary=(f"{src} completed {len(flows)} {_ADMIN_OUT[port]} (TCP/{port}) "
                         f"session(s) to {len(dsts)} external address(es), "
                         f"{human_bytes(total)} transferred."),
                explanation=(
                    f"{_ADMIN_OUT[port]} is an administrative or file-sharing protocol that "
                    "normally stays inside a network. An established session to a public "
                    "address can indicate data transfer to an attacker-controlled server, "
                    "credential leakage (e.g. forced SMB authentication) or remote control."),
                evidence={
                    "source": src, "service": _ADMIN_OUT[port], "port": port,
                    "destinations": dsts[:20], "sessions": len(flows), "bytes": total,
                    "flow_ids": [f.id for f in flows[:20]],
                },
                hosts=[src] + dsts[:10],
                first_ts=min(f.first_ts for f in flows), last_ts=max(f.last_ts for f in flows),
                caveats=["Cloud-hosted servers administered directly over the internet "
                         "produce this traffic legitimately."],
                recommendations=[
                    f"Verify the destination(s) are organisation-owned; otherwise block "
                    f"outbound TCP/{port} at the perimeter.",
                ],
                mitre=[mitre("T1021", "Remote Services"),
                       mitre("T1048", "Exfiltration Over Alternative Protocol")])

        for (src, dst, port), flows in tooling.items():
            total = sum(f.bytes for f in flows)
            yield Finding(
                detector=self.name, category=self.category,
                title=f"Outbound session on port {port} ({_TOOLING_PORTS[port]})",
                severity="medium", confidence=0.4,
                summary=(f"{src} established {len(flows)} session(s) to {dst}:{port}, a port "
                         f"associated with: {_TOOLING_PORTS[port]}."),
                explanation=(
                    "The destination port is a default in widely used offensive tooling or "
                    "anonymity software. Port numbers are easily changed and frequently "
                    "reused by unrelated software, so this is a prompt to look at the "
                    "session, not a conclusion."),
                evidence={
                    "source": src, "destination": dst, "port": port,
                    "association": _TOOLING_PORTS[port], "sessions": len(flows),
                    "bytes_sent": sum(f.bytes_fwd for f in flows),
                    "bytes_received": sum(f.bytes_rev for f in flows),
                    "duration_seconds": round(max(f.last_ts for f in flows)
                                              - min(f.first_ts for f in flows), 1),
                    "application_identified": flows[0].app or None,
                    "flow_ids": [f.id for f in flows[:20]],
                },
                hosts=[src, dst],
                first_ts=min(f.first_ts for f in flows), last_ts=max(f.last_ts for f in flows),
                caveats=["Many legitimate applications use these ports; the association is "
                         "by convention only."],
                recommendations=[
                    f"Inspect the session in the connection explorer and identify the "
                    f"process on {src} that owns it.",
                ],
                mitre=[mitre("T1571", "Non-Standard Port")])

        for src, flows in uncommon.items():
            dests: dict[tuple, list] = defaultdict(list)
            for f in flows:
                dests[(f.dst, f.proto, f.dport)].append(f)
            if not dests:
                continue
            rows = sorted(dests.items(), key=lambda kv: -sum(f.bytes for f in kv[1]))
            total = sum(f.bytes for f in flows)
            yield Finding(
                detector=self.name, category=self.category,
                title="Outbound sessions on uncommon ports",
                severity="low", confidence=clamp(0.3 + 0.05 * len(rows), 0.3, 0.6),
                summary=(f"{src} established sessions to {len(rows)} external "
                         f"destination/port combination(s) outside the usual web, mail and "
                         f"DNS ports ({human_bytes(total)} total)."),
                explanation=(
                    "Most client traffic to the internet uses a small set of well-known "
                    "ports. Sessions on other ports whose protocol could not be identified "
                    "from payload deserve a look because custom command-and-control "
                    "channels often use arbitrary ports."),
                evidence={
                    "source": src,
                    "destinations": [
                        {"destination": d, "protocol": p, "port": port, "sessions": len(fl),
                         "bytes": sum(f.bytes for f in fl), "name": ctx.name_of(d) or None}
                        for (d, p, port), fl in rows[:15]],
                    "flow_ids": [f.id for f in flows[:20]],
                },
                hosts=[src] + [d for (d, _p, _port), _ in rows[:5]],
                first_ts=min(f.first_ts for f in flows), last_ts=max(f.last_ts for f in flows),
                caveats=["Games, VoIP, VPNs, peer-to-peer and many business applications "
                         "use non-standard ports."],
                recommendations=["Confirm the applications involved; tighten egress "
                                 "filtering to required ports where practical."],
                mitre=[mitre("T1571", "Non-Standard Port")])

        yield from self._http_direct_ip(ctx)
        yield from self._tls_no_sni(ctx)

    def _http_direct_ip(self, ctx):
        groups: dict[tuple, list] = defaultdict(list)
        for tx in ctx.http:
            if not tx.method or not ctx.addr.is_internal(tx.src) or not ctx.addr.is_external(tx.dst):
                continue
            if tx.host and not _is_ip_literal(tx.host):
                continue
            groups[(tx.src, tx.dst)].append(tx)
        for (src, dst), txs in groups.items():
            agents = sorted({t.user_agent for t in txs if t.user_agent})
            scripted = [a for a in agents if any(s in a.lower() for s in _SCRIPTED_UA)]
            no_agent = not agents
            conf = 0.45 + (0.15 if scripted or no_agent else 0.0)
            yield Finding(
                detector=self.name, category=self.category,
                title="HTTP requests to a bare IP address",
                severity="low", confidence=conf,
                summary=(f"{src} made {len(txs)} cleartext HTTP request(s) to {dst} addressed "
                         "by IP rather than hostname"
                         + (" using a scripted client" if scripted else "") + "."),
                explanation=(
                    "Browsing almost always targets hostnames. HTTP requests whose Host "
                    "header is a raw IP address are more typical of scripts, installers and "
                    "malware staging or command-and-control that avoids DNS."),
                evidence={
                    "source": src, "destination": dst, "requests": len(txs),
                    "user_agents": agents[:5] or ["<none sent>"],
                    "scripted_client": bool(scripted),
                    "sample_requests": [f"{t.method} {t.uri[:120]}" for t in txs[:8]],
                    "response_statuses": sorted({t.status for t in txs if t.status})[:8],
                    "flow_ids": sorted({t.flow_id for t in txs})[:20],
                },
                hosts=[src, dst],
                first_ts=min(t.ts for t in txs), last_ts=max(t.ts for t in txs),
                caveats=["Appliance management pages, internal tools exposed publicly and "
                         "some update mechanisms use IP-literal URLs."],
                recommendations=["Review the requested paths and any downloaded content; "
                                 "check the destination's reputation."],
                mitre=[mitre("T1071.001", "Application Layer Protocol: Web Protocols"),
                       mitre("T1105", "Ingress Tool Transfer")])

    def _tls_no_sni(self, ctx):
        groups: dict[tuple, list] = defaultdict(list)
        for t in ctx.tls:
            if t.sni or not t.ja3:
                continue        # only sessions where a ClientHello was actually parsed
            if ctx.addr.is_internal(t.src) and ctx.addr.is_external(t.dst):
                groups[(t.src, t.dst, t.dport)].append(t)
        for (src, dst, port), infos in groups.items():
            yield Finding(
                detector=self.name, category=self.category,
                title="TLS to an external address without SNI",
                severity="low", confidence=0.4,
                summary=(f"{src} opened {len(infos)} TLS session(s) to {dst}:{port} whose "
                         "ClientHello carried no server name."),
                explanation=(
                    "Mainstream browsers and HTTP libraries send the Server Name Indication "
                    "extension. Its absence suggests a client connecting by IP address or a "
                    "custom TLS stack; the JA3 fingerprint in the evidence can be compared "
                    "with other sessions from the same host."),
                evidence={
                    "source": src, "destination": dst, "port": port, "sessions": len(infos),
                    "ja3": sorted({t.ja3 for t in infos})[:3],
                    "tls_version": sorted({t.version for t in infos if t.version})[:3],
                    "flow_ids": [t.flow_id for t in infos[:20]],
                },
                hosts=[src, dst],
                first_ts=min(t.ts for t in infos), last_ts=max(t.ts for t in infos),
                caveats=["Encrypted Client Hello, some VPNs, IoT devices and non-HTTP "
                         "TLS services legitimately omit SNI."],
                recommendations=["Compare the JA3 fingerprint with the host's other TLS "
                                 "clients and identify the destination owner."],
                mitre=[mitre("T1573.002", "Encrypted Channel: Asymmetric Cryptography")])
