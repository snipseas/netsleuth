"""DNS-based detections: tunnelling indicators and suspicious query patterns."""

from __future__ import annotations

from collections import Counter, defaultdict

from ..analysis.addr import registered_domain
from .base import Detector, Finding, clamp, human_bytes, mitre, shannon_entropy

_IGNORED_SUFFIXES = (".arpa", ".local", ".lan", ".home", ".internal", ".localdomain")
_TUNNEL_TYPES = frozenset(("TXT", "NULL", "CNAME", "MX", "KEY", "TYPE65399"))
_VOWELS = frozenset("aeiou")

# TLDs that abuse-tracking organisations have repeatedly reported as carrying
# a disproportionate share of malicious registrations. Presence here is weak
# evidence on its own and is reported at "info" severity only.
_HIGH_ABUSE_TLDS = frozenset((
    "top", "xyz", "tk", "ml", "ga", "cf", "gq", "icu", "cyou", "rest", "cam",
    "buzz", "click", "link", "work", "zip", "mov", "su", "pw", "bid", "loan",
))
_PUBLIC_RESOLVERS = {
    "8.8.8.8": "Google", "8.8.4.4": "Google", "1.1.1.1": "Cloudflare",
    "1.0.0.1": "Cloudflare", "9.9.9.9": "Quad9", "149.112.112.112": "Quad9",
    "208.67.222.222": "OpenDNS", "208.67.220.220": "OpenDNS",
}


def _subdomain(qname: str, domain: str) -> str:
    if qname == domain:
        return ""
    return qname[:-(len(domain) + 1)] if qname.endswith("." + domain) else qname


def _ignored(qname: str) -> bool:
    return not qname or "." not in qname or qname.endswith(_IGNORED_SUFFIXES)


def dga_score(label: str) -> float:
    """0..1 score for how machine-generated a domain label looks.

    Combines character entropy, vowel scarcity, digit mixing and long
    consonant runs. This is a lexical heuristic, not a classifier: it has
    both false positives (CDN hashes, abbreviations) and false negatives
    (dictionary-based DGAs).
    """
    n = len(label)
    if n < 7:
        return 0.0
    letters = [c for c in label if c.isalpha()]
    digits = sum(c.isdigit() for c in label)
    ent = shannon_entropy(label)
    vowel_ratio = (sum(c in _VOWELS for c in letters) / len(letters)) if letters else 0.0
    run = best = 0
    for c in label:
        if c.isalpha() and c not in _VOWELS:
            run += 1
            best = max(best, run)
        else:
            run = 0
    score = 0.0
    score += 0.4 * clamp((ent - 2.8) / 1.2)
    score += 0.25 * clamp((0.32 - vowel_ratio) / 0.22) if letters else 0.25
    score += 0.2 * clamp((best - 3) / 4)
    score += 0.15 * clamp(digits / n / 0.3) if 0 < digits < n else 0.0
    return clamp(score)


class DnsTunnelDetector(Detector):
    name = "dns_tunnel"
    category = "Command and Control"
    description = ("Looks for domains receiving many unique, long, high-entropy "
                   "subdomain queries from one client - the shape of data "
                   "encoded into DNS names.")

    def run(self, ctx):
        cfg = ctx.config
        groups: dict[tuple, list] = defaultdict(list)
        for q in ctx.dns:
            if q.proto != "DNS" or _ignored(q.qname):
                continue
            groups[(q.client, registered_domain(q.qname))].append(q)

        for (client, domain), qs in groups.items():
            n = len(qs)
            if n < cfg.tunnel_min_queries:
                continue
            subs = [_subdomain(q.qname, domain) for q in qs]
            unique = set(subs)
            unique.discard("")
            if not unique:
                continue
            unique_ratio = len(unique) / n
            lengths = [len(s) for s in unique]
            avg_len = sum(lengths) / len(lengths)
            max_len = max(lengths)
            joined = [s.replace(".", "") for s in unique]
            avg_entropy = sum(shannon_entropy(s) for s in joined) / len(joined)
            types = Counter(q.qtype for q in qs)
            tunnel_type_ratio = sum(c for t, c in types.items() if t in _TUNNEL_TYPES) / n
            encoded_bytes = sum(len(s) for s in joined)
            resp_bytes = sum(q.rsize for q in qs)

            # each signal contributes independently; several must agree
            signals = {
                "many_unique_subdomains": unique_ratio >= cfg.tunnel_min_unique_ratio,
                "long_labels": avg_len >= cfg.tunnel_min_avg_label_len,
                "high_entropy": avg_entropy >= cfg.tunnel_min_entropy,
                "unusual_record_types": tunnel_type_ratio >= 0.3,
                "large_volume": encoded_bytes >= 4096,
            }
            hits = sum(signals.values())
            if hits < 3 or not signals["many_unique_subdomains"]:
                continue
            conf = clamp(0.25 + 0.14 * hits + 0.1 * min(1.0, n / 200))
            first = min(q.ts for q in qs)
            last = max(q.ts for q in qs)
            severity = "high" if hits >= 4 and encoded_bytes >= 16_384 else "medium"
            yield Finding(
                detector=self.name, category=self.category,
                title="DNS tunnelling indicators",
                severity=severity, confidence=conf,
                summary=(f"{client} sent {n} queries for {len(unique)} unique subdomains of "
                         f"{domain} (average subdomain length {avg_len:.0f} characters, "
                         f"about {human_bytes(encoded_bytes)} carried in query names)."),
                explanation=(
                    "Tools that tunnel data over DNS encode it into query names, so the "
                    "parent domain receives a stream of unique, long, random-looking "
                    "subdomains - often with TXT/NULL/CNAME queries so responses can carry "
                    f"data back. This client/domain pair matched {hits} of 5 such signals: "
                    + ", ".join(k.replace("_", " ") for k, v in signals.items() if v) + "."),
                evidence={
                    "client": client, "domain": domain, "queries": n,
                    "unique_subdomains": len(unique),
                    "unique_ratio": round(unique_ratio, 2),
                    "avg_subdomain_length": round(avg_len, 1),
                    "max_subdomain_length": max_len,
                    "avg_entropy_bits_per_char": round(avg_entropy, 2),
                    "record_types": dict(types.most_common(6)),
                    "bytes_in_query_names": encoded_bytes,
                    "response_bytes": resp_bytes,
                    "resolvers": sorted({q.server for q in qs})[:5],
                    "signals_matched": [k for k, v in signals.items() if v],
                    "sample_queries": [q.qname[:120] for q in qs[:8]],
                    "duration_seconds": round(last - first, 1),
                },
                hosts=[client], first_ts=first, last_ts=last,
                caveats=[
                    "Some security and CDN products legitimately use DNS as a data channel "
                    "(reputation lookups, telemetry, load-balancing hashes) and produce the "
                    "same statistical shape.",
                    "The registered domain is derived with a simplified public-suffix list.",
                ],
                recommendations=[
                    f"Look up ownership and reputation of {domain} and determine which "
                    f"process on {client} issued the queries.",
                    "If unexplained, block the domain at the resolver and review resolver "
                    "logs for other clients querying it.",
                    "Consider limiting clients to internal resolvers and alerting on "
                    "excessive unique-subdomain rates.",
                ],
                mitre=[mitre("T1071.004", "Application Layer Protocol: DNS"),
                       mitre("T1048.003", "Exfiltration Over Unencrypted Non-C2 Protocol")])


class SuspiciousDnsDetector(Detector):
    name = "dns_suspicious"
    category = "Suspicious DNS"
    description = ("NXDOMAIN bursts with algorithmic-looking names, direct use of "
                   "external resolvers, and queries to high-abuse TLDs.")

    def run(self, ctx):
        yield from self._nxdomain_bursts(ctx)
        yield from self._external_resolvers(ctx)
        yield from self._abuse_tlds(ctx)

    def _nxdomain_bursts(self, ctx):
        cfg = ctx.config
        per_client: dict[str, list] = defaultdict(list)
        totals: Counter = Counter()
        for q in ctx.dns:
            if q.proto != "DNS" or _ignored(q.qname):
                continue
            totals[q.client] += 1
            if q.rcode == "NXDOMAIN":
                per_client[q.client].append(q)
        for client, qs in per_client.items():
            domains: dict[str, float] = {}
            for q in qs:
                d = registered_domain(q.qname)
                if d not in domains:
                    domains[d] = dga_score(d.split(".")[0])
            if len(domains) < cfg.dga_min_nxdomain:
                continue
            scores = sorted(domains.values(), reverse=True)
            algorithmic = [d for d, s in domains.items() if s >= cfg.dga_min_score]
            frac = len(algorithmic) / len(domains)
            nx_ratio = len(qs) / max(1, totals[client])
            if len(algorithmic) < cfg.dga_min_nxdomain * 0.6 or frac < 0.5:
                continue
            first = min(q.ts for q in qs)
            last = max(q.ts for q in qs)
            conf = clamp(0.3 + 0.3 * frac + 0.2 * min(1.0, len(algorithmic) / 40)
                         + 0.15 * min(1.0, nx_ratio / 0.5))
            yield Finding(
                detector=self.name, category=self.category,
                title="NXDOMAIN burst with algorithmic-looking names",
                severity="medium", confidence=conf,
                summary=(f"{client} received NXDOMAIN for {len(domains)} distinct domains; "
                         f"{len(algorithmic)} of them look machine-generated."),
                explanation=(
                    "Malware using a domain generation algorithm (DGA) tries many "
                    "pseudo-random domains until one resolves, which appears as a run of "
                    "failed lookups for names with high character entropy, few vowels and "
                    "long consonant runs. The lexical score is heuristic."),
                evidence={
                    "client": client, "nxdomain_responses": len(qs),
                    "distinct_nxdomain_domains": len(domains),
                    "algorithmic_looking": len(algorithmic),
                    "nxdomain_ratio_for_client": round(nx_ratio, 2),
                    "median_lexical_score": round(scores[len(scores) // 2], 2),
                    "sample_domains": sorted(algorithmic)[:12],
                    "duration_seconds": round(last - first, 1),
                },
                hosts=[client], first_ts=first, last_ts=last,
                caveats=[
                    "Browsers probe random hostnames to detect DNS hijacking, and "
                    "misconfigured search suffixes cause NXDOMAIN storms.",
                    "CDN and tracking hostnames can score as algorithmic.",
                ],
                recommendations=[
                    f"Identify the process on {client} issuing the lookups.",
                    "Check whether any similar-looking name did resolve and what the host "
                    "connected to afterwards.",
                ],
                mitre=[mitre("T1568.002", "Dynamic Resolution: Domain Generation Algorithms")])

    def _external_resolvers(self, ctx):
        usage: dict[str, set] = defaultdict(set)         # resolver -> clients
        per_client: dict[tuple, list] = defaultdict(list)
        for q in ctx.dns:
            if q.proto != "DNS":
                continue
            usage[q.server].add(q.client)
            per_client[(q.client, q.server)].append(q)
        internal_resolvers = [s for s in usage if ctx.addr.is_internal(s)]
        if not internal_resolvers:
            return      # no internal resolver observed: external DNS is the norm here
        clients_total = len({c for cs in usage.values() for c in cs}) or 1
        for (client, server), qs in per_client.items():
            if not ctx.addr.is_internal(client) or not ctx.addr.is_external(server):
                continue
            if client in internal_resolvers:
                continue    # a resolver forwarding upstream is expected
            share = len(usage[server]) / clients_total
            if share > 0.5:
                continue    # most clients use it: effectively the site resolver
            known = _PUBLIC_RESOLVERS.get(server)
            first = min(q.ts for q in qs)
            last = max(q.ts for q in qs)
            yield Finding(
                detector=self.name, category=self.category,
                title="Direct use of an external DNS resolver",
                severity="low", confidence=0.45 if known else 0.6,
                summary=(f"{client} sent {len(qs)} DNS queries directly to {server}"
                         + (f" ({known} public DNS)" if known else "")
                         + " although an internal resolver is in use on this network."),
                explanation=(
                    "When a network provides an internal resolver, hosts that query external "
                    "resolvers directly bypass DNS logging and filtering. Malware does this "
                    "to avoid sinkholing; so do some applications and manually configured "
                    "devices."),
                evidence={
                    "client": client, "resolver": server,
                    "well_known_public_resolver": known or False,
                    "queries": len(qs),
                    "internal_resolvers_observed": sorted(internal_resolvers)[:5],
                    "clients_using_this_resolver": len(usage[server]),
                    "sample_queries": list(dict.fromkeys(q.qname for q in qs))[:8],
                },
                hosts=[client, server], first_ts=first, last_ts=last,
                caveats=[
                    "Browsers, VPN clients and IoT devices frequently ship with hard-coded "
                    "public resolvers.",
                ],
                recommendations=[
                    "Decide whether direct external DNS is permitted; if not, block outbound "
                    "port 53 except from the internal resolvers.",
                ],
                mitre=[mitre("T1071.004", "Application Layer Protocol: DNS")])

    def _abuse_tlds(self, ctx):
        per_client: dict[str, dict] = defaultdict(dict)
        for q in ctx.dns:
            if q.proto != "DNS" or _ignored(q.qname):
                continue
            tld = q.qname.rsplit(".", 1)[-1]
            if tld in _HIGH_ABUSE_TLDS:
                per_client[q.client].setdefault(registered_domain(q.qname), q)
        for client, doms in per_client.items():
            qs = list(doms.values())
            yield Finding(
                detector=self.name, category=self.category,
                title="Lookups for domains under high-abuse TLDs",
                severity="info", confidence=0.3,
                summary=(f"{client} queried {len(doms)} domain(s) under top-level domains "
                         "with historically elevated abuse rates."),
                explanation=(
                    "Certain TLDs carry a disproportionate share of malicious registrations "
                    "because they are cheap or free. A lookup under one of them is weak "
                    "evidence by itself and is listed for context alongside other findings."),
                evidence={"client": client, "domains": sorted(doms)[:20]},
                hosts=[client],
                first_ts=min(q.ts for q in qs), last_ts=max(q.ts for q in qs),
                caveats=["Plenty of legitimate sites use these TLDs."],
                recommendations=["Review the listed domains if the host has other findings."],
                mitre=[])
