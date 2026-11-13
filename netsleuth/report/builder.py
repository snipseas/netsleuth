"""Investigation report generation (JSON model, Markdown and standalone HTML).

The report is assembled from the capture store only, so it can be produced
at any time after analysis. All capture-derived strings are escaped on
output: hostnames, URIs and user agents are attacker-controlled data.
"""

from __future__ import annotations

import html
import json
import time

from ..detect.base import human_bytes, human_duration
from ..storage.store import CaptureStore

SEV_ORDER = ("high", "medium", "low", "info")
_DISCLAIMER = (
    "Findings are produced by heuristics over packet metadata. They describe traffic "
    "that matches patterns associated with malicious activity; they are indicators to "
    "investigate, not confirmation that an attack occurred. Severity expresses how much "
    "a finding would matter if confirmed; confidence expresses how closely the observed "
    "data matches the pattern.")


def _ts(ts) -> str:
    if ts is None:
        return "-"
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(ts))


def _conf_label(c: float) -> str:
    return "high" if c >= 0.7 else "medium" if c >= 0.4 else "low"


def build_report(store: CaptureStore) -> dict:
    """Collect everything the report needs into one JSON-serialisable dict."""
    s = store.summary()
    findings = store.findings()
    hosts = store.hosts(sort="bytes", limit=40)["items"]
    flagged = store.hosts(sort="severity", limit=200)["items"]
    flagged = [h for h in flagged if h["findings"]][:20]
    sev = s.get("findings_by_severity", {})

    # executive summary: deliberately plain and non-committal
    lines = [
        f"The capture '{s.get('filename', '')}' contains {s.get('packets', 0):,} packets "
        f"({human_bytes(s.get('bytes', 0))}) recorded over "
        f"{human_duration(s.get('duration', 0))}, from {_ts(s.get('start_ts'))} to "
        f"{_ts(s.get('end_ts'))}. {s.get('hosts', 0)} addresses and "
        f"{s.get('flows', 0):,} connections were identified.",
    ]
    notable = [f for f in findings if f["severity"] in ("high", "medium")]
    if not findings:
        lines.append("No detector produced a finding. This means no traffic matched the "
                     "implemented heuristics; it does not establish that the network was clean.")
    else:
        lines.append(
            f"Automated analysis produced {len(findings)} finding(s): "
            + ", ".join(f"{sev.get(k, 0)} {k}" for k in SEV_ORDER if sev.get(k)) + ".")
        if notable:
            cats: dict[str, int] = {}
            for f in notable:
                cats[f["category"]] = cats.get(f["category"], 0) + 1
            lines.append("The findings that most warrant review concern: "
                         + ", ".join(f"{c.lower()} ({n})" for c, n in cats.items()) + ".")
        if flagged:
            top = flagged[:3]
            lines.append("Hosts associated with the most severe findings: "
                         + ", ".join(f"{h['ip']} ({h['findings']} finding(s), highest: "
                                     f"{h['max_severity']})" for h in top) + ".")
    lines.append(_DISCLAIMER)

    recs: dict[str, list[str]] = {}
    for f in findings:
        if f["severity"] in ("high", "medium", "low"):
            for r in f["recommendations"]:
                recs.setdefault(r, []).append(f["title"])
    recommendations = [{"action": r, "related_findings": sorted(set(t))[:4]}
                       for r, t in list(recs.items())[:25]]

    return {
        "generated_at": time.time(),
        "tool": f"NetSleuth {s.get('netsleuth_version', '')}",
        "capture": s,
        "executive_summary": lines,
        "hosts": hosts,
        "flagged_hosts": flagged,
        "communication": {
            "protocols": _protocol_table(store),
            "top_conversations": store.top_conversations(15),
            "top_services": store.top_services(15),
            "top_domains": store.top_domains(15),
        },
        "findings": findings,
        "recommendations": recommendations,
        "detectors": store.meta("detectors", []),
        "limitations": [
            _DISCLAIMER,
            "Encrypted payloads are not decrypted; TLS analysis uses handshake metadata only.",
            "IP fragments are not reassembled and tunnelled traffic (GRE, IP-in-IP, VXLAN) "
            "is not decapsulated.",
            "Internal/external classification is based on address ranges (RFC 1918, ULA and "
            "configured networks), not on knowledge of the monitored organisation.",
            "Absence of a finding is not evidence of absence: the detectors cover a defined "
            "set of behaviours and tuned thresholds.",
        ] + [f"Analysis note: {w}" for w in s.get("warnings", [])],
    }


def _protocol_table(store: CaptureStore) -> list[dict]:
    agg: dict[str, list[int]] = {}
    for row in store.meta("protocols", []):
        label = row["app"] or row["transport"] or row["net"]
        a = agg.setdefault(label, [0, 0])
        a[0] += row["packets"]
        a[1] += row["bytes"] or 0
    return [{"protocol": k, "packets": v[0], "bytes": v[1]}
            for k, v in sorted(agg.items(), key=lambda kv: -kv[1][1])]


# ----------------------------------------------------------------- Markdown ---
def _md(text) -> str:
    """Escape capture-derived text for a Markdown table cell / inline text."""
    s = "" if text is None else str(text)
    for ch in "\\`*_{}[]<>|#":
        s = s.replace(ch, "\\" + ch)
    return s.replace("\n", " ").replace("\r", " ")


def _evidence_lines(evidence: dict) -> list[tuple[str, str]]:
    out = []
    for k, v in evidence.items():
        if v is None or v == [] or v == {}:
            continue
        if isinstance(v, (list, dict)):
            v = json.dumps(v, ensure_ascii=True) if isinstance(v, dict) or (v and isinstance(v[0], dict)) \
                else ", ".join(str(x) for x in v)
        out.append((k.replace("_", " "), str(v)[:600]))
    return out


def render_markdown(r: dict) -> str:
    c = r["capture"]
    o = [f"# Network Investigation Report: {_md(c.get('filename'))}", "",
         f"Generated {_ts(r['generated_at'])} by {r['tool']}", "",
         "## 1. Executive summary", ""]
    o += [p + "\n" for p in r["executive_summary"]]
    o += ["## 2. Capture details", "", "| Property | Value |", "|---|---|",
          f"| File | {_md(c.get('filename'))} |",
          f"| SHA-256 | `{c.get('sha256')}` |",
          f"| Size | {human_bytes(c.get('file_size', 0))} ({c.get('format')}) |",
          f"| Link type(s) | {_md(', '.join(c.get('link_types', [])))} |",
          f"| Time range | {_ts(c.get('start_ts'))} to {_ts(c.get('end_ts'))} |",
          f"| Packets / bytes | {c.get('packets', 0):,} / {human_bytes(c.get('bytes', 0))} |",
          f"| Connections | {c.get('flows', 0):,} |",
          f"| Malformed packets | {c.get('malformed_packets', 0):,} |", ""]
    o += ["## 3. Identified hosts", "",
          "| Address | Scope | Names | Sent | Received | Peers | Findings |", "|---|---|---|---|---|---|---|"]
    for h in r["hosts"]:
        o.append(f"| {_md(h['ip'])} | {h['scope']} | {_md(', '.join((h['names'] or [])[:3]))} | "
                 f"{human_bytes(h['bytes_out'])} | {human_bytes(h['bytes_in'])} | {h['peers']} | "
                 f"{h['findings'] or ''} {h['max_severity']} |")
    comm = r["communication"]
    o += ["", "## 4. Communication patterns", "", "### Protocols", "",
          "| Protocol | Packets | Bytes |", "|---|---|---|"]
    o += [f"| {_md(p['protocol'])} | {p['packets']:,} | {human_bytes(p['bytes'])} |"
          for p in comm["protocols"][:15]]
    o += ["", "### Top conversations", "", "| Endpoint A | Endpoint B | Connections | Bytes | Protocols |",
          "|---|---|---|---|---|"]
    o += [f"| {_md(x['a'])} | {_md(x['b'])} | {x['flows']:,} | {human_bytes(x['bytes'])} | {_md(x['protos'])} |"
          for x in comm["top_conversations"]]
    o += ["", "### Top services", "", "| Service | Connections | Clients | Servers | Bytes |", "|---|---|---|---|---|"]
    o += [f"| {x['port']}/{x['proto'].lower()} {_md(x['app'] or '')} | {x['flows']:,} | {x['clients']} | "
          f"{x['servers']} | {human_bytes(x['bytes'])} |" for x in comm["top_services"]]
    if comm["top_domains"]:
        o += ["", "### Most queried DNS names", "", "| Name | Queries | Clients |", "|---|---|---|"]
        o += [f"| {_md(x['qname'])} | {x['queries']} | {x['clients']} |" for x in comm["top_domains"]]
    o += ["", "## 5. Suspicious activity and supporting evidence", ""]
    if not r["findings"]:
        o.append("No findings.\n")
    for i, f in enumerate(r["findings"], 1):
        o += [f"### 5.{i} {_md(f['title'])}", "",
              f"- **Severity:** {f['severity']}  |  **Confidence:** {f['confidence']:.2f} "
              f"({_conf_label(f['confidence'])})  |  **Category:** {_md(f['category'])}",
              f"- **Observed:** {_ts(f['first_ts'])} to {_ts(f['last_ts'])}",
              f"- **Hosts:** {_md(', '.join(f['hosts'][:8]))}", "",
              _md(f["summary"]), "", f"**Why this was flagged.** {_md(f['explanation'])}", "",
              "**Evidence**", ""]
        o += [f"- {_md(k)}: {_md(v)}" for k, v in _evidence_lines(f["evidence"])]
        if f["caveats"]:
            o += ["", "**Benign explanations to rule out**", ""] + [f"- {_md(x)}" for x in f["caveats"]]
        if f["mitre"]:
            o += ["", "**Possibly related ATT&CK techniques:** "
                  + ", ".join(f"{m['id']} {_md(m['name'])}" for m in f["mitre"])]
        o.append("")
    o += ["## 6. Technical recommendations", ""]
    if not r["recommendations"]:
        o.append("No specific recommendations.\n")
    o += [f"{i}. {_md(x['action'])} _(from: {_md('; '.join(x['related_findings']))})_"
          for i, x in enumerate(r["recommendations"], 1)]
    o += ["", "## 7. Method and limitations", ""] + [f"- {_md(x)}" for x in r["limitations"]]
    return "\n".join(o) + "\n"


# --------------------------------------------------------------------- HTML ---
_CSS = """
:root{--bg:#fff;--fg:#1a1f2b;--muted:#5b6475;--line:#dfe3ea;--panel:#f5f7fa;
--high:#b3261e;--medium:#a85d00;--low:#1f6f8b;--info:#5b6475}
*{box-sizing:border-box}body{font:14px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif;
color:var(--fg);background:var(--bg);margin:0}main{max-width:1000px;margin:0 auto;padding:40px 28px 80px}
h1{font-size:26px;margin:0 0 4px}h2{font-size:18px;margin:40px 0 12px;padding-bottom:6px;
border-bottom:2px solid var(--fg)}h3{font-size:15px;margin:22px 0 8px}
.sub{color:var(--muted);margin-bottom:24px}table{border-collapse:collapse;width:100%;margin:8px 0 16px;font-size:13px}
th,td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--line);vertical-align:top;word-break:break-word}
th{background:var(--panel);font-weight:600}td.n,th.n{text-align:right;white-space:nowrap;font-variant-numeric:tabular-nums}
code,.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:16px 0}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:10px 12px}
.tile b{display:block;font-size:20px}.tile span{color:var(--muted);font-size:12px}
.finding{border:1px solid var(--line);border-left-width:5px;border-radius:6px;padding:14px 18px;margin:14px 0;break-inside:avoid}
.finding.high{border-left-color:var(--high)}.finding.medium{border-left-color:var(--medium)}
.finding.low{border-left-color:var(--low)}.finding.info{border-left-color:var(--info)}
.finding h3{margin:0 0 6px}.badge{display:inline-block;padding:1px 8px;border-radius:10px;font-size:11px;
font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:#fff;margin-right:6px}
.badge.high{background:var(--high)}.badge.medium{background:var(--medium)}.badge.low{background:var(--low)}
.badge.info{background:var(--info)}.meta{color:var(--muted);font-size:12px;margin-bottom:8px}
.ev td:first-child{width:32%;color:var(--muted)}ul{margin:6px 0 10px;padding-left:20px}
.note{background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:10px 14px;color:var(--muted);font-size:13px}
@media print{main{padding:0}h2{break-after:avoid}}
"""


def render_html(r: dict) -> str:
    e = html.escape
    c = r["capture"]
    sev = c.get("findings_by_severity", {})
    o = ["<!doctype html><html lang='en'><head><meta charset='utf-8'>",
         "<meta name='viewport' content='width=device-width,initial-scale=1'>",
         f"<title>Investigation report - {e(str(c.get('filename', '')))}</title>",
         f"<style>{_CSS}</style></head><body><main>",
         "<h1>Network Investigation Report</h1>",
         f"<div class='sub'>{e(str(c.get('filename', '')))} &middot; generated "
         f"{e(_ts(r['generated_at']))} by {e(r['tool'])}</div>",
         "<h2>1. Executive summary</h2>"]
    o += [f"<p>{e(p)}</p>" for p in r["executive_summary"][:-1]]
    o.append(f"<p class='note'>{e(r['executive_summary'][-1])}</p>")
    o.append("<div class='tiles'>")
    for label, value in (("Packets", f"{c.get('packets', 0):,}"), ("Data", human_bytes(c.get("bytes", 0))),
                         ("Duration", human_duration(c.get("duration", 0))), ("Hosts", c.get("hosts", 0)),
                         ("Connections", f"{c.get('flows', 0):,}"),
                         ("Findings", " / ".join(f"{sev.get(k, 0)} {k}" for k in SEV_ORDER if sev.get(k)) or "0")):
        o.append(f"<div class='tile'><b>{e(str(value))}</b><span>{e(label)}</span></div>")
    o.append("</div>")

    o.append("<h2>2. Capture details</h2><table>")
    for k, v in (("File", c.get("filename")), ("SHA-256", c.get("sha256")),
                 ("Size / format", f"{human_bytes(c.get('file_size', 0))} ({c.get('format')})"),
                 ("Link type(s)", ", ".join(c.get("link_types", []))),
                 ("First packet", _ts(c.get("start_ts"))), ("Last packet", _ts(c.get("end_ts"))),
                 ("Malformed packets", f"{c.get('malformed_packets', 0):,}")):
        o.append(f"<tr><th style='width:22%'>{e(k)}</th><td class='mono'>{e(str(v))}</td></tr>")
    o.append("</table>")

    o.append("<h2>3. Identified hosts</h2><table><tr><th>Address</th><th>Scope</th><th>Names</th>"
             "<th class='n'>Sent</th><th class='n'>Received</th><th class='n'>Peers</th><th>Findings</th></tr>")
    for h in r["hosts"]:
        badge = (f"<span class='badge {e(h['max_severity'])}'>{h['findings']} {e(h['max_severity'])}</span>"
                 if h["findings"] else "")
        o.append(f"<tr><td class='mono'>{e(h['ip'])}</td><td>{e(h['scope'] or '')}</td>"
                 f"<td>{e(', '.join((h['names'] or [])[:3]))}</td><td class='n'>{human_bytes(h['bytes_out'])}</td>"
                 f"<td class='n'>{human_bytes(h['bytes_in'])}</td><td class='n'>{h['peers']}</td><td>{badge}</td></tr>")
    o.append("</table>")

    comm = r["communication"]
    o.append("<h2>4. Communication patterns</h2><h3>Protocols</h3><table><tr><th>Protocol</th>"
             "<th class='n'>Packets</th><th class='n'>Bytes</th></tr>")
    o += [f"<tr><td>{e(p['protocol'])}</td><td class='n'>{p['packets']:,}</td><td class='n'>{human_bytes(p['bytes'])}</td></tr>"
          for p in comm["protocols"][:15]]
    o.append("</table><h3>Top conversations</h3><table><tr><th>Endpoint A</th><th>Endpoint B</th>"
             "<th class='n'>Connections</th><th class='n'>Bytes</th><th>Protocols</th></tr>")
    o += [f"<tr><td class='mono'>{e(x['a'])}</td><td class='mono'>{e(x['b'])}</td><td class='n'>{x['flows']:,}</td>"
          f"<td class='n'>{human_bytes(x['bytes'])}</td><td>{e(x['protos'] or '')}</td></tr>"
          for x in comm["top_conversations"]]
    o.append("</table><h3>Top services</h3><table><tr><th>Service</th><th class='n'>Connections</th>"
             "<th class='n'>Clients</th><th class='n'>Servers</th><th class='n'>Bytes</th></tr>")
    o += [f"<tr><td>{x['port']}/{e(x['proto'].lower())} {e(x['app'] or '')}</td><td class='n'>{x['flows']:,}</td>"
          f"<td class='n'>{x['clients']}</td><td class='n'>{x['servers']}</td><td class='n'>{human_bytes(x['bytes'])}</td></tr>"
          for x in comm["top_services"]]
    o.append("</table>")
    if comm["top_domains"]:
        o.append("<h3>Most queried DNS names</h3><table><tr><th>Name</th><th class='n'>Queries</th><th class='n'>Clients</th></tr>")
        o += [f"<tr><td class='mono'>{e(x['qname'])}</td><td class='n'>{x['queries']}</td><td class='n'>{x['clients']}</td></tr>"
              for x in comm["top_domains"]]
        o.append("</table>")

    o.append("<h2>5. Suspicious activity and supporting evidence</h2>")
    if not r["findings"]:
        o.append("<p>No findings.</p>")
    for i, f in enumerate(r["findings"], 1):
        sv = e(f["severity"])
        o.append(f"<div class='finding {sv}'><h3>5.{i} {e(f['title'])}</h3>"
                 f"<div class='meta'><span class='badge {sv}'>{sv}</span>confidence {f['confidence']:.2f} "
                 f"({_conf_label(f['confidence'])}) &middot; {e(f['category'])} &middot; "
                 f"{e(_ts(f['first_ts']))} to {e(_ts(f['last_ts']))}</div>"
                 f"<p><b>{e(f['summary'])}</b></p><p>{e(f['explanation'])}</p><table class='ev'>")
        o += [f"<tr><td>{e(k)}</td><td class='mono'>{e(v)}</td></tr>" for k, v in _evidence_lines(f["evidence"])]
        o.append("</table>")
        if f["caveats"]:
            o.append("<b>Benign explanations to rule out</b><ul>" + "".join(f"<li>{e(x)}</li>" for x in f["caveats"]) + "</ul>")
        if f["mitre"]:
            o.append("<div class='meta'>Possibly related ATT&amp;CK techniques: "
                     + ", ".join(f"{e(m['id'])} {e(m['name'])}" for m in f["mitre"]) + "</div>")
        o.append("</div>")

    o.append("<h2>6. Technical recommendations</h2>")
    if r["recommendations"]:
        o.append("<ol>" + "".join(
            f"<li>{e(x['action'])} <span class='meta'>({e('; '.join(x['related_findings']))})</span></li>"
            for x in r["recommendations"]) + "</ol>")
    else:
        o.append("<p>No specific recommendations.</p>")
    o.append("<h2>7. Method and limitations</h2><ul>" + "".join(f"<li>{e(x)}</li>" for x in r["limitations"]) + "</ul>")
    o.append("</main></body></html>")
    return "".join(o)
