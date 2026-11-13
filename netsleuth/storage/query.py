"""A small, safe filter language for the packet and connection explorers.

Syntax (terms are AND-ed, whitespace separated)::

    ip:10.0.0.5 port:443 proto:tcp app:tls flag:syn len>1000 -proto:arp "client hello"

Every value is bound as an SQL parameter and every column name comes from a
fixed whitelist, so user input never reaches the SQL text.
"""

from __future__ import annotations

import re
import shlex


class FilterError(ValueError):
    pass


_TERM = re.compile(r"^(-|!)?([a-z_]+)(:|=|>=|<=|>|<)(.+)$", re.I)
_IPISH = re.compile(r"^[0-9a-fA-F:.]{3,45}$")
_FLAG_BITS = {"fin": 1, "syn": 2, "rst": 4, "psh": 8, "ack": 16, "urg": 32}

# kind -> key -> handler description
_PACKET_KEYS = {
    "ip": ("either", "p.src", "p.dst"),
    "host": ("either", "p.src", "p.dst"),
    "src": ("eq", "p.src"),
    "dst": ("eq", "p.dst"),
    "port": ("either_int", "p.sport", "p.dport"),
    "sport": ("int", "p.sport"),
    "dport": ("int", "p.dport"),
    "proto": ("eq_upper", "p.proto"),
    "net": ("eq_nocase", "p.net"),
    "app": ("app", ""),
    "flow": ("int", "p.flow_id"),
    "len": ("num", "p.len"),
    "no": ("num", "p.no"),
    "flag": ("flag", "p.flags"),
    "info": ("like", "p.info"),
}
_FLOW_KEYS = {
    "ip": ("either", "f.src", "f.dst"),
    "host": ("either", "f.src", "f.dst"),
    "src": ("eq", "f.src"),
    "dst": ("eq", "f.dst"),
    "port": ("either_int", "f.sport", "f.dport"),
    "sport": ("int", "f.sport"),
    "dport": ("int", "f.dport"),
    "proto": ("eq_upper", "f.proto"),
    "app": ("eq_nocase", "f.app"),
    "state": ("eq_upper", "f.state"),
    "id": ("int", "f.id"),
    "bytes": ("num", "(f.bytes_fwd + f.bytes_rev)"),
    "packets": ("num", "(f.pkts_fwd + f.pkts_rev)"),
    "duration": ("num", "f.duration"),
    "sni": ("like", "f.sni"),
    "name": ("like_any", "f.sni", "f.http_host"),
    "scope": ("eq_nocase", "f.dst_scope"),
}
_KEYS = {"packets": _PACKET_KEYS, "flows": _FLOW_KEYS}
_FREE_TEXT = {
    "packets": ("p.info",),
    "flows": ("f.sni", "f.http_host", "f.app", "f.detail"),
}
_IP_COLS = {"packets": ("p.src", "p.dst"), "flows": ("f.src", "f.dst")}


def _like(value: str) -> str:
    esc = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{esc}%"


def _to_int(value: str, key: str) -> int:
    try:
        n = int(value)
    except ValueError:
        raise FilterError(f"'{key}' expects a number, got '{value[:40]}'") from None
    if not -(1 << 62) < n < (1 << 62):
        raise FilterError(f"'{key}' value out of range")
    return n


def _to_num(value: str, key: str) -> float:
    try:
        n = float(value)
    except ValueError:
        raise FilterError(f"'{key}' expects a number, got '{value[:40]}'") from None
    if n != n or n in (float("inf"), float("-inf")):
        raise FilterError(f"'{key}' value out of range")
    return n


def parse_filter(text: str, kind: str) -> tuple[str, list]:
    """Translate a filter expression into (sql_where_fragment, params)."""
    keys = _KEYS[kind]
    text = (text or "").strip()
    if not text:
        return "", []
    if len(text) > 500:
        raise FilterError("filter expression too long")
    try:
        tokens = shlex.split(text)
    except ValueError:
        raise FilterError("unbalanced quotes in filter") from None
    if len(tokens) > 24:
        raise FilterError("too many filter terms")
    clauses: list[str] = []
    params: list = []
    for tok in tokens:
        m = _TERM.match(tok)
        if not m or m.group(2).lower() not in keys:
            if m and m.group(3) in (":", "=") and re.fullmatch(r"[a-z_]+", m.group(2), re.I) \
                    and not _IPISH.match(tok):
                raise FilterError(
                    f"unknown filter key '{m.group(2)}' (valid: {', '.join(sorted(keys))})")
            # bare term: an address matches either endpoint, anything else
            # is a substring search over descriptive columns
            neg = tok.startswith(("-", "!")) and len(tok) > 1
            word = tok[1:] if neg else tok
            if _IPISH.match(word) and ("." in word or ":" in word):
                a, b = _IP_COLS[kind]
                clause = f"({a} = ? OR {b} = ?)"
                params += [word, word]
            else:
                cols = _FREE_TEXT[kind]
                clause = "(" + " OR ".join(f"{c} LIKE ? ESCAPE '\\'" for c in cols) + ")"
                params += [_like(word)] * len(cols)
            clauses.append(f"({clause}) IS NOT TRUE" if neg else clause)
            continue
        neg, key, op, value = bool(m.group(1)), m.group(2).lower(), m.group(3), m.group(4)
        spec = keys[key]
        mode = spec[0]
        if op in (">", "<", ">=", "<=") and mode != "num":
            raise FilterError(f"'{key}' does not support the '{op}' operator")
        if mode == "eq":
            clause = f"{spec[1]} = ?"
            params.append(value)
        elif mode == "eq_upper":
            clause = f"{spec[1]} = ?"
            params.append(value.upper())
        elif mode == "eq_nocase":
            clause = f"{spec[1]} = ? COLLATE NOCASE"
            params.append(value)
        elif mode == "either":
            clause = f"({spec[1]} = ? OR {spec[2]} = ?)"
            params += [value, value]
        elif mode == "int":
            clause = f"{spec[1]} = ?"
            params.append(_to_int(value, key))
        elif mode == "either_int":
            n = _to_int(value, key)
            clause = f"({spec[1]} = ? OR {spec[2]} = ?)"
            params += [n, n]
        elif mode == "num":
            sql_op = "=" if op in (":", "=") else op
            clause = f"{spec[1]} {sql_op} ?"
            params.append(_to_num(value, key))
        elif mode == "like":
            clause = f"{spec[1]} LIKE ? ESCAPE '\\'"
            params.append(_like(value))
        elif mode == "like_any":
            clause = "(" + " OR ".join(f"{c} LIKE ? ESCAPE '\\'" for c in spec[1:]) + ")"
            params += [_like(value)] * (len(spec) - 1)
        elif mode == "flag":
            bit = _FLAG_BITS.get(value.lower())
            if bit is None:
                raise FilterError(f"unknown TCP flag '{value[:20]}' (valid: {', '.join(_FLAG_BITS)})")
            clause = f"({spec[1]} & ?) != 0"
            params.append(bit)
        elif mode == "app":
            clause = "p.flow_id IN (SELECT id FROM flows WHERE app = ? COLLATE NOCASE)"
            params.append(value)
        else:  # pragma: no cover - table and code are kept in sync
            raise FilterError(f"unsupported filter key '{key}'")
        clauses.append(f"({clause}) IS NOT TRUE" if neg else clause)
    return " AND ".join(clauses), params
