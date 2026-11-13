"""Flow tracking, TCP session reconstruction and application-layer extraction.

A *flow* is one conversation: a TCP connection, a UDP exchange between two
endpoints (bounded by an idle timeout) or an ICMP exchange between two hosts.
`src`/`sport` always denote the originator.

TCP payload is reassembled in sequence order per direction (handling
retransmission, overlap and limited reordering) but only as far as needed to
identify the application protocol and extract message heads; bulk payload is
never retained.
"""

from __future__ import annotations

from collections import deque

from ..config import Limits
from ..ingest.decode import ACK, FIN, RST, SYN, Packet
from ..ingest.dns import DnsMessage, parse_dns
from ..ingest.http import HttpDirection, looks_like_request
from ..ingest import tls as tlsmod
from .addr import service_name

_M32 = 0xFFFFFFFF
_HALF = 0x80000000

L7_HTTP, L7_TLS, L7_DNS, L7_FTP, L7_DONE = 1, 2, 3, 4, 9

DNS_PORTS = {53: "DNS", 5353: "mDNS", 5355: "LLMNR"}

STATE_DESCRIPTIONS = {
    "S0": "Connection attempt seen, no reply",
    "S1": "Established, not terminated within the capture",
    "SF": "Established and closed normally",
    "REJ": "Connection attempt rejected (RST)",
    "S2": "Established; originator closed, no close from responder",
    "S3": "Established; responder closed, no close from originator",
    "RSTO": "Established; aborted by originator (RST)",
    "RSTR": "Established; aborted by responder (RST)",
    "RSTOS0": "Originator sent SYN then RST; no reply seen",
    "SH": "Originator sent SYN then FIN; no reply seen",
    "OTH": "Mid-stream traffic; no handshake captured",
    "REPLIED": "Datagrams seen in both directions",
    "UNANSWERED": "Datagrams from originator only",
    "-": "",
}
FAILED_STATES = frozenset(("S0", "REJ", "RSTOS0", "SH"))


class Stream:
    """In-order reassembly buffer for one direction of a TCP connection."""

    __slots__ = ("base", "nxt", "buf", "skip", "pending", "active")

    MAX_PENDING = 64
    MAX_GAP = 1 << 20

    def __init__(self, base: int):
        self.base = base            # sequence number of stream offset 0
        self.nxt = 0                # next contiguous stream offset expected
        self.buf = bytearray()      # contiguous bytes not yet consumed
        self.skip = 0               # bytes to discard on arrival (bodies)
        self.pending = None         # out-of-order segments: offset -> bytes
        self.active = True

    def add(self, seq: int, data: bytes) -> bool:
        """Offer a segment. Returns True when new contiguous bytes arrived."""
        rel = (seq - self.base) & _M32
        if rel >= _HALF:
            return False            # entirely before the stream start
        nxt = self.nxt
        if rel > nxt:
            if rel - nxt <= self.MAX_GAP:
                if self.pending is None:
                    self.pending = {}
                if len(self.pending) < self.MAX_PENDING:
                    self.pending[rel] = data
            return False
        if rel < nxt:
            overlap = nxt - rel
            if overlap >= len(data):
                return False        # pure retransmission
            data = data[overlap:]
        self._append(data)
        pending = self.pending
        while pending:
            ready = [r for r in pending if r <= self.nxt]
            if not ready:
                break
            for r in sorted(ready):
                seg = pending.pop(r)
                overlap = self.nxt - r
                if overlap < len(seg):
                    self._append(seg[overlap:] if overlap else seg)
        return True

    def _append(self, data: bytes) -> None:
        n = len(data)
        self.nxt += n
        if self.skip:
            if self.skip >= n:
                self.skip -= n
                return
            data = data[self.skip:]
            self.skip = 0
        self.buf += data

    def skip_ahead(self, n: int) -> None:
        """Discard the next `n` stream bytes, buffered or yet to arrive."""
        have = len(self.buf)
        if n <= have:
            del self.buf[:n]
        else:
            self.buf.clear()
            self.skip += n - have

    def deactivate(self) -> None:
        self.active = False
        self.buf.clear()
        self.pending = None


class Flow:
    __slots__ = (
        "id", "proto", "src", "sport", "dst", "dport", "first_ts", "last_ts",
        "pkts_fwd", "pkts_rev", "bytes_fwd", "bytes_rev", "payload_fwd", "payload_rev",
        "syn", "synack", "est", "fin_fwd", "fin_rev", "rst_fwd", "rst_rev",
        "first_flags", "flags_fwd", "flags_rev", "syn_count", "retrans", "ooo",
        "isn_fwd", "isn_rev", "nxt_fwd", "nxt_rev", "hole_fwd", "hole_rev", "s_fwd", "s_rev",
        "l7", "l7_state", "app", "app_by", "sni", "http_host", "detail",
        "state", "tls",
    )

    def __init__(self, fid: int, proto: str, src: str, sport: int, dst: str,
                 dport: int, ts: float):
        self.id = fid
        self.proto = proto
        self.src = src
        self.sport = sport
        self.dst = dst
        self.dport = dport
        self.first_ts = ts
        self.last_ts = ts
        self.pkts_fwd = self.pkts_rev = 0
        self.bytes_fwd = self.bytes_rev = 0
        self.payload_fwd = self.payload_rev = 0
        self.syn = self.synack = self.est = False
        self.fin_fwd = self.fin_rev = self.rst_fwd = self.rst_rev = False
        self.first_flags = None
        self.flags_fwd = self.flags_rev = 0
        self.syn_count = 0
        self.retrans = self.ooo = 0
        self.isn_fwd = self.isn_rev = None
        self.nxt_fwd = self.nxt_rev = None
        self.hole_fwd = self.hole_rev = None   # most recent sequence gap (start, end)
        self.s_fwd = self.s_rev = None
        self.l7 = None
        self.l7_state = None
        self.app = ""
        self.app_by = ""        # "payload" (content inspected) or "port" (inferred)
        self.sni = ""
        self.http_host = ""
        self.detail = ""
        self.state = "-"
        self.tls = None

    # -- derived views used by detectors and reports ----------------------
    @property
    def duration(self) -> float:
        return self.last_ts - self.first_ts

    @property
    def packets(self) -> int:
        return self.pkts_fwd + self.pkts_rev

    @property
    def bytes(self) -> int:
        return self.bytes_fwd + self.bytes_rev

    @property
    def failed(self) -> bool:
        """TCP attempt that never produced an established connection."""
        return self.state in FAILED_STATES

    @property
    def established(self) -> bool:
        if self.proto == "TCP":
            return self.est
        return self.pkts_rev > 0

    @property
    def closed(self) -> bool:
        return self.rst_fwd or self.rst_rev or (self.fin_fwd and self.fin_rev)


class HttpTx:
    __slots__ = ("ts", "flow_id", "src", "dst", "dport", "method", "host", "uri",
                 "version", "user_agent", "referer", "req_content_type", "req_len",
                 "auth_scheme", "status", "resp_content_type", "resp_len", "server")

    def __init__(self, ts, flow):
        self.ts = ts
        self.flow_id = flow.id
        self.src = flow.src
        self.dst = flow.dst
        self.dport = flow.dport
        self.method = self.host = self.uri = self.version = ""
        self.user_agent = self.referer = self.req_content_type = ""
        self.req_len = None
        self.auth_scheme = ""
        self.status = None
        self.resp_content_type = self.server = ""
        self.resp_len = None


class TlsInfo:
    __slots__ = ("ts", "flow_id", "src", "dst", "dport", "sni", "client_version",
                 "version", "cipher", "alpn", "ja3", "ja3_string", "ja3s",
                 "ciphers_offered")

    def __init__(self, ts, flow):
        self.ts = ts
        self.flow_id = flow.id
        self.src = flow.src
        self.dst = flow.dst
        self.dport = flow.dport
        self.sni = ""
        self.client_version = ""
        self.version = ""
        self.cipher = ""
        self.alpn = ""
        self.ja3 = self.ja3_string = self.ja3s = ""
        self.ciphers_offered = 0


class DnsTx:
    __slots__ = ("ts", "flow_id", "client", "server", "proto", "transport", "txid",
                 "qname", "qtype", "rcode", "answers", "rtt", "qsize", "rsize",
                 "answered", "retries")

    def __init__(self, ts, flow_id, client, server, proto, transport, txid, qname, qtype):
        self.ts = ts
        self.flow_id = flow_id
        self.client = client
        self.server = server
        self.proto = proto
        self.transport = transport
        self.txid = txid
        self.qname = qname
        self.qtype = qtype
        self.rcode = None
        self.answers: list[str] = []
        self.rtt = None
        self.qsize = 0
        self.rsize = 0
        self.answered = False
        self.retries = 0


class FlowTracker:
    """Consumes decoded packets and maintains the flow table."""

    def __init__(self, limits: Limits | None = None):
        self.limits = limits or Limits()
        self.flows: list[Flow] = []
        self._active: dict[tuple, Flow] = {}
        self.http: list[HttpTx] = []
        self.tls: list[TlsInfo] = []
        self.dns: list[DnsTx] = []
        self._dns_pending: dict[tuple, DnsTx] = {}
        self.names: dict[str, set[str]] = {}          # ip -> names learned from DNS answers
        self.icmp_unreachable: dict[tuple[str, str], int] = {}  # (target, prober) -> count
        self.flows_dropped = 0
        self.records_dropped = 0

    # ------------------------------------------------------------------
    def update(self, pkt: Packet) -> Flow | None:
        proto = pkt.proto
        src, dst = pkt.src, pkt.dst
        if src is None or dst is None or pkt.net == "ARP":
            return None
        is_tcp = proto == "TCP"
        is_udp = proto == "UDP"
        if (is_tcp or is_udp) and pkt.sport is not None:
            sport, dport = pkt.sport, pkt.dport
        else:
            sport = dport = 0
        a = (src, sport)
        b = (dst, dport)
        key = (proto, a, b) if a <= b else (proto, b, a)
        ts = pkt.ts
        flow = self._active.get(key)
        if flow is not None:
            if is_tcp:
                flags = pkt.flags or 0
                if (flags & SYN and not flags & ACK and
                        (flow.closed or (flow.syn and flow.isn_fwd != pkt.seq
                                         and flow.src == src and flow.sport == sport))):
                    flow = None     # the 5-tuple is being reused by a new connection
                elif ts - flow.last_ts > self.limits.tcp_idle_timeout:
                    flow = None
            elif ts - flow.last_ts > self.limits.udp_idle_timeout:
                flow = None
        if flow is None:
            if len(self.flows) >= self.limits.max_flows:
                self.flows_dropped += 1
                return None
            flow = self._new_flow(pkt, proto, src, sport, dst, dport, is_tcp, is_udp)
            self._active[key] = flow

        fwd = flow.src == src and flow.sport == sport
        if ts > flow.last_ts:
            flow.last_ts = ts
        plen = len(pkt.payload)
        if fwd:
            flow.pkts_fwd += 1
            flow.bytes_fwd += pkt.wirelen
            flow.payload_fwd += plen
        else:
            flow.pkts_rev += 1
            flow.bytes_rev += pkt.wirelen
            flow.payload_rev += plen

        if is_tcp:
            if pkt.flags is not None:
                self._tcp(flow, pkt, fwd, plen)
        elif is_udp:
            if plen:
                self._udp(flow, pkt, fwd)
        elif pkt.icmp_type is not None:
            if (proto == "ICMP" and pkt.icmp_type == 3) or (proto == "ICMPv6" and pkt.icmp_type == 1):
                k = (src, dst)
                self.icmp_unreachable[k] = self.icmp_unreachable.get(k, 0) + 1
        return flow

    def _new_flow(self, pkt, proto, src, sport, dst, dport, is_tcp, is_udp) -> Flow:
        swap = False
        if is_tcp and pkt.flags is not None:
            flags = pkt.flags
            if flags & SYN:
                swap = bool(flags & ACK)       # SYN-ACK first: the SYN was missed
            else:
                # Mid-stream: the lower port is taken to be the server. A
                # segment without ACK cannot belong to an existing session
                # (FIN/NULL/Xmas probes), so its sender is the originator.
                swap = bool(flags & ACK) and sport < dport
        elif is_udp:
            swap = sport < 1024 <= dport       # reply seen before its request
        if swap:
            src, sport, dst, dport = dst, dport, src, sport
        flow = Flow(len(self.flows) + 1, proto, src, sport, dst, dport, pkt.ts)
        if is_tcp:
            flow.first_flags = pkt.flags
        self.flows.append(flow)
        return flow

    # -- TCP -------------------------------------------------------------
    def _tcp(self, flow: Flow, pkt: Packet, fwd: bool, plen: int) -> None:
        flags = pkt.flags
        seq = pkt.seq
        if fwd:
            flow.flags_fwd |= flags
        else:
            flow.flags_rev |= flags
        if flags & SYN:
            if flags & ACK:
                flow.synack = True
                if fwd:
                    flow.isn_fwd = seq
                else:
                    flow.isn_rev = seq
            elif fwd:
                if flow.syn and flow.isn_fwd == seq:
                    flow.retrans += 1
                flow.syn = True
                flow.isn_fwd = seq
                flow.syn_count += 1
            else:
                flow.isn_rev = seq             # simultaneous open
        if flags & RST:
            if fwd:
                flow.rst_fwd = True
            else:
                flow.rst_rev = True
        elif flags & FIN:
            if fwd:
                flow.fin_fwd = True
            else:
                flow.fin_rev = True
        if (not flow.est and flow.synack and fwd and flags & ACK
                and not flags & (SYN | RST)):
            flow.est = True

        if not plen:
            return
        seg_end = (seq + plen) & _M32
        nxt = flow.nxt_fwd if fwd else flow.nxt_rev
        if nxt is None:
            isn = flow.isn_fwd if fwd else flow.isn_rev
            if isn is not None:
                nxt = (isn + 1) & _M32         # first data byte follows the SYN
        if nxt is not None:
            d = (seg_end - nxt) & _M32
            if d == 0 or d >= _HALF:
                # Nothing new beyond what was already seen. If it lands in
                # the most recent gap it is a late (reordered) segment,
                # otherwise a retransmission.
                hole = flow.hole_fwd if fwd else flow.hole_rev
                if (hole is not None and ((seq - hole[0]) & _M32) < _HALF
                        and ((hole[1] - seg_end) & _M32) < _HALF):
                    hole = (seg_end, hole[1]) if seg_end != hole[1] else None
                    if fwd:
                        flow.hole_fwd = hole
                    else:
                        flow.hole_rev = hole
                else:
                    flow.retrans += 1
                seg_end = nxt
            elif 0 < ((seq - nxt) & _M32) < _HALF:
                flow.ooo += 1                  # gap: reordering or capture loss
                if fwd:
                    flow.hole_fwd = (nxt, seq)
                else:
                    flow.hole_rev = (nxt, seq)
        if fwd:
            flow.nxt_fwd = seg_end
        else:
            flow.nxt_rev = seg_end

        if flow.l7 == L7_DONE:
            return
        st = flow.s_fwd if fwd else flow.s_rev
        if st is None:
            isn = flow.isn_fwd if fwd else flow.isn_rev
            st = Stream(((isn + 1) & _M32) if isn is not None else seq)
            if fwd:
                flow.s_fwd = st
            else:
                flow.s_rev = st
        if st.active and st.add(seq, pkt.payload):
            self._l7(flow, st, fwd, pkt)
            if len(st.buf) > self.limits.stream_buffer_bytes:
                st.deactivate()
            self._maybe_done(flow)

    def _maybe_done(self, flow: Flow) -> None:
        f, r = flow.s_fwd, flow.s_rev
        if (f is not None and not f.active) and (r is not None and not r.active):
            flow.l7 = L7_DONE
            flow.s_fwd = flow.s_rev = None
            flow.l7_state = None

    def _finish_l7(self, flow: Flow) -> None:
        flow.l7 = L7_DONE
        flow.s_fwd = flow.s_rev = None
        flow.l7_state = None

    def _l7(self, flow: Flow, st: Stream, fwd: bool, pkt: Packet) -> None:
        kind = flow.l7
        if kind is None:
            kind = self._classify(flow, st, fwd)
            if kind is None:
                return
        if kind == L7_HTTP:
            self._http(flow, st, fwd, pkt)
        elif kind == L7_TLS:
            self._tls(flow, st, fwd, pkt)
        elif kind == L7_DNS:
            self._dns_tcp(flow, st, fwd, pkt)
        elif kind == L7_FTP:
            self._ftp(flow, st, fwd)

    def _classify(self, flow: Flow, st: Stream, fwd: bool):
        buf = st.buf
        undecided = False
        if fwd:
            r = looks_like_request(buf)
            if r:
                return self._set_l7(flow, L7_HTTP, "HTTP")
            undecided |= r is None
        elif buf.startswith(b"HTTP/1."):
            return self._set_l7(flow, L7_HTTP, "HTTP")
        t = tlsmod.looks_like_tls(buf)
        if t:
            return self._set_l7(flow, L7_TLS, "TLS")
        undecided |= t is None
        if buf.startswith(b"SSH-"):
            if b"\n" in buf or len(buf) > 255:
                banner = bytes(buf[:buf.find(b"\n")] if b"\n" in buf else buf[:80])
                flow.app, flow.app_by = "SSH", "payload"
                flow.detail = "".join(
                    chr(c) if 0x20 <= c < 0x7F else "." for c in banner.strip()[:80])
                self._finish_l7(flow)
            return None
        if 53 in (flow.dport, flow.sport) and len(buf) >= 2:
            return self._set_l7(flow, L7_DNS, "")
        if not fwd and flow.dport == 21 and buf[:3] == b"220":
            return self._set_l7(flow, L7_FTP, "FTP")
        if undecided and len(buf) < 16:
            return None
        # Unrecognised payload: fall back to a port-based label, clearly
        # marked as an inference rather than an identification.
        guess = service_name("TCP", flow.dport)
        if guess and not flow.app:
            flow.app, flow.app_by = guess, "port"
        self._finish_l7(flow)
        return None

    def _set_l7(self, flow: Flow, kind: int, app: str):
        flow.l7 = kind
        if app:
            flow.app, flow.app_by = app, "payload"
        if kind == L7_HTTP:
            flow.l7_state = (HttpDirection(True), HttpDirection(False), deque(), deque())
        return kind

    def _http(self, flow: Flow, st: Stream, fwd: bool, pkt: Packet) -> None:
        req_p, resp_p, methods, pending = flow.l7_state
        if fwd:
            for m in req_p.feed(st, methods):
                if len(self.http) >= self.limits.max_app_records:
                    self.records_dropped += 1
                    continue
                tx = HttpTx(pkt.ts, flow)
                tx.method, tx.uri, tx.version = m["method"], m["uri"], m["version"]
                tx.host, tx.user_agent, tx.referer = m["host"], m["user_agent"], m["referer"]
                tx.req_content_type, tx.req_len = m["content_type"], m["content_length"]
                tx.auth_scheme = m["auth_scheme"]
                self.http.append(tx)
                if len(pending) < 256:
                    pending.append(tx)
                if not flow.http_host:
                    flow.http_host = tx.host
                if not pkt.info:
                    pkt.info = f"{tx.method} {tx.uri[:160]} {tx.version}"
        else:
            for m in resp_p.feed(st, methods):
                if m["status"] < 200:
                    continue
                if pending:
                    tx = pending.popleft()
                elif len(self.http) < self.limits.max_app_records:
                    tx = HttpTx(pkt.ts, flow)      # response without a captured request
                    self.http.append(tx)
                else:
                    self.records_dropped += 1
                    continue
                tx.status = m["status"]
                tx.resp_content_type, tx.resp_len = m["content_type"], m["content_length"]
                tx.server = m["server"]
                if not pkt.info:
                    pkt.info = f"{m['version']} {m['status']}"

    def _tls(self, flow: Flow, st: Stream, fwd: bool, pkt: Packet) -> None:
        res = tlsmod.extract_handshake(st.buf)
        if res == tlsmod.NEED_MORE:
            if len(st.buf) > 32_768:
                st.deactivate()
            return
        if res == tlsmod.INVALID:
            st.deactivate()
            return
        hs_type, body = res
        st.deactivate()
        info = flow.tls
        if info is None:
            if len(self.tls) >= self.limits.max_app_records:
                self.records_dropped += 1
                return
            info = flow.tls = TlsInfo(pkt.ts, flow)
            self.tls.append(info)
        if hs_type == 1:
            ch = tlsmod.parse_client_hello(body)
            if ch:
                info.sni = flow.sni = ch["sni"]
                info.client_version = tlsmod.version_name(ch["max_version"])
                info.alpn = ",".join(ch["alpn"])
                info.ja3, info.ja3_string = ch["ja3"], ch["ja3_string"]
                info.ciphers_offered = ch["ciphers"]
                pkt.info = "TLS Client Hello" + (f" (SNI={ch['sni']})" if ch["sni"] else " (no SNI)")
        elif hs_type == 2:
            sh = tlsmod.parse_server_hello(body)
            if sh:
                info.version = tlsmod.version_name(sh["version"])
                info.cipher = tlsmod.cipher_name(sh["cipher"])
                info.ja3s = sh["ja3s"]
                if sh["alpn"]:
                    info.alpn = sh["alpn"]
                pkt.info = f"TLS Server Hello ({tlsmod.version_name(sh['version'])})"

    def _dns_tcp(self, flow: Flow, st: Stream, fwd: bool, pkt: Packet) -> None:
        buf = st.buf
        while len(buf) >= 2:
            ln = (buf[0] << 8) | buf[1]
            if ln < 12:
                st.deactivate()
                return
            if len(buf) < 2 + ln:
                return
            msg = parse_dns(bytes(buf[2:2 + ln]))
            del buf[:2 + ln]
            if msg is None:
                st.deactivate()
                return
            flow.app, flow.app_by = "DNS", "payload"
            self._dns_message(flow, pkt, msg, "DNS", "TCP")

    def _ftp(self, flow: Flow, st: Stream, fwd: bool) -> None:
        if not fwd:
            st.buf.clear()
            return
        buf = st.buf
        while True:
            idx = buf.find(b"\n")
            if idx < 0:
                break
            line = bytes(buf[:idx]).strip()
            del buf[:idx + 1]
            cmd = line[:5].upper()
            if cmd.startswith(b"USER "):
                user = "".join(chr(c) if 0x20 < c < 0x7F else "." for c in line[5:37])
                flow.detail = f"cleartext login, user={user}"
            elif cmd.startswith(b"PASS "):
                if not flow.detail:
                    flow.detail = "cleartext login"
                self._finish_l7(flow)
                return

    # -- UDP -------------------------------------------------------------
    def _udp(self, flow: Flow, pkt: Packet, fwd: bool) -> None:
        label = DNS_PORTS.get(flow.dport) or DNS_PORTS.get(flow.sport)
        if label:
            msg = parse_dns(pkt.payload)
            if msg is not None:
                flow.app, flow.app_by = label, "payload"
                self._dns_message(flow, pkt, msg, label, "UDP")
                return
        if not flow.app:
            p = pkt.payload
            if (443 in (flow.dport, flow.sport) and len(p) >= 5 and p[0] & 0x80
                    and (p[1:5] in (b"\x00\x00\x00\x01", b"\x6b\x33\x43\xcf") or p[1] == 0xFF)):
                flow.app, flow.app_by = "QUIC", "payload"
            else:
                guess = service_name("UDP", flow.dport)
                if guess:
                    flow.app, flow.app_by = guess, "port"

    # -- DNS ---------------------------------------------------------------
    def _dns_message(self, flow: Flow, pkt: Packet, msg: DnsMessage,
                     label: str, transport: str) -> None:
        qname, qtype = msg.qname.lower(), msg.qtype
        if msg.is_response:
            server, client, cport = pkt.src, pkt.dst, pkt.dport
        else:
            client, server, cport = pkt.src, pkt.dst, pkt.sport
        key = (client, cport, server, msg.txid, qname, qtype)
        if msg.is_response:
            pkt.info = (f"{label} response 0x{msg.txid:04x} {qtype} {qname or '<root>'} "
                        f"{msg.rcode_name}" + (f" ({len(msg.answers)} answers)" if msg.answers else ""))
            tx = self._dns_pending.pop(key, None) if label != "mDNS" else None
            if tx is None:
                if not self._room(self.dns):
                    return
                tx = DnsTx(pkt.ts, flow.id, client, server, label, transport,
                           msg.txid, qname, qtype)
                self.dns.append(tx)
            else:
                tx.rtt = max(0.0, pkt.ts - tx.ts)
            tx.answered = True
            tx.rcode = msg.rcode_name
            tx.rsize = msg.size
            answers = []
            for name, rtype, _ttl, rdata in msg.answers[:16]:
                answers.append(f"{rtype} {rdata}")
                if rtype in ("A", "AAAA") and label == "DNS":
                    names = self.names.get(rdata)
                    if names is None:
                        if len(self.names) >= self.limits.max_hosts:
                            continue
                        names = self.names[rdata] = set()
                    if len(names) < 8:
                        names.add(qname or name.lower())
            tx.answers = answers
        else:
            pkt.info = f"{label} query 0x{msg.txid:04x} {qtype} {qname or '<root>'}"
            if label != "mDNS":
                prev = self._dns_pending.get(key)
                if prev is not None:
                    prev.retries += 1
                    return
            if not self._room(self.dns):
                return
            tx = DnsTx(pkt.ts, flow.id, client, server, label, transport,
                       msg.txid, qname, qtype)
            tx.qsize = msg.size
            self.dns.append(tx)
            if label != "mDNS":
                if len(self._dns_pending) > 100_000:
                    self._dns_pending.clear()
                self._dns_pending[key] = tx

    def _room(self, table: list) -> bool:
        if len(table) >= self.limits.max_app_records:
            self.records_dropped += 1
            return False
        return True

    # ------------------------------------------------------------------
    def finalize(self) -> None:
        """Compute final connection states and release parser buffers."""
        self._active.clear()
        self._dns_pending.clear()
        for f in self.flows:
            f.s_fwd = f.s_rev = None
            f.l7_state = None
            if f.proto == "TCP":
                f.state = _tcp_state(f)
                if not f.app and (f.payload_fwd or f.payload_rev):
                    guess = service_name("TCP", f.dport)
                    if guess:
                        f.app, f.app_by = guess, "port"
            elif f.proto == "UDP":
                f.state = "REPLIED" if f.pkts_rev else "UNANSWERED"


def _tcp_state(f: Flow) -> str:
    if f.syn:
        if f.synack:
            if f.rst_fwd:
                return "RSTO"
            if f.rst_rev:
                return "RSTR"
            if f.fin_fwd and f.fin_rev:
                return "SF"
            if f.fin_fwd:
                return "S2"
            if f.fin_rev:
                return "S3"
            return "S1"
        if f.rst_rev:
            return "REJ"
        if f.rst_fwd:
            return "RSTOS0"
        if f.fin_fwd:
            return "SH"
        return "S0"
    if not f.est and f.payload_fwd and f.payload_rev:
        f.est = True
    return "OTH"
