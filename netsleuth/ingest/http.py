"""Incremental HTTP/1.x message-head extraction from reassembled TCP streams.

Only message heads are kept. Bodies are framed (Content-Length / chunked) so
that follow-up messages on a keep-alive connection are found, but body bytes
are skipped rather than buffered.
"""

from __future__ import annotations

from collections import deque

METHODS = frozenset((
    b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS", b"PATCH",
    b"CONNECT", b"TRACE", b"PROPFIND", b"PROPPATCH", b"MKCOL", b"COPY",
    b"MOVE", b"LOCK", b"UNLOCK", b"REPORT", b"SEARCH", b"PURGE",
))
MAX_HEAD = 16_384
MAX_CHUNK_LINE = 256

_HEAD, _CHUNK_SIZE, _TRAILER = 0, 1, 2


def looks_like_request(buf) -> bool | None:
    """True/False once decidable, None while more bytes are needed."""
    sp = buf.find(b" ", 0, 12)
    if sp < 0:
        return None if len(buf) < 10 and bytes(buf).isalpha() else False
    return bytes(buf[:sp]) in METHODS


def _clean(raw: bytes, limit: int) -> str:
    s = raw[:limit].decode("latin-1")
    if s.isprintable():
        return s
    return "".join(c if c.isprintable() else f"\\x{ord(c):02x}" for c in s)


def _headers(lines: list[bytes]) -> dict[bytes, bytes]:
    out: dict[bytes, bytes] = {}
    for line in lines:
        k, sep, v = line.partition(b":")
        if sep:
            out.setdefault(k.strip().lower(), v.strip())
    return out


def _int(v: bytes | None) -> int | None:
    if v is None:
        return None
    try:
        n = int(v)
    except ValueError:
        return None
    return n if 0 <= n < 1 << 48 else None


def parse_request_head(head: bytes) -> dict | None:
    lines = head.split(b"\r\n")
    parts = lines[0].split(b" ")
    if len(parts) < 3 or parts[0] not in METHODS or not parts[-1].startswith(b"HTTP/"):
        return None
    # Be lenient like real servers: a request target containing raw spaces
    # is kept whole instead of rejecting the message.
    parts = [parts[0], b" ".join(parts[1:-1]), parts[-1]]
    h = _headers(lines[1:])
    auth = h.get(b"authorization")
    return {
        "kind": "request",
        "method": parts[0].decode("ascii"),
        "uri": _clean(parts[1], 2048),
        "version": _clean(parts[2], 16),
        "host": _clean(h.get(b"host", b""), 255),
        "user_agent": _clean(h.get(b"user-agent", b""), 512),
        "referer": _clean(h.get(b"referer", b""), 1024),
        "content_type": _clean(h.get(b"content-type", b""), 128),
        "content_length": _int(h.get(b"content-length")),
        # Only the scheme is retained - never the credential itself.
        "auth_scheme": _clean(auth.split(b" ", 1)[0], 32) if auth else "",
        "chunked": b"chunked" in h.get(b"transfer-encoding", b"").lower(),
    }


def parse_response_head(head: bytes) -> dict | None:
    lines = head.split(b"\r\n")
    parts = lines[0].split(b" ", 2)
    if len(parts) < 2 or not parts[0].startswith(b"HTTP/"):
        return None
    try:
        status = int(parts[1])
    except ValueError:
        return None
    if not 100 <= status <= 999:
        return None
    h = _headers(lines[1:])
    return {
        "kind": "response",
        "status": status,
        "version": _clean(parts[0], 16),
        "server": _clean(h.get(b"server", b""), 128),
        "content_type": _clean(h.get(b"content-type", b""), 128),
        "content_length": _int(h.get(b"content-length")),
        "chunked": b"chunked" in h.get(b"transfer-encoding", b"").lower(),
    }


class HttpDirection:
    """Parser state for one direction of a connection."""

    __slots__ = ("is_request", "mode", "done")

    def __init__(self, is_request: bool):
        self.is_request = is_request
        self.mode = _HEAD
        self.done = False

    def feed(self, stream, methods: deque) -> list[dict]:
        """Consume what is parseable from `stream.buf`; return message heads.

        `methods` is the queue of request methods awaiting a response; it is
        appended to by the request side and consumed by the response side so
        that HEAD responses are framed correctly.
        """
        out: list[dict] = []
        buf = stream.buf
        while not self.done:
            if self.mode == _HEAD:
                idx = buf.find(b"\r\n\r\n")
                if idx < 0:
                    if len(buf) > MAX_HEAD:
                        self._stop(stream)
                    break
                head = bytes(buf[:idx])
                del buf[:idx + 4]
                msg = (parse_request_head(head) if self.is_request
                       else parse_response_head(head))
                if msg is None:
                    self._stop(stream)
                    break
                out.append(msg)
                if self.is_request:
                    if len(methods) < 256:
                        methods.append(msg["method"])
                    if msg["method"] == "CONNECT":
                        self._stop(stream)   # tunnel: no further HTTP framing
                    elif msg["chunked"]:
                        self.mode = _CHUNK_SIZE
                    elif msg["content_length"]:
                        stream.skip_ahead(msg["content_length"])
                else:
                    status = msg["status"]
                    method = methods.popleft() if methods and status >= 200 else None
                    msg["request_method"] = method
                    if status < 200 and status != 101:
                        continue             # interim response, head follows
                    if status == 101 or method == "CONNECT":
                        self._stop(stream)
                    elif method == "HEAD" or status in (204, 304):
                        continue
                    elif msg["chunked"]:
                        self.mode = _CHUNK_SIZE
                    elif msg["content_length"] is not None:
                        if msg["content_length"]:
                            stream.skip_ahead(msg["content_length"])
                    else:
                        self._stop(stream)   # body delimited by connection close
            elif self.mode == _CHUNK_SIZE:
                idx = buf.find(b"\r\n")
                if idx < 0:
                    if len(buf) > MAX_CHUNK_LINE:
                        self._stop(stream)
                    break
                try:
                    size = int(bytes(buf[:idx]).split(b";", 1)[0].strip() or b"x", 16)
                except ValueError:
                    self._stop(stream)
                    break
                del buf[:idx + 2]
                if size == 0:
                    self.mode = _TRAILER
                elif size > 1 << 40:
                    self._stop(stream)
                else:
                    stream.skip_ahead(size + 2)
            else:  # _TRAILER
                if buf.startswith(b"\r\n"):
                    del buf[:2]
                    self.mode = _HEAD
                    continue
                idx = buf.find(b"\r\n\r\n")
                if idx < 0:
                    if len(buf) > MAX_HEAD:
                        self._stop(stream)
                    break
                del buf[:idx + 4]
                self.mode = _HEAD
        return out

    def _stop(self, stream) -> None:
        self.done = True
        stream.deactivate()
