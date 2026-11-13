"""Streaming readers for the classic PCAP and PCAPNG capture formats.

The readers are deliberately defensive: every length field read from the file
is validated against hard limits before any allocation happens, and structural
damage ends iteration with a recorded warning instead of an exception, so that
everything readable before the damage is still analysed.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass
from typing import BinaryIO, Iterator

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),      # little endian, microseconds
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),      # big endian, microseconds
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),  # little endian, nanoseconds
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),  # big endian, nanoseconds
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

BT_IDB = 0x00000001
BT_PB = 0x00000002
BT_SPB = 0x00000003
BT_EPB = 0x00000006


class CaptureFormatError(ValueError):
    """The input is not a capture file we can read at all."""


@dataclass(frozen=True)
class ReaderLimits:
    # libpcap's MAXIMUM_SNAPLEN; a record claiming more than this is corruption.
    max_packet_bytes: int = 262_144
    # Upper bound for a single pcapng block (option blocks, name resolution...).
    max_block_bytes: int = 16 * 1024 * 1024
    max_interfaces: int = 4096


class RawPacket:
    """One captured frame, exactly as stored in the file."""

    __slots__ = ("no", "ts", "caplen", "wirelen", "linktype", "offset", "data")

    def __init__(self, no, ts, caplen, wirelen, linktype, offset, data):
        self.no = no
        self.ts = ts
        self.caplen = caplen
        self.wirelen = wirelen
        self.linktype = linktype
        self.offset = offset  # byte offset of the frame data inside the file
        self.data = data


class CaptureReader:
    """Iterate over the packets of a capture file.

    Usage::

        with CaptureReader(path) as reader:
            for raw in reader:
                ...
        reader.warnings  # structural problems met while reading
    """

    def __init__(self, path: str | os.PathLike, limits: ReaderLimits | None = None):
        self.path = os.fspath(path)
        self.limits = limits or ReaderLimits()
        self.warnings: list[str] = []
        self.format = ""
        self.linktypes: set[int] = set()
        self.packets_read = 0
        self.file_size = os.path.getsize(self.path)
        self._f: BinaryIO = open(self.path, "rb", buffering=1024 * 1024)
        try:
            magic = self._f.read(4)
            if magic in PCAP_MAGICS:
                self.format = "pcap"
                self._endian, self._ts_div = PCAP_MAGICS[magic]
                self._read_pcap_header()
            elif magic == PCAPNG_MAGIC:
                self.format = "pcapng"
                self._f.seek(0)
            elif magic[:2] == b"\x1f\x8b":
                raise CaptureFormatError(
                    "file is gzip-compressed; decompress it before analysis")
            else:
                raise CaptureFormatError(
                    "not a PCAP or PCAPNG file (unrecognised magic number)")
        except Exception:
            self._f.close()
            raise

    # -- context management -------------------------------------------------
    def __enter__(self) -> "CaptureReader":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        self._f.close()

    @property
    def bytes_read(self) -> int:
        try:
            return self._f.tell()
        except ValueError:
            return self.file_size

    def __iter__(self) -> Iterator[RawPacket]:
        if self.format == "pcap":
            return self._iter_pcap()
        return self._iter_pcapng()

    # -- classic pcap -------------------------------------------------------
    def _read_pcap_header(self) -> None:
        rest = self._f.read(20)
        if len(rest) < 20:
            raise CaptureFormatError("truncated PCAP global header")
        major, minor, _tz, _sig, snaplen, network = struct.unpack(
            self._endian + "HHiIII", rest)
        self.version = (major, minor)
        self.snaplen = snaplen
        # The upper bits may carry FCS length information; the link type
        # itself lives in the low 16 bits.
        self._linktype = network & 0xFFFF
        self.linktypes.add(self._linktype)

    def _iter_pcap(self) -> Iterator[RawPacket]:
        read = self._f.read
        unpack = struct.Struct(self._endian + "IIII").unpack
        div = float(self._ts_div)
        max_len = self.limits.max_packet_bytes
        linktype = self._linktype
        offset = 24
        no = 0
        while True:
            head = read(16)
            if len(head) < 16:
                if head:
                    self.warnings.append(
                        f"truncated record header at offset {offset}; "
                        "capture ends mid-record")
                return
            sec, frac, incl, orig = unpack(head)
            if incl > max_len:
                self.warnings.append(
                    f"record at offset {offset} claims {incl} captured bytes "
                    f"(limit {max_len}); file is corrupt beyond this point, "
                    "stopped reading")
                return
            data = read(incl)
            if len(data) < incl:
                self.warnings.append(
                    f"truncated packet data at offset {offset + 16}; "
                    "last record dropped")
                return
            no += 1
            self.packets_read = no
            yield RawPacket(no, sec + frac / div, incl,
                            orig if orig >= incl else incl,
                            linktype, offset + 16, data)
            offset += 16 + incl

    # -- pcapng -------------------------------------------------------------
    def _iter_pcapng(self) -> Iterator[RawPacket]:
        read = self._f.read
        limits = self.limits
        endian = None
        u32x2 = None
        interfaces: list[tuple[int, float, int, int]] = []
        offset = 0
        no = 0
        bad_iface = 0
        bad_len = 0
        while True:
            head = read(8)
            if len(head) < 8:
                if head:
                    self.warnings.append(
                        f"truncated block header at offset {offset}")
                break
            if head[:4] == PCAPNG_MAGIC:
                bom = read(4)
                if bom == b"\x1a\x2b\x3c\x4d":
                    endian = ">"
                elif bom == b"\x4d\x3c\x2b\x1a":
                    endian = "<"
                else:
                    msg = f"invalid byte-order magic in section header at offset {offset}"
                    if no == 0 and offset == 0:
                        raise CaptureFormatError(msg)
                    self.warnings.append(msg + "; stopped reading")
                    break
                u32x2 = struct.Struct(endian + "II").unpack
                total = struct.unpack(endian + "I", head[4:8])[0]
                if total < 28 or total > limits.max_block_bytes or total % 4:
                    msg = f"invalid section header length {total} at offset {offset}"
                    if offset == 0:
                        raise CaptureFormatError(msg)
                    self.warnings.append(msg + "; stopped reading")
                    break
                rest = read(total - 12)
                if len(rest) < total - 12:
                    self.warnings.append("truncated section header block")
                    break
                interfaces = []  # interface numbering restarts per section
                offset += total
                continue
            if endian is None:
                raise CaptureFormatError("PCAPNG file does not start with a section header")
            btype, total = u32x2(head)
            if total < 12 or total > limits.max_block_bytes or total % 4:
                self.warnings.append(
                    f"block at offset {offset} has invalid length {total}; "
                    "file is corrupt beyond this point, stopped reading")
                break
            body = read(total - 8)
            if len(body) < total - 8:
                self.warnings.append(
                    f"truncated block at offset {offset}; capture ends mid-block")
                break
            blen = total - 12  # body without the trailing length field

            if btype == BT_EPB or btype == BT_PB:
                if blen < 20:
                    bad_len += 1
                else:
                    if btype == BT_EPB:
                        iface, ts_hi, ts_lo, caplen, wirelen = struct.unpack_from(
                            endian + "IIIII", body, 0)
                    else:
                        iface, _drops, ts_hi, ts_lo, caplen, wirelen = struct.unpack_from(
                            endian + "HHIIII", body, 0)
                    if iface >= len(interfaces):
                        bad_iface += 1
                    elif caplen > blen - 20 or caplen > limits.max_packet_bytes:
                        bad_len += 1
                    else:
                        linktype, ts_res, ts_off, _snap = interfaces[iface]
                        ts = ((ts_hi << 32) | ts_lo) / ts_res + ts_off
                        no += 1
                        self.packets_read = no
                        yield RawPacket(no, ts, caplen,
                                        wirelen if wirelen >= caplen else caplen,
                                        linktype, offset + 28, body[20:20 + caplen])
            elif btype == BT_SPB:
                if blen < 4 or not interfaces:
                    bad_len += 1
                else:
                    wirelen = struct.unpack_from(endian + "I", body, 0)[0]
                    linktype, _res, _off, snap = interfaces[0]
                    caplen = min(wirelen, blen - 4)
                    if snap:
                        caplen = min(caplen, snap)
                    if caplen > limits.max_packet_bytes:
                        bad_len += 1
                    else:
                        no += 1
                        self.packets_read = no
                        # Simple packet blocks carry no timestamp at all.
                        yield RawPacket(no, 0.0, caplen, max(wirelen, caplen),
                                        linktype, offset + 12, body[4:4 + caplen])
            elif btype == BT_IDB:
                if blen < 8:
                    bad_len += 1
                elif len(interfaces) >= limits.max_interfaces:
                    self.warnings.append("too many interface blocks; stopped reading")
                    break
                else:
                    interfaces.append(self._parse_idb(body, blen, endian))
            # every other block type (name resolution, statistics, secrets,
            # custom blocks) carries no packets and is skipped
            offset += total

        if bad_iface:
            self.warnings.append(
                f"{bad_iface} packet block(s) referenced an undefined interface and were skipped")
        if bad_len:
            self.warnings.append(
                f"{bad_len} block(s) had inconsistent lengths and were skipped")

    def _parse_idb(self, body: bytes, blen: int, endian: str):
        linktype, _res, snaplen = struct.unpack_from(endian + "HHI", body, 0)
        self.linktypes.add(linktype)
        ts_res = 1_000_000.0
        ts_off = 0
        pos = 8
        opt = struct.Struct(endian + "HH")
        while pos + 4 <= blen:
            code, length = opt.unpack_from(body, pos)
            pos += 4
            if code == 0 or pos + length > blen:
                break
            if code == 9 and length >= 1:  # if_tsresol
                v = body[pos]
                ts_res = float(2 ** (v & 0x7F)) if v & 0x80 else float(10 ** min(v, 18))
            elif code == 14 and length >= 8:  # if_tsoffset
                ts_off = struct.unpack_from(endian + "q", body, pos)[0]
            pos += (length + 3) & ~3
        return (linktype, ts_res, ts_off, snaplen)


def sniff_format(path: str | os.PathLike) -> str:
    """Return 'pcap' or 'pcapng', or raise CaptureFormatError."""
    with open(path, "rb") as f:
        magic = f.read(4)
    if magic in PCAP_MAGICS:
        return "pcap"
    if magic == PCAPNG_MAGIC:
        return "pcapng"
    if magic[:2] == b"\x1f\x8b":
        raise CaptureFormatError("file is gzip-compressed; decompress it before analysis")
    raise CaptureFormatError("not a PCAP or PCAPNG file (unrecognised magic number)")
