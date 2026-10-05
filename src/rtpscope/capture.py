"""Readers for the pcap and pcapng capture file formats.

Only what packet analysis needs is extracted from each record: the capture
timestamp, the link-layer type and the captured bytes. Both formats are read in
either byte order, and a pcapng file may hold several sections and interfaces,
each with its own link type and timestamp resolution.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass
from os import PathLike
from pathlib import Path
from typing import BinaryIO

__all__ = ["CaptureError", "Frame", "iter_frames", "read_frames"]

# A single record larger than this means the length field is garbage.
_MAX_RECORD_LENGTH = 64 * 1024 * 1024

_PCAP_MAGIC_MICROSECONDS = 0xA1B2C3D4
_PCAP_MAGIC_NANOSECONDS = 0xA1B23C4D

_PCAPNG_SECTION_HEADER = b"\x0a\x0d\x0d\x0a"
_PCAPNG_BYTE_ORDER_MAGIC = 0x1A2B3C4D
_PCAPNG_INTERFACE_DESCRIPTION = 0x00000001
_PCAPNG_OBSOLETE_PACKET = 0x00000002
_PCAPNG_ENHANCED_PACKET = 0x00000006

_OPTION_END = 0
_OPTION_IF_TSRESOL = 9
_OPTION_IF_TSOFFSET = 14


class CaptureError(Exception):
    """The capture file is malformed or in a format this reader does not support."""


@dataclass(frozen=True, slots=True)
class Frame:
    """One captured link-layer frame."""

    timestamp: float
    """Capture time in seconds since the Unix epoch."""

    linktype: int
    """Link-layer header type, as a ``LINKTYPE_*`` value from the tcpdump registry."""

    data: bytes
    """Captured bytes. May be shorter than the frame on the wire if a snap length was set."""


def read_frames(path: str | PathLike[str]) -> Iterator[Frame]:
    """Yield every frame in the pcap or pcapng file at ``path``."""
    with Path(path).open("rb") as stream:
        yield from iter_frames(stream)


def iter_frames(stream: BinaryIO) -> Iterator[Frame]:
    """Yield every frame from an open binary capture stream.

    The format is detected from the first four bytes. A record that is cut short
    at the end of the file, as an interrupted capture leaves behind, ends the
    iteration instead of raising.

    Raises:
        CaptureError: if the stream is not a pcap/pcapng capture or is corrupt.
    """
    magic = stream.read(4)
    if len(magic) < 4:
        raise CaptureError("file is too short to be a packet capture")
    if magic == _PCAPNG_SECTION_HEADER:
        yield from _iter_pcapng(stream)
    else:
        yield from _iter_pcap(stream, magic)


# --- pcap -------------------------------------------------------------------


def _pcap_format(magic: bytes) -> tuple[str, float]:
    """Return the struct byte-order prefix and the timestamp fraction unit."""
    for order in ("<", ">"):
        (value,) = struct.unpack(order + "I", magic)
        if value == _PCAP_MAGIC_MICROSECONDS:
            return order, 1e-6
        if value == _PCAP_MAGIC_NANOSECONDS:
            return order, 1e-9
    raise CaptureError(f"not a pcap or pcapng file (magic number {magic.hex()})")


def _iter_pcap(stream: BinaryIO, magic: bytes) -> Iterator[Frame]:
    order, fraction_unit = _pcap_format(magic)

    header = stream.read(20)
    if len(header) < 20:
        raise CaptureError("pcap file header is truncated")
    # version major/minor, thiszone, sigfigs and snaplen are not needed.
    (network,) = struct.unpack_from(order + "I", header, 16)
    # The upper bits of this field can carry FCS information; the link type is the low 16.
    linktype = network & 0xFFFF

    record_header = struct.Struct(order + "IIII")
    while True:
        raw = stream.read(record_header.size)
        if len(raw) < record_header.size:
            return
        seconds, fraction, captured_length, _original_length = record_header.unpack(raw)
        if captured_length > _MAX_RECORD_LENGTH:
            raise CaptureError(f"record length {captured_length} is implausibly large")
        data = stream.read(captured_length)
        if len(data) < captured_length:
            return
        yield Frame(seconds + fraction * fraction_unit, linktype, data)


# --- pcapng -----------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Interface:
    linktype: int
    units_per_second: int
    offset_seconds: int


def _iter_pcapng(stream: BinaryIO) -> Iterator[Frame]:
    # The caller has consumed the type of the first block, which is always a section header.
    order = _read_section_header(stream)
    interfaces: list[_Interface] = []

    while True:
        raw_type = stream.read(4)
        if len(raw_type) < 4:
            return
        if raw_type == _PCAPNG_SECTION_HEADER:
            # A new section may switch byte order and starts a fresh interface list.
            order = _read_section_header(stream)
            interfaces = []
            continue

        body = _read_block_body(stream, order)
        if body is None:
            return
        (block_type,) = struct.unpack(order + "I", raw_type)

        if block_type == _PCAPNG_INTERFACE_DESCRIPTION:
            interfaces.append(_parse_interface(body, order))
        elif block_type in (_PCAPNG_ENHANCED_PACKET, _PCAPNG_OBSOLETE_PACKET):
            if len(body) < 20:
                raise CaptureError("pcapng packet block is truncated")
            if block_type == _PCAPNG_ENHANCED_PACKET:
                interface_id, high, low, captured_length = struct.unpack_from(order + "IIII", body)
            else:
                interface_id, _drops, high, low, captured_length = struct.unpack_from(
                    order + "HHIII", body
                )
            data = body[20 : 20 + captured_length]
            yield _packet_frame(interfaces, interface_id, high, low, data)
        # Every other block (statistics, name resolution, simple packets without
        # timestamps, custom blocks, ...) carries nothing we need.


def _read_section_header(stream: BinaryIO) -> str:
    """Read the rest of a section header block and return its byte order."""
    raw = stream.read(8)
    if len(raw) < 8:
        raise CaptureError("pcapng section header is truncated")
    raw_length, byte_order_magic = raw[:4], raw[4:]
    for order in ("<", ">"):
        if struct.unpack(order + "I", byte_order_magic)[0] == _PCAPNG_BYTE_ORDER_MAGIC:
            break
    else:
        raise CaptureError("pcapng section header has an invalid byte-order magic")

    (total_length,) = struct.unpack(order + "I", raw_length)
    _check_block_length(total_length, minimum=28)
    # Skip version, section length, options and the trailing length field.
    remainder = total_length - 12
    if len(stream.read(remainder)) < remainder:
        raise CaptureError("pcapng section header is truncated")
    return order


def _read_block_body(stream: BinaryIO, order: str) -> bytes | None:
    """Read a block whose type has been consumed; return its body or None at EOF."""
    raw_length = stream.read(4)
    if len(raw_length) < 4:
        return None
    (total_length,) = struct.unpack(order + "I", raw_length)
    _check_block_length(total_length, minimum=12)
    remainder = stream.read(total_length - 8)
    if len(remainder) < total_length - 8:
        return None
    return remainder[:-4]  # drop the trailing copy of the length


def _check_block_length(total_length: int, *, minimum: int) -> None:
    if total_length < minimum or total_length % 4 or total_length > _MAX_RECORD_LENGTH:
        raise CaptureError(f"pcapng block has an invalid length ({total_length})")


def _parse_interface(body: bytes, order: str) -> _Interface:
    if len(body) < 8:
        raise CaptureError("pcapng interface description block is truncated")
    (linktype,) = struct.unpack_from(order + "H", body)
    units_per_second = 1_000_000
    offset_seconds = 0
    for code, value in _iter_options(body[8:], order):
        if code == _OPTION_IF_TSRESOL and value:
            exponent = value[0] & 0x7F
            units_per_second = 2**exponent if value[0] & 0x80 else 10**exponent
        elif code == _OPTION_IF_TSOFFSET and len(value) >= 8:
            (offset_seconds,) = struct.unpack_from(order + "q", value)
    return _Interface(linktype, units_per_second, offset_seconds)


def _iter_options(buffer: bytes, order: str) -> Iterator[tuple[int, bytes]]:
    position = 0
    while position + 4 <= len(buffer):
        code, length = struct.unpack_from(order + "HH", buffer, position)
        if code == _OPTION_END:
            return
        position += 4
        yield code, buffer[position : position + length]
        position += (length + 3) & ~3  # values are padded to 32 bits


def _packet_frame(
    interfaces: list[_Interface], interface_id: int, high: int, low: int, data: bytes
) -> Frame:
    if interface_id >= len(interfaces):
        raise CaptureError(f"packet refers to undeclared interface {interface_id}")
    interface = interfaces[interface_id]
    ticks = (high << 32) | low
    timestamp = ticks / interface.units_per_second + interface.offset_seconds
    return Frame(timestamp, interface.linktype, data)
