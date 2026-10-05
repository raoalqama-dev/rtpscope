"""RTP header parsing (RFC 3550, section 5.1)."""

from __future__ import annotations

import struct
from dataclasses import dataclass

__all__ = ["RTP_VERSION", "RtpError", "RtpHeader", "is_rtcp", "parse_rtp"]

RTP_VERSION = 2

_FIXED_HEADER = struct.Struct("!BBHII")


class RtpError(ValueError):
    """The bytes are not a well-formed RTP packet."""


@dataclass(frozen=True, slots=True)
class RtpHeader:
    """The fields of an RTP header, plus where the payload sits in the packet."""

    marker: bool
    payload_type: int
    sequence: int
    timestamp: int
    ssrc: int
    csrcs: tuple[int, ...]
    extension_profile: int | None
    """Profile identifier of the header extension, or ``None`` when there is none."""

    payload_offset: int
    payload_length: int
    padding_length: int


def parse_rtp(data: bytes) -> RtpHeader:
    """Parse the RTP header at the start of ``data``.

    Raises:
        RtpError: if ``data`` is too short, has the wrong version, or its CSRC
            list, header extension or padding run past the end of the packet.
    """
    if len(data) < _FIXED_HEADER.size:
        raise RtpError("packet is shorter than the 12-byte RTP header")
    first, second, sequence, timestamp, ssrc = _FIXED_HEADER.unpack_from(data)

    version = first >> 6
    if version != RTP_VERSION:
        raise RtpError(f"RTP version is {version}, expected {RTP_VERSION}")

    csrc_count = first & 0x0F
    offset = _FIXED_HEADER.size + 4 * csrc_count
    if len(data) < offset:
        raise RtpError("CSRC list runs past the end of the packet")
    csrcs = struct.unpack_from(f"!{csrc_count}I", data, _FIXED_HEADER.size)

    extension_profile = None
    if first & 0x10:
        if len(data) < offset + 4:
            raise RtpError("header extension runs past the end of the packet")
        extension_profile, extension_words = struct.unpack_from("!HH", data, offset)
        offset += 4 + 4 * extension_words
        if len(data) < offset:
            raise RtpError("header extension runs past the end of the packet")

    padding_length = 0
    if first & 0x20:
        padding_length = data[-1]
        if padding_length == 0 or offset + padding_length > len(data):
            raise RtpError(f"invalid padding length {padding_length}")

    return RtpHeader(
        marker=bool(second & 0x80),
        payload_type=second & 0x7F,
        sequence=sequence,
        timestamp=timestamp,
        ssrc=ssrc,
        csrcs=csrcs,
        extension_profile=extension_profile,
        payload_offset=offset,
        payload_length=len(data) - offset - padding_length,
        padding_length=padding_length,
    )


def is_rtcp(data: bytes) -> bool:
    """Return whether ``data`` looks like RTCP rather than RTP.

    RTCP packet types occupy 192-223 in the second byte, which RTP can only
    produce with payload types 64-95 and the marker bit set; RFC 5761 rules out
    those payload types precisely so the two can share a port.
    """
    return len(data) >= 8 and data[0] >> 6 == RTP_VERSION and 192 <= data[1] <= 223
