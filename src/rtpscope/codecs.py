"""Static RTP payload type assignments (RFC 3551, tables 4 and 5).

Payload types 96-127 are dynamic: their meaning is negotiated per call (usually
in SDP), so they cannot be resolved from the RTP header alone.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, Literal

__all__ = ["DYNAMIC_PAYLOAD_TYPES", "STATIC_PAYLOAD_TYPES", "Codec", "static_codec"]


@dataclass(frozen=True, slots=True)
class Codec:
    """An RTP payload format."""

    name: str
    media: Literal["audio", "video", "audio/video"]
    clock_rate: int
    """RTP timestamp units per second."""


DYNAMIC_PAYLOAD_TYPES: Final = range(96, 128)

STATIC_PAYLOAD_TYPES: Final[Mapping[int, Codec]] = MappingProxyType(
    {
        0: Codec("PCMU", "audio", 8000),
        3: Codec("GSM", "audio", 8000),
        4: Codec("G723", "audio", 8000),
        5: Codec("DVI4", "audio", 8000),
        6: Codec("DVI4", "audio", 16000),
        7: Codec("LPC", "audio", 8000),
        8: Codec("PCMA", "audio", 8000),
        # G.722 samples at 16 kHz but keeps an 8 kHz RTP clock for historical reasons.
        9: Codec("G722", "audio", 8000),
        10: Codec("L16", "audio", 44100),
        11: Codec("L16", "audio", 44100),
        12: Codec("QCELP", "audio", 8000),
        13: Codec("CN", "audio", 8000),
        14: Codec("MPA", "audio", 90000),
        15: Codec("G728", "audio", 8000),
        16: Codec("DVI4", "audio", 11025),
        17: Codec("DVI4", "audio", 22050),
        18: Codec("G729", "audio", 8000),
        25: Codec("CelB", "video", 90000),
        26: Codec("JPEG", "video", 90000),
        28: Codec("nv", "video", 90000),
        31: Codec("H261", "video", 90000),
        32: Codec("MPV", "video", 90000),
        33: Codec("MP2T", "audio/video", 90000),
        34: Codec("H263", "video", 90000),
    }
)


def static_codec(payload_type: int) -> Codec | None:
    """Return the codec statically assigned to ``payload_type``, if there is one."""
    return STATIC_PAYLOAD_TYPES.get(payload_type)
