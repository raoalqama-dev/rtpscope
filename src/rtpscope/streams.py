"""Finding RTP streams among the UDP traffic of a capture."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from itertools import pairwise
from os import PathLike

from rtpscope.capture import read_frames
from rtpscope.codecs import Codec, static_codec
from rtpscope.decode import Datagram, decode_udp
from rtpscope.rtp import RtpError, is_rtcp, parse_rtp

__all__ = [
    "DEFAULT_MIN_PACKETS",
    "RtpPacket",
    "RtpStream",
    "StreamKey",
    "find_streams",
    "load_streams",
]

DEFAULT_MIN_PACKETS = 10

# A forward step of up to this many sequence numbers still counts as in order.
# It tolerates a loss burst of about two seconds at the 50 packets/s of voice.
_MAX_SEQUENCE_STEP = 100
_MIN_IN_ORDER_FRACTION = 0.8
_SEQUENCE_MODULUS = 1 << 16


@dataclass(frozen=True, slots=True, order=True)
class StreamKey:
    """Identifies an RTP stream: the UDP flow it travels on and its SSRC."""

    src: str
    sport: int
    dst: str
    dport: int
    ssrc: int

    @property
    def source(self) -> str:
        """Source address and port, e.g. ``10.0.0.1:4000`` or ``[2001:db8::1]:4000``."""
        return _endpoint(self.src, self.sport)

    @property
    def destination(self) -> str:
        """Destination address and port, formatted like :attr:`source`."""
        return _endpoint(self.dst, self.dport)


@dataclass(frozen=True, slots=True)
class RtpPacket:
    """What later analysis needs to know about one RTP packet, without its payload."""

    arrival: float
    """Capture timestamp in seconds since the Unix epoch."""

    sequence: int
    timestamp: int
    payload_type: int
    marker: bool
    payload_length: int


@dataclass(slots=True)
class RtpStream:
    """The packets of one RTP stream, in capture order.

    Streams returned by :func:`find_streams` always hold at least two packets.
    """

    key: StreamKey
    packets: list[RtpPacket] = field(default_factory=list)

    @property
    def first_seen(self) -> float:
        return self.packets[0].arrival

    @property
    def last_seen(self) -> float:
        return self.packets[-1].arrival

    @property
    def duration(self) -> float:
        """Seconds between the first and the last packet."""
        return self.last_seen - self.first_seen

    @property
    def packet_count(self) -> int:
        return len(self.packets)

    @property
    def payload_bytes(self) -> int:
        """Total RTP payload carried, excluding RTP headers and padding."""
        return sum(packet.payload_length for packet in self.packets)

    @property
    def payload_type(self) -> int:
        """The most common payload type.

        A voice stream can mix in comfort noise or DTMF event packets, so the
        dominant type is the one that identifies the codec.
        """
        counts = Counter(packet.payload_type for packet in self.packets)
        return counts.most_common(1)[0][0]

    @property
    def codec(self) -> Codec | None:
        """The codec of :attr:`payload_type` if it is statically assigned."""
        return static_codec(self.payload_type)


def find_streams(
    datagrams: Iterable[Datagram], *, min_packets: int = DEFAULT_MIN_PACKETS
) -> list[RtpStream]:
    """Group the RTP packets among ``datagrams`` into streams.

    Any UDP payload that happens to parse as an RTP header makes a candidate,
    so a candidate is only reported once it has at least ``min_packets``
    packets and most of them advance the sequence number by a small step. This
    is the same idea as the probation period of RFC 3550, appendix A.1, and
    random UDP payloads practically never pass it.

    Streams are returned in the order their first packet was captured.

    Raises:
        ValueError: if ``min_packets`` is less than 2.
    """
    if min_packets < 2:
        raise ValueError("min_packets must be at least 2")

    candidates: dict[StreamKey, RtpStream] = {}
    for datagram in datagrams:
        payload = datagram.payload
        if is_rtcp(payload):
            continue
        try:
            header = parse_rtp(payload)
        except RtpError:
            continue

        key = StreamKey(datagram.src, datagram.sport, datagram.dst, datagram.dport, header.ssrc)
        stream = candidates.get(key)
        if stream is None:
            stream = candidates[key] = RtpStream(key)
        stream.packets.append(
            RtpPacket(
                arrival=datagram.timestamp,
                sequence=header.sequence,
                timestamp=header.timestamp,
                payload_type=header.payload_type,
                marker=header.marker,
                payload_length=header.payload_length,
            )
        )

    streams = [s for s in candidates.values() if _looks_like_stream(s.packets, min_packets)]
    streams.sort(key=lambda stream: (stream.first_seen, stream.key))
    return streams


def load_streams(
    path: str | PathLike[str], *, min_packets: int = DEFAULT_MIN_PACKETS
) -> list[RtpStream]:
    """Read the pcap or pcapng file at ``path`` and return the RTP streams in it."""
    return find_streams(_udp_datagrams(path), min_packets=min_packets)


def _udp_datagrams(path: str | PathLike[str]) -> Iterator[Datagram]:
    for frame in read_frames(path):
        datagram = decode_udp(frame)
        if datagram is not None:
            yield datagram


def _looks_like_stream(packets: list[RtpPacket], min_packets: int) -> bool:
    if len(packets) < min_packets:
        return False
    in_order = sum(
        1
        for previous, current in pairwise(packets)
        if 0 < (current.sequence - previous.sequence) % _SEQUENCE_MODULUS <= _MAX_SEQUENCE_STEP
    )
    return in_order >= _MIN_IN_ORDER_FRACTION * (len(packets) - 1)


def _endpoint(address: str, port: int) -> str:
    return f"[{address}]:{port}" if ":" in address else f"{address}:{port}"
