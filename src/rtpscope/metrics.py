"""Per-stream quality metrics: sequence accounting, interarrival jitter and timing.

The sequence and jitter algorithms follow RFC 3550: extended sequence numbers
come from appendix A.1 and the interarrival jitter estimate from appendix A.8.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from itertools import pairwise
from typing import Final

from rtpscope.codecs import static_codec
from rtpscope.streams import RtpPacket, RtpStream

__all__ = [
    "MAX_DROPOUT",
    "MAX_MISORDER",
    "SequenceTracker",
    "StreamMetrics",
    "analyze_stream",
    "percentile",
    "resolve_clock_rate",
]

MAX_DROPOUT: Final = 3000
"""A forward jump of fewer sequence numbers than this is treated as packet loss."""

MAX_MISORDER: Final = 100
"""A packet fewer than this many sequence numbers behind the highest one arrived late."""

_SEQUENCE_MODULUS: Final = 1 << 16
_TIMESTAMP_MODULUS: Final = 1 << 32
_JITTER_GAIN: Final = 1 / 16


class SequenceTracker:
    """Turns 16-bit RTP sequence numbers into extended sequence numbers.

    This is the ``update_seq`` algorithm of RFC 3550, appendix A.1. A step
    forward of less than :data:`MAX_DROPOUT` advances the highest sequence
    number seen (counting a wrap past 65535 as a new cycle), and a packet less
    than :data:`MAX_MISORDER` behind it is a late or duplicate arrival. Anything
    else is a jump: the packet is held back from the accounting unless the very
    next packet follows it, in which case the sender has restarted its sequence
    numbers and the tracker resynchronises.

    After a resynchronisation the new numbering continues straight after the
    highest extended number seen so far, so a restart is not mistaken for loss.
    """

    __slots__ = ("_bad_sequence", "_cycles", "_highest", "_max_sequence", "_offset", "resets")

    def __init__(self) -> None:
        self._max_sequence: int | None = None
        self._cycles = 0
        self._offset = 0
        self._highest = 0
        self._bad_sequence: int | None = None
        self.resets = 0
        """How many times the sender was found to have restarted its sequence numbers."""

    def extend(self, sequence: int) -> int | None:
        """Return the extended sequence number of the next packet in arrival order.

        Returns ``None`` for a packet that jumped too far to be placed; it is
        either a stray or the first packet of a restart, which only the next
        packet can tell apart.

        Raises:
            ValueError: if ``sequence`` is not a 16-bit number.
        """
        if not 0 <= sequence < _SEQUENCE_MODULUS:
            raise ValueError(f"sequence number {sequence} is outside 0-65535")

        max_sequence = self._max_sequence
        if max_sequence is None:
            return self._restart(sequence, self._offset)

        step = (sequence - max_sequence) % _SEQUENCE_MODULUS
        if step < MAX_DROPOUT:
            if sequence < max_sequence:
                self._cycles += _SEQUENCE_MODULUS
            self._max_sequence = sequence
            extended = self._offset + self._cycles + sequence
        elif step <= _SEQUENCE_MODULUS - MAX_MISORDER:
            if sequence != self._bad_sequence:
                self._bad_sequence = (sequence + 1) % _SEQUENCE_MODULUS
                return None
            self.resets += 1
            return self._restart(sequence, self._highest + 1 - sequence)
        else:
            # A late or duplicate packet, possibly from before the latest wrap.
            cycles = self._cycles - _SEQUENCE_MODULUS if sequence > max_sequence else self._cycles
            extended = self._offset + cycles + sequence

        self._bad_sequence = None
        self._highest = max(self._highest, extended)
        return extended

    def _restart(self, sequence: int, offset: int) -> int:
        self._max_sequence = sequence
        self._cycles = 0
        self._offset = offset
        self._bad_sequence = None
        self._highest = offset + sequence
        return self._highest


@dataclass(frozen=True, slots=True)
class StreamMetrics:
    """What happened to one RTP stream on the wire.

    Times are in milliseconds and rates in bits per second.
    """

    clock_rate: int | None
    """RTP timestamp units per second used for jitter, or ``None`` if unknown."""

    packets_received: int
    """Every packet captured, duplicates included."""

    packets_expected: int
    """Span of extended sequence numbers, from the lowest to the highest seen."""

    packets_lost: int
    """Sequence numbers in the expected span that never arrived."""

    loss_percent: float
    duplicates: int
    """Packets whose extended sequence number had already been seen."""

    out_of_order: int
    """Packets that arrived after one with a higher extended sequence number."""

    max_loss_burst: int
    """The longest run of consecutive missing sequence numbers."""

    sequence_resets: int
    """How many times the sender restarted its sequence numbers mid-stream."""

    interarrival_mean_ms: float
    interarrival_p95_ms: float
    interarrival_max_ms: float
    jitter_mean_ms: float | None
    """Mean of the running RFC 3550 jitter estimate, or ``None`` without a clock rate."""

    jitter_max_ms: float | None
    """Peak of the running RFC 3550 jitter estimate, or ``None`` without a clock rate."""

    bitrate_bps: float | None
    """RTP payload bit rate, or ``None`` if all packets arrived at the same instant."""


def resolve_clock_rate(
    payload_type: int, clock_rates: Mapping[int, int] | None = None
) -> int | None:
    """Return the RTP clock rate of ``payload_type``.

    An entry in ``clock_rates`` wins over the static assignment, which is how
    dynamic payload types (96-127) get a rate at all.
    """
    if clock_rates is not None and payload_type in clock_rates:
        return clock_rates[payload_type]
    codec = static_codec(payload_type)
    return codec.clock_rate if codec is not None else None


def analyze_stream(
    stream: RtpStream, *, clock_rates: Mapping[int, int] | None = None
) -> StreamMetrics:
    """Measure loss, reordering, jitter and timing for ``stream``.

    ``clock_rates`` maps payload types to RTP clock rates and overrides the
    static assignments; jitter is left out when the rate of the stream's
    payload type is unknown.

    Raises:
        ValueError: if the stream has fewer than two packets, or a clock rate
            in ``clock_rates`` is not positive.
    """
    packets = stream.packets
    if len(packets) < 2:
        raise ValueError("a stream needs at least two packets to be analysed")
    if clock_rates is not None and any(rate <= 0 for rate in clock_rates.values()):
        raise ValueError("clock rates must be positive")

    tracker = SequenceTracker()
    seen: set[int] = set()
    duplicates = out_of_order = 0
    highest: int | None = None
    # Packets that take part in the jitter estimate: first copies of the main payload type.
    payload_type = stream.payload_type
    timed: list[RtpPacket] = []
    for packet in packets:
        extended = tracker.extend(packet.sequence)
        if extended is None:
            continue
        if extended in seen:
            duplicates += 1
            continue
        seen.add(extended)
        if highest is not None and extended < highest:
            out_of_order += 1
        highest = extended if highest is None else max(highest, extended)
        if packet.payload_type == payload_type:
            timed.append(packet)

    ordered = sorted(seen)
    expected = ordered[-1] - ordered[0] + 1
    lost = expected - len(ordered)
    burst = max((after - before - 1 for before, after in pairwise(ordered)), default=0)

    gaps_ms = [(after.arrival - before.arrival) * 1000 for before, after in pairwise(packets)]
    clock_rate = resolve_clock_rate(payload_type, clock_rates)
    jitter = _jitter_ms(timed, clock_rate) if clock_rate is not None else []
    duration = stream.duration
    payload_bits = 8 * (stream.payload_bytes - packets[0].payload_length)

    return StreamMetrics(
        clock_rate=clock_rate,
        packets_received=len(packets),
        packets_expected=expected,
        packets_lost=lost,
        loss_percent=100 * lost / expected,
        duplicates=duplicates,
        out_of_order=out_of_order,
        max_loss_burst=burst,
        sequence_resets=tracker.resets,
        interarrival_mean_ms=math.fsum(gaps_ms) / len(gaps_ms),
        interarrival_p95_ms=percentile(gaps_ms, 95),
        interarrival_max_ms=max(gaps_ms),
        jitter_mean_ms=math.fsum(jitter) / len(jitter) if jitter else None,
        jitter_max_ms=max(jitter) if jitter else None,
        bitrate_bps=payload_bits / duration if duration > 0 else None,
    )


def percentile(values: Sequence[float], rank: float) -> float:
    """The ``rank``-th percentile of ``values``, interpolating between neighbours.

    This is the "linear" method (Hyndman and Fan's type 7), the default of
    NumPy and of spreadsheet ``PERCENTILE`` functions.

    Raises:
        ValueError: if ``values`` is empty or ``rank`` is outside 0-100.
    """
    if not values:
        raise ValueError("percentile of an empty sequence")
    if not 0 <= rank <= 100:
        raise ValueError(f"percentile rank {rank} is outside 0-100")
    ordered = sorted(values)
    position = (len(ordered) - 1) * rank / 100
    below = math.floor(position)
    above = min(below + 1, len(ordered) - 1)
    fraction = position - below
    return ordered[below] + (ordered[above] - ordered[below]) * fraction


def _jitter_ms(packets: Sequence[RtpPacket], clock_rate: int) -> list[float]:
    """The running interarrival jitter after each packet but the first (RFC 3550, A.8).

    For consecutive arrivals i and j the transit-time difference is
    ``D = (Rj - Ri) - (Sj - Si)`` in timestamp units, where R is the arrival
    time and S the RTP timestamp, and the estimate moves 1/16 of the way
    towards ``|D|`` with every packet. RTP timestamps may wrap past 2**32.
    """
    estimates: list[float] = []
    jitter = 0.0
    for before, after in pairwise(packets):
        elapsed = (after.arrival - before.arrival) * clock_rate
        advance = (after.timestamp - before.timestamp) % _TIMESTAMP_MODULUS
        if advance >= _TIMESTAMP_MODULUS // 2:
            advance -= _TIMESTAMP_MODULUS
        jitter += (abs(elapsed - advance) - jitter) * _JITTER_GAIN
        estimates.append(jitter * 1000 / clock_rate)
    return estimates
