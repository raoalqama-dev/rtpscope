from collections.abc import Iterable, Sequence
from dataclasses import replace

import pytest

from rtpscope.capture import Frame
from rtpscope.decode import decode_udp
from rtpscope.metrics import (
    MAX_DROPOUT,
    MAX_MISORDER,
    SequenceTracker,
    analyze_stream,
    percentile,
    resolve_clock_rate,
)
from rtpscope.streams import RtpPacket, RtpStream, StreamKey, find_streams
from tests import builders

KEY = StreamKey("10.0.0.1", 40000, "10.0.0.2", 50000, 0x11223344)
START = 1000.0
ZERO = pytest.approx(0.0, abs=1e-6)


def packet(
    index: int,
    *,
    delay_ms: float = 0.0,
    sequence: int | None = None,
    payload_type: int = 0,
    samples: int = 160,
) -> RtpPacket:
    """The ``index``-th packet of a 20 ms voice stream, optionally delayed in transit."""
    return RtpPacket(
        arrival=START + index * 0.02 + delay_ms / 1000,
        sequence=1000 + index if sequence is None else sequence,
        timestamp=index * samples,
        payload_type=payload_type,
        marker=False,
        payload_length=160,
    )


def stream(packets: Iterable[RtpPacket]) -> RtpStream:
    return RtpStream(KEY, list(packets))


def in_order(count: int, *, skip: Sequence[int] = ()) -> list[RtpPacket]:
    return [packet(index) for index in range(count) if index not in skip]


# --- a clean stream ---------------------------------------------------------------


def test_a_clean_stream_has_no_impairments() -> None:
    metrics = analyze_stream(stream(in_order(50)))

    assert metrics.clock_rate == 8000
    assert metrics.packets_received == metrics.packets_expected == 50
    assert metrics.packets_lost == 0
    assert metrics.loss_percent == 0.0
    assert metrics.duplicates == metrics.out_of_order == metrics.max_loss_burst == 0
    assert metrics.sequence_resets == 0
    assert metrics.interarrival_mean_ms == pytest.approx(20.0)
    assert metrics.interarrival_p95_ms == pytest.approx(20.0)
    assert metrics.interarrival_max_ms == pytest.approx(20.0)
    assert metrics.jitter_mean_ms == ZERO
    assert metrics.jitter_max_ms == ZERO
    assert metrics.bitrate_bps == pytest.approx(64_000)


# --- interarrival jitter (RFC 3550, A.8) -------------------------------------------


def test_jitter_of_a_single_late_packet() -> None:
    # Packet 2 is 10 ms (80 timestamp units at 8 kHz) late, so the transit time
    # differences are 0, +80, -80, 0 and the estimate J += (|D| - J) / 16 runs
    # 0 -> 0 -> 5 -> 9.6875 -> 9.08203125 units, i.e. 1/8 of that in ms.
    packets = [packet(0), packet(1), packet(2, delay_ms=10), packet(3), packet(4)]

    metrics = analyze_stream(stream(packets))

    assert metrics.jitter_max_ms == pytest.approx(9.6875 / 8)
    assert metrics.jitter_mean_ms == pytest.approx((0 + 5 + 9.6875 + 9.08203125) / 4 / 8)


def test_jitter_converges_to_a_constant_transit_swing() -> None:
    # Every other packet is 10 ms late, so |D| is 80 units for every pair and
    # after n updates J = 80 * (1 - (15/16)**n) units, approaching 10 ms.
    count = 100
    packets = [packet(index, delay_ms=10 * (index % 2)) for index in range(count)]
    updates = count - 1

    metrics = analyze_stream(stream(packets))

    decay = (15 / 16) ** updates
    assert metrics.jitter_max_ms == pytest.approx(10 * (1 - decay))
    # The mean of 10 * (1 - (15/16)**n) over n = 1..99, summing the geometric series.
    assert metrics.jitter_mean_ms == pytest.approx(10 - 10 * 15 * (1 - decay) / updates)


def test_rtp_timestamp_wraparound_does_not_disturb_jitter() -> None:
    first = 2**32 - 3 * 160
    packets = [replace(p, timestamp=(first + p.timestamp) % 2**32) for p in in_order(10)]

    metrics = analyze_stream(stream(packets))

    assert metrics.jitter_max_ms == ZERO


def test_jitter_needs_a_clock_rate() -> None:
    packets = [packet(index, payload_type=111, samples=960) for index in range(20)]

    unknown = analyze_stream(stream(packets))
    known = analyze_stream(stream(packets), clock_rates={111: 48000})

    assert unknown.clock_rate is None
    assert unknown.jitter_mean_ms is unknown.jitter_max_ms is None
    assert known.clock_rate == 48000
    assert known.jitter_max_ms == ZERO


def test_a_clock_rate_override_replaces_the_static_rate() -> None:
    # A wideband stream sent with PT 0 advances 320 units per 20 ms, not 160.
    packets = [packet(index, samples=320) for index in range(20)]

    assert (analyze_stream(stream(packets)).jitter_max_ms or 0) > 10
    assert analyze_stream(stream(packets), clock_rates={0: 16000}).jitter_max_ms == ZERO


def test_jitter_skips_duplicates_and_other_payload_types() -> None:
    packets = in_order(20)
    # A DTMF event packet reuses an older timestamp, and a duplicate arrives late.
    packets[10] = replace(packets[10], payload_type=101, timestamp=packets[8].timestamp)
    packets.insert(6, replace(packets[4], arrival=packets[5].arrival + 0.015))

    metrics = analyze_stream(stream(packets))

    assert metrics.duplicates == 1
    assert metrics.jitter_max_ms == ZERO


# --- sequence accounting ---------------------------------------------------------


@pytest.mark.parametrize(
    ("skip", "lost", "burst"),
    [
        ((), 0, 0),
        ((7,), 1, 1),
        ((5, 6, 7, 12), 4, 3),
        ((1, 3, 5, 7, 9), 5, 1),
    ],
)
def test_loss_count_percentage_and_longest_burst(
    skip: tuple[int, ...], lost: int, burst: int
) -> None:
    metrics = analyze_stream(stream(in_order(20, skip=skip)))

    assert metrics.packets_received == 20 - lost
    assert metrics.packets_expected == 20
    assert metrics.packets_lost == lost
    assert metrics.loss_percent == pytest.approx(100 * lost / 20)
    assert metrics.max_loss_burst == burst


def test_duplicates_are_counted_apart_from_loss() -> None:
    packets = in_order(10)
    packets.insert(6, replace(packets[4], arrival=packets[5].arrival + 0.001))

    metrics = analyze_stream(stream(packets))

    assert metrics.packets_received == 11
    assert metrics.packets_expected == 10
    assert metrics.duplicates == 1
    assert metrics.packets_lost == 0
    assert metrics.out_of_order == 0


@pytest.mark.parametrize(
    "order",
    [
        [0, 1, 2, 4, 3, 5, 6, 7],
        [0, 1, 2, 4, 5, 6, 3, 7],
    ],
)
def test_late_packets_are_out_of_order_not_lost(order: list[int]) -> None:
    metrics = analyze_stream(stream(packet(index) for index in order))

    assert metrics.out_of_order == 1
    assert metrics.packets_lost == 0
    assert metrics.duplicates == 0


def wrapping(count: int) -> list[RtpPacket]:
    return [packet(index, sequence=(65530 + index) % 65536) for index in range(count)]


def test_sequence_wraparound_is_not_loss() -> None:
    metrics = analyze_stream(stream(wrapping(16)))

    assert metrics.packets_expected == 16
    assert metrics.packets_lost == 0
    assert metrics.sequence_resets == 0


def test_loss_across_the_wrap() -> None:
    packets = [p for p in wrapping(16) if p.sequence not in (65535, 0)]

    metrics = analyze_stream(stream(packets))

    assert metrics.packets_expected == 16
    assert metrics.packets_lost == 2
    assert metrics.max_loss_burst == 2


def test_reordering_across_the_wrap() -> None:
    packets = wrapping(16)
    packets[5], packets[6] = packets[6], packets[5]  # 0 arrives before 65535

    metrics = analyze_stream(stream(packets))

    assert metrics.out_of_order == 1
    assert metrics.packets_lost == 0
    assert metrics.packets_expected == 16


def test_a_sequence_restart_is_not_loss() -> None:
    packets = in_order(10) + [packet(10 + index, sequence=40000 + index) for index in range(10)]

    metrics = analyze_stream(stream(packets))

    assert metrics.sequence_resets == 1
    assert metrics.packets_received == 20
    # The first packet after the jump is held back until the next one confirms it.
    assert metrics.packets_expected == 19
    assert metrics.packets_lost == 0
    assert metrics.out_of_order == 0


def test_a_stray_sequence_number_is_ignored() -> None:
    packets = in_order(20)
    packets.insert(8, packet(8, delay_ms=5, sequence=30000))

    metrics = analyze_stream(stream(packets))

    assert metrics.sequence_resets == 0
    assert metrics.packets_received == 21
    assert metrics.packets_expected == 20
    assert metrics.packets_lost == 0


# --- SequenceTracker ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("sequences", "extended", "resets"),
    [
        ([65534, 65535, 0, 1], [65534, 65535, 65536, 65537], 0),
        ([65535, 0, 65534, 1], [65535, 65536, 65534, 65537], 0),
        ([10, 10, 11], [10, 10, 11], 0),
        ([10, 10 + MAX_DROPOUT - 1], [10, 10 + MAX_DROPOUT - 1], 0),
        ([10, 10 + MAX_DROPOUT, 11], [10, None, 11], 0),
        ([500, 500 - MAX_MISORDER + 1], [500, 500 - MAX_MISORDER + 1], 0),
        ([500, 500 - MAX_MISORDER], [500, None], 0),
        ([10, 11, 30000, 30001, 30002], [10, 11, None, 12, 13], 1),
        ([10, 11, 30000, 12, 13], [10, 11, None, 12, 13], 0),
        ([10, 30000, 11, 30001], [10, None, 11, None], 0),
        ([65535, 0, 30000, 30001, 65535], [65535, 65536, None, 65537, None], 1),
    ],
)
def test_sequence_tracker(sequences: list[int], extended: list[int | None], resets: int) -> None:
    tracker = SequenceTracker()

    assert [tracker.extend(sequence) for sequence in sequences] == extended
    assert tracker.resets == resets


@pytest.mark.parametrize("sequence", [-1, 65536])
def test_sequence_tracker_rejects_out_of_range_numbers(sequence: int) -> None:
    with pytest.raises(ValueError, match="outside 0-65535"):
        SequenceTracker().extend(sequence)


# --- interarrival times, bitrate and inputs ------------------------------------------


def test_interarrival_statistics() -> None:
    # Gaps of 20, 20, 60, 20 and 20 ms: the last three packets are 40 ms late.
    packets = [packet(index, delay_ms=40 if index >= 3 else 0) for index in range(6)]

    metrics = analyze_stream(stream(packets))

    assert metrics.interarrival_mean_ms == pytest.approx(28.0)
    assert metrics.interarrival_p95_ms == pytest.approx(52.0)
    assert metrics.interarrival_max_ms == pytest.approx(60.0)


def test_bitrate_is_undefined_without_elapsed_time() -> None:
    packets = [replace(packet(index), arrival=START) for index in range(5)]

    assert analyze_stream(stream(packets)).bitrate_bps is None


def test_a_stream_needs_two_packets() -> None:
    with pytest.raises(ValueError, match="at least two packets"):
        analyze_stream(stream([packet(0)]))


def test_clock_rates_must_be_positive() -> None:
    with pytest.raises(ValueError, match="positive"):
        analyze_stream(stream(in_order(5)), clock_rates={0: 0})


@pytest.mark.parametrize(
    ("payload_type", "overrides", "rate"),
    [
        (0, None, 8000),
        (9, None, 8000),
        (111, None, None),
        (111, {111: 48000}, 48000),
        (0, {0: 16000}, 16000),
        (0, {111: 48000}, 8000),
    ],
)
def test_resolve_clock_rate(
    payload_type: int, overrides: dict[int, int] | None, rate: int | None
) -> None:
    assert resolve_clock_rate(payload_type, overrides) == rate


@pytest.mark.parametrize(
    ("values", "rank", "expected"),
    [
        ([1.0, 2.0, 3.0, 4.0], 50, 2.5),
        ([4.0, 1.0, 3.0, 2.0], 0, 1.0),
        ([1.0, 2.0, 3.0, 4.0], 100, 4.0),
        ([20.0, 20.0, 60.0, 20.0, 20.0], 95, 52.0),
        ([7.0], 95, 7.0),
    ],
)
def test_percentile(values: list[float], rank: float, expected: float) -> None:
    assert percentile(values, rank) == pytest.approx(expected)


@pytest.mark.parametrize(("values", "rank"), [([], 50), ([1.0], -1), ([1.0], 100.5)])
def test_percentile_rejects_bad_input(values: list[float], rank: float) -> None:
    with pytest.raises(ValueError, match="percentile"):
        percentile(values, rank)


def test_metrics_of_a_decoded_capture() -> None:
    frames = builders.voice_frames(60, first_sequence=65520, payload_type=8)
    lossy = [frame for index, frame in enumerate(frames) if index not in (14, 15, 16, 40)]
    decoded = (decode_udp(Frame(timestamp, 1, data)) for timestamp, data in lossy)

    (found,) = find_streams(datagram for datagram in decoded if datagram is not None)
    metrics = analyze_stream(found)

    assert metrics.packets_received == 56
    assert metrics.packets_expected == 60
    assert metrics.packets_lost == 4
    assert metrics.max_loss_burst == 3
    assert metrics.interarrival_max_ms == pytest.approx(80.0, abs=1e-3)
    assert metrics.jitter_max_ms == pytest.approx(0.0, abs=1e-3)
