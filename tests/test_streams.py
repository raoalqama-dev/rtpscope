import random
from pathlib import Path

import pytest

from rtpscope.capture import Frame
from rtpscope.codecs import static_codec
from rtpscope.decode import Datagram, decode_udp
from rtpscope.streams import StreamKey, find_streams, load_streams
from tests import builders


def datagrams(frames: list[tuple[float, bytes]]) -> list[Datagram]:
    decoded = (decode_udp(Frame(timestamp, 1, data)) for timestamp, data in frames)
    return [datagram for datagram in decoded if datagram is not None]


def test_a_single_voice_stream() -> None:
    (stream,) = find_streams(datagrams(builders.voice_frames(50, payload_type=8)))

    assert stream.key == StreamKey("10.0.0.1", 40000, "10.0.0.2", 50000, 0x11223344)
    assert stream.packet_count == 50
    assert stream.duration == pytest.approx(49 * 0.02)
    assert stream.first_seen == pytest.approx(1_700_000_000.0)
    assert stream.payload_type == 8
    assert stream.codec == static_codec(8)
    assert stream.payload_bytes == 50 * 160
    assert [packet.sequence for packet in stream.packets] == list(range(1000, 1050))


def test_both_directions_of_a_call_are_separate_streams() -> None:
    forward = builders.voice_frames(30, ssrc=1)
    backward = builders.voice_frames(
        30, src="10.0.0.2", sport=50000, dst="10.0.0.1", dport=40000, ssrc=2, start=1_700_000_000.01
    )

    streams = find_streams(datagrams(sorted(forward + backward)))

    assert [(stream.key.src, stream.key.ssrc) for stream in streams] == [
        ("10.0.0.1", 1),
        ("10.0.0.2", 2),
    ]


def test_an_ssrc_change_on_the_same_flow_starts_a_new_stream() -> None:
    before = builders.voice_frames(20, ssrc=0xAAAA)
    after = builders.voice_frames(20, ssrc=0xBBBB, start=1_700_000_001.0, first_sequence=7)

    streams = find_streams(datagrams(before + after))

    assert [stream.key.ssrc for stream in streams] == [0xAAAA, 0xBBBB]


def test_the_same_ssrc_on_another_flow_is_another_stream() -> None:
    first = builders.voice_frames(20, sport=40000)
    second = builders.voice_frames(20, sport=40002, start=1_700_000_005.0)

    streams = find_streams(datagrams(first + second))

    assert [stream.key.sport for stream in streams] == [40000, 40002]


def test_sequence_wraparound_and_moderate_loss_are_still_a_stream() -> None:
    frames = builders.voice_frames(40, first_sequence=65520)
    lossy = [frame for index, frame in enumerate(frames) if index % 7 != 3]

    (stream,) = find_streams(datagrams(lossy))

    assert stream.packets[0].sequence == 65520
    assert any(packet.sequence < 100 for packet in stream.packets)


def test_random_udp_payloads_are_not_mistaken_for_rtp() -> None:
    generator = random.Random(1234)
    frames = []
    for index in range(2000):
        # Force the version bits to 2 so every payload parses as an RTP header.
        payload = bytes([0x80]) + generator.randbytes(171)
        packet = builders.ipv4("10.1.1.1", "10.1.1.2", builders.udp(5000, 6000, payload))
        frames.append((1_700_000_000 + index * 0.01, builders.ethernet(packet)))

    assert find_streams(datagrams(frames)) == []


def test_rtcp_and_non_rtp_traffic_are_ignored() -> None:
    noise = []
    for index in range(30):
        rtcp = builders.udp(40001, 50001, builders.rtcp_receiver_report(0x11223344))
        dns = builders.udp(53, 33333, b"\x12\x34\x01\x00\x00\x01" + bytes(20))
        timestamp = 1_700_000_000.005 + index * 0.02
        noise.append((timestamp, builders.ethernet(builders.ipv4("10.0.0.1", "10.0.0.2", rtcp))))
        noise.append((timestamp, builders.ethernet(builders.ipv4("10.0.0.9", "10.0.0.1", dns))))

    streams = find_streams(datagrams(sorted(builders.voice_frames(30) + noise)))

    assert len(streams) == 1
    assert streams[0].packet_count == 30


def test_short_candidates_are_dropped_below_min_packets() -> None:
    frames = builders.voice_frames(5)

    assert find_streams(datagrams(frames)) == []
    assert len(find_streams(datagrams(frames), min_packets=5)) == 1


def test_min_packets_must_allow_a_sequence_check() -> None:
    with pytest.raises(ValueError, match="at least 2"):
        find_streams([], min_packets=1)


def test_dominant_payload_type_wins_over_comfort_noise() -> None:
    frames = builders.voice_frames(20, payload_type=0)
    comfort_noise = builders.rtp(1020, 20 * 160, 0x11223344, payload_type=13, payload=b"\x40")
    packet = builders.ipv4("10.0.0.1", "10.0.0.2", builders.udp(40000, 50000, comfort_noise))
    frames.append((1_700_000_000.4, builders.ethernet(packet)))

    (stream,) = find_streams(datagrams(frames))

    assert stream.payload_type == 0
    assert stream.codec is not None
    assert stream.codec.name == "PCMU"


def test_dynamic_payload_type_has_no_static_codec() -> None:
    (stream,) = find_streams(datagrams(builders.voice_frames(20, payload_type=111)))

    assert stream.payload_type == 111
    assert stream.codec is None


def test_ipv6_endpoints_are_bracketed() -> None:
    key = StreamKey("2001:db8::1", 4000, "10.0.0.2", 5000, 1)

    assert key.source == "[2001:db8::1]:4000"
    assert key.destination == "10.0.0.2:5000"


def test_load_streams_reads_a_capture_file(tmp_path: Path) -> None:
    path = tmp_path / "call.pcapng"
    frames = builders.voice_frames(25)
    path.write_bytes(builders.pcapng([(0, timestamp, data) for timestamp, data in frames]))

    (stream,) = load_streams(path)

    assert stream.packet_count == 25
