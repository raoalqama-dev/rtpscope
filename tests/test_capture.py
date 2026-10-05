import io
import struct
from pathlib import Path

import pytest

from rtpscope.capture import CaptureError, Frame, iter_frames, read_frames
from tests import builders

FRAMES = [(1_700_000_000.25, b"first frame"), (1_700_000_001.5, b"second")]


def frames_of(capture: bytes) -> list[Frame]:
    return list(iter_frames(io.BytesIO(capture)))


@pytest.mark.parametrize("big_endian", [False, True])
@pytest.mark.parametrize("nanoseconds", [False, True])
def test_pcap_in_any_byte_order_and_resolution(big_endian: bool, nanoseconds: bool) -> None:
    capture = builders.pcap(FRAMES, linktype=113, big_endian=big_endian, nanoseconds=nanoseconds)

    frames = frames_of(capture)

    assert [frame.data for frame in frames] == [b"first frame", b"second"]
    assert [frame.timestamp for frame in frames] == pytest.approx([t for t, _ in FRAMES])
    assert {frame.linktype for frame in frames} == {113}


def test_pcap_nanosecond_timestamps_keep_sub_microsecond_detail() -> None:
    capture = builders.pcap([(1000.000000250, b"x")], nanoseconds=True)

    (frame,) = frames_of(capture)

    assert frame.timestamp - 1000 == pytest.approx(250e-9, abs=1e-12)


def test_pcap_linktype_ignores_fcs_bits() -> None:
    capture = bytearray(builders.pcap(FRAMES))
    struct.pack_into("<I", capture, 20, 0x10000000 | 1)  # FCS-present flag + Ethernet

    assert {frame.linktype for frame in frames_of(bytes(capture))} == {1}


def test_truncated_final_record_ends_iteration() -> None:
    capture = builders.pcap(FRAMES)[:-3]

    assert [frame.data for frame in frames_of(capture)] == [b"first frame"]


def test_empty_capture_has_no_frames() -> None:
    assert frames_of(builders.pcap([])) == []


@pytest.mark.parametrize("big_endian", [False, True])
def test_pcapng_in_any_byte_order(big_endian: bool) -> None:
    capture = builders.pcapng(
        [(0, timestamp, data) for timestamp, data in FRAMES], big_endian=big_endian
    )

    frames = frames_of(capture)

    assert [frame.data for frame in frames] == [b"first frame", b"second"]
    assert [frame.timestamp for frame in frames] == pytest.approx([t for t, _ in FRAMES])


@pytest.mark.parametrize(
    ("tsresol", "expected_fraction"),
    [(None, 0.123456), (9, 0.123456789), (3, 0.123), (0x80 | 10, 0.123046875)],
)
def test_pcapng_timestamp_resolution(tsresol: int | None, expected_fraction: float) -> None:
    capture = builders.pcapng([(0, 1000 + expected_fraction, b"x")], interfaces=[(1, tsresol)])

    (frame,) = frames_of(capture)

    assert frame.timestamp - 1000 == pytest.approx(expected_fraction, abs=1e-12)


def test_pcapng_frames_take_the_link_type_of_their_interface() -> None:
    capture = builders.pcapng(
        [(0, 1.0, b"eth"), (1, 2.0, b"raw"), (0, 3.0, b"eth again")],
        interfaces=[(1, None), (101, 9)],
    )

    assert [(frame.linktype, frame.data) for frame in frames_of(capture)] == [
        (1, b"eth"),
        (101, b"raw"),
        (1, b"eth again"),
    ]


def test_pcapng_skips_blocks_it_does_not_need() -> None:
    capture = builders.pcapng([(0, 1.0, b"data")], extra_block=True)

    assert [frame.data for frame in frames_of(capture)] == [b"data"]


def test_pcapng_with_several_sections() -> None:
    first = builders.pcapng([(0, 1.0, b"little")], interfaces=[(1, None)])
    second = builders.pcapng([(0, 2.0, b"big")], interfaces=[(101, None)], big_endian=True)

    frames = frames_of(first + second)

    assert [(frame.linktype, frame.data) for frame in frames] == [(1, b"little"), (101, b"big")]


def test_pcapng_packet_on_undeclared_interface_is_an_error() -> None:
    capture = builders.pcapng([(0, 1.0, b"x")], interfaces=[(1, None)])
    # The enhanced packet block is the last 36 bytes; point it at interface 3,
    # which was never described.
    patched = bytearray(capture)
    struct.pack_into("<I", patched, len(capture) - 36 + 8, 3)

    with pytest.raises(CaptureError, match="undeclared interface 3"):
        frames_of(bytes(patched))


@pytest.mark.parametrize(
    ("capture", "message"),
    [
        (b"", "too short"),
        (b"\x00\x01", "too short"),
        (b"GIF89a" + bytes(30), "not a pcap or pcapng file"),
        (struct.pack("<I", 0xA1B2C3D4) + bytes(5), "header is truncated"),
        (b"\x0a\x0d\x0d\x0a" + struct.pack("<II", 28, 0xDEADBEEF), "byte-order magic"),
        (b"\x0a\x0d\x0d\x0a" + struct.pack("<II", 30, 0x1A2B3C4D), "invalid length"),
    ],
)
def test_malformed_captures_raise(capture: bytes, message: str) -> None:
    with pytest.raises(CaptureError, match=message):
        frames_of(capture)


def test_implausible_record_length_raises() -> None:
    capture = builders.pcap([]) + struct.pack("<IIII", 0, 0, 0x7FFFFFFF, 0x7FFFFFFF)

    with pytest.raises(CaptureError, match="implausibly large"):
        frames_of(capture)


def test_read_frames_from_a_file(tmp_path: Path) -> None:
    path = tmp_path / "capture.pcap"
    path.write_bytes(builders.pcap(FRAMES))

    assert [frame.data for frame in read_frames(path)] == [b"first frame", b"second"]
