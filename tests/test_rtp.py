import pytest

from rtpscope.rtp import RtpError, RtpHeader, is_rtcp, parse_rtp
from tests import builders


def test_fixed_header_fields() -> None:
    packet = builders.rtp(
        0xBEEF, 0xDEADBEEF, 0x01020304, payload_type=8, marker=True, payload=b"abcd"
    )

    assert parse_rtp(packet) == RtpHeader(
        marker=True,
        payload_type=8,
        sequence=0xBEEF,
        timestamp=0xDEADBEEF,
        ssrc=0x01020304,
        csrcs=(),
        extension_profile=None,
        payload_offset=12,
        payload_length=4,
        padding_length=0,
    )


def test_csrc_list() -> None:
    header = parse_rtp(builders.rtp(1, 2, 3, csrcs=[10, 20, 30], payload=b"xy"))

    assert header.csrcs == (10, 20, 30)
    assert header.payload_offset == 12 + 3 * 4
    assert header.payload_length == 2


def test_header_extension_is_skipped() -> None:
    header = parse_rtp(builders.rtp(1, 2, 3, extension=(0xBEDE, bytes(8)), payload=b"xyz"))

    assert header.extension_profile == 0xBEDE
    assert header.payload_offset == 12 + 4 + 8
    assert header.payload_length == 3


def test_padding_is_excluded_from_the_payload() -> None:
    header = parse_rtp(builders.rtp(1, 2, 3, payload=b"12345", padding=3))

    assert header.padding_length == 3
    assert header.payload_length == 5


def test_header_without_payload() -> None:
    assert parse_rtp(builders.rtp(1, 2, 3, payload=b"")).payload_length == 0


@pytest.mark.parametrize(
    ("packet", "message"),
    [
        (b"\x80\x00\x00", "shorter than the 12-byte RTP header"),
        (b"\x40" + bytes(11), "version is 1"),
        (builders.rtp(1, 2, 3, csrcs=[1, 2], payload=b"")[:16], "CSRC list"),
        (builders.rtp(1, 2, 3, extension=(1, bytes(8)), payload=b"")[:18], "header extension"),
        (builders.rtp(1, 2, 3, extension=(1, b""), payload=b"")[:14], "header extension"),
        (b"\xa0" + bytes(10) + b"\x00", "invalid padding length 0"),
        (b"\xa0" + bytes(10) + b"\x20", "invalid padding length 32"),
    ],
)
def test_malformed_packets_raise(packet: bytes, message: str) -> None:
    with pytest.raises(RtpError, match=message):
        parse_rtp(packet)


@pytest.mark.parametrize("packet_type", [200, 201, 202, 203, 204, 205, 206, 207])
def test_rtcp_is_recognised(packet_type: int) -> None:
    packet = bytes([0x80, packet_type]) + bytes(6)

    assert is_rtcp(packet)


@pytest.mark.parametrize(
    "packet",
    [
        builders.rtp(1, 2, 3, payload_type=0),
        builders.rtp(1, 2, 3, payload_type=111, marker=True),
        bytes([0x40, 200]) + bytes(6),  # wrong version
        bytes([0x80, 200]),  # too short
    ],
)
def test_rtp_and_garbage_are_not_rtcp(packet: bytes) -> None:
    assert not is_rtcp(packet)


def test_rtcp_builder_round_trip() -> None:
    assert is_rtcp(builders.rtcp_receiver_report(42))
