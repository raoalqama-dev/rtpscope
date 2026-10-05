import pytest

from rtpscope.capture import Frame
from rtpscope.decode import (
    LINKTYPE_ETHERNET,
    LINKTYPE_IPV4,
    LINKTYPE_IPV6,
    LINKTYPE_LINUX_SLL,
    LINKTYPE_LINUX_SLL2,
    LINKTYPE_LOOP,
    LINKTYPE_NULL,
    LINKTYPE_RAW,
    Datagram,
    decode_udp,
)
from tests import builders

PAYLOAD = b"media payload"
UDP = builders.udp(40000, 50000, PAYLOAD)
IPV4_PACKET = builders.ipv4("192.0.2.10", "198.51.100.20", UDP)
IPV6_PACKET = builders.ipv6("2001:db8::10", "2001:db8::20", UDP)

EXPECTED_V4 = Datagram(12.5, "192.0.2.10", 40000, "198.51.100.20", 50000, PAYLOAD)
EXPECTED_V6 = Datagram(12.5, "2001:db8::10", 40000, "2001:db8::20", 50000, PAYLOAD)


def decode(linktype: int, data: bytes) -> Datagram | None:
    return decode_udp(Frame(12.5, linktype, data))


@pytest.mark.parametrize(
    ("linktype", "data", "expected"),
    [
        (LINKTYPE_ETHERNET, builders.ethernet(IPV4_PACKET), EXPECTED_V4),
        (
            LINKTYPE_ETHERNET,
            builders.ethernet(IPV6_PACKET, ethertype=builders.ETHERTYPE_IPV6),
            EXPECTED_V6,
        ),
        (LINKTYPE_ETHERNET, builders.ethernet(IPV4_PACKET, vlans=[100]), EXPECTED_V4),
        (LINKTYPE_ETHERNET, builders.ethernet(IPV4_PACKET, vlans=[100, 200]), EXPECTED_V4),
        (LINKTYPE_RAW, IPV4_PACKET, EXPECTED_V4),
        (LINKTYPE_RAW, IPV6_PACKET, EXPECTED_V6),
        (LINKTYPE_IPV4, IPV4_PACKET, EXPECTED_V4),
        (LINKTYPE_IPV6, IPV6_PACKET, EXPECTED_V6),
        (LINKTYPE_NULL, builders.null_loopback(IPV4_PACKET), EXPECTED_V4),
        (LINKTYPE_LOOP, builders.null_loopback(IPV6_PACKET, family=30), EXPECTED_V6),
        (LINKTYPE_LINUX_SLL, builders.linux_sll(IPV4_PACKET), EXPECTED_V4),
        (
            LINKTYPE_LINUX_SLL2,
            builders.linux_sll2(IPV6_PACKET, protocol=builders.ETHERTYPE_IPV6),
            EXPECTED_V6,
        ),
    ],
    ids=[
        "ethernet-ipv4",
        "ethernet-ipv6",
        "vlan",
        "q-in-q",
        "raw-ipv4",
        "raw-ipv6",
        "linktype-ipv4",
        "linktype-ipv6",
        "null",
        "loop-ipv6",
        "linux-sll",
        "linux-sll2",
    ],
)
def test_udp_is_found_behind_every_supported_link_layer(
    linktype: int, data: bytes, expected: Datagram
) -> None:
    assert decode(linktype, data) == expected


def test_ethernet_padding_is_trimmed_using_the_ip_total_length() -> None:
    frame = builders.ethernet(IPV4_PACKET) + bytes(18)

    datagram = decode(LINKTYPE_ETHERNET, frame)

    assert datagram is not None
    assert datagram.payload == PAYLOAD


def test_zero_ip_total_length_falls_back_to_the_captured_size() -> None:
    packet = builders.ipv4("192.0.2.10", "198.51.100.20", UDP, total_length=0)

    assert decode(LINKTYPE_RAW, packet) == EXPECTED_V4


def test_ipv6_extension_headers_are_walked() -> None:
    packet = builders.ipv6(
        "2001:db8::10", "2001:db8::20", UDP, hop_by_hop=True, fragment=(0, False)
    )

    assert decode(LINKTYPE_RAW, packet) == EXPECTED_V6


@pytest.mark.parametrize(
    "packet",
    [
        builders.ipv4("192.0.2.10", "198.51.100.20", UDP, flags_and_offset=0x2000),
        builders.ipv4("192.0.2.10", "198.51.100.20", UDP, flags_and_offset=0x0010),
        builders.ipv6("2001:db8::10", "2001:db8::20", UDP, fragment=(0, True)),
        builders.ipv6("2001:db8::10", "2001:db8::20", UDP, fragment=(16, False)),
    ],
    ids=["ipv4-first-fragment", "ipv4-later-fragment", "ipv6-first-fragment", "ipv6-later"],
)
def test_fragments_are_skipped(packet: bytes) -> None:
    assert decode(LINKTYPE_RAW, packet) is None


@pytest.mark.parametrize(
    ("linktype", "data"),
    [
        (LINKTYPE_RAW, builders.ipv4("192.0.2.10", "198.51.100.20", b"tcp" * 10, protocol=6)),
        (LINKTYPE_RAW, builders.ipv6("2001:db8::1", "2001:db8::2", b"tcp" * 10, next_header=6)),
        (LINKTYPE_ETHERNET, builders.ethernet(b"arp request", ethertype=0x0806)),
        (LINKTYPE_LINUX_SLL, builders.linux_sll(b"arp request", protocol=0x0806)),
        (LINKTYPE_RAW, b""),
        (LINKTYPE_RAW, b"\x45\x00"),
        (LINKTYPE_RAW, b"\x60" + bytes(10)),
        (LINKTYPE_RAW, b"\x20" + bytes(40)),
        (LINKTYPE_ETHERNET, bytes(10)),
        (LINKTYPE_NULL, b"\x02\x00\x00\x00"),
        (147, IPV4_PACKET),
        (LINKTYPE_RAW, IPV4_PACKET[:24]),
    ],
    ids=[
        "tcp-over-ipv4",
        "tcp-over-ipv6",
        "arp",
        "sll-arp",
        "empty",
        "short-ipv4",
        "short-ipv6",
        "bad-ip-version",
        "short-ethernet",
        "null-without-payload",
        "unsupported-linktype",
        "truncated-udp-header",
    ],
)
def test_frames_without_a_udp_datagram_give_none(linktype: int, data: bytes) -> None:
    assert decode(linktype, data) is None


def test_snapped_udp_payload_keeps_what_was_captured() -> None:
    packet = builders.ipv4("192.0.2.10", "198.51.100.20", UDP)

    datagram = decode(LINKTYPE_RAW, packet[:-5])

    assert datagram is not None
    assert datagram.payload == PAYLOAD[:-5]
