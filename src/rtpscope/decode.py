"""Decoding of captured frames down to UDP datagrams.

RTP almost always travels over UDP, so this module peels off the link layer
(Ethernet with optional VLAN tags, Linux cooked capture, BSD loopback or raw
IP) and the IPv4/IPv6 header and hands back the UDP payload together with the
addressing that identifies the flow. IP fragments are skipped rather than
reassembled: media packets are far smaller than any real path MTU.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass
from functools import lru_cache

from rtpscope.capture import Frame

__all__ = [
    "LINKTYPE_ETHERNET",
    "LINKTYPE_IPV4",
    "LINKTYPE_IPV6",
    "LINKTYPE_LINUX_SLL",
    "LINKTYPE_LINUX_SLL2",
    "LINKTYPE_LOOP",
    "LINKTYPE_NULL",
    "LINKTYPE_RAW",
    "Datagram",
    "decode_udp",
]

LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LOOP = 108
LINKTYPE_LINUX_SLL = 113
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229
LINKTYPE_LINUX_SLL2 = 276

_ETHERTYPE_IPV4 = 0x0800
_ETHERTYPE_IPV6 = 0x86DD
_IP_ETHERTYPES = frozenset({_ETHERTYPE_IPV4, _ETHERTYPE_IPV6})
_VLAN_ETHERTYPES = frozenset({0x8100, 0x88A8, 0x9100})

_PROTOCOL_UDP = 17
_IPV6_HOP_BY_HOP = 0
_IPV6_ROUTING = 43
_IPV6_FRAGMENT = 44
_IPV6_DESTINATION_OPTIONS = 60
_IPV6_SKIPPABLE = frozenset({_IPV6_HOP_BY_HOP, _IPV6_ROUTING, _IPV6_DESTINATION_OPTIONS})


@dataclass(frozen=True, slots=True)
class Datagram:
    """A UDP datagram and the addressing needed to tell flows apart."""

    timestamp: float
    src: str
    sport: int
    dst: str
    dport: int
    payload: bytes


def decode_udp(frame: Frame) -> Datagram | None:
    """Return the UDP datagram carried by ``frame``, or ``None`` if there is none.

    ``None`` is returned for anything that is not UDP over IPv4/IPv6, for
    unsupported link types, for IP fragments and for frames too short to parse.
    """
    packet = _network_layer(frame.linktype, frame.data)
    if packet is None:
        return None

    version = packet[0] >> 4 if packet else 0
    if version == 4:
        located = _ipv4_payload(packet)
    elif version == 6:
        located = _ipv6_payload(packet)
    else:
        return None
    if located is None:
        return None

    src, dst, segment = located
    if len(segment) < 8:
        return None
    sport, dport, length = struct.unpack_from("!HHH", segment)
    # A length below the header size is invalid (or a jumbogram); keep what was captured.
    payload = segment[8:length] if length >= 8 else segment[8:]
    return Datagram(frame.timestamp, src, sport, dst, dport, payload)


def _network_layer(linktype: int, data: bytes) -> bytes | None:
    """Strip the link-layer header and return the IP packet, if there is one."""
    if linktype == LINKTYPE_ETHERNET:
        return _strip_ethernet(data)
    if linktype in (LINKTYPE_RAW, LINKTYPE_IPV4, LINKTYPE_IPV6):
        return data
    if linktype in (LINKTYPE_NULL, LINKTYPE_LOOP):
        # A 4-byte address family follows, in the capturing host's byte order for
        # NULL. The IP version nibble is a more reliable guide than its value.
        return data[4:] if len(data) > 4 else None
    if linktype == LINKTYPE_LINUX_SLL:
        return _strip_fixed(data, ethertype_offset=14, header_length=16)
    if linktype == LINKTYPE_LINUX_SLL2:
        return _strip_fixed(data, ethertype_offset=0, header_length=20)
    return None


def _strip_ethernet(data: bytes) -> bytes | None:
    offset = 12  # destination and source MAC addresses
    while len(data) >= offset + 2:
        (ethertype,) = struct.unpack_from("!H", data, offset)
        if ethertype in _VLAN_ETHERTYPES:
            offset += 4  # 802.1Q / 802.1ad tag: TPID + TCI
            continue
        return data[offset + 2 :] if ethertype in _IP_ETHERTYPES else None
    return None


def _strip_fixed(data: bytes, *, ethertype_offset: int, header_length: int) -> bytes | None:
    if len(data) < header_length:
        return None
    (ethertype,) = struct.unpack_from("!H", data, ethertype_offset)
    return data[header_length:] if ethertype in _IP_ETHERTYPES else None


def _ipv4_payload(packet: bytes) -> tuple[str, str, bytes] | None:
    if len(packet) < 20:
        return None
    header_length = (packet[0] & 0x0F) * 4
    if header_length < 20 or len(packet) < header_length:
        return None
    (total_length,) = struct.unpack_from("!H", packet, 2)
    (flags_and_offset,) = struct.unpack_from("!H", packet, 6)
    if flags_and_offset & 0x3FFF:  # more-fragments flag or a non-zero offset
        return None
    if packet[9] != _PROTOCOL_UDP:
        return None
    # Total length trims Ethernet padding. It reads 0 on frames captured before
    # segmentation offload filled it in, so fall back to the captured size.
    end = total_length if header_length <= total_length <= len(packet) else len(packet)
    return _address(packet[12:16]), _address(packet[16:20]), packet[header_length:end]


def _ipv6_payload(packet: bytes) -> tuple[str, str, bytes] | None:
    if len(packet) < 40:
        return None
    (payload_length,) = struct.unpack_from("!H", packet, 4)
    end = min(40 + payload_length, len(packet)) if payload_length else len(packet)
    next_header = packet[6]
    offset = 40

    while next_header != _PROTOCOL_UDP:
        if next_header in _IPV6_SKIPPABLE:
            if end < offset + 2:
                return None
            following, length = packet[offset], (packet[offset + 1] + 1) * 8
        elif next_header == _IPV6_FRAGMENT:
            if end < offset + 8:
                return None
            (fragment_field,) = struct.unpack_from("!H", packet, offset + 2)
            if fragment_field & 0xFFF9:  # non-zero offset or more-fragments flag
                return None
            following, length = packet[offset], 8
        else:
            return None
        next_header = following
        offset += length
        if offset > end:
            return None

    return _address(packet[8:24]), _address(packet[24:40]), packet[offset:end]


@lru_cache(maxsize=4096)
def _address(raw: bytes) -> str:
    return str(ipaddress.ip_address(raw))
