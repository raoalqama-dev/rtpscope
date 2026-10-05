"""Build packets and capture files byte by byte, so tests need no binary fixtures."""

from __future__ import annotations

import ipaddress
import struct
from collections.abc import Iterable, Sequence

# --- RTP / UDP / IP -----------------------------------------------------------


def rtp(
    sequence: int,
    timestamp: int,
    ssrc: int,
    *,
    payload_type: int = 0,
    marker: bool = False,
    payload: bytes = b"\xd5" * 160,
    csrcs: Sequence[int] = (),
    extension: tuple[int, bytes] | None = None,
    padding: int = 0,
) -> bytes:
    first = 0x80 | len(csrcs)
    if extension is not None:
        first |= 0x10
    if padding:
        first |= 0x20
    second = (0x80 if marker else 0) | payload_type
    packet = struct.pack("!BBHII", first, second, sequence & 0xFFFF, timestamp & 0xFFFFFFFF, ssrc)
    packet += b"".join(struct.pack("!I", csrc) for csrc in csrcs)
    if extension is not None:
        profile, body = extension
        assert len(body) % 4 == 0, "extension body must be a whole number of 32-bit words"
        packet += struct.pack("!HH", profile, len(body) // 4) + body
    packet += payload
    if padding:
        packet += bytes(padding - 1) + bytes([padding])
    return packet


def rtcp_receiver_report(ssrc: int) -> bytes:
    return struct.pack("!BBHI", 0x80, 201, 1, ssrc)


def udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def ipv4(
    src: str,
    dst: str,
    payload: bytes,
    *,
    protocol: int = 17,
    flags_and_offset: int = 0,
    total_length: int | None = None,
) -> bytes:
    length = 20 + len(payload) if total_length is None else total_length
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        length,
        0,
        flags_and_offset,
        64,
        protocol,
        0,
        ipaddress.IPv4Address(src).packed,
        ipaddress.IPv4Address(dst).packed,
    )
    return header + payload


def ipv6(
    src: str,
    dst: str,
    payload: bytes,
    *,
    next_header: int = 17,
    hop_by_hop: bool = False,
    fragment: tuple[int, bool] | None = None,
) -> bytes:
    """An IPv6 packet, optionally with a hop-by-hop and/or a fragment extension header."""
    extensions: list[tuple[int, bytes]] = []
    if hop_by_hop:
        extensions.append((0, bytes([1, 4, 0, 0, 0, 0])))  # PadN option fills the 8 bytes
    if fragment is not None:
        offset, more = fragment
        extensions.append((44, struct.pack("!BHI", 0, (offset << 3) | int(more), 0x1234)))

    chain = b""
    types = [kind for kind, _ in extensions] + [next_header]
    for (kind, extension), following in zip(extensions, types[1:], strict=True):
        if kind == 44:
            chain += bytes([following]) + extension  # the fragment header has no length field
        else:
            length_field = (2 + len(extension)) // 8 - 1
            chain += bytes([following, length_field]) + extension

    body = chain + payload
    header = struct.pack(
        "!IHBB16s16s",
        6 << 28,
        len(body),
        types[0],
        64,
        ipaddress.IPv6Address(src).packed,
        ipaddress.IPv6Address(dst).packed,
    )
    return header + body


# --- link layers ----------------------------------------------------------------

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD


def ethernet(
    payload: bytes, *, ethertype: int = ETHERTYPE_IPV4, vlans: Sequence[int] = ()
) -> bytes:
    macs = bytes.fromhex("001122334455") + bytes.fromhex("66778899aabb")
    tags = b"".join(struct.pack("!HH", 0x8100, vlan) for vlan in vlans)
    return macs + tags + struct.pack("!H", ethertype) + payload


def linux_sll(payload: bytes, *, protocol: int = ETHERTYPE_IPV4) -> bytes:
    return struct.pack("!HHH8sH", 0, 1, 6, bytes(8), protocol) + payload


def linux_sll2(payload: bytes, *, protocol: int = ETHERTYPE_IPV4) -> bytes:
    return struct.pack("!HHIHBB8s", protocol, 0, 1, 1, 0, 6, bytes(8)) + payload


def null_loopback(payload: bytes, *, family: int = 2) -> bytes:
    return struct.pack("<I", family) + payload


# --- capture files -------------------------------------------------------------


def pcap(
    frames: Iterable[tuple[float, bytes]],
    *,
    linktype: int = 1,
    nanoseconds: bool = False,
    big_endian: bool = False,
) -> bytes:
    order = ">" if big_endian else "<"
    magic = 0xA1B23C4D if nanoseconds else 0xA1B2C3D4
    scale = 1_000_000_000 if nanoseconds else 1_000_000
    chunks = [struct.pack(order + "IHHiIII", magic, 2, 4, 0, 0, 262144, linktype)]
    for timestamp, data in frames:
        ticks = round(timestamp * scale)
        seconds, fraction = divmod(ticks, scale)
        chunks.append(struct.pack(order + "IIII", seconds, fraction, len(data), len(data)))
        chunks.append(data)
    return b"".join(chunks)


def pcapng(
    packets: Iterable[tuple[int, float, bytes]],
    *,
    interfaces: Sequence[tuple[int, int | None]] = ((1, None),),
    big_endian: bool = False,
    extra_block: bool = False,
) -> bytes:
    """A single-section pcapng file.

    ``packets`` holds ``(interface_id, timestamp, data)`` tuples and ``interfaces``
    holds ``(linktype, if_tsresol)`` pairs, ``None`` meaning the default resolution.
    """
    order = ">" if big_endian else "<"
    out = [_block(order, 0x0A0D0D0A, struct.pack(order + "IHHq", 0x1A2B3C4D, 1, 0, -1))]
    units: list[int] = []
    for linktype, tsresol in interfaces:
        options = b""
        if tsresol is not None:
            options = _option(order, 9, bytes([tsresol])) + struct.pack(order + "HH", 0, 0)
        out.append(_block(order, 1, struct.pack(order + "HHI", linktype, 0, 262144) + options))
        units.append(_units_per_second(tsresol))
    if extra_block:
        out.append(_block(order, 0x00000BAD, b"custom data"))  # custom block, must be skipped
    for interface_id, timestamp, data in packets:
        ticks = round(timestamp * units[interface_id])
        body = struct.pack(
            order + "IIIII", interface_id, ticks >> 32, ticks & 0xFFFFFFFF, len(data), len(data)
        )
        out.append(_block(order, 6, body + data))
    return b"".join(out)


def _block(order: str, block_type: int, body: bytes) -> bytes:
    padded = body + bytes(-len(body) % 4)
    total = 12 + len(padded)
    return struct.pack(order + "II", block_type, total) + padded + struct.pack(order + "I", total)


def _option(order: str, code: int, value: bytes) -> bytes:
    return struct.pack(order + "HH", code, len(value)) + value + bytes(-len(value) % 4)


def _units_per_second(tsresol: int | None) -> int:
    if tsresol is None:
        return 1_000_000
    exponent = tsresol & 0x7F
    return 2**exponent if tsresol & 0x80 else 10**exponent


# --- whole streams -------------------------------------------------------------


def voice_frames(
    count: int,
    *,
    src: str = "10.0.0.1",
    sport: int = 40000,
    dst: str = "10.0.0.2",
    dport: int = 50000,
    ssrc: int = 0x11223344,
    payload_type: int = 0,
    start: float = 1_700_000_000.0,
    interval: float = 0.02,
    first_sequence: int = 1000,
    samples_per_packet: int = 160,
) -> list[tuple[float, bytes]]:
    """Ethernet frames carrying a constant-rate RTP voice stream over IPv4."""
    frames = []
    for index in range(count):
        packet = rtp(
            first_sequence + index,
            index * samples_per_packet,
            ssrc,
            payload_type=payload_type,
            marker=index == 0,
        )
        frames.append(
            (start + index * interval, ethernet(ipv4(src, dst, udp(sport, dport, packet))))
        )
    return frames
