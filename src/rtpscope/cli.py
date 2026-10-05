"""The ``rtpscope`` command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from rtpscope import __version__
from rtpscope.capture import CaptureError
from rtpscope.streams import DEFAULT_MIN_PACKETS, RtpStream, load_streams

__all__ = ["build_parser", "format_streams_table", "main", "stream_summary"]


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command line and return the process exit status."""
    args = build_parser().parse_args(argv)
    status: int = args.handler(args)
    return status


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rtpscope",
        description="Find and analyse RTP media streams in pcap/pcapng captures.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(title="commands", required=True, metavar="COMMAND")

    streams = commands.add_parser(
        "streams",
        help="list the RTP streams in a capture",
        description="List the RTP streams found in a capture file.",
    )
    streams.add_argument("capture", type=Path, help="pcap or pcapng file to read")
    streams.add_argument("--json", action="store_true", help="print JSON instead of a table")
    streams.add_argument(
        "--min-packets",
        type=_min_packets,
        default=DEFAULT_MIN_PACKETS,
        metavar="N",
        help=f"ignore candidate streams with fewer packets (default: {DEFAULT_MIN_PACKETS})",
    )
    streams.set_defaults(handler=_run_streams)
    return parser


def _run_streams(args: argparse.Namespace) -> int:
    try:
        streams = load_streams(args.capture, min_packets=args.min_packets)
    except FileNotFoundError:
        return _fail(f"no such file: {args.capture}")
    except (CaptureError, OSError) as error:
        return _fail(f"cannot read {args.capture}: {error}")

    if args.json:
        print(json.dumps([stream_summary(stream) for stream in streams], indent=2))
    else:
        print(format_streams_table(streams))
    return 0


def stream_summary(stream: RtpStream) -> dict[str, Any]:
    """A JSON-serialisable summary of ``stream``."""
    codec = stream.codec
    return {
        "src": stream.key.src,
        "sport": stream.key.sport,
        "dst": stream.key.dst,
        "dport": stream.key.dport,
        "ssrc": stream.key.ssrc,
        "payload_type": stream.payload_type,
        "codec": codec.name if codec else None,
        "clock_rate": codec.clock_rate if codec else None,
        "packets": stream.packet_count,
        "payload_bytes": stream.payload_bytes,
        "first_seen": stream.first_seen,
        "duration": stream.duration,
    }


_TABLE_HEADER = ("#", "Source", "Destination", "SSRC", "Payload", "Packets", "Start", "Duration")
_RIGHT_ALIGNED = frozenset({0, 5, 6, 7})


def format_streams_table(streams: Sequence[RtpStream]) -> str:
    """Render ``streams`` as a plain-text table.

    Start times are relative to the first stream, in seconds.
    """
    if not streams:
        return "No RTP streams found."
    origin = min(stream.first_seen for stream in streams)
    rows = [
        (
            str(index),
            stream.key.source,
            stream.key.destination,
            f"0x{stream.key.ssrc:08X}",
            _payload_label(stream),
            str(stream.packet_count),
            f"{stream.first_seen - origin:.3f}s",
            f"{stream.duration:.3f}s",
        )
        for index, stream in enumerate(streams, start=1)
    ]
    return _render_table(_TABLE_HEADER, rows)


def _payload_label(stream: RtpStream) -> str:
    codec = stream.codec
    if codec is None:
        return f"PT {stream.payload_type}"
    return f"{codec.name} ({stream.payload_type})"


def _render_table(header: Sequence[str], rows: Sequence[Sequence[str]]) -> str:
    widths = [max(len(row[column]) for row in (header, *rows)) for column in range(len(header))]

    def line(cells: Sequence[str]) -> str:
        padded = (
            cell.rjust(width) if column in _RIGHT_ALIGNED else cell.ljust(width)
            for column, (cell, width) in enumerate(zip(cells, widths, strict=True))
        )
        return "  ".join(padded).rstrip()

    rule = "  ".join("-" * width for width in widths)
    return "\n".join([line(header), rule, *(line(row) for row in rows)])


def _min_packets(value: str) -> int:
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected an integer, got {value!r}") from None
    if number < 2:
        raise argparse.ArgumentTypeError("must be at least 2")
    return number


def _fail(message: str) -> int:
    print(f"rtpscope: error: {message}", file=sys.stderr)
    return 2
