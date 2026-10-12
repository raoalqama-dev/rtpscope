"""The ``rtpscope`` command-line interface."""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from rtpscope import __version__
from rtpscope.capture import CaptureError
from rtpscope.metrics import StreamMetrics, analyze_stream
from rtpscope.streams import DEFAULT_MIN_PACKETS, RtpStream, load_streams

__all__ = [
    "analysis_summary",
    "build_parser",
    "format_metrics_table",
    "format_streams_table",
    "main",
    "stream_summary",
]


class _CommandError(Exception):
    """A failure that ends the command with a message on stderr and exit status 2."""


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command line and return the process exit status."""
    args = build_parser().parse_args(argv)
    try:
        status: int = args.handler(args)
    except _CommandError as error:
        return _fail(str(error))
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
    _add_capture_arguments(streams)
    streams.set_defaults(handler=_run_streams)

    analyze = commands.add_parser(
        "analyze",
        help="measure loss, jitter and timing for each RTP stream",
        description="Measure loss, reordering, jitter and timing for each RTP stream "
        "in a capture file.",
    )
    _add_capture_arguments(analyze)
    analyze.add_argument(
        "--clock-rate",
        type=_clock_rate,
        action="append",
        default=[],
        metavar="PT=HZ",
        help="RTP clock rate of a payload type, e.g. 111=48000 (repeatable); overrides the "
        "static rate and gives dynamic payload types a jitter measurement",
    )
    analyze.set_defaults(handler=_run_analyze)
    return parser


def _add_capture_arguments(command: argparse.ArgumentParser) -> None:
    command.add_argument("capture", type=Path, help="pcap or pcapng file to read")
    command.add_argument("--json", action="store_true", help="print JSON instead of a table")
    command.add_argument(
        "--min-packets",
        type=_min_packets,
        default=DEFAULT_MIN_PACKETS,
        metavar="N",
        help=f"ignore candidate streams with fewer packets (default: {DEFAULT_MIN_PACKETS})",
    )


def _run_streams(args: argparse.Namespace) -> int:
    streams = _load_streams(args)
    if args.json:
        print(json.dumps([stream_summary(stream) for stream in streams], indent=2))
    else:
        print(format_streams_table(streams))
    return 0


def _run_analyze(args: argparse.Namespace) -> int:
    clock_rates = dict(args.clock_rate)
    analyses = [
        (stream, analyze_stream(stream, clock_rates=clock_rates)) for stream in _load_streams(args)
    ]
    if args.json:
        summaries = [analysis_summary(stream, metrics) for stream, metrics in analyses]
        print(json.dumps(summaries, indent=2))
    else:
        print(format_metrics_table(analyses))
    return 0


def _load_streams(args: argparse.Namespace) -> list[RtpStream]:
    try:
        return load_streams(args.capture, min_packets=args.min_packets)
    except FileNotFoundError:
        raise _CommandError(f"no such file: {args.capture}") from None
    except (CaptureError, OSError) as error:
        raise _CommandError(f"cannot read {args.capture}: {error}") from None


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


def analysis_summary(stream: RtpStream, metrics: StreamMetrics) -> dict[str, Any]:
    """A JSON-serialisable summary of ``stream`` with its metrics under ``"metrics"``."""
    return {**stream_summary(stream), "metrics": dataclasses.asdict(metrics)}


_NO_STREAMS = "No RTP streams found."

_STREAMS_HEADER = ("#", "Source", "Destination", "SSRC", "Payload", "Packets", "Start", "Duration")
_STREAMS_RIGHT_ALIGNED = frozenset({0, 5, 6, 7})


def format_streams_table(streams: Sequence[RtpStream]) -> str:
    """Render ``streams`` as a plain-text table.

    Start times are relative to the first stream, in seconds.
    """
    if not streams:
        return _NO_STREAMS
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
    return _render_table(_STREAMS_HEADER, rows, _STREAMS_RIGHT_ALIGNED)


_METRICS_HEADER = (
    "#",
    "Source",
    "Destination",
    "SSRC",
    "Payload",
    "Recv",
    "Lost",
    "Loss",
    "Dup",
    "Reorder",
    "Burst",
    "Jitter",
    "Max jitter",
    "Max IAT",
    "Bitrate",
)
_METRICS_RIGHT_ALIGNED = frozenset({0, *range(5, len(_METRICS_HEADER))})


def format_metrics_table(analyses: Sequence[tuple[RtpStream, StreamMetrics]]) -> str:
    """Render each stream and its metrics as one row of a plain-text table.

    Jitter is the mean and the peak of the running RFC 3550 estimate; a dash
    means the clock rate of the payload type is unknown.
    """
    if not analyses:
        return _NO_STREAMS
    rows = [
        (
            str(index),
            stream.key.source,
            stream.key.destination,
            f"0x{stream.key.ssrc:08X}",
            _payload_label(stream),
            str(metrics.packets_received),
            str(metrics.packets_lost),
            f"{metrics.loss_percent:.2f}%",
            str(metrics.duplicates),
            str(metrics.out_of_order),
            str(metrics.max_loss_burst),
            _milliseconds(metrics.jitter_mean_ms, 2),
            _milliseconds(metrics.jitter_max_ms, 2),
            _milliseconds(metrics.interarrival_max_ms, 1),
            "-" if metrics.bitrate_bps is None else f"{metrics.bitrate_bps / 1000:.1f}kb/s",
        )
        for index, (stream, metrics) in enumerate(analyses, start=1)
    ]
    return _render_table(_METRICS_HEADER, rows, _METRICS_RIGHT_ALIGNED)


def _payload_label(stream: RtpStream) -> str:
    codec = stream.codec
    if codec is None:
        return f"PT {stream.payload_type}"
    return f"{codec.name} ({stream.payload_type})"


def _milliseconds(value: float | None, decimals: int) -> str:
    return "-" if value is None else f"{value:.{decimals}f}ms"


def _render_table(
    header: Sequence[str], rows: Sequence[Sequence[str]], right_aligned: frozenset[int]
) -> str:
    widths = [max(len(row[column]) for row in (header, *rows)) for column in range(len(header))]

    def line(cells: Sequence[str]) -> str:
        padded = (
            cell.rjust(width) if column in right_aligned else cell.ljust(width)
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


def _clock_rate(value: str) -> tuple[int, int]:
    try:
        payload_type, rate = (int(part) for part in value.split("="))
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"expected PT=HZ such as 111=48000, got {value!r}"
        ) from None
    if not 0 <= payload_type <= 127:
        raise argparse.ArgumentTypeError(f"payload type {payload_type} is outside 0-127")
    if rate <= 0:
        raise argparse.ArgumentTypeError("clock rate must be positive")
    return payload_type, rate


def _fail(message: str) -> int:
    print(f"rtpscope: error: {message}", file=sys.stderr)
    return 2
