# rtpscope

[![CI](https://github.com/raoalqama-dev/rtpscope/actions/workflows/ci.yml/badge.svg)](https://github.com/raoalqama-dev/rtpscope/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue)
![License](https://img.shields.io/badge/license-MIT-green)

Call-quality analysis for VoIP traffic in packet captures.

Point `rtpscope` at a `.pcap` or `.pcapng` file and it finds the RTP media streams
inside, measures what happened to them on the wire and estimates how the call
sounded to a listener. The core has no third-party dependencies: capture files,
link layers, IP and RTP are all parsed directly.

> Status: early development. Stream discovery works today; the metrics below are on the roadmap.

## Install

```bash
pip install git+https://github.com/raoalqama-dev/rtpscope.git
```

## Usage

List the RTP streams in a capture:

```console
$ rtpscope streams call.pcap
#  Source              Destination         SSRC        Payload   Packets   Start  Duration
-  ------------------  ------------------  ----------  --------  -------  ------  --------
1  192.168.1.20:16384  203.0.113.5:30000   0x5A3C19E2  PCMA (8)     1500  0.000s   29.980s
2  203.0.113.5:30000   192.168.1.20:16384  0x0B7D44A1  PCMA (8)     1490  0.212s   29.780s
3  192.168.1.20:16386  203.0.113.5:30002   0x77E0A2B9  PT 96         900  1.040s   29.967s
```

Add `--json` for machine-readable output, and `--min-packets N` to change how many
packets a candidate needs before it is reported as a stream (default 10).

From Python:

```python
from rtpscope import load_streams

for stream in load_streams("call.pcapng"):
    codec = stream.codec.name if stream.codec else f"PT {stream.payload_type}"
    print(stream.key.source, "->", stream.key.destination, codec, stream.packet_count)
```

## How stream detection works

RTP has no fixed port, so every UDP payload is a candidate:

1. **Capture files.** Classic pcap (micro- and nanosecond, either byte order) and
   pcapng (multiple sections and interfaces, per-interface timestamp resolution
   and offset) are read by a small built-in parser.
2. **Link and network layers.** Ethernet (including stacked VLAN tags), Linux
   cooked capture v1/v2, BSD loopback and raw IP are unwrapped; IPv4 and IPv6
   (with extension headers) are walked to the UDP header. IP fragments are skipped.
3. **RTP header.** Payloads that are RTCP (packet types 192-223, per RFC 5761) are
   set aside; the rest are parsed as RTP (RFC 3550), including CSRC lists, header
   extensions and padding.
4. **Grouping and validation.** Packets are grouped by UDP flow and SSRC. A group is
   only reported once it has enough packets and at least 80% of consecutive packets
   advance the sequence number by a small step, in the spirit of the RTP probation
   period (RFC 3550, appendix A.1). Random UDP payloads practically never pass.

## Roadmap

- [x] Capture parsing and RTP stream discovery
- [ ] Per-stream metrics: interarrival jitter, loss, duplicates and reordering (RFC 3550)
- [ ] MOS estimation with the ITU-T G.107 E-model
- [ ] SIP/SDP call correlation
- [ ] Anomaly detection over time windows
- [ ] HTML report
- [ ] REST API and container image

## Development

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"

pytest --cov                     # tests build their own captures byte by byte
ruff check . && ruff format --check .
mypy
```

## License

MIT
