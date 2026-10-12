# rtpscope

[![CI](https://github.com/raoalqama-dev/rtpscope/actions/workflows/ci.yml/badge.svg)](https://github.com/raoalqama-dev/rtpscope/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue)
![License](https://img.shields.io/badge/license-MIT-green)

Call-quality analysis for VoIP traffic in packet captures.

Point `rtpscope` at a `.pcap` or `.pcapng` file and it finds the RTP media streams
inside, measures what happened to them on the wire and estimates how the call
sounded to a listener. The core has no third-party dependencies: capture files,
link layers, IP and RTP are all parsed directly.

> Status: early development. Stream discovery and per-stream metrics work today; MOS
> estimation and the rest of the roadmap are in progress.

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
1  192.168.1.20:16384  203.0.113.5:30000   0x5A3C19E2  PCMA (8)     1496  0.000s   29.981s
2  203.0.113.5:30000   192.168.1.20:16384  0x0B7D44A1  PCMA (8)     1484  0.223s   29.780s
3  192.168.1.20:16386  203.0.113.5:30002   0x77E0A2B9  PT 96         900  1.040s   17.979s
```

Measure what happened to each stream on the wire:

```console
$ rtpscope analyze call.pcap --clock-rate 96=48000
#  Source              Destination         SSRC        Payload   Recv  Lost   Loss  Dup  Reorder  Burst  Jitter  Max jitter  Max IAT   Bitrate
-  ------------------  ------------------  ----------  --------  ----  ----  -----  ---  -------  -----  ------  ----------  -------  --------
1  192.168.1.20:16384  203.0.113.5:30000   0x5A3C19E2  PCMA (8)  1496     4  0.27%    0        0      3  1.31ms      1.94ms   79.8ms  63.8kb/s
2  203.0.113.5:30000   192.168.1.20:16384  0x0B7D44A1  PCMA (8)  1484     7  0.47%    1        1      5  6.08ms      9.13ms  117.1ms  63.7kb/s
3  192.168.1.20:16386  203.0.113.5:30002   0x77E0A2B9  PT 96      900     0  0.00%    0        0      0  0.67ms      0.93ms   22.0ms  64.0kb/s
```

| Column | Meaning |
| --- | --- |
| Recv | packets captured, duplicates included |
| Lost, Loss | sequence numbers that never arrived, as a count and a share of those expected |
| Dup | packets whose sequence number had already been seen |
| Reorder | packets that arrived after one with a higher sequence number |
| Burst | the longest run of consecutive lost packets |
| Jitter, Max jitter | mean and peak of the RFC 3550 interarrival jitter estimate |
| Max IAT | the longest gap between two consecutive packets |
| Bitrate | RTP payload bit rate, headers excluded |

Jitter needs the RTP clock rate of the payload type. Static payload types (PCMU,
PCMA, G.722, G.729, ...) have one; dynamic types (96-127) don't, so their jitter
shows as `-` unless you pass `--clock-rate PT=HZ` (repeatable; it also overrides a
static rate). `--json` prints every metric, including the mean and 95th percentile
interarrival time and the number of sequence restarts, nested under `"metrics"`.

Both commands take `--json` for machine-readable output, and `--min-packets N` to
change how many packets a candidate needs before it is reported as a stream
(default 10).

From Python:

```python
from rtpscope import analyze_stream, load_streams

for stream in load_streams("call.pcapng"):
    codec = stream.codec.name if stream.codec else f"PT {stream.payload_type}"
    metrics = analyze_stream(stream, clock_rates={96: 48000})
    jitter = "n/a" if metrics.jitter_max_ms is None else f"{metrics.jitter_max_ms:.2f} ms"
    route = f"{stream.key.source} -> {stream.key.destination}"
    print(f"{route} {codec}: loss {metrics.loss_percent:.2f}%, max jitter {jitter}")
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

## How the metrics are computed

- **Extended sequence numbers** follow RFC 3550, appendix A.1. RTP sequence numbers
  are 16 bits, so a step forward of less than 3000 is new data (a wrap past 65535
  starts a new cycle), and a packet less than 100 behind the highest one is a late
  arrival or a duplicate. A bigger jump is held back: if the very next packet follows
  it, the sender has restarted its numbering, and the new numbers are spliced on
  straight after the old ones so the restart isn't counted as loss. A lone packet
  with a wild sequence number is ignored.
- **Loss** is the span from the lowest to the highest extended sequence number,
  minus the distinct numbers received. RFC 3550's cumulative loss subtracts every
  packet received instead, so duplicates hide loss and can even make it negative;
  counting duplicates separately keeps both numbers honest. As with RTCP, packets
  lost after the last one received can't be seen.
- **Loss bursts** are measured after the whole stream is read, so a packet that
  arrives late fills its gap instead of being counted as lost.
- **Jitter** is the running estimate of RFC 3550, appendix A.8: for consecutive
  arrivals the transit-time difference is `D = (Rj - Ri) - (Sj - Si)`, with arrival
  times `R` converted to RTP timestamp units using the codec clock rate, and the
  estimate moves 1/16 of the way towards `|D|` with every packet. RTP timestamp wraps
  are handled. Only the first copy of each packet of the stream's main payload type
  takes part: a duplicate or a DTMF event packet would look like a timing error when
  it isn't. The mean and peak of the running estimate are reported, in milliseconds,
  as Wireshark's RTP analysis does. When the clock rate is unknown no jitter is
  reported rather than a guess: assuming 8 kHz for a 48 kHz Opus stream would read
  each 20 ms packet as 120 ms of audio, a 100 ms timing error on every packet.
- **Interarrival times** are the gaps between consecutive packets in capture order;
  the 95th percentile interpolates linearly between neighbours (the NumPy default).
- **Bitrate** is the RTP payload carried after the first packet, divided by the time
  from the first packet to the last: each interval delivers one packet, so a clean
  20 ms G.711 stream reads exactly 64 kbit/s, its nominal rate.

## Roadmap

- [x] Capture parsing and RTP stream discovery
- [x] Per-stream metrics: interarrival jitter, loss, duplicates and reordering (RFC 3550)
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
