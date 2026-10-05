# rtpscope

Call-quality analysis for VoIP traffic in packet captures.

Point `rtpscope` at a `.pcap` or `.pcapng` file and it finds the RTP media streams
inside, measures what happened to them on the wire (jitter, loss, reordering) and
estimates how the call sounded to a listener.

> Status: early development.
