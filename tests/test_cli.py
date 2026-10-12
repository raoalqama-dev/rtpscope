import dataclasses
import json
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

import pytest

from rtpscope import StreamMetrics, __version__
from rtpscope.cli import main
from tests import builders

COMMANDS = ["streams", "analyze"]


def call_frames(*, lost: Sequence[int] = ()) -> list[tuple[float, bytes]]:
    """Both directions of a call: PCMU one way, a dynamic payload type the other."""
    forward = builders.voice_frames(50, ssrc=0x1111, payload_type=0)
    backward = builders.voice_frames(
        40,
        src="10.0.0.2",
        sport=50000,
        dst="10.0.0.1",
        dport=40000,
        ssrc=0x2222,
        payload_type=111,
        start=1_700_000_000.5,
    )
    kept = [frame for index, frame in enumerate(forward) if index not in lost]
    return sorted(kept + backward)


@pytest.fixture
def call_capture(tmp_path: Path) -> Path:
    path = tmp_path / "call.pcap"
    path.write_bytes(builders.pcap(call_frames()))
    return path


@pytest.fixture
def lossy_capture(tmp_path: Path) -> Path:
    path = tmp_path / "lossy.pcap"
    path.write_bytes(builders.pcap(call_frames(lost=(10, 11, 30))))
    return path


def test_streams_table(call_capture: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["streams", str(call_capture)]) == 0

    lines = capsys.readouterr().out.splitlines()
    assert lines[0].split() == [
        "#",
        "Source",
        "Destination",
        "SSRC",
        "Payload",
        "Packets",
        "Start",
        "Duration",
    ]
    assert lines[2].split() == [
        "1",
        "10.0.0.1:40000",
        "10.0.0.2:50000",
        "0x00001111",
        "PCMU",
        "(0)",
        "50",
        "0.000s",
        "0.980s",
    ]
    assert lines[3].split() == [
        "2",
        "10.0.0.2:50000",
        "10.0.0.1:40000",
        "0x00002222",
        "PT",
        "111",
        "40",
        "0.500s",
        "0.780s",
    ]


def test_streams_json(call_capture: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["streams", str(call_capture), "--json"]) == 0

    streams = json.loads(capsys.readouterr().out)
    assert [stream["ssrc"] for stream in streams] == [0x1111, 0x2222]
    assert streams[0]["codec"] == "PCMU"
    assert streams[0]["clock_rate"] == 8000
    assert streams[0]["packets"] == 50
    assert streams[1]["codec"] is None
    assert streams[1]["payload_type"] == 111


def test_analyze_table(lossy_capture: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["analyze", str(lossy_capture)]) == 0

    lines = capsys.readouterr().out.splitlines()
    assert lines[0].split() == [
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
        "Max",
        "jitter",
        "Max",
        "IAT",
        "Bitrate",
    ]
    assert lines[2].split() == [
        "1",
        "10.0.0.1:40000",
        "10.0.0.2:50000",
        "0x00001111",
        "PCMU",
        "(0)",
        "47",
        "3",
        "6.00%",
        "0",
        "0",
        "2",
        "0.00ms",
        "0.00ms",
        "60.0ms",
        "60.1kb/s",
    ]
    # Without a clock rate for the dynamic payload type there is no jitter.
    assert lines[3].split() == [
        "2",
        "10.0.0.2:50000",
        "10.0.0.1:40000",
        "0x00002222",
        "PT",
        "111",
        "40",
        "0",
        "0.00%",
        "0",
        "0",
        "0",
        "-",
        "-",
        "20.0ms",
        "64.0kb/s",
    ]


def test_analyze_json(lossy_capture: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["analyze", str(lossy_capture), "--json"]) == 0

    forward, backward = json.loads(capsys.readouterr().out)
    assert forward["ssrc"] == 0x1111
    assert forward["packets"] == 47
    assert set(forward["metrics"]) == {field.name for field in dataclasses.fields(StreamMetrics)}
    assert forward["metrics"]["packets_expected"] == 50
    assert forward["metrics"]["packets_lost"] == 3
    assert forward["metrics"]["loss_percent"] == pytest.approx(6.0)
    assert forward["metrics"]["max_loss_burst"] == 2
    assert forward["metrics"]["interarrival_max_ms"] == pytest.approx(60.0, abs=1e-3)
    assert backward["metrics"]["clock_rate"] is None
    assert backward["metrics"]["jitter_max_ms"] is None


def test_analyze_clock_rate_option(call_capture: Path, capsys: pytest.CaptureFixture[str]) -> None:
    arguments = ["analyze", str(call_capture), "--json", "--clock-rate", "111=16000"]
    assert main([*arguments, "--clock-rate", "111=8000"]) == 0

    _, backward = json.loads(capsys.readouterr().out)
    assert backward["clock_rate"] is None  # the static assignment is unchanged
    assert backward["metrics"]["clock_rate"] == 8000  # the last value given wins
    assert backward["metrics"]["jitter_max_ms"] == pytest.approx(0.0, abs=1e-3)


@pytest.mark.parametrize("value", ["111", "x=8000", "111=fast", "1=2=3", "128=8000", "111=0"])
def test_invalid_clock_rate_is_rejected(
    call_capture: Path, value: str, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(["analyze", str(call_capture), "--clock-rate", value])

    assert exit_info.value.code == 2
    assert "--clock-rate" in capsys.readouterr().err


@pytest.mark.parametrize("command", COMMANDS)
def test_capture_without_rtp(
    tmp_path: Path, command: str, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "empty.pcap"
    path.write_bytes(builders.pcap([]))

    assert main([command, str(path)]) == 0
    assert capsys.readouterr().out.strip() == "No RTP streams found."


@pytest.mark.parametrize("command", COMMANDS)
def test_min_packets_option(
    call_capture: Path, command: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main([command, str(call_capture), "--min-packets", "45", "--json"]) == 0

    assert len(json.loads(capsys.readouterr().out)) == 1


@pytest.mark.parametrize("value", ["1", "lots"])
def test_invalid_min_packets_is_rejected(
    call_capture: Path, value: str, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(["streams", str(call_capture), "--min-packets", value])

    assert exit_info.value.code == 2
    assert "--min-packets" in capsys.readouterr().err


@pytest.mark.parametrize("command", COMMANDS)
def test_missing_file(tmp_path: Path, command: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert main([command, str(tmp_path / "nope.pcap")]) == 2
    assert "no such file" in capsys.readouterr().err


@pytest.mark.parametrize("command", COMMANDS)
def test_not_a_capture(tmp_path: Path, command: str, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "notes.txt"
    path.write_text("definitely not a capture file")

    assert main([command, str(path)]) == 2
    assert "not a pcap or pcapng file" in capsys.readouterr().err


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        main(["--version"])

    assert __version__ in capsys.readouterr().out


@pytest.mark.parametrize("command", COMMANDS)
def test_module_entry_point(call_capture: Path, command: str) -> None:
    result = subprocess.run(
        [sys.executable, "-m", "rtpscope", command, str(call_capture), "--json"],
        capture_output=True,
        text=True,
        check=True,
    )

    assert len(json.loads(result.stdout)) == 2
