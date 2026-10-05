import json
import subprocess
import sys
from pathlib import Path

import pytest

from rtpscope import __version__
from rtpscope.cli import main
from tests import builders


@pytest.fixture
def call_capture(tmp_path: Path) -> Path:
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
    path = tmp_path / "call.pcap"
    path.write_bytes(builders.pcap(sorted(forward + backward)))
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


def test_capture_without_rtp(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "empty.pcap"
    path.write_bytes(builders.pcap([]))

    assert main(["streams", str(path)]) == 0
    assert capsys.readouterr().out.strip() == "No RTP streams found."


def test_min_packets_option(call_capture: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["streams", str(call_capture), "--min-packets", "45", "--json"]) == 0

    assert len(json.loads(capsys.readouterr().out)) == 1


@pytest.mark.parametrize("value", ["1", "lots"])
def test_invalid_min_packets_is_rejected(
    call_capture: Path, value: str, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(["streams", str(call_capture), "--min-packets", value])

    assert exit_info.value.code == 2
    assert "--min-packets" in capsys.readouterr().err


def test_missing_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["streams", str(tmp_path / "nope.pcap")]) == 2
    assert "no such file" in capsys.readouterr().err


def test_not_a_capture(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "notes.txt"
    path.write_text("definitely not a capture file")

    assert main(["streams", str(path)]) == 2
    assert "not a pcap or pcapng file" in capsys.readouterr().err


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        main(["--version"])

    assert __version__ in capsys.readouterr().out


def test_module_entry_point(call_capture: Path) -> None:
    result = subprocess.run(
        [sys.executable, "-m", "rtpscope", "streams", str(call_capture), "--json"],
        capture_output=True,
        text=True,
        check=True,
    )

    assert len(json.loads(result.stdout)) == 2
