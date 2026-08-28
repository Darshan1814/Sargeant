"""
Loghub integration tests: 100% OCSF conversion for Windows CBS and macOS syslog.
Verifies NGRE is used (not Drain3/DLQ), parser_id traceability, and OCSF validity.

Run from repo root:
    PARSERS_DIR=$(pwd)/parsers/registry \
    DUCKDB_PATH=/tmp/test_loghub.db \
    pytest backend/tests/test_loghub.py -v
"""
import os
import sys
import tempfile
from pathlib import Path

# Must be set before importing fingerprint / pipeline (module-level reads)
_REPO_ROOT = Path(__file__).parent.parent.parent
os.environ.setdefault("PARSERS_DIR", str(_REPO_ROOT / "parsers" / "registry"))
os.environ.setdefault("DUCKDB_PATH", str(Path(tempfile.mkdtemp()) / "test_loghub.db"))

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from fingerprint import fingerprint
from pipeline import process

LOGHUB_WIN = _REPO_ROOT / "loghub" / "Windows" / "Windows_2k.log"
LOGHUB_MAC = _REPO_ROOT / "loghub" / "Mac" / "Mac_2k.log"

pytestmark = pytest.mark.skipif(
    not LOGHUB_WIN.exists() or not LOGHUB_MAC.exists(),
    reason="loghub not cloned; run: git clone https://github.com/logpai/loghub.git ulpf/loghub",
)


def _load_lines(path: Path) -> list[str]:
    return [l for l in path.read_text(errors="replace").splitlines() if l.strip()]


# ── Windows CBS fingerprint ───────────────────────────────────────────────────

def test_windows_cbs_fingerprint_detects_parser():
    line = "2016-09-28 04:30:30, Info                  CBS    Loaded Servicing Stack v6.1.7601.23505"
    fp = fingerprint(line)
    assert fp.detected_parser_id == "WIN-CBS-001", (
        f"Expected WIN-CBS-001, got {fp.detected_parser_id} (confidence={fp.confidence})"
    )
    assert fp.confidence >= 0.5
    assert not fp.use_drain3


def test_windows_csi_fingerprint_detects_parser():
    line = "2016-09-28 04:30:31, Info                  CSI    00000001@2016/9/27:20:30:31.455 WcpInitialize"
    fp = fingerprint(line)
    assert fp.detected_parser_id == "WIN-CBS-001", (
        f"CSI lines must also map to WIN-CBS-001, got {fp.detected_parser_id}"
    )
    assert fp.confidence >= 0.5


# ── macOS syslog fingerprint ──────────────────────────────────────────────────

def test_macos_syslog_fingerprint_detects_parser():
    line = "Jul  1 09:00:55 calvisitor-10-105-160-95 kernel[0]: IOThunderboltSwitch<0>(0x0)::listenerCallback"
    fp = fingerprint(line)
    assert fp.detected_parser_id == "MAC-ULOG-001", (
        f"Expected MAC-ULOG-001, got {fp.detected_parser_id} (confidence={fp.confidence})"
    )
    assert fp.confidence >= 0.5


def test_macos_syslog_unknown_process_fingerprint():
    line = "Jul  1 09:01:06 calvisitor-10-105-160-95 QQ[10018]: FA||Url||taskID dealloc"
    fp = fingerprint(line)
    assert fp.detected_parser_id == "MAC-ULOG-001", (
        f"Non-standard process should still match MAC-ULOG-001: {fp.detected_parser_id}"
    )
    assert fp.confidence >= 0.5


# ── Windows CBS pipeline: single lines ───────────────────────────────────────

@pytest.mark.parametrize("line", [
    "2016-09-28 04:30:30, Info                  CBS    Loaded Servicing Stack v6.1.7601.23505",
    "2016-09-28 04:30:31, Info                  CSI    00000001@2016/9/27:20:30:31.455 WcpInitialize (wcp.dll version 0.0.0.6)",
    "2016-09-28 04:30:31, Info                  CBS    Ending TrustedInstaller initialization.",
])
def test_windows_single_line_ngre(line):
    result = process(line)
    assert result["path"] == "ngre", f"Expected ngre, got {result['path']} for: {line[:60]}"
    assert result["parser_id"] == "WIN-CBS-001"
    norm = result["normalized"]
    assert norm["class_uid"] == 1001
    assert norm["metadata"]["parser_id"] == "WIN-CBS-001"
    assert norm["metadata"]["uid"] == result["event_id"]
    assert norm["time"].startswith("2016-09-28"), f"Wrong timestamp: {norm['time']}"


# ── macOS syslog pipeline: single lines ──────────────────────────────────────

@pytest.mark.parametrize("line", [
    "Jul  1 09:00:55 calvisitor-10-105-160-95 kernel[0]: IOThunderboltSwitch<0>(0x0)::listenerCallback",
    "Jul  1 09:01:05 calvisitor-10-105-160-95 com.apple.CDScheduler[43]: Thermal pressure state: 1",
    "Jul  1 09:01:06 calvisitor-10-105-160-95 QQ[10018]: FA||Url||taskID[2019352994] dealloc",
    "Jul  1 09:02:26 authorMacBook-Pro kernel[0]: ARPT: 620702.879952: AirPort_Brcm43xx::syncPowerState",
])
def test_macos_single_line_ngre(line):
    result = process(line)
    assert result["path"] == "ngre", f"Expected ngre, got {result['path']} for: {line[:60]}"
    assert result["parser_id"] == "MAC-ULOG-001"
    norm = result["normalized"]
    assert norm["class_uid"] == 1001
    assert norm["metadata"]["parser_id"] == "MAC-ULOG-001"
    assert norm["metadata"]["uid"] == result["event_id"]
    assert norm.get("device", {}).get("os", {}).get("family") == "macOS"


# ── OCSF validity helper ──────────────────────────────────────────────────────

def _assert_valid_ocsf(norm: dict, context: str):
    for field in ("class_uid", "time", "severity_id", "metadata"):
        assert field in norm, f"Missing OCSF field '{field}' [{context}]"
    assert isinstance(norm["class_uid"], int), f"class_uid not int [{context}]"
    assert isinstance(norm["severity_id"], int), f"severity_id not int [{context}]"
    assert norm["time"], f"Empty time field [{context}]"
    assert norm["metadata"].get("uid"), f"Missing metadata.uid [{context}]"
    assert norm["metadata"].get("parser_id"), f"Missing metadata.parser_id [{context}]"


# ── Bulk: all 1999 Windows lines ─────────────────────────────────────────────

def test_windows_bulk_100pct_conversion():
    lines = _load_lines(LOGHUB_WIN)
    assert len(lines) > 0, "Windows_2k.log is empty"

    ngre = drain3 = dlq = 0
    failures = []

    for i, line in enumerate(lines):
        result = process(line)
        path = result["path"]
        if path == "ngre":
            ngre += 1
        elif path == "drain3":
            drain3 += 1
        else:
            dlq += 1
            failures.append(f"Line {i+1} → DLQ: {line[:80]}")

        _assert_valid_ocsf(result["normalized"], f"WIN line {i+1}")
        assert result["normalized"]["metadata"]["uid"] == result["event_id"], (
            f"event_id mismatch at line {i+1}"
        )

    total = len(lines)
    pct_ngre = 100 * ngre / total
    print(f"\nWindows bulk: {total} lines — NGRE={ngre} ({pct_ngre:.1f}%), "
          f"Drain3={drain3}, DLQ={dlq}")

    assert dlq == 0, (
        f"{dlq}/{total} Windows lines ended in DLQ:\n" + "\n".join(failures[:10])
    )
    assert pct_ngre >= 90, (
        f"Expected ≥90% NGRE for Windows logs, got {pct_ngre:.1f}% ({ngre}/{total})"
    )


def test_windows_bulk_parser_id():
    lines = _load_lines(LOGHUB_WIN)
    wrong = []
    for i, line in enumerate(lines):
        result = process(line)
        if result["path"] == "ngre" and result["parser_id"] != "WIN-CBS-001":
            wrong.append(f"Line {i+1}: got parser_id={result['parser_id']}")

    assert not wrong, (
        f"NGRE-parsed Windows lines with wrong parser_id:\n" + "\n".join(wrong[:10])
    )


def test_windows_bulk_timestamps_extracted():
    lines = _load_lines(LOGHUB_WIN)[:50]  # first 50 lines
    for i, line in enumerate(lines):
        result = process(line)
        norm = result["normalized"]
        assert norm["time"].startswith("2016"), (
            f"Windows CBS timestamp wrong at line {i+1}: {norm['time']}"
        )


def test_windows_bulk_os_family():
    lines = _load_lines(LOGHUB_WIN)[:50]
    for i, line in enumerate(lines):
        result = process(line)
        norm = result["normalized"]
        if result["path"] == "ngre":
            os_family = norm.get("device", {}).get("os", {}).get("family")
            assert os_family == "Windows", (
                f"Expected device.os.family=Windows at line {i+1}, got {os_family}"
            )


# ── Bulk: all 1999 macOS lines ────────────────────────────────────────────────

def test_macos_bulk_100pct_conversion():
    lines = _load_lines(LOGHUB_MAC)
    assert len(lines) > 0, "Mac_2k.log is empty"

    ngre = drain3 = dlq = 0
    failures = []

    for i, line in enumerate(lines):
        result = process(line)
        path = result["path"]
        if path == "ngre":
            ngre += 1
        elif path == "drain3":
            drain3 += 1
        else:
            dlq += 1
            failures.append(f"Line {i+1} → DLQ: {line[:80]}")

        _assert_valid_ocsf(result["normalized"], f"Mac line {i+1}")
        assert result["normalized"]["metadata"]["uid"] == result["event_id"], (
            f"event_id mismatch at line {i+1}"
        )

    total = len(lines)
    pct_ngre = 100 * ngre / total
    print(f"\nmacOS bulk: {total} lines — NGRE={ngre} ({pct_ngre:.1f}%), "
          f"Drain3={drain3}, DLQ={dlq}")

    assert dlq == 0, (
        f"{dlq}/{total} macOS lines ended in DLQ:\n" + "\n".join(failures[:10])
    )
    assert pct_ngre >= 90, (
        f"Expected ≥90% NGRE for macOS logs, got {pct_ngre:.1f}% ({ngre}/{total})"
    )


def test_macos_bulk_parser_id():
    lines = _load_lines(LOGHUB_MAC)
    wrong = []
    for i, line in enumerate(lines):
        result = process(line)
        if result["path"] == "ngre" and result["parser_id"] != "MAC-ULOG-001":
            wrong.append(f"Line {i+1}: got parser_id={result['parser_id']}")

    assert not wrong, (
        f"NGRE-parsed macOS lines with wrong parser_id:\n" + "\n".join(wrong[:10])
    )


def test_macos_bulk_os_family():
    lines = _load_lines(LOGHUB_MAC)[:50]
    for i, line in enumerate(lines):
        result = process(line)
        norm = result["normalized"]
        if result["path"] == "ngre":
            os_family = norm.get("device", {}).get("os", {}).get("family")
            assert os_family == "macOS", (
                f"Expected device.os.family=macOS at line {i+1}, got {os_family}"
            )


def test_macos_bulk_process_and_pid_extracted():
    lines = _load_lines(LOGHUB_MAC)[:50]
    for i, line in enumerate(lines):
        result = process(line)
        if result["path"] == "ngre":
            norm = result["normalized"]
            proc = norm.get("actor", {}).get("process", {})
            assert proc.get("name"), f"Missing actor.process.name at Mac line {i+1}"
            # pid 0 is valid (kernel[0]); check presence, not truthiness.
            assert proc.get("pid") is not None, f"Missing actor.process.pid at Mac line {i+1}"


# ── Cross-system: no cross-contamination ─────────────────────────────────────

def test_windows_line_not_parsed_as_mac():
    line = "2016-09-28 04:30:30, Info                  CBS    Loaded Servicing Stack"
    result = process(line)
    assert result["parser_id"] != "MAC-ULOG-001", (
        "Windows CBS line incorrectly parsed as macOS"
    )


def test_mac_line_not_parsed_as_windows():
    line = "Jul  1 09:00:55 calvisitor-10-105-160-95 kernel[0]: IOThunderboltSwitch"
    result = process(line)
    assert result["parser_id"] != "WIN-CBS-001", (
        "macOS syslog line incorrectly parsed as Windows CBS"
    )
    assert result["parser_id"] != "WIN-EVTLOG-001", (
        "macOS syslog line incorrectly parsed as Windows EventLog"
    )


# ── DLQ path sanity ───────────────────────────────────────────────────────────

def test_dlq_path_for_garbage_input():
    # Input that no parser can handle and Drain3 would give minimal output
    # The DLQ path requires all three paths to fail; in practice Drain3 always catches.
    # This test ensures the pipeline returns a valid OCSF event even for garbage.
    garbage = "\x00\x01\x02 !!@#$%^&*()" * 5
    result = process(garbage)
    norm = result["normalized"]
    # Must always return an OCSF event — path is drain3 or dlq
    assert result["path"] in ("drain3", "dlq"), (
        f"Garbage should not be parsed by NGRE, got path={result['path']}"
    )
    _assert_valid_ocsf(norm, "garbage DLQ")
    assert norm["metadata"]["uid"] == result["event_id"]
