"""
Android logcat parser-family tests. Every standard `logcat -v <format>` layout
must parse deterministically (NGRE via the Android family), never Drain3, with
correct OCSF class, severity from priority, and event_time from the log.
"""
import os
import sys
import tempfile
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).parent.parent.parent
os.environ.setdefault("PARSERS_DIR", str(_REPO_ROOT / "parsers" / "registry"))
os.environ.setdefault("DUCKDB_PATH", str(Path(tempfile.mkdtemp()) / "test_android.db"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from pipeline import process  # noqa: E402

CANON = {
    "class_uid", "time", "severity_id", "metadata", "actor", "device",
    "raw_data", "unmapped",
}

SAMPLES = {
    "threadtime": "08-10 09:20:19.692  3907  3921 W dumpsys : Thread Pool max thread count is 0",
    "time":       "08-10 09:20:19.692 W/dumpsys( 3907): Thread Pool max thread count is 0",
    "brief":      "E/AndroidRuntime( 6944): FATAL EXCEPTION: main",
    "process":    "W( 3907) Alarm set (OplusStorage)",
    "event":      "08-10 09:20:19.100  1000  1000 I am_proc_start: [0,6944,10123,com.app]",
    "network":    "08-10 09:21:00.001 I/ConnectivityService( 1200): NetworkAgent switched",
    "json":       '{"time":"08-10 09:20:19.692","pid":3907,"priority":"E","tag":"X","message":"boom"}',
    "long":       "[ 08-10 09:20:19.692  3907: 3921 W/dumpsys ]\nThread Pool max thread count is 0",
}


@pytest.mark.parametrize("name,raw", list(SAMPLES.items()))
def test_android_format_parses_via_family(name, raw):
    r = process(raw)
    assert r["path"] == "ngre", f"{name} took {r['path']} (parser {r['parser_id']})"
    assert r["parser_id"].startswith("ANDROID-LOGCAT-"), r["parser_id"]
    norm = r["normalized"]
    for f in CANON:
        assert f in norm, f"{name}: missing OCSF field {f}"
    assert norm["device"]["os"]["family"] == "Android"
    # Full Android-native view preserved, losslessly.
    assert "android" in norm["unmapped"], f"{name}: android block not preserved"
    assert norm["raw_data"] == raw.strip() or norm["raw_data"] == raw


def test_android_priority_maps_to_severity():
    r = process("08-10 09:20:19.692 E/App( 100): crash")
    assert r["normalized"]["severity"] == "High"       # E = Error
    r2 = process("08-10 09:20:19.692 W/App( 100): warn")
    assert r2["normalized"]["severity"] == "Medium"    # W = Warning


def test_android_event_time_not_processing_time():
    r = process("08-10 09:20:19.692  3907  3921 I dumpsys : hi")
    # event_time comes from the log (month 08, day 10), NOT the current year-only now()
    assert r["normalized"]["time"].startswith(f"{__import__('datetime').datetime.now().year}-08-10")
    assert r["normalized"]["metadata"]["original_time"], "original_time must be preserved"


def test_android_tag_and_pid_extracted():
    r = process("08-10 09:20:19.692 W/dumpsys( 3907): message here")
    proc = r["normalized"]["actor"]["process"]
    assert proc["name"] == "dumpsys"
    assert proc["pid"] == 3907
