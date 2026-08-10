"""
Exact regression tests from the ULPF update spec (PART 32, 33, 34, 35).
These lock in the root-cause fixes so they can't silently regress.
"""
import os
import sys
import tempfile
from pathlib import Path

_REPO_ROOT = Path(__file__).parent.parent.parent
os.environ.setdefault("PARSERS_DIR", str(_REPO_ROOT / "parsers" / "registry"))
os.environ.setdefault("DUCKDB_PATH", str(Path(tempfile.mkdtemp()) / "test_spec.db"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from pipeline import process  # noqa: E402


def _ips(norm):
    return [o["value"] for o in norm["observables"] if o.get("type") == "IP Address"]


# ── PART 32 — Android logcat (exact spec input, spaced "( 3974 )") ────────────

def test_part32_android_logcat():
    raw = ("08-10 09:08:13.239 W/dumpsys ( 3974): Thread Pool max thread count is 0. "
           "Cannot cache binder as linkToDeath cannot be implemented. serviceName: package")
    r = process(raw)
    assert r["parser_id"].startswith("ANDROID-LOGCAT-"), r["parser_id"]
    assert r["path"] == "ngre"
    n = r["normalized"]
    a = n["unmapped"]["android"]
    assert a["priority"] == "W"
    assert a["priority_label"] == "Warning"
    assert a["tag"] == "dumpsys"
    assert str(a["pid"]) == "3974"
    # Full message preserved, not truncated.
    assert "serviceName: package" in a["message"]
    assert n["device"]["os"]["family"] == "Android"
    assert n["actor"]["process"]["name"] == "dumpsys"
    assert n["actor"]["process"]["pid"] == 3974
    # No false IP.
    assert _ips(n) == []
    # unmapped is not a dumping ground: only the source-specific block.
    assert set(n["unmapped"].keys()) <= {"android"}


# ── PART 33 — Windows key=value must not go to Drain3 ─────────────────────────

def test_part33_windows_key_value():
    raw = "Provider=Microsoft-Windows-Kernel-General EventID=12 Level=Information"
    r = process(raw)
    assert r["path"] != "drain3", "recognizable winkv must not fall to Drain3"
    w = r["normalized"]["unmapped"]["windows"]
    assert w["provider"] == "Microsoft-Windows-Kernel-General"
    assert str(w["event_id"]) == "12"
    assert w["level"] == "Information"


# ── PART 34 — Windows CBS package/version, no false IP ────────────────────────

def test_part34_windows_cbs():
    raw = ("2016-09-29 02:04:40, Info                  CBS    Read out cached package "
           "applicability for package: Package_for_KB2928120~31bf3856ad364e35~amd64~~"
           "6.1.1.2, ApplicableState: 0, CurrentState:0")
    r = process(raw)
    assert r["parser_id"] == "WIN-CBS-001"
    n = r["normalized"]
    pkg = n["unmapped"]["windows"]["package"]
    assert pkg["kb"] == "KB2928120"
    assert pkg["architecture"] == "amd64"
    assert pkg["version"] == "6.1.1.2"
    assert n["unmapped"]["windows"]["applicable_state"] == 0
    assert n["unmapped"]["windows"]["current_state"] == 0
    # 6.1.1.2 MUST NOT be an IP.
    assert "6.1.1.2" not in _ips(n)
    # event_time from the log, not processing time.
    assert n["time"].startswith("2016-09-29")


# ── PART 35 — false-positive type suite ───────────────────────────────────────

def test_part35_version_strings_not_ips():
    for ver in ["6.1.1.2", "10.0.19041.1", "2026.08.27.12"]:
        r = process(f"Log Name: Application\nSource: Setup\nEvent ID: 1\n"
                    f"Computer: X\nversion={ver}")
        assert ver not in _ips(r["normalized"]), f"{ver} wrongly typed as IP"


def test_part35_real_ip_is_ip():
    raw = ("Log Name: Security\nSource: Microsoft-Windows-Security-Auditing\n"
           "Event ID: 4624\nComputer: DC01\nNew Logon:\n  Account Name: a\n"
           "  Logon Type: 3\n  Source Network Address: 10.10.1.20")
    assert "10.10.1.20" in _ips(process(raw)["normalized"])
