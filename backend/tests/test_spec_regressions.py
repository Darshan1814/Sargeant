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
from engine.streaming import group_records, iter_records_from_text  # noqa: E402


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


# ── PART 36 — robustness: malformed / unknown / multi-line / mixed batches ────
# Spec #2 (every record carries a stable raw_sha256), #5 (never fabricate — an
# unparseable line is flagged for review, not force-fit to a family) and #14
# (the same guarantees hold whether records arrive one-per-line or multi-line
# grouped, and across all three families in one batch).

# One deliberately un-family-shaped line per family + free text. None matches a
# family detector or a registry parser, so each must land on the Drain3 safety
# net — enveloped, hashed, and marked needs_review — rather than crash or be
# mis-attributed.
_MALFORMED = [
    # Windows-flavoured but structurally empty (no provider/eventid values).
    "Provider= EventID= Level=",
    # Linux-flavoured garbage (no RFC3164/5424/dmesg/auditd shape).
    ">>> corrupt syslog fragment <<< pid= host=",
    # Android-flavoured partial (no valid logcat header).
    "08-10 W/ : ",
    # Pure free text with no structure at all.
    "the quick brown fox jumped over the lazy dog",
]


def test_part36_malformed_all_families_route_to_drain3_safely():
    for raw in _MALFORMED:
        r = process(raw)  # must never raise
        assert r["path"] == "drain3", (raw, r["path"])
        assert r["parser_id"] == "DRAIN3-FALLBACK", (raw, r["parser_id"])
        # #5: unparseable ⇒ flagged for a human, never silently trusted.
        assert r["needs_review"] is True, raw
        # #2: a stable content hash is present even on the fallback path.
        assert r["normalized"]["metadata"]["raw_sha256"], raw
        # #5 again: no source timestamp was invented for a line that has none.
        assert r["normalized"]["metadata"]["original_time"] in (None, ""), raw


def test_part36_multiline_windows_4625_grouped_and_parsed():
    """A multi-line Windows Security block is one logical record: group_records
    must fold the 8 physical lines into 1, and process() must then reach the
    WIN-SEC-4625 registry parser and recover the real Source Network Address —
    not fragment into per-line drain3 fallbacks."""
    block = ("Log Name:      Security\n"
             "Source:        Microsoft-Windows-Security-Auditing\n"
             "Event ID:      4625\n"
             "Computer:      DC01\n"
             "An account failed to log on.\n"
             "  Account Name:            bob\n"
             "  Logon Type:              3\n"
             "  Source Network Address:  10.10.1.20")
    groups = group_records(block)
    assert len(groups) == 1, groups  # 8 physical lines → 1 logical record
    r = process(groups[0])
    assert r["parser_id"] == "WIN-SEC-4625", r["parser_id"]
    assert r["path"] == "ngre"
    assert r["needs_review"] is False
    assert "10.10.1.20" in _ips(r["normalized"])


def test_part36_multiline_android_long_grouped_and_parsed():
    """Android 'long' format spans a bracketed header line plus a message line;
    it must group to a single ANDROID-LOGCAT-LONG record."""
    rec = "[ 08-10 09:08:13.239  3974: 3974 W/dumpsys ]\nThread pool exhausted"
    groups = group_records(rec)
    assert len(groups) == 1, groups
    r = process(groups[0])
    assert r["parser_id"] == "ANDROID-LOGCAT-LONG", r["parser_id"]
    assert r["path"] == "ngre"
    assert r["normalized"]["device"]["os"]["family"] == "Android"


def test_part36_mixed_batch_routes_each_family_without_cross_contamination():
    """A single heterogeneous batch (Windows multi-line + Linux + Android +
    macOS) must split into the right number of records and route each to its
    own family/registry parser — no line bleeds into another family."""
    blob = "\n".join([
        # Windows 4625 (multi-line) — folds to one record.
        "Log Name:      Security",
        "Source:        Microsoft-Windows-Security-Auditing",
        "Event ID:      4625",
        "Computer:      DC01",
        "  Source Network Address:  10.10.1.20",
        # Linux syslog (RFC3164).
        "Aug 01 00:00:05 srv sshd[44218]: Accepted publickey for alice "
        "from 203.0.113.9 port 55214 ssh2",
        # Android threadtime.
        "08-10 09:20:19.692 I/ConnectivityService( 1234): NetworkAgent switched",
        # macOS kernel (must reach the macOS registry, not the Linux family).
        "Jul  1 09:00:55 calvisitor kernel[0]: IOThunderboltSwitch listenerCallback",
    ])
    records = list(iter_records_from_text(blob))
    assert len(records) == 4, [r.raw for r in records]

    results = [process(rec.raw) for rec in records]
    parser_ids = [r["parser_id"] for r in results]
    families = [r["normalized"]["device"]["os"]["family"] for r in results]

    assert parser_ids == [
        "WIN-SEC-4625",
        "LINUX-SYSLOG-RFC3164",
        "ANDROID-LOGCAT-TIME",
        "MAC-ULOG-001",
    ], parser_ids
    assert families == ["Windows", "Linux", "Android", "macOS"], families

    # No cross-contamination: the Windows record owns the only IP, and the
    # macOS line was NOT swallowed by the Linux family detector.
    assert "10.10.1.20" in _ips(results[0]["normalized"])
    assert results[3]["path"] == "ngre"

    # Every record in the batch is enveloped and hashed (spec #2).
    for rec, r in zip(records, results):
        assert r["normalized"]["metadata"]["raw_sha256"] == rec.raw_sha256
