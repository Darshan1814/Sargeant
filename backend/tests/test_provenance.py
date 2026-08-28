"""
Provenance & truthful-metadata tests (spec PARTs 8, 20-26, 32-35).

Asserts: parse_status, ocsf_mapping_status, confidence_breakdown, readable
parse_stages, timestamp inference marking, and the exact regression inputs.
"""
import os
import sys
import tempfile
from pathlib import Path

_REPO_ROOT = Path(__file__).parent.parent.parent
os.environ.setdefault("PARSERS_DIR", str(_REPO_ROOT / "parsers" / "registry"))
os.environ.setdefault("DUCKDB_PATH", str(Path(tempfile.mkdtemp()) / "test_prov.db"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from pipeline import process  # noqa: E402


# ── PART 32: Android with variable whitespace + serviceName in message ────────

def test_android_variable_whitespace_and_message_intact():
    raw = ("08-10 09:08:13.239 W/dumpsys ( 3974): Thread Pool max thread count is 0. "
           "Cannot cache binder as linkToDeath cannot be implemented. serviceName: package")
    r = process(raw)
    assert r["parser_id"].startswith("ANDROID-LOGCAT-")
    assert r["path"] == "ngre"
    n = r["normalized"]
    assert n["actor"]["process"]["name"] == "dumpsys"
    assert n["actor"]["process"]["pid"] == 3974
    assert n["device"]["os"]["name"] == "Android"
    assert "serviceName: package" in n["message"], "message must not be truncated"
    ips = [o["value"] for o in n["observables"] if o.get("type") == "IP Address"]
    assert ips == [], f"no false IPs, got {ips}"


# ── PART 33: Windows key=value must not go to Drain3 ──────────────────────────

def test_windows_kv_not_drain3():
    r = process("Provider=Microsoft-Windows-Kernel-General EventID=12 Level=Information")
    assert r["path"] != "drain3"
    assert r["parser_id"] != "DRAIN3-FALLBACK"
    wb = r["normalized"]["unmapped"].get("windows", {})
    assert wb.get("event_id") == "12"


# ── PART 34: CBS 6.1.1.2 is not an IP ─────────────────────────────────────────

def test_cbs_version_not_ip_regression():
    raw = ("2016-09-29 02:04:40, Info                  CBS    Read out cached package "
           "applicability for package: Package_for_KB2928120~31bf3856ad364e35~amd64~~"
           "6.1.1.2, ApplicableState: 0, CurrentState:0")
    r = process(raw)
    assert r["parser_id"] == "WIN-CBS-001"
    ips = [o["value"] for o in r["normalized"]["observables"] if o.get("type") == "IP Address"]
    assert "6.1.1.2" not in ips and ips == []


# ── PART 20-23: parse_status + ocsf_mapping_status honesty ────────────────────

def test_confident_class_is_parsed_and_mapped():
    raw = ("Log Name: Security\nSource: Microsoft-Windows-Security-Auditing\n"
           "Event ID: 4624\nComputer: DC01\nNew Logon:\n  Account Name: jsmith\n"
           "  Logon Type: 3\n  Source Network Address: 10.0.0.5")
    n = process(raw)["normalized"]
    assert n["parse_status"] == "parsed"
    assert n["ocsf_mapping_status"] == "mapped"      # 3002 Authentication is confident
    assert n["confidence_breakdown"]["ocsf"] > 0


def test_generic_class_is_partial_and_unmapped():
    n = process("08-10 09:08:13.239 W/dumpsys ( 3974): thread pool warning")["normalized"]
    assert n["parse_status"] == "partially_parsed"   # parsed format, unknown OCSF class
    assert n["ocsf_mapping_status"] == "unmapped"
    assert n["confidence_breakdown"]["ocsf"] == 0.0
    assert n["confidence_breakdown"]["format"] == 1.0  # but we DO know the format


def test_drain3_is_fallback_status():
    n = process("zzz totally unstructured blob 999 qqq")["normalized"]
    assert n["parse_status"] == "fallback"
    assert n["parse_stages"][-1] == "drain3_fallback"


# ── PART 26: readable parse_stages ────────────────────────────────────────────

def test_parse_stages_human_readable():
    n = process("Provider=Microsoft-Windows-Kernel-General EventID=12 Level=Information")["normalized"]
    assert "format_detection" in n["parse_stages"]
    assert "ocsf_mapping" in n["parse_stages"]


# ── PART 8: timestamp inference marking ───────────────────────────────────────

def test_timestamp_inference_marks():
    # Android: no year, no tz → both inferred.
    n = process("08-10 09:08:13.239 W/dumpsys ( 3974): x")["normalized"]
    assert n["metadata"]["timestamp_year_source"] == "inferred"
    assert n["metadata"]["timestamp_timezone_source"] != "source"
    # CBS: real year present → source.
    n2 = process("2016-09-29 02:04:40, Info                  CBS    Loaded Stack")["normalized"]
    assert n2["metadata"]["timestamp_year_source"] == "source"
