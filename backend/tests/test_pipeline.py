"""
Full pipeline test suite.
Run via: pytest -v
"""
import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).parent.parent.parent
os.environ.setdefault("PARSERS_DIR", str(_REPO_ROOT / "parsers" / "registry"))
os.environ.setdefault("DUCKDB_PATH", str(Path(tempfile.mkdtemp()) / "test_pipeline.db"))

sys.path.insert(0, str(Path(__file__).parent.parent))

from fingerprint import fingerprint
from pipeline import process

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str) -> str:
    return (FIXTURES / name).read_text()


# ── 1. Windows parser detection ───────────────────────────────────────────────

def test_windows_parser_detects_correctly():
    raw = _load("sample_windows_security.evtx.txt")
    result = fingerprint(raw)
    # This fixture is an Event ID 4624 logon. The SPECIALIZED WIN-SEC-4624 parser
    # (which knows the 4624 field layout) must win over the generic catch-all
    # WIN-EVTLOG-001 — that is the whole point of the specialized registry:
    # specialized-with-known-process reaches 1.0, generic caps at 0.9.
    assert result.detected_parser_id == "WIN-SEC-4624", (
        f"Expected WIN-SEC-4624, got {result.detected_parser_id} "
        f"(candidates: {[(c.parser_id, round(c.score, 2)) for c in result.candidates[:3]]})"
    )
    assert result.confidence > 0.8, f"Confidence too low: {result.confidence}"
    # The generic parser must still be present as a viable fallback.
    generic = next((c for c in result.candidates if c.parser_id == "WIN-EVTLOG-001"), None)
    assert generic is not None and generic.score >= 0.5, (
        "generic WIN-EVTLOG-001 should remain a strong fallback candidate"
    )


# ── 2. macOS parser detection ─────────────────────────────────────────────────

def test_macos_parser_detects_correctly():
    raw = _load("sample_macos_syslog.log")
    result = fingerprint(raw)
    assert result.detected_parser_id == "MAC-ULOG-001", (
        f"Expected MAC-ULOG-001, got {result.detected_parser_id}"
    )
    assert result.confidence > 0.5, f"Confidence too low: {result.confidence}"


# ── 3. Unknown format falls back to Drain3 ────────────────────────────────────

def test_unknown_format_falls_back_to_drain3():
    raw = _load("sample_unknown_format.log")
    result = process(raw)
    assert result["path"] == "drain3", f"Expected drain3 path, got {result['path']}"
    assert result["needs_review"] is True
    # The Drain3 template is preserved losslessly. Under the CANONICAL uniform
    # OCSF envelope, Drain3-only fields live under `unmapped` (so a Drain3 event
    # has the identical top-level skeleton as a fully-parsed NGRE event). The
    # pipeline result also surfaces it at the top level for convenience.
    assert result.get("drain3_template") is not None, "template missing on result"
    assert result["normalized"]["unmapped"].get("drain3_template") is not None, (
        "drain3_template must be preserved under normalized.unmapped (lossless)"
    )


# ── 4. OCSF mapping produces valid schema ─────────────────────────────────────

def test_ocsf_mapping_produces_valid_schema():
    raw = _load("sample_windows_security.evtx.txt")
    result = process(raw)
    norm = result["normalized"]
    required_fields = ["class_uid", "time", "severity_id"]
    for field in required_fields:
        assert field in norm, f"Missing required OCSF field: {field}"
    assert isinstance(norm["class_uid"], int)
    assert isinstance(norm["severity_id"], int)
    assert isinstance(norm["time"], str) and len(norm["time"]) > 0


# ── 5. Raw and normalized share event_id ─────────────────────────────────────

def test_raw_and_normalized_share_event_id():
    raw = _load("sample_macos_syslog.log")
    result = process(raw)
    assert "event_id" in result
    assert result["normalized"]["metadata"]["uid"] == result["event_id"], (
        "event_id mismatch between pipeline result and OCSF metadata.uid"
    )


# ── 6. End-to-end ingest to query ─────────────────────────────────────────────

def test_end_to_end_ingest_to_query():
    from fastapi.testclient import TestClient
    import db

    db.init_db()

    from main import app
    client = TestClient(app)

    raw = _load("sample_windows_system.evtx.txt")
    resp = client.post("/api/ingest", data={"raw_log": raw})
    assert resp.status_code == 200, f"Ingest failed: {resp.text}"
    event_id = resp.json()["event_id"]

    resp2 = client.get(f"/api/events/{event_id}")
    assert resp2.status_code == 200, f"Event not retrievable: {resp2.text}"
    data = resp2.json()
    assert data["raw_log"] == raw.strip()
    assert "normalized" in data
    assert data["event_id"] == event_id


# ── 7. DLQ path produces valid OCSF with parser_id=DLQ ───────────────────────

def test_dlq_path_produces_valid_ocsf():
    from unittest.mock import patch
    import fingerprint as fp_mod
    import pipeline as pipe_mod

    raw = "some totally unknown log line that no parser can match"

    # Force drain3 to fail so we hit the DLQ path
    with patch.object(pipe_mod, "_apply_drain3", side_effect=RuntimeError("forced")):
        with patch.object(fp_mod, "_load_parsers", return_value=[]):
            result = pipe_mod.process(raw)

    assert result["path"] == "dlq", f"Expected dlq path, got {result['path']}"
    assert result["parser_id"] == "DLQ"
    assert result["dlq"] is True
    assert result["needs_review"] is True

    norm = result["normalized"]
    assert "class_uid" in norm
    assert "time" in norm
    assert "severity_id" in norm
    assert norm["metadata"]["parser_id"] == "DLQ"
    assert norm["metadata"]["uid"] == result["event_id"]


# ── 8. DLQ endpoint returns data ──────────────────────────────────────────────

def test_dlq_api_endpoint():
    from fastapi.testclient import TestClient
    import db

    db.init_db()
    from main import app
    client = TestClient(app)

    resp = client.get("/api/dlq")
    assert resp.status_code == 200
    body = resp.json()
    assert "total" in body
    assert "items" in body
    assert isinstance(body["items"], list)


# ── 9. False-IP regression: version strings must NOT become IP observables ────

def test_cbs_version_not_detected_as_ip():
    """A KB package version like 6.1.1.2 must never be tagged as an IP Address.
    Fixed at the observable-extraction layer (ocsf_mapper._valid_ipv4)."""
    raw = ("2016-09-29 02:04:40, Info                  CBS    Read out cached package "
           "applicability for package: Package_for_KB2928120~31bf3856ad364e35~amd64~~"
           "6.1.1.2, ApplicableState: 0, CurrentState:0")
    result = process(raw)
    assert result["parser_id"] == "WIN-CBS-001"
    obs_ips = [o["value"] for o in result["normalized"]["observables"]
               if o.get("type") == "IP Address"]
    assert "6.1.1.2" not in obs_ips, f"version string mis-tagged as IP: {obs_ips}"
    assert obs_ips == [], f"no IPs should be extracted from this CBS line, got {obs_ips}"


def test_real_ip_still_detected_as_observable():
    """A genuine Source Network Address must still be extracted as an IP."""
    raw = ("Log Name:      Security\nSource:        Microsoft-Windows-Security-Auditing\n"
           "Event ID:      4624\nComputer:      DC01\nNew Logon:\n"
           "  Account Name:  jsmith\n  Logon Type:  3\n  Source Network Address:  10.0.0.42")
    result = process(raw)
    obs_ips = [o["value"] for o in result["normalized"]["observables"]
               if o.get("type") == "IP Address"]
    assert "10.0.0.42" in obs_ips, f"real IP not extracted: {obs_ips}"


def test_various_version_strings_not_ips():
    """Assorted version/build strings that look like IPv4 must not be observables."""
    for ver in ["6.1.1.2", "1.2.3.4", "10.0.19041.1"]:
        raw = f"Log Name: Application\nSource: Setup\nEvent ID: 1\nComputer: X\nversion={ver}"
        result = process(raw)
        obs_ips = [o["value"] for o in result["normalized"]["observables"]
                   if o.get("type") == "IP Address"]
        assert ver not in obs_ips, f"{ver} (after 'version=') wrongly tagged as IP"
