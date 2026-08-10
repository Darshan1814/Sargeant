"""
Parametrized parser-coverage test (the honest bar).

For every synthetic fixture we assert, end to end through ``pipeline.process``:
  1. it routes to the EXPECTED parser_id (NGRE path), and
  2. the emitted event is valid, uniform OCSF.

For the malformed corpus we assert the pipeline degrades gracefully:
  * every malformed line lands on the Drain3 (or DLQ) path — never NGRE, and
  * NOT ONE raises an unhandled exception (the real bar: zero crashes).

We also assert the canonical envelope is identical in shape across Windows and
macOS output, which is the user's "both outputs should look the same" acceptance
criterion.

Run:  pytest backend/tests/test_parser_coverage.py -v
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).parent.parent.parent
os.environ.setdefault("PARSERS_DIR", str(_REPO_ROOT / "parsers" / "registry"))
os.environ.setdefault("DUCKDB_PATH", str(Path(tempfile.mkdtemp()) / "test_coverage.db"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from pipeline import process  # noqa: E402
from fingerprint import fingerprint  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures" / "synthetic"

# Required OCSF fields every event must carry regardless of source/path.
_REQUIRED_OCSF = ("class_uid", "time", "severity_id", "metadata", "actor",
                  "device", "raw_data", "unmapped")


def _load_jsonl(name: str) -> list[dict]:
    path = FIXTURES / name
    if not path.exists():
        return []
    return [json.loads(l) for l in path.read_text().splitlines() if l.strip()]


def _id(rows, prefix):
    return [f"{prefix}-{i}-{r.get('expected_parser_id', r.get('os',''))}"
            for i, r in enumerate(rows)]


_WIN = _load_jsonl("windows.jsonl")
_MAC = _load_jsonl("macos.jsonl")
_MAL = _load_jsonl("malformed.jsonl")


def _assert_valid_ocsf(norm: dict, ctx: str):
    for f in _REQUIRED_OCSF:
        assert f in norm, f"[{ctx}] missing OCSF field '{f}'"
    assert isinstance(norm["class_uid"], int), f"[{ctx}] class_uid not int"
    assert isinstance(norm["severity_id"], int), f"[{ctx}] severity_id not int"
    assert isinstance(norm["time"], str) and norm["time"], f"[{ctx}] empty time"
    assert norm["metadata"].get("uid"), f"[{ctx}] missing metadata.uid"
    # raw log must be preserved for full traceability (no line lost)
    assert norm.get("raw_data"), f"[{ctx}] raw_data not preserved"


# ── Windows: expected-parser routing + valid OCSF ─────────────────────────────

@pytest.mark.parametrize("row", _WIN, ids=_id(_WIN, "win"))
def test_windows_fixture_routes_and_maps(row):
    raw, expected = row["raw"], row["expected_parser_id"]
    result = process(raw)
    assert result["path"] == "ngre", (
        f"{expected}: expected NGRE path, got {result['path']} "
        f"(detected {result['parser_id']})"
    )
    assert result["parser_id"] == expected, (
        f"misroute: expected {expected}, got {result['parser_id']}"
    )
    _assert_valid_ocsf(result["normalized"], expected)


# ── macOS: expected-parser routing + valid OCSF ───────────────────────────────

@pytest.mark.parametrize("row", _MAC, ids=_id(_MAC, "mac"))
def test_macos_fixture_routes_and_maps(row):
    raw, expected = row["raw"], row["expected_parser_id"]
    result = process(raw)
    assert result["path"] == "ngre", (
        f"{expected}: expected NGRE path, got {result['path']} "
        f"(detected {result['parser_id']})"
    )
    assert result["parser_id"] == expected, (
        f"misroute: expected {expected}, got {result['parser_id']}"
    )
    _assert_valid_ocsf(result["normalized"], expected)


# ── Malformed: graceful degradation, zero crashes ─────────────────────────────

@pytest.mark.parametrize("row", _MAL, ids=_id(_MAL, "mal"))
def test_malformed_falls_back_without_crashing(row):
    raw = row["raw"]
    # The bar: process() must never raise.
    result = process(raw)
    assert result["path"] in ("drain3", "dlq"), (
        f"malformed line unexpectedly matched a parser via {result['path']} "
        f"({result['parser_id']}): {raw!r}"
    )
    assert result["needs_review"] is True
    _assert_valid_ocsf(result["normalized"], "malformed")


def test_at_least_two_malformed_per_os():
    """Attachment requirement: ≥2 malformed samples per OS."""
    per_os = {}
    for r in _MAL:
        per_os[r.get("os", "?")] = per_os.get(r.get("os", "?"), 0) + 1
    assert per_os.get("windows", 0) >= 2, f"need ≥2 windows malformed, got {per_os}"
    assert per_os.get("macos", 0) >= 2, f"need ≥2 macos malformed, got {per_os}"


# ── Uniformity: Windows and macOS OCSF envelopes are structurally identical ───

def test_windows_and_macos_envelopes_have_same_shape():
    assert _WIN and _MAC, "fixtures missing"
    win = process(_WIN[0]["raw"])["normalized"]
    mac = process(_MAC[0]["raw"])["normalized"]

    def skeleton(d, depth=0):
        # compare only the fixed top-level canonical keys (order-independent)
        return sorted(k for k in d.keys())

    win_top = skeleton(win)
    mac_top = skeleton(mac)
    assert win_top == mac_top, (
        "Windows/macOS OCSF top-level shape differs:\n"
        f"  win-only: {set(win_top) - set(mac_top)}\n"
        f"  mac-only: {set(mac_top) - set(win_top)}"
    )


# ── Coverage summary (informational, always passes) ───────────────────────────

def test_report_measured_coverage(capsys):
    """Prints HONEST measured coverage — no 100% claims."""
    rows = [("windows", r) for r in _WIN] + [("macos", r) for r in _MAC]
    ngre = drain3 = dlq = 0
    for _os, r in rows:
        p = process(r["raw"])["path"]
        ngre += p == "ngre"
        drain3 += p == "drain3"
        dlq += p == "dlq"
    total = len(rows) or 1
    mal_fallback = sum(process(r["raw"])["path"] in ("drain3", "dlq") for r in _MAL)
    with capsys.disabled():
        print(f"\n─ measured coverage (synthetic corpus) ─")
        print(f"  known-format fixtures : {total}")
        print(f"  via NGRE  : {ngre}/{total} = {100*ngre/total:.1f}%")
        print(f"  via Drain3: {drain3}/{total} = {100*drain3/total:.1f}%")
        print(f"  via DLQ   : {dlq}/{total} = {100*dlq/total:.1f}%")
        print(f"  malformed → graceful fallback: {mal_fallback}/{len(_MAL)}")
    assert ngre == total, "every known-format fixture must parse via NGRE"
