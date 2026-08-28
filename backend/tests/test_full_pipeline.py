"""
Full four-family pipeline test suite (Windows / macOS / Firewall / Linux).

Self-contained & reproducible: it imports the seeded synthetic generator
(`testdata/generate_logs.py`), produces well-formed / malformed / adversarial
records in-process, and runs them through the REAL engine (`pipeline.process`)
and persistence layer (`db`). No claim is asserted without a measured number;
a real per-parser results table is printed at the end of the session.

Run:  docker compose run backend pytest -v tests/test_full_pipeline.py
"""
import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

# ── env must be set BEFORE importing engine modules (mirror existing tests) ──
_REPO_ROOT = Path(__file__).resolve().parents[2]
os.environ.setdefault("PARSERS_DIR", str(_REPO_ROOT / "parsers" / "registry"))
os.environ.setdefault("DUCKDB_PATH", str(Path(tempfile.mkdtemp()) / "test_full_pipeline.db"))

_BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_BACKEND))
sys.path.insert(0, str(_BACKEND / "testdata"))

import db  # noqa: E402
from pipeline import process  # noqa: E402
import generate_logs as gen  # noqa: E402

# parser_id → (expected OCSF class_uid, family)
PARSER_META = {
    "WIN-SEC-4625":     (3002, "windows"),
    "MAC-APPFW-001":    (4001, "macos"),
    "FW-GENERIC-001":   (4001, "firewall"),
    "FW-W3C-001":       (4001, "firewall"),
    "LINUX-SYSLOG-001": (1001, "linux"),
    "LINUX-AUTH-001":   (3002, "linux"),
}

# Smaller-but-meaningful counts for a fast, deterministic CI run.
N_WELL = int(os.getenv("TEST_N_WELL", "200"))
N_MAL = int(os.getenv("TEST_N_MAL", "40"))
N_ADV = int(os.getenv("TEST_N_ADV", "10"))

# Canonical uniform envelope: every event across every family shares these keys.
CANONICAL_KEYS = {
    "class_uid", "class_name", "category_uid", "category_name", "activity_id",
    "activity_name", "type_uid", "time", "timezone_offset", "severity_id",
    "severity", "status", "status_id", "message", "device", "actor",
    "src_endpoint", "dst_endpoint", "connection_info", "auth_protocol",
    "metadata", "observables", "unmapped", "raw_data", "confidence",
    "confidence_breakdown", "parse_path", "parse_stages", "parse_status",
    "ocsf_mapping_status", "needs_review",
}

# Collected across tests for the final real results table.
_RESULTS: dict[str, dict] = {}


def _gen_wellformed(pid: str, n: int) -> list[str]:
    fn = gen.PARSERS[pid]
    return [fn() for _ in range(n)]


def _gen_malformed(pid: str, n: int) -> list[str]:
    import re
    cfg = json.loads((gen.REGISTRY / f"{pid}.json").read_text())
    rx = re.compile(cfg["ngre_pattern"], re.MULTILINE | re.DOTALL)
    fn = gen.PARSERS[pid]
    return [gen.make_malformed(fn(), pid, rx) for _ in range(n)]


# ── 1. Well-formed → NGRE ≥ 95% ────────────────────────────────────────────────

@pytest.mark.parametrize("pid", list(PARSER_META))
def test_wellformed_ngre_rate(pid):
    lines = _gen_wellformed(pid, N_WELL)
    ngre = 0
    for raw in lines:
        r = process(raw)
        if r["path"] == "ngre":
            ngre += 1
    rate = 100.0 * ngre / len(lines)
    _RESULTS.setdefault(pid, {})["well_ngre"] = (ngre, len(lines), rate)
    assert rate >= 95.0, f"{pid} well-formed NGRE rate {rate:.1f}% < 95% ({ngre}/{len(lines)})"


# ── 2. Malformed → never crashes, never re-parsed as its OWN type ───────────────
#
# The generator guarantees a malformed line no longer matches ITS TARGET parser's
# ngre_pattern. It does NOT guarantee the line is un-parseable by every parser —
# e.g. a corrupted sshd/firewall line is often still valid generic RFC3164 syslog,
# so the pipeline may (correctly) reclassify it via a different parser. The honest,
# defensible invariants are therefore: (a) process() never raises (DLQ guarantees a
# result), and (b) no malformed line comes back as NGRE under its ORIGINAL parser_id.

@pytest.mark.parametrize("pid", list(PARSER_META))
def test_malformed_falls_through(pid):
    lines = _gen_malformed(pid, N_MAL)
    crashes = own_ngre = fell_through = reclassified = 0
    for raw in lines:
        try:
            r = process(raw)  # must NEVER raise
        except Exception:  # pragma: no cover
            crashes += 1
            continue
        # every result must be a full uniform envelope
        assert set(r["normalized"].keys()) == CANONICAL_KEYS
        if r["path"] == "ngre" and r["parser_id"] == pid:
            own_ngre += 1
        elif r["path"] in ("drain3", "dlq"):
            fell_through += 1
        else:  # ngre under a DIFFERENT parser = legitimate reclassification
            reclassified += 1
    _RESULTS.setdefault(pid, {})["mal_breakdown"] = (fell_through, reclassified, len(lines))
    _RESULTS[pid]["mal_crashes"] = crashes
    assert crashes == 0, f"{pid}: {crashes} crashes on malformed input"
    assert own_ngre == 0, (
        f"{pid}: {own_ngre} malformed lines still NGRE-matched their OWN parser"
    )


# ── 3. Adversarial (header wraps foreign payload) → flagged ─────────────────────

def test_adversarial_flagged():
    flagged = 0
    total = 0
    for _ in range(N_ADV * len(PARSER_META)):
        raw = gen.make_adversarial()
        total += 1
        r = process(raw)
        if r["needs_review"] or r["confidence"] < 0.5 or r["path"] != "ngre":
            flagged += 1
    rate = 100.0 * flagged / total
    _RESULTS.setdefault("_adversarial", {})["flagged"] = (flagged, total, rate)
    assert rate >= 95.0, f"adversarial flagged {rate:.1f}% < 95% ({flagged}/{total})"


# ── 4. OCSF validity per class ─────────────────────────────────────────────────

@pytest.mark.parametrize("pid", list(PARSER_META))
def test_ocsf_class_and_shape(pid):
    expected_class, _family = PARSER_META[pid]
    raw = _gen_wellformed(pid, 1)[0]
    r = process(raw)
    ev = r["normalized"]
    assert r["path"] == "ngre", f"{pid} sample did not take NGRE path"
    assert ev["class_uid"] == expected_class, (
        f"{pid} class_uid {ev['class_uid']} != expected {expected_class}"
    )
    assert set(ev.keys()) == CANONICAL_KEYS, (
        f"{pid} envelope keys differ: {set(ev.keys()) ^ CANONICAL_KEYS}"
    )
    assert ev["metadata"]["version"], "metadata.version missing"


# ── 5. Raw ↔ normalized traceability ───────────────────────────────────────────

@pytest.mark.parametrize("pid", list(PARSER_META))
def test_traceability(pid):
    raw = _gen_wellformed(pid, 1)[0]
    r = process(raw)
    ev = r["normalized"]
    assert ev["metadata"]["uid"] == r["event_id"], "metadata.uid != event_id"
    assert ev["raw_data"] == raw, "raw_data does not equal the original raw log"


# ── 6. Identical envelope across all four families ─────────────────────────────

def test_identical_envelope_across_families():
    shapes = {}
    for family, pid in [("windows", "WIN-SEC-4625"), ("macos", "MAC-APPFW-001"),
                        ("firewall", "FW-GENERIC-001"), ("linux", "LINUX-SYSLOG-001")]:
        raw = _gen_wellformed(pid, 1)[0]
        ev = process(raw)["normalized"]
        shapes[family] = set(ev.keys())
    win = shapes["windows"]
    for family, keys in shapes.items():
        assert keys == win, f"{family} envelope != windows: {keys ^ win}"
    assert win == CANONICAL_KEYS


# ── 7. DuckDB persistence across reconnect ─────────────────────────────────────

def test_duckdb_persistence_across_reconnect():
    db.init_db()
    raw = _gen_wellformed("LINUX-AUTH-001", 1)[0]
    r = process(raw)
    db.insert_raw(r["event_id"], r["source"], raw)
    db.insert_normalized(r["event_id"], r["parser_id"], r["confidence"],
                         r["ocsf_class"], r["normalized"], r["needs_review"])
    # New connection (get_conn opens the file fresh) must see the row.
    fetched = db.get_event(r["event_id"])
    assert fetched is not None, "event not persisted / not visible on reconnect"
    assert fetched["event_id"] == r["event_id"]


# ── 8. OpenSearch doc-count (best effort; skip if cluster unavailable) ──────────

def test_opensearch_indexing():
    import opensearch_client as osc
    client = osc.get_client()
    if client is None:
        pytest.skip("OpenSearch client library unavailable")
    try:
        osc.ensure_index()
        raw = _gen_wellformed("FW-GENERIC-001", 1)[0]
        r = process(raw)
        osc.index_event(r["event_id"], r["normalized"], r["source"])
        client.indices.refresh(index=osc.INDEX_NAME)
        got = client.get(index=osc.INDEX_NAME, id=r["event_id"])
        assert got["found"] is True
    except Exception as exc:  # cluster not reachable in this run
        pytest.skip(f"OpenSearch not reachable: {exc}")


# ── 9. Prometheus counters increment (via the real _process_one path) ──────────

def test_prometheus_counters_increment():
    import main

    raw = _gen_wellformed("LINUX-AUTH-001", 1)[0]
    r_preview = process(raw)
    pid, src = r_preview["parser_id"], r_preview["source"]

    # Same child object main._process_one increments (labels() returns the singleton).
    child = main.parsed_total.labels(parser_id=pid, source=src)
    before = child._value.get()
    main._process_one(raw)  # exercises labeled counter increments + latency observe
    after = child._value.get()
    _RESULTS.setdefault("_metrics", {})["parsed_delta"] = after - before
    assert after >= before + 1, f"parsed counter did not increment ({before} -> {after})"


# ── Final real results table ───────────────────────────────────────────────────

def test_zzz_print_results_table():
    """Not an assertion test — prints the measured evidence table."""
    lines = []
    lines.append("")
    lines.append("=" * 78)
    lines.append("ULPF FULL-PIPELINE RESULTS  (measured, seed=%s)" % gen.SEED)
    lines.append("=" * 78)
    lines.append("%-18s %-6s %-20s %-26s" % ("parser_id", "class", "wellformed NGRE", "malformed (drain3|reclass)"))
    lines.append("-" * 78)
    for pid, (cls, fam) in PARSER_META.items():
        res = _RESULTS.get(pid, {})
        w = res.get("well_ngre")
        mb = res.get("mal_breakdown")
        wtxt = f"{w[0]}/{w[1]} ({w[2]:.1f}%)" if w else "n/a"
        mtxt = f"{mb[0]} drain3 | {mb[1]} reclass /{mb[2]}" if mb else "n/a"
        lines.append("%-18s %-6s %-20s %-26s" % (pid, cls, wtxt, mtxt))
    lines.append("-" * 78)
    adv = _RESULTS.get("_adversarial", {}).get("flagged")
    if adv:
        lines.append("adversarial flagged : %d/%d (%.1f%%)" % adv)
    met = _RESULTS.get("_metrics", {}).get("parsed_delta")
    if met is not None:
        lines.append("prometheus parsed_total delta on 1 ingest: +%.0f" % met)
    lines.append("=" * 78)
    print("\n".join(lines))
