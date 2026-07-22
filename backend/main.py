"""
FastAPI application: ingest, parsers, events, DLQ, stats, metrics, health.
"""
from __future__ import annotations
import csv
import io
import json
import os
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from prometheus_fastapi_instrumentator import Instrumentator
from prometheus_client import Counter, Histogram

import db
import opensearch_client as os_client
from pipeline import process
from fingerprint import fingerprint

# Big-data streaming/storage clients (all gracefully degrade if unavailable).
try:
    from storage import minio_client, clickhouse_client, kafka_client
except Exception:  # pragma: no cover - defensive
    minio_client = clickhouse_client = kafka_client = None

PARSERS_DIR = Path(os.getenv("PARSERS_DIR", "/app/parsers/registry"))
PROMETHEUS_HOST = os.getenv("PROMETHEUS_HOST", "prometheus")
PROMETHEUS_PORT = int(os.getenv("PROMETHEUS_PORT", "9090"))

app = FastAPI(title="ULPF — Universal Log Pre-processing Framework", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

Instrumentator().instrument(app).expose(app)

# Custom metrics — wrapped to survive re-imports in test environments.
# Counters are LABELED by (parser_id, source); unlabeled PromQL sums
# (e.g. `sum(ulpf_parsed_total)`) still work, so existing panels keep working
# while Phase-2 per-source panels can slice by label.
_LABELS = ("parser_id", "source")


def _labeled_counter(name: str, doc: str):
    try:
        from prometheus_client import REGISTRY
        existing = REGISTRY._names_to_collectors.get(name)
        if existing is not None:
            return existing
        return Counter(name, doc, _LABELS)
    except Exception:
        return Counter(name, doc, _LABELS)


def _histogram(name: str, doc: str):
    try:
        from prometheus_client import REGISTRY
        existing = REGISTRY._names_to_collectors.get(name)
        if existing is not None:
            return existing
        return Histogram(name, doc, _LABELS)
    except Exception:
        return Histogram(name, doc, _LABELS)


parsed_total          = _labeled_counter("ulpf_parsed_total",          "Total log events processed")
ngre_hits_total       = _labeled_counter("ulpf_ngre_hits_total",       "Events processed via NGRE")
drain3_fallback_total = _labeled_counter("ulpf_drain3_fallback_total", "Events falling back to Drain3")
dlq_total             = _labeled_counter("ulpf_dlq_total",             "Events routed to DLQ")
parse_errors_total    = _labeled_counter("ulpf_parse_errors_total",    "Parse errors encountered")
parse_latency         = _histogram("ulpf_parse_latency_seconds",       "Per-event parse+persist latency (s)")

# In-memory batch-ingest job registry (real counters, not simulated progress).
JOBS: dict[str, dict] = {}
_JOBS_LOCK = threading.Lock()


@app.on_event("startup")
async def startup():
    db.init_db()
    try:
        os_client.ensure_index()
    except Exception:
        pass  # OpenSearch may not be ready yet; DuckDB is authoritative
    # Best-effort init of the big-data tier — never blocks startup.
    if clickhouse_client is not None:
        try:
            clickhouse_client.ensure_schema()
        except Exception:
            pass


# ── Ingest ────────────────────────────────────────────────────────────────────

@app.post("/api/ingest")
async def ingest(
    raw_log: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
    source_hint: Optional[str] = Form(None),
):
    if file:
        raw_text = (await file.read()).decode("utf-8", errors="replace")
        # Reassemble multi-line / wrapped events into logical records first.
        records = _group_records(raw_text)
        if len(records) > 1:
            # Bulk ingest: process each logical record individually
            results = []
            for rec in records:
                r = _process_one(rec, source_hint)
                results.append(r)
            return {"bulk": True, "count": len(results), "results": results}
        raw_text = (records[0] if records else raw_text).strip()
    elif raw_log:
        raw_text = raw_log.strip()
    else:
        raise HTTPException(status_code=400, detail="Provide raw_log or file")

    return _process_one(raw_text, source_hint)


def _process_one(raw_text: str, source_hint: str | None = None) -> dict:
    _t0 = time.perf_counter()
    try:
        result = process(raw_text)
        parser_id = result.get("parser_id", "UNKNOWN")
        source = result.get("source", source_hint or "unknown")
        event_id = result["event_id"]
        normalized = result["normalized"]
        parsed_total.labels(parser_id=parser_id, source=source).inc()
        path = result.get("path", "drain3")
        if path == "ngre":
            ngre_hits_total.labels(parser_id=parser_id, source=source).inc()
        elif path == "dlq":
            dlq_total.labels(parser_id=parser_id, source=source).inc()
        else:
            drain3_fallback_total.labels(parser_id=parser_id, source=source).inc()

        # ── MinIO raw archive (immutable evidence) → raw_object_id + sha256 ──
        # Threaded into OCSF metadata for full raw↔normalized↔archive traceability.
        archive = None
        if minio_client is not None:
            try:
                archive = minio_client.archive_raw(raw_text, source)
            except Exception:
                archive = None
        raw_object_id = (archive or {}).get("raw_object_id", "")
        raw_sha256 = (archive or {}).get("raw_sha256", "")
        if raw_sha256:
            normalized.setdefault("metadata", {})["raw_object_id"] = raw_object_id
            normalized["metadata"]["raw_sha256"] = raw_sha256

        db.insert_raw(event_id, result["source"], raw_text)
        db.insert_normalized(
            event_id,
            result["parser_id"],
            result["confidence"],
            result["ocsf_class"],
            normalized,
            result["needs_review"],
        )

        # DLQ: also store in dedicated DLQ table for review
        if result.get("dlq"):
            db.insert_dlq(
                event_id,
                result["source"],
                raw_text,
                result.get("dlq_error", ""),
                [c["parser_id"] for c in result.get("candidates", [])],
            )

        # ── OpenSearch full-text index (best effort) ──
        try:
            os_client.index_event(event_id, normalized, result["source"])
        except Exception:
            pass

        # ── ClickHouse analytics store (best effort, replay-linked) ──
        if clickhouse_client is not None:
            try:
                clickhouse_client.insert_event(
                    event_id, normalized, result["source"],
                    raw_object_id=raw_object_id, raw_sha256=raw_sha256,
                )
            except Exception:
                pass

        # ── Kafka OUTPUT streams (best effort) ──
        # NOTE: we publish the parsed result to logs.normalized / logs.dlq as an
        # output bus for downstream consumers. We deliberately DO NOT publish to
        # logs.raw here — that topic is the INPUT for the kafka-consumer worker;
        # republishing it would make the consumer re-process events the backend
        # already handled (double-count). External collectors feed logs.raw.
        if kafka_client is not None:
            try:
                if result.get("dlq"):
                    kafka_client.publish_dlq(event_id, raw_text,
                                             result.get("dlq_error", ""))
                else:
                    kafka_client.publish_normalized(event_id, normalized)
            except Exception:
                pass

        parse_latency.labels(parser_id=parser_id, source=source).observe(
            time.perf_counter() - _t0
        )
        return result
    except Exception as exc:
        parse_errors_total.labels(parser_id="UNKNOWN", source=source_hint or "unknown").inc()
        raise HTTPException(status_code=500, detail=str(exc))


# ── Batch ingest with LIVE progress ────────────────────────────────────────────

def _extract_raw_lines(payload) -> list[str]:
    """Accept the generator's .jsonl (one JSON string per line), a JSON array of
    raw strings, or {"logs": [...]}/{"jsonl": "<text>"}. Multi-line records that
    were JSON-encoded survive intact."""
    lines: list[str] = []
    if isinstance(payload, dict):
        if isinstance(payload.get("logs"), list):
            return [str(x) for x in payload["logs"]]
        if isinstance(payload.get("jsonl"), str):
            payload = payload["jsonl"]
        else:
            raise HTTPException(status_code=400, detail="Provide 'logs' (list) or 'jsonl' (text)")
    if isinstance(payload, list):
        return [str(x) for x in payload]
    if isinstance(payload, str):
        for ln in payload.splitlines():
            ln = ln.strip()
            if not ln:
                continue
            try:
                dec = json.loads(ln)
                lines.append(dec if isinstance(dec, str) else ln)
            except json.JSONDecodeError:
                lines.append(ln)
        return lines
    raise HTTPException(status_code=400, detail="Unsupported batch payload")


import re as _re

# A line that STARTS a new logical record. Everything until the next such line
# (or a blank line) is treated as a continuation of the same event. This lets a
# multi-line / wrapped Windows export (one event across several physical lines)
# be reassembled before parsing, instead of each fragment failing individually.
_RECORD_START_RE = _re.compile(
    r"""^(?:
        \d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}      # ISO timestamp  2026-08-27 08:12:14
      | \d{2}/\d{2}/\d{2,4}\s+\d{2}:\d{2}:\d{2}     # US date time
      | (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}  # syslog
      | Log\ Name\s*:                                # evtx text block header
      | <Event[\s>]                                  # event XML
      | \#(?:Fields|Version|Software)\s*:            # W3C / firewall header
      | \d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3}       # Android logcat  08-10 09:20:19.692
      | \[\s*\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3}  # Android long "[ 08-10 ... ]"
      | [VDIWEFS]/[^(]+\(\s*\d+\s*\):                # Android brief/tag  W/dumpsys( 3907):
    )""",
    _re.IGNORECASE | _re.VERBOSE,
)

# A line that starts a compact winkv record ONLY when it is not already a
# continuation of an open record. Used to open a record when the file has no
# timestamp wrappers at all (pure "Provider=… / EventID=…" blocks).
_WINKV_START_RE = _re.compile(r"^\s*(?:Provider|EventID)\s*=", _re.IGNORECASE)

# A bare wrapper/prefix line such as "2026-08-27 08:12:14 INFO [Windows Event Log]"
# is NOT its own event — it is a header line for the record that follows. When a
# boundary line matches this it should merge forward into the next real record
# rather than stand alone.
_WRAPPER_PREFIX_RE = _re.compile(
    r"^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}\s+\w+\s+\[[^\]]+\]\s*$",
    _re.IGNORECASE,
)


def _group_records(raw_text: str) -> list[str]:
    """Group physical lines into logical multi-line records.

    A record begins at a `_RECORD_START_RE` match (or after a blank line) and
    absorbs following continuation lines. Falls back to one-record-per-line when
    no boundaries are detected (e.g. a clean single-line-per-event file), so
    existing single-line corpora behave exactly as before.
    """
    lines = raw_text.splitlines()
    records: list[str] = []
    current: list[str] = []

    def flush():
        if current:
            rec = "\n".join(current).strip()
            if rec:
                records.append(rec)

    def _has_provider(lines_buf: list[str]) -> bool:
        return any(_WINKV_START_RE.match(l) for l in lines_buf)

    saw_boundary = False
    pending_prefix = None  # a wrapper/header line waiting to merge into next record
    for line in lines:
        if not line.strip():
            flush(); current = []
            pending_prefix = None
            continue

        if _RECORD_START_RE.match(line):
            saw_boundary = True
            # A bare "timestamp LEVEL [Windows Event Log]" wrapper is a header for
            # the NEXT record: close any open record, hold the wrapper to prepend
            # to whatever record follows (never emit it standalone).
            if _WRAPPER_PREFIX_RE.match(line):
                flush(); current = []
                pending_prefix = line
                continue
            flush(); current = []
            if pending_prefix:
                current.append(pending_prefix)
                pending_prefix = None
            current.append(line)
            continue

        # A "Provider="/"EventID=" line opens a NEW record only if the current
        # record ALREADY has one (i.e. this is a different event). Otherwise it's
        # a continuation (fields of the same event wrapped onto multiple lines).
        if _WINKV_START_RE.match(line) and _has_provider(current):
            saw_boundary = True
            flush(); current = [line]
            continue

        if current:
            current.append(line)
        elif pending_prefix:
            current = [pending_prefix, line]
            pending_prefix = None
        else:
            current = [line]
    if pending_prefix and not current:
        current = [pending_prefix]
    flush()

    # If we never detected a single boundary, treat each non-empty line as its
    # own record (preserves prior behavior for simple one-line-per-event files).
    if not saw_boundary:
        return [ln.strip() for ln in lines if ln.strip()]
    return records


# Human-readable pipeline stage for the live progress bar. Purely cosmetic —
# derived from the real parse path, not a simulated timeline.
_STAGE_BY_PATH = {
    "ngre":   "NGRE parsing → OCSF mapping → DuckDB + OpenSearch",
    "drain3": "Drain3 fallback → OCSF mapping → DuckDB + OpenSearch",
    "dlq":    "DLQ (unparsed) → DuckDB",
}

# Caps keep the job registry bounded; display-only, never affects the pipeline.
_COLLECT_CAP = 500   # per-line detail rows returned for manual uploads
_BATCH_CAP   = 200   # summary rows returned for generated-batch runs


def _run_job(job_id: str, raw_lines: list[str], source_hint: str | None,
             collect: bool = False):
    """Single job runner for BOTH generated batches and manual uploads.

    `_process_one` is invoked identically in every case — there is no separate
    code path for uploaded vs generated logs. `collect` only controls how much
    per-line detail we surface back to the UI (full OCSF for uploads so the
    side-by-side view can render; slim summary rows for large generated batches).
    """
    counts = {"ngre": 0, "drain3": 0, "dlq": 0, "error": 0}
    cap = _COLLECT_CAP if collect else _BATCH_CAP
    for i, raw in enumerate(raw_lines, start=1):
        row = None
        try:
            r = _process_one(raw, source_hint)
            path = r.get("path", "drain3")
            counts[path] = counts.get(path, 0) + 1
            stage = _STAGE_BY_PATH.get(path, "parsing")
            if len(JOBS[job_id].get("results", [])) < cap:
                row = {
                    "line_no": i,
                    "raw": raw,
                    "parser_id": r.get("parser_id"),
                    "confidence": r.get("confidence"),
                    "path": path,
                    "event_id": r.get("event_id"),
                    "ocsf_class": r.get("ocsf_class"),
                    "message": (r.get("normalized") or {}).get("message"),
                    "needs_review": r.get("needs_review"),
                    # Full OCSF envelope only when the UI needs to render it.
                    "normalized": r.get("normalized") if collect else None,
                }
        except HTTPException as exc:
            counts["error"] += 1
            stage = "error"
            import logging; logging.getLogger("ulpf").error(
                "record %d failed: %s | raw=%r", i, exc.detail, raw[:200])
        except Exception as exc:
            counts["error"] += 1
            stage = "error"
            import logging, traceback; logging.getLogger("ulpf").error(
                "record %d crashed: %s\n%s", i, exc, traceback.format_exc())
        with _JOBS_LOCK:
            job = JOBS[job_id]
            job["processed"] = i
            job["percent"] = round(100.0 * i / job["total"], 1) if job["total"] else 100.0
            job["current_stage"] = stage
            job["counts"] = dict(counts)
            if row is not None:
                job.setdefault("results", []).append(row)
    with _JOBS_LOCK:
        JOBS[job_id]["current_stage"] = "done"
        JOBS[job_id]["status"] = "completed"


@app.post("/api/ingest/batch")
async def ingest_batch(payload: dict):
    """Kick off a background batch ingest and return a job_id immediately.

    Body (JSON, one of):
      {"logs": ["raw line", ...]}          — explicit list of raw records
      {"jsonl": "<text>"}                  — generator .jsonl (one JSON string/line)
      {"logs": [...], "source_hint": "linux"}
    """
    source_hint = payload.get("source_hint") if isinstance(payload, dict) else None
    raw_lines = _extract_raw_lines(payload)
    if not raw_lines:
        raise HTTPException(status_code=400, detail="No log lines found in payload")

    job_id = uuid.uuid4().hex
    with _JOBS_LOCK:
        JOBS[job_id] = {
            "job_id": job_id,
            "total": len(raw_lines),
            "processed": 0,
            "percent": 0.0,
            "current_stage": "queued",
            "status": "running",
            "counts": {"ngre": 0, "drain3": 0, "dlq": 0, "error": 0},
            "results": [],
        }
    # Real thread so /status polling reflects genuine advancing counters.
    t = threading.Thread(target=_run_job, args=(job_id, raw_lines, source_hint),
                         kwargs={"collect": False}, daemon=True)
    t.start()
    return {"job_id": job_id, "total": len(raw_lines)}


@app.get("/api/ingest/status/{job_id}")
def ingest_status(job_id: str):
    with _JOBS_LOCK:
        job = JOBS.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="Unknown job_id")
        return dict(job)


# ── Manual upload (file OR pasted text → identical pipeline) ────────────────────

@app.post("/api/upload")
async def upload(request: Request):
    """Bring-your-own-log ingest. Accepts a multipart file OR a raw text paste,
    splits into logical records, and runs each through the SAME pipeline as
    generated batches (`_run_job` → `_process_one`).

    We parse the multipart body MANUALLY with a large ``max_part_size`` because
    Starlette's default form parser caps a single part at 1 MB and otherwise
    raises "There was an error parsing the body" on larger log files.
    """
    raw_text: str | None = None
    content_type = request.headers.get("content-type", "")

    if content_type.startswith("multipart/form-data"):
        # 200 MB per-part cap — well above realistic single-file log uploads.
        form = await request.form(max_part_size=200 * 1024 * 1024)
        upload_file = form.get("file")
        text_field = form.get("text")
        if upload_file is not None and hasattr(upload_file, "read"):
            raw_bytes = await upload_file.read()
            raw_text = raw_bytes.decode("utf-8", errors="replace")
        elif isinstance(text_field, str):
            raw_text = text_field
    else:
        # Fallback: raw body as text/plain (e.g. large paste posted directly).
        body = await request.body()
        if body:
            raw_text = body.decode("utf-8", errors="replace")

    if raw_text is None:
        raise HTTPException(status_code=400, detail="Provide a file or text")

    # Reassemble multi-line / wrapped events into logical records before parsing.
    raw_lines = _group_records(raw_text)
    if not raw_lines:
        raise HTTPException(status_code=400, detail="No non-empty log lines found")

    job_id = uuid.uuid4().hex
    with _JOBS_LOCK:
        JOBS[job_id] = {
            "job_id": job_id,
            "total": len(raw_lines),
            "processed": 0,
            "percent": 0.0,
            "current_stage": "queued",
            "status": "running",
            "counts": {"ngre": 0, "drain3": 0, "dlq": 0, "error": 0},
            "results": [],
            "kind": "upload",
        }
    t = threading.Thread(target=_run_job, args=(job_id, raw_lines, None),
                         kwargs={"collect": True}, daemon=True)
    t.start()
    return {"job_id": job_id, "total": len(raw_lines)}


# ── Test-data provider for the /fetch page ─────────────────────────────────────

_TESTDATA_FAMILIES = {
    "windows":  ["WIN-SEC-4625"],
    "macos":    ["MAC-APPFW-001"],
    "firewall": ["FW-GENERIC-001", "FW-W3C-001"],
    "linux":    ["LINUX-SYSLOG-001", "LINUX-AUTH-001"],
}
_TESTDATA_ROOT = Path(os.getenv("TESTDATA_DIR", "/app/testdata/generated"))


@app.get("/api/testdata/{family}")
def get_testdata(family: str, n: int = 40):
    """Return pre-generated well-formed raw logs for a family so the /fetch page
    can POST them to the EXISTING /api/ingest/batch endpoint. Each .jsonl line is
    a JSON-encoded raw string; we decode back to the raw log text."""
    family = family.lower()
    parser_ids = _TESTDATA_FAMILIES.get(family)
    if not parser_ids:
        raise HTTPException(status_code=404, detail=f"Unknown family '{family}'")

    per_source = max(1, n // len(parser_ids))
    logs: list[str] = []
    for pid in parser_ids:
        path = _TESTDATA_ROOT / pid / "wellformed.jsonl"
        if not path.exists():
            continue
        taken = 0
        for line in path.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                dec = json.loads(line)
                logs.append(dec if isinstance(dec, str) else line)
            except json.JSONDecodeError:
                logs.append(line)
            taken += 1
            if taken >= per_source:
                break
    if not logs:
        raise HTTPException(status_code=404, detail=f"No test data found for '{family}'")
    return {"family": family, "count": len(logs), "logs": logs}


# ── Parsers ───────────────────────────────────────────────────────────────────

@app.get("/api/parsers")
def list_parsers():
    parsers = []
    for f in PARSERS_DIR.glob("*.json"):
        try:
            parsers.append(json.loads(f.read_text()))
        except Exception:
            pass
    return parsers


@app.post("/api/parsers")
def create_parser(parser: dict):
    if "parser_id" not in parser:
        parser["parser_id"] = f"CUSTOM-{uuid.uuid4().hex[:8].upper()}"
    path = PARSERS_DIR / f"{parser['parser_id']}.json"
    path.write_text(json.dumps(parser, indent=2))
    return parser


@app.get("/api/parsers/{parser_id}")
def get_parser(parser_id: str):
    path = PARSERS_DIR / f"{parser_id}.json"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Parser not found")
    return json.loads(path.read_text())


@app.put("/api/parsers/{parser_id}")
def update_parser(parser_id: str, parser: dict):
    path = PARSERS_DIR / f"{parser_id}.json"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Parser not found")
    parser["parser_id"] = parser_id
    path.write_text(json.dumps(parser, indent=2))
    return parser


@app.post("/api/parsers/{parser_id}/test")
def test_parser(parser_id: str, body: dict):
    import re as _re
    sample = body.get("sample_log", "")
    path = PARSERS_DIR / f"{parser_id}.json"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Parser not found")
    parser = json.loads(path.read_text())
    pattern = parser.get("ngre_pattern", "")
    m = _re.search(pattern, sample, _re.MULTILINE | _re.DOTALL)
    if m:
        return {"matched": True, "fields": m.groupdict(), "parser_id": parser_id}
    return {"matched": False, "fields": {}, "parser_id": parser_id}


# ── Events ────────────────────────────────────────────────────────────────────

@app.get("/api/events")
def list_events(
    limit: int = 50,
    offset: int = 0,
    source: Optional[str] = None,
    ocsf_class: Optional[int] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    q: Optional[str] = None,
):
    if q:
        return os_client.search_events(q, size=limit)
    return db.list_events(limit, offset, source, ocsf_class, date_from, date_to)


@app.get("/api/events/{event_id}")
def get_event(event_id: str):
    event = db.get_event(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event


# ── DLQ ───────────────────────────────────────────────────────────────────────

@app.get("/api/dlq")
def list_dlq(limit: int = 50, offset: int = 0):
    return {
        "total": db.get_dlq_count(),
        "items": db.list_dlq(limit, offset),
    }


# ── Compare ───────────────────────────────────────────────────────────────────

@app.get("/api/compare")
def compare_events(event_a: Optional[str] = None, event_b: Optional[str] = None):
    if not event_a or not event_b:
        raise HTTPException(status_code=400, detail="Provide event_a and event_b query params")
    a = db.get_event(event_a)
    b = db.get_event(event_b)
    if not a or not b:
        raise HTTPException(status_code=404, detail="One or both events not found")
    return {"event_a": a, "event_b": b}


# ── Stats ─────────────────────────────────────────────────────────────────────

@app.get("/api/stats")
def get_stats():
    return db.get_stats()


# ── Coverage (per-parser NGRE / Drain3 / failure) ──────────────────────────────

@app.get("/api/coverage")
def coverage():
    """Per-parser and per-family coverage derived from persisted events.

    NGRE   = real parser matched; Drain3 = structural fallback; failure = DLQ.
    Percentages are of the grand total so the three sum to ~100%."""
    stats = db.get_stats()
    cov = stats.get("coverage", {})
    total = cov.get("total", 0) or 0

    def pct(n: int) -> float:
        return round(100.0 * n / total, 1) if total else 0.0

    # Per-parser breakdown (every parser is NGRE except the two fallbacks).
    per_parser = []
    for row in stats.get("by_parser", []):
        pid, cnt = row["parser_id"], row["count"]
        if pid == "DRAIN3-FALLBACK":
            path = "drain3"
        elif pid == "DLQ":
            path = "dlq"
        else:
            path = "ngre"
        per_parser.append({
            "parser_id": pid,
            "count": cnt,
            "path": path,
            "pct_of_total": pct(cnt),
        })

    families = {
        "windows":  {"ngre": cov.get("ngre_windows", 0),  "pct_ngre": cov.get("pct_ngre_windows", 0.0)},
        "macos":    {"ngre": cov.get("ngre_macos", 0),    "pct_ngre": cov.get("pct_ngre_macos", 0.0)},
        "firewall": {"ngre": cov.get("ngre_firewall", 0), "pct_ngre": cov.get("pct_ngre_firewall", 0.0)},
        "linux":    {"ngre": cov.get("ngre_linux", 0),    "pct_ngre": cov.get("pct_ngre_linux", 0.0)},
        "other":    {"ngre": cov.get("ngre_other", 0),    "pct_ngre": pct(cov.get("ngre_other", 0))},
    }

    return {
        "total": total,
        "ngre": cov.get("ngre_total", 0),
        "drain3": cov.get("drain3", 0),
        "failure": cov.get("dlq", 0),
        "pct_ngre": cov.get("pct_ngre", 0.0),
        "pct_drain3": cov.get("pct_drain3", 0.0),
        "pct_failure": cov.get("pct_dlq", 0.0),
        "by_family": families,
        "by_parser": per_parser,
    }


# ── Export (json / csv / parquet) ──────────────────────────────────────────────

@app.get("/api/export/{fmt}")
def export_events(fmt: str, limit: int = 100000):
    fmt = fmt.lower()
    if fmt not in ("json", "csv", "parquet"):
        raise HTTPException(status_code=400, detail="fmt must be json, csv, or parquet")

    if fmt == "parquet":
        # DuckDB writes real Parquet directly from the source-of-truth table.
        tmp = tempfile.NamedTemporaryFile(suffix=".parquet", delete=False)
        tmp.close()
        conn = db.get_conn()
        try:
            conn.execute(
                f"COPY (SELECT event_id, parser_id, confidence, ocsf_class, "
                f"needs_review, ingested_at, normalized FROM normalized_events "
                f"LIMIT {int(limit)}) TO '{tmp.name}' (FORMAT PARQUET)"
            )
        finally:
            conn.close()
        return FileResponse(tmp.name, media_type="application/octet-stream",
                            filename="ulpf_events.parquet")

    conn = db.get_conn()
    rows = conn.execute(
        "SELECT event_id, parser_id, confidence, ocsf_class, needs_review, normalized "
        "FROM normalized_events LIMIT ?", [int(limit)]
    ).fetchall()
    conn.close()

    if fmt == "json":
        out = []
        for r in rows:
            norm = r[5]
            if isinstance(norm, str):
                try:
                    norm = json.loads(norm)
                except json.JSONDecodeError:
                    pass
            out.append({
                "event_id": r[0], "parser_id": r[1], "confidence": r[2],
                "ocsf_class": r[3], "needs_review": r[4], "normalized": norm,
            })
        return JSONResponse(out)

    # csv (flat summary columns; normalized JSON kept as one embedded column)
    def _gen():
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["event_id", "parser_id", "confidence", "ocsf_class", "needs_review", "normalized"])
        yield buf.getvalue(); buf.seek(0); buf.truncate(0)
        for r in rows:
            norm = r[5] if isinstance(r[5], str) else json.dumps(r[5])
            w.writerow([r[0], r[1], r[2], r[3], r[4], norm])
            yield buf.getvalue(); buf.seek(0); buf.truncate(0)
    return StreamingResponse(_gen(), media_type="text/csv",
                            headers={"Content-Disposition": "attachment; filename=ulpf_events.csv"})


# ── Replay (MinIO raw → re-parse through current parsers) ──────────────────────

@app.post("/api/replay/{event_id}")
def replay_event(event_id: str):
    """Re-parse an event's ORIGINAL raw bytes through the CURRENT parser set.

    This is the payoff of keeping the immutable MinIO archive: after a parser is
    improved, old events can be re-normalized without the original collector.
    Falls back to the DuckDB-stored raw_log when MinIO is unavailable."""
    raw_log = None
    existing = db.get_event(event_id)
    raw_object_id = None
    if existing:
        raw_object_id = (existing.get("normalized", {}) or {}).get("metadata", {}).get("raw_object_id")

    if minio_client is not None and raw_object_id:
        try:
            raw_log = minio_client.fetch_raw(raw_object_id)
        except Exception:
            raw_log = None
    if raw_log is None and existing:
        raw_log = existing.get("raw_log")
    if raw_log is None:
        raise HTTPException(status_code=404, detail="No raw data available to replay")

    # Re-process (produces a NEW event_id + fresh normalization).
    result = _process_one(raw_log, existing.get("source") if existing else None)
    return {
        "replayed_from": event_id,
        "raw_object_id": raw_object_id,
        "new_event_id": result["event_id"],
        "parser_id": result["parser_id"],
        "path": result["path"],
        "normalized": result["normalized"],
    }


# ── ClickHouse analytics query (read-only) ─────────────────────────────────────

@app.get("/api/analytics/summary")
def analytics_summary():
    """Cross-source analytics from ClickHouse (empty list if CH unavailable)."""
    if clickhouse_client is None or not clickhouse_client.available():
        return {"available": False, "by_class": [], "by_source": [], "top_users": []}
    db_name = clickhouse_client.CH_DATABASE
    tbl = f"{db_name}.{clickhouse_client.TABLE}"
    return {
        "available": True,
        "by_class": clickhouse_client.query(
            f"SELECT ocsf_class_name AS class, count() AS c FROM {tbl} "
            f"GROUP BY class ORDER BY c DESC LIMIT 20"),
        "by_source": clickhouse_client.query(
            f"SELECT os_family AS source, count() AS c FROM {tbl} "
            f"GROUP BY source ORDER BY c DESC LIMIT 20"),
        "top_users": clickhouse_client.query(
            f"SELECT user_name AS user, count() AS c FROM {tbl} "
            f"WHERE user_name != '' GROUP BY user ORDER BY c DESC LIMIT 20"),
    }


# ── Health ────────────────────────────────────────────────────────────────────

GRAFANA_HOST = os.getenv("GRAFANA_HOST", "grafana")
GRAFANA_PORT = int(os.getenv("GRAFANA_PORT", "3000"))


def _health_report() -> dict:
    checks = {"duckdb": "down", "opensearch": "down",
              "prometheus": "down", "grafana": "down"}

    # DuckDB: real read probe against the source-of-truth table.
    try:
        conn = db.get_conn()
        conn.execute("SELECT COUNT(*) FROM normalized_events").fetchone()
        conn.close()
        checks["duckdb"] = "up"
    except Exception as exc:
        checks["duckdb"] = f"down: {exc}"

    # OpenSearch: cluster health (surface the real green/yellow/red status).
    try:
        client = os_client.get_client()
        if client is not None:
            h = client.cluster.health()
            checks["opensearch"] = h.get("status", "up")
    except Exception as exc:
        checks["opensearch"] = f"down: {exc}"

    # Prometheus: readiness endpoint.
    try:
        import requests
        resp = requests.get(
            f"http://{PROMETHEUS_HOST}:{PROMETHEUS_PORT}/-/healthy", timeout=2
        )
        checks["prometheus"] = "up" if resp.status_code == 200 else f"http {resp.status_code}"
    except Exception as exc:
        checks["prometheus"] = f"down: {exc}"

    # Grafana: API health endpoint (reachable/unreachable).
    try:
        import requests
        resp = requests.get(
            f"http://{GRAFANA_HOST}:{GRAFANA_PORT}/api/health", timeout=2
        )
        checks["grafana"] = "up" if resp.status_code == 200 else f"http {resp.status_code}"
    except Exception as exc:
        checks["grafana"] = f"down: {exc}"

    # Big-data streaming tier (optional; report availability without failing).
    try:
        if minio_client is not None and minio_client.get_client() is not None:
            minio_client.get_client().bucket_exists(minio_client.MINIO_BUCKET)
            checks["minio"] = "up"
        else:
            checks["minio"] = "disabled"
    except Exception as exc:
        checks["minio"] = f"down: {exc}"

    try:
        if clickhouse_client is not None and clickhouse_client.get_client() is not None:
            clickhouse_client.get_client().command("SELECT 1")
            checks["clickhouse"] = "up"
        else:
            checks["clickhouse"] = "disabled"
    except Exception as exc:
        checks["clickhouse"] = f"down: {exc}"

    checks["kafka"] = "up" if (kafka_client is not None and kafka_client.available()) else "disabled"

    overall = "ok" if checks["duckdb"] == "up" else "degraded"
    return {"status": overall, **checks}


@app.get("/health")
def health():
    return _health_report()


# nginx only proxies /api/* to the backend, so the browser reaches health here.
@app.get("/api/health")
def api_health():
    return _health_report()
