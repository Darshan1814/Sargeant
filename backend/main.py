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
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from prometheus_fastapi_instrumentator import Instrumentator
from prometheus_client import Counter, Histogram

import store as db  # two-tier façade (SQLite hot + DuckDB cold); same surface as db
import opensearch_client as os_client
from pipeline import process
from ocsf_mapper import CLASS_INFO
from fingerprint import fingerprint

# Parallel processing engine (spec #12–#14). `group_records` is the SINGLE source
# of truth for multi-line grouping — imported here so the batch/upload path groups
# lines identically to the parallel workers and the Kafka consumer.
from engine.streaming import group_records, iter_records, Record
from engine.parallel import run_parallel

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
    db.start_tiering()  # age hot SQLite rows → cold DuckDB past ULPF_HOT_RETENTION
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
    """Parse + persist ONE raw record (the synchronous single-ingest path).

    Thin wrapper: capture the ingestion timestamp, parse, then persist. Kept so
    the HTTP `/api/ingest` and `/api/replay` endpoints behave exactly as before.
    Batch/upload go through the parallel engine, which calls `_persist_result`
    directly with results parsed in worker processes.
    """
    ingestion_time = datetime.now(timezone.utc).isoformat()
    try:
        result = process(raw_text)
        return _persist_result(result, raw_text, ingestion_time, source_hint)
    except HTTPException:
        raise
    except Exception as exc:
        parse_errors_total.labels(parser_id="UNKNOWN", source=source_hint or "unknown").inc()
        raise HTTPException(status_code=500, detail=str(exc))


def _sqlite_now() -> str:
    """UTC timestamp in SQLite's own default column format
    (``strftime('%Y-%m-%d %H:%M:%f','now')`` → 'YYYY-MM-DD HH:MM:SS.mmm').

    The single-record inserts rely on that DB default; the batched inserts must
    supply ``ingested_at`` explicitly, so we reproduce the exact same format here.
    Keeping the format identical means hot→cold tiering (a string comparison on
    ``ingested_at``) treats batched and single rows the same way."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


class _PersistSink:
    """Buffers the two heavy per-record stores — SQLite rows and the OpenSearch
    document — and writes them in CHUNKS: one ``executemany``+commit per table
    and one OpenSearch ``_bulk`` per chunk, instead of one transaction/HTTP call
    per record.

    This is the throughput fix for the 20K batch/upload path. The persist stage
    labelled "→ DuckDB + OpenSearch" in the live progress bar was, for every
    single record, building a fresh single-doc index request and doing two
    per-row SQLite commits — serially in the main process — which starved the
    parallel parsers and pinned the UI at a crawl. Buffering collapses ~40K
    fsync-bearing commits and 20K HTTP round-trips into ~N/``flush_every`` of
    each. Row and doc CONTENT is byte-identical to the per-record path (same
    columns, same ``json.dumps``, same flat doc builder); only batching changes,
    so the normalized schema/semantics and parser accuracy are untouched.

    Not thread-safe by design: the parallel engine invokes the persist callback
    from the MAIN process in sequence order, so there is exactly one caller.

    Accepted trade-off: DB/OpenSearch write failures now surface at flush time
    (per chunk) rather than per record, so a chunked DB error won't set
    ``result["__persist_error__"]`` on the individual record. ``flush`` is guarded
    and this is the non-happy path; the authoritative data still lives in SQLite.
    """

    def __init__(self, flush_every: int = 1000):
        self.flush_every = max(1, flush_every)
        self._raw: list = []   # (event_id, source, raw_log, ingested_at)
        self._norm: list = []  # (event_id, parser_id, confidence, ocsf_class, normalized, needs_review, ingested_at)
        self._dlq: list = []   # (event_id, source, raw_log, error_message, attempted, ingested_at)
        self._os: list = []    # (event_id, normalized, source)

    def add_raw(self, event_id, source, raw_log, ingested_at):
        self._raw.append((event_id, source, raw_log, ingested_at))

    def add_normalized(self, event_id, parser_id, confidence, ocsf_class,
                       normalized, needs_review, ingested_at):
        self._norm.append((event_id, parser_id, confidence, ocsf_class,
                           normalized, needs_review, ingested_at))

    def add_dlq(self, event_id, source, raw_log, error_message, attempted, ingested_at):
        self._dlq.append((event_id, source, raw_log, error_message, attempted, ingested_at))

    def add_os(self, event_id, normalized, source):
        self._os.append((event_id, normalized, source))

    def maybe_flush(self) -> None:
        # Flush on the normalized count — every record adds exactly one norm row,
        # so this bounds buffered rows to ~flush_every per table.
        if len(self._norm) >= self.flush_every:
            self.flush()

    def flush(self) -> None:
        """Write everything buffered so far. Safe to call on an empty sink and at
        job end to drain the final partial chunk."""
        if self._raw:
            db.insert_raw_many(self._raw)
            self._raw = []
        if self._norm:
            db.insert_normalized_many(self._norm)
            self._norm = []
        if self._dlq:
            db.insert_dlq_many(self._dlq)
            self._dlq = []
        if self._os:
            try:
                os_client.bulk_index(self._os)  # best effort; DuckDB/SQLite own truth
            except Exception:
                pass
            self._os = []


def _persist_result(result: dict, raw_text: str, ingestion_time: str,
                    source_hint: str | None = None, sink: "_PersistSink | None" = None) -> dict:
    """Persist ONE parsed result. Runs in the MAIN process only (single DB writer).

    Extracted from `_process_one` so the parallel engine can parse in worker
    processes and hand result dicts back here for IDENTICAL persistence — the
    normalized schema and every storage side effect are exactly what the
    sequential path produced (spec #14: optimize the engine, not correctness).

    When ``sink`` is provided (the batch/upload path) the heavy stores — SQLite
    rows and the OpenSearch document — are BUFFERED into the sink and flushed in
    chunks (one commit + one ``_bulk`` per chunk) instead of once per record.
    Row content is byte-identical to the ``sink is None`` single-record path;
    only the number of transactions/HTTP calls changes. Metrics, MinIO archival
    and Kafka publishing stay per-record regardless (MinIO must run inline to
    thread raw_sha256 into metadata *before* the event is stored).
    """
    _t0 = time.perf_counter()
    parser_id = result.get("parser_id", "UNKNOWN")
    source = result.get("source", source_hint or "unknown")
    event_id = result["event_id"]
    normalized = result["normalized"]

    # ── Three distinct timestamps (spec #6) ─────────────────────────────────
    # event_time     → normalized["time"]            (when the event happened)
    # processed_time → normalized.metadata.processed_time (set by the mapper)
    # ingestion_time → when ULPF RECEIVED this raw record (captured at read time)
    # These must never collapse into one another.
    meta = normalized.setdefault("metadata", {})
    meta["ingestion_time"] = ingestion_time

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

    if sink is None:
        # Single-record path (synchronous /api/ingest): UNCHANGED — one commit
        # per insert and a single-doc OpenSearch index, exactly as before.
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
    else:
        # Batch/upload path: BUFFER these stores into the sink; it writes them in
        # chunks (one executemany+commit per table, one OpenSearch _bulk per
        # chunk). Same columns, same JSON, same flat doc as the single-record
        # branch — only the transaction/HTTP granularity changes. ``ingested_at``
        # is stamped here in SQLite's own default format so every buffered row
        # records its real persist moment and the hot→cold tiering predicate
        # (a string compare on ingested_at) keeps working unchanged.
        ingested_at = _sqlite_now()
        sink.add_raw(event_id, result["source"], raw_text, ingested_at)
        sink.add_normalized(
            event_id,
            result["parser_id"],
            result["confidence"],
            result["ocsf_class"],
            normalized,
            result["needs_review"],
            ingested_at,
        )
        if result.get("dlq"):
            sink.add_dlq(
                event_id,
                result["source"],
                raw_text,
                result.get("dlq_error", ""),
                [c["parser_id"] for c in result.get("candidates", [])],
                ingested_at,
            )
        sink.add_os(event_id, normalized, result["source"])
        sink.maybe_flush()

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


# Multi-line record grouping now lives in engine.streaming — the single source of
# truth so the batch path, the parallel engine and the Kafka consumer all group
# physical lines into logical records IDENTICALLY. This is a prerequisite for the
# "single-thread output == parallel output" equivalence guarantee (spec #14).
# The alias preserves every existing call site (`_group_records(...)`).
_group_records = group_records


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

# Throughput actually observed on the most recent completed job. Stays None until
# a batch/upload has run, so the UI can honestly show "not yet measured" instead
# of a fabricated events/sec figure.
_LAST_JOB_PERF: dict | None = None


def _run_job(job_id: str, raw_lines: list[str], source_hint: str | None,
             collect: bool = False):
    """Single job runner for BOTH generated batches and manual uploads.

    Drives the parallel engine: records are parsed across a bounded worker pool
    but PERSISTED here in the main process, strictly in sequence order. Parsing
    is byte-for-byte what the sequential path produced — the engine only changes
    *where* `process()` runs, never *what* it computes (spec #14). `collect` only
    controls how much per-line detail we surface back to the UI.

    All ingested records in one job share a single `ingestion_time` — the moment
    ULPF received this batch — kept distinct from per-event time / processed_time.
    """
    ingestion_time = datetime.now(timezone.utc).isoformat()
    counts = {"ngre": 0, "drain3": 0, "dlq": 0, "error": 0}
    cap = _COLLECT_CAP if collect else _BATCH_CAP
    # Wall-clock start, so the reported throughput is MEASURED work rather than a
    # nominal figure. Consumed by the job status payload and /api/overview.
    _job_t0 = time.perf_counter()
    with _JOBS_LOCK:
        JOBS[job_id]["started_at"] = ingestion_time

    # Chunked persistence for the whole job: SQLite rows and OpenSearch docs are
    # buffered and flushed per chunk instead of once per record (the 20K-batch
    # bottleneck). Content persisted is identical to the single-record path.
    sink = _PersistSink(int(os.getenv("ULPF_PERSIST_FLUSH", "1000")))

    def _persist(result: dict, rec: Record) -> None:
        # Runs in the main process, in seq order. Must never raise out of the
        # engine, or one bad DB write would abort the whole job.
        try:
            _persist_result(result, rec.raw, ingestion_time, source_hint, sink=sink)
        except Exception as exc:  # pragma: no cover - defensive persistence guard
            import logging, traceback
            logging.getLogger("ulpf").error(
                "persist failed seq=%d: %s\n%s", rec.seq_id, exc,
                traceback.format_exc())
            result["__persist_error__"] = str(exc)

    def _progress(done: int, result: dict, rec: Record) -> None:
        if result.get("__persist_error__"):
            counts["error"] += 1
            stage = "error"
        else:
            path = result.get("path", "drain3")
            counts[path] = counts.get(path, 0) + 1
            stage = _STAGE_BY_PATH.get(path, "parsing")
        with _JOBS_LOCK:
            job = JOBS[job_id]
            if (not result.get("__persist_error__")
                    and len(job.get("results", [])) < cap):
                norm = result.get("normalized") or {}
                job.setdefault("results", []).append({
                    "line_no": rec.seq_id,
                    "raw": rec.raw,
                    "parser_id": result.get("parser_id"),
                    "confidence": result.get("confidence"),
                    "path": result.get("path", "drain3"),
                    "event_id": result.get("event_id"),
                    "ocsf_class": result.get("ocsf_class"),
                    "message": norm.get("message"),
                    "needs_review": result.get("needs_review"),
                    # Full OCSF envelope only when the UI needs to render it.
                    "normalized": result.get("normalized") if collect else None,
                })
            job["processed"] = done
            job["percent"] = round(100.0 * done / job["total"], 1) if job["total"] else 100.0
            job["current_stage"] = stage
            job["counts"] = dict(counts)

    try:
        records = iter_records(raw_lines)
        run_parallel(records, persist_fn=_persist, progress_fn=_progress,
                     n_records=len(raw_lines))
    except Exception as exc:  # pragma: no cover - never leave a job hung
        import logging, traceback
        logging.getLogger("ulpf").error(
            "job %s crashed: %s\n%s", job_id, exc, traceback.format_exc())
        with _JOBS_LOCK:
            JOBS[job_id]["current_stage"] = "error"
            JOBS[job_id]["status"] = "error"
        return
    finally:
        # Drain the final partial chunk (and any full chunks not yet flushed).
        # In the finally so a mid-job crash still persists what was parsed.
        try:
            sink.flush()
        except Exception as exc:  # pragma: no cover - best-effort final flush
            import logging, traceback
            logging.getLogger("ulpf").error(
                "final sink flush failed for job %s: %s\n%s",
                job_id, exc, traceback.format_exc())

    elapsed = max(time.perf_counter() - _job_t0, 1e-9)
    with _JOBS_LOCK:
        job = JOBS[job_id]
        job["current_stage"] = "done"
        job["status"] = "completed"
        job["elapsed_seconds"] = round(elapsed, 3)
        job["throughput_eps"] = round(job.get("processed", 0) / elapsed, 1)
        job["finished_at"] = datetime.now(timezone.utc).isoformat()
        # Remember the most recent measurement so the overview can report a real
        # observed rate instead of inventing one. None until a job has run.
        global _LAST_JOB_PERF
        _LAST_JOB_PERF = {
            "events": job.get("processed", 0),
            "elapsed_seconds": round(elapsed, 3),
            "throughput_eps": job["throughput_eps"],
            "measured_at": job["finished_at"],
        }


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


# ── Evaluator-facing overview ─────────────────────────────────────────────────
# One request that answers the seven questions an evaluator asks in the first ten
# seconds: how many events arrived, how many were parsed, how many need review,
# what sources were seen, what event categories were identified, how many reached
# the common schema, and whether processing is healthy.
#
# It speaks in OUTCOMES and SOURCE FAMILIES. Parser ids, fallback engine names and
# internal path tokens are deliberately absent — those stay on the per-event
# technical details payload, which is where a developer needs them.

# os_family (as recorded in the normalized envelope) → operator-facing label.
_SOURCE_LABEL = {
    "windows": "Windows",
    "linux": "Linux",
    "darwin": "macOS",
    "macos": "macOS",
    "mac": "macOS",
    "android": "Android",
}

# The five user-facing statuses. Mutually exclusive and derived only from
# recorded outcomes — never from a guess about intent.
_STATUS_SUCCESS = ("SUCCESS", "Successfully parsed and mapped")
_STATUS_PARTIAL = ("PARTIAL", "Parsed, but some fields could not be mapped")
_STATUS_REVIEW = ("REVIEW", "Processed with low mapping confidence")
_STATUS_UNRESOLVED = ("UNRESOLVED", "Source or event type could not be determined")
_STATUS_ERROR = ("ERROR", "Processing failed")


def _user_facing_status(parse_status: str | None, mapping_status: str | None,
                        field_coverage: float | None = None) -> dict:
    """Collapse the internal parse/mapping state into one operator-facing status.

    Kept in ONE place so the overview table, the per-event card and the review
    queue can never disagree about what a given event's status is.
    """
    ps = (parse_status or "").lower()
    ms = (mapping_status or "").lower()
    if ps == "failed":
        code, label = _STATUS_ERROR
    elif ps == "fallback":
        code, label = _STATUS_UNRESOLVED
    elif ms == "mapped":
        # Mapped confidently. If some extracted fields still had no canonical
        # home, that is PARTIAL rather than a clean success — an honest
        # distinction the previous UI collapsed into one label.
        if field_coverage is not None and field_coverage < 1.0:
            code, label = _STATUS_PARTIAL
        else:
            code, label = _STATUS_SUCCESS
    else:
        code, label = _STATUS_REVIEW
    return {"code": code, "label": label}


@app.get("/api/overview")
def overview():
    """Operational summary for the Overview page. Every figure is derived from
    persisted events — no hardcoded counts or percentages."""
    stats = db.get_stats()
    ov = db.get_overview()
    total = int(ov.get("total", 0) or 0)

    def pct(n: int) -> float:
        return round(100.0 * n / total, 1) if total else 0.0

    def as_map(group: str) -> dict:
        return {r["key"]: r["count"] for r in ov.get(group, [])}

    parse = as_map("by_parse_status")
    mapping = as_map("by_mapping_status")
    mr = as_map("by_mapping_review")

    parsed_ok = int(parse.get("parsed", 0))
    partial = int(parse.get("partially_parsed", 0))
    fallback = int(parse.get("fallback", 0))
    failed = int(parse.get("failed", 0))
    unresolved = fallback + failed
    mapped = int(mapping.get("mapped", 0))
    unmapped = int(mapping.get("unmapped", 0))
    needs_review = int(stats.get("needs_review", 0) or 0)

    # Mutually exclusive mapping buckets (sum to total).
    mapped_clean = int(mr.get("mapped|0", 0))
    mapped_flagged = int(mr.get("mapped|1", 0))

    # ── Source families ──
    src_acc: dict = {}
    for row in ov.get("by_os_family", []):
        fam = row.get("key")
        key = str(fam or "").strip().lower()
        if not key or key == "unknown":
            label = "Unidentified"
        else:
            label = _SOURCE_LABEL.get(key, str(fam))
        src_acc[label] = src_acc.get(label, 0) + int(row.get("count", 0))
    sources = [
        {"label": k, "count": v, "pct": pct(v),
         "identified": k != "Unidentified"}
        for k, v in sorted(src_acc.items(), key=lambda kv: kv[1], reverse=True)
    ]

    # ── Event types: human names first, numeric class as secondary detail ──
    types_acc: dict = {}
    for row in ov.get("by_class", []):
        raw_uid = row.get("key")
        try:
            uid = int(raw_uid)
        except (TypeError, ValueError):
            uid = None
        info = CLASS_INFO.get(uid) if uid is not None else None
        name = info[0] if info else "Unclassified"
        entry = types_acc.setdefault(name, {"name": name, "class_uid": uid, "count": 0})
        entry["count"] += int(row.get("count", 0))
    event_types = sorted(types_acc.values(), key=lambda r: r["count"], reverse=True)
    for e in event_types:
        e["pct"] = pct(e["count"])

    # ── Activities (what actually happened), human labels only ──
    activities = [
        {"name": r["key"] or "Unknown", "count": r["count"], "pct": pct(r["count"])}
        for r in ov.get("by_activity", []) if r.get("count")
    ][:12]

    severities = [
        {"name": r["key"] or "Unknown", "count": r["count"], "pct": pct(r["count"])}
        for r in ov.get("by_severity", [])
    ]

    # ── Pipeline funnel. Each stage carries the definition used to compute it so
    # the UI can explain the number instead of asserting it. ──
    identified_source = total - src_acc.get("Unidentified", 0)
    pipeline = [
        {"stage": "Received", "count": total, "pct": pct(total),
         "definition": "Raw records accepted for processing"},
        {"stage": "Format Detected", "count": total - failed, "pct": pct(total - failed),
         "definition": "A log format was determined for the record"},
        {"stage": "Source Identified", "count": identified_source, "pct": pct(identified_source),
         "definition": "The originating system family was determined"},
        {"stage": "Parsed", "count": parsed_ok + partial, "pct": pct(parsed_ok + partial),
         "definition": "Fields were extracted by a matched parser"},
        {"stage": "Normalized", "count": total, "pct": pct(total),
         "definition": "A canonical event was produced. Every record reaches this "
                       "stage by design — nothing is discarded"},
        {"stage": "OCSF Mapped", "count": mapped, "pct": pct(mapped),
         "definition": "Event semantics were confidently mapped to an OCSF class"},
        {"stage": "Validated", "count": mapped_clean, "pct": pct(mapped_clean),
         "definition": "Mapped and passing schema validation without review flags"},
        {"stage": "Ready", "count": mapped_clean, "pct": pct(mapped_clean),
         "definition": "Searchable and analytics-ready"},
    ]

    # ── Recent activity ──
    recent = []
    for r in db.list_recent(12):
        st = _user_facing_status(r.get("parse_status"), r.get("mapping_status"))
        uid = r.get("class_uid")
        try:
            uid = int(uid)
        except (TypeError, ValueError):
            uid = None
        info = CLASS_INFO.get(uid) if uid is not None else None
        fam = str(r.get("os_family") or "").strip().lower()
        recent.append({
            "event_id": r.get("event_id"),
            "time": r.get("time") or r.get("ingested_at"),
            "source": _SOURCE_LABEL.get(fam, r.get("os_family") or "Unidentified"),
            "event_type": info[0] if info else "Unclassified",
            "class_uid": uid,
            "activity": r.get("activity_name") or "Unknown",
            "host": r.get("hostname"),
            "severity": r.get("severity"),
            "status": st,
            "confidence": r.get("confidence"),
        })

    # ── Throughput: only ever a MEASURED figure. None until a job has run. ──
    perf = _LAST_JOB_PERF

    return {
        "title": "ULPF",
        "subtitle": "Universal Log Pre-processing Framework",
        "tagline": "Convert heterogeneous logs into a common, lossless, "
                   "analytics-ready representation.",
        "kpis": {
            "total_events": total,
            "successfully_parsed": {"count": parsed_ok, "pct": pct(parsed_ok)},
            "needs_review": {"count": needs_review, "pct": pct(needs_review)},
            "unresolved": {"count": unresolved, "pct": pct(unresolved)},
            "ocsf_mapped": {"count": mapped, "pct": pct(mapped)},
            "processing_rate": perf,
        },
        "pipeline": pipeline,
        "sources": sources,
        "event_types": event_types,
        "activities": activities,
        "severities": severities,
        "quality": {
            "parsing": [
                {"label": "Successfully Parsed", "count": parsed_ok, "pct": pct(parsed_ok)},
                {"label": "Partially Parsed", "count": partial, "pct": pct(partial)},
                {"label": "Unresolved", "count": unresolved, "pct": pct(unresolved)},
            ],
            "mapping": [
                {"label": "OCSF Mapped", "count": mapped_clean, "pct": pct(mapped_clean)},
                # Named precisely to avoid colliding with the overall "Needs
                # Review" KPI: this row counts only events that DID map but
                # still carry a review flag, so the three rows stay exclusive.
                {"label": "Mapped, flagged for review", "count": mapped_flagged,
                 "pct": pct(mapped_flagged)},
                {"label": "Unmapped", "count": unmapped, "pct": pct(unmapped)},
            ],
        },
        "recent": recent,
        "health": _health_report(),
    }


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
        # DuckDB writes real Parquet, unioning the hot (SQLite) + cold (DuckDB) tiers.
        tmp = tempfile.NamedTemporaryFile(suffix=".parquet", delete=False)
        tmp.close()
        db.export_parquet(tmp.name, limit)
        return FileResponse(tmp.name, media_type="application/octet-stream",
                            filename="ulpf_events.parquet")

    rows = db.iter_normalized_for_export(limit)

    if fmt == "json":
        out = []
        for r in rows:
            out.append({
                "event_id": r["event_id"], "parser_id": r["parser_id"],
                "confidence": r["confidence"], "ocsf_class": r["ocsf_class"],
                "needs_review": r["needs_review"], "normalized": r["normalized"],
            })
        return JSONResponse(out)

    # csv (flat summary columns; normalized JSON kept as one embedded column)
    def _gen():
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["event_id", "parser_id", "confidence", "ocsf_class", "needs_review", "normalized"])
        yield buf.getvalue(); buf.seek(0); buf.truncate(0)
        for r in rows:
            norm = r["normalized"]
            norm = norm if isinstance(norm, str) else json.dumps(norm)
            w.writerow([r["event_id"], r["parser_id"], r["confidence"],
                        r["ocsf_class"], r["needs_review"], norm])
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

    # Storage: real read probe across both tiers (SQLite hot + DuckDB cold).
    try:
        db.count_normalized()
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
