"""
Parallel chunk processor.

Runs the EXACT same ``pipeline.process(raw)`` a sequential run would, only across
a bounded pool of worker processes, with bounded in-flight work and deterministic
in-order persistence. Nothing here changes parsing correctness — a worker calls
``process`` and returns its result dict; ALL persistence stays in the main process
(the DuckDB/SQLite writer), exactly as before.

Design (maps to spec #12–#14)
-----------------------------
* **Process pool, parse-only** (confirmed architecture decision): workers do CPU-
  bound regex parsing; the GIL would otherwise serialise threads, so processes buy
  real parallelism. Workers never touch the database.
* **Streaming chunker → bounded chunks**: input is grouped into ``Record``s
  (stable seq_id + raw_sha256) and batched into ``Chunk``s to amortise IPC.
* **Bounded in-flight backpressure**: at most ``max_inflight`` chunks are submitted
  at once, so a fast producer / slow DB never blows up memory (spec #12 backpressure).
* **Deterministic ordering**: chunks are persisted strictly in ``chunk_id`` order
  and records in-chunk order, so output ordering is independent of which worker
  finished first — single-thread output == parallel output (spec #14).
* **Per-record isolation**: a worker that raises on one record does not stop the
  others; that record is turned into a DLQ-shaped result and persisted (spec #12).
* **Auto-sizing with hard caps**: worker/chunk/in-flight counts are derived from
  CPU count and input size, but never unbounded — every knob has an env cap (#13).
* **spawn context**: workers are spawned (not forked) so they never inherit the
  parent's DuckDB connection / locks / threads.
"""
from __future__ import annotations

import multiprocessing as mp
import os
import uuid
from collections import deque
from dataclasses import dataclass
from typing import Callable, Iterable, Iterator, Optional

from .streaming import Chunk, Record, iter_chunks

# Imported at module top so the `spawn` workers import it once on start. This must
# NOT import main.py (which builds the FastAPI app) — only the pure pipeline.
from pipeline import process as _pipeline_process, _minimal_ocsf


# ── Auto-sizing ──────────────────────────────────────────────────────────────

def _env_int(name: str, default: int) -> int:
    try:
        v = int(os.getenv(name, "").strip())
        return v if v > 0 else default
    except (TypeError, ValueError):
        return default


@dataclass(frozen=True)
class EngineConfig:
    workers: int
    chunk_size: int
    max_inflight: int          # chunks concurrently submitted
    sequential: bool           # True → run in-process, no pool


# Hard ceilings (overridable by env, but always finite — never "unlimited").
_MAX_WORKERS_CAP = _env_int("ULPF_MAX_WORKERS", 8)
_CHUNK_SIZE_ENV = _env_int("ULPF_CHUNK_SIZE", 0)        # 0 → auto
_MAX_INFLIGHT_ENV = _env_int("ULPF_MAX_INFLIGHT", 0)    # 0 → auto
_PARALLEL_MIN = _env_int("ULPF_PARALLEL_MIN", 256)      # below → sequential


def autosize(n_records: Optional[int]) -> EngineConfig:
    """Choose worker/chunk/in-flight counts from CPU count + input size.

    ``n_records`` may be None (unknown/streaming) → conservative defaults. All
    values are clamped by the env caps above; nothing is ever unbounded.
    """
    cpu = os.cpu_count() or 2
    workers = max(1, min(cpu - 1, _MAX_WORKERS_CAP))

    # Small inputs: skip the pool entirely (spawn cost > parse cost).
    known = n_records if isinstance(n_records, int) and n_records >= 0 else None
    if known is not None:
        workers = max(1, min(workers, known)) if known else 1
    sequential = (
        workers <= 1
        or (known is not None and known < _PARALLEL_MIN)
    )

    if _CHUNK_SIZE_ENV > 0:
        chunk_size = _CHUNK_SIZE_ENV
    elif known is not None and known > 0:
        # Aim for ~8 chunks per worker so load balances without tiny-chunk IPC churn.
        import math
        chunk_size = max(64, min(1000, math.ceil(known / (workers * 8))))
    else:
        chunk_size = 200

    if _MAX_INFLIGHT_ENV > 0:
        max_inflight = _MAX_INFLIGHT_ENV
    else:
        max_inflight = max(2, workers * 2)

    return EngineConfig(
        workers=workers,
        chunk_size=chunk_size,
        max_inflight=max_inflight,
        sequential=sequential,
    )


# ── Worker (runs in a spawned subprocess) ────────────────────────────────────

def _dlq_result(raw: str, error: str) -> dict:
    """Build a fully-shaped DLQ result dict, identical in structure to what
    ``pipeline.process`` returns on its own DLQ path.

    Used for the (rare) cases the pipeline itself could not handle: a poison
    record that makes ``process`` raise, or a whole worker chunk dying. Routing
    these through ``_minimal_ocsf`` means the main process only ever sees normal,
    OCSF-enveloped results — persistence/progress need no special-casing, and
    nothing is silently dropped (spec #12: failed records → DLQ, others continue).
    """
    event_id = str(uuid.uuid4())
    normalized = _minimal_ocsf(event_id, raw, error, [])
    return {
        "event_id": event_id,
        "parser_id": "DLQ",
        "confidence": 0.0,
        "path": "dlq",
        "needs_review": True,
        "normalized": normalized,
        "raw_log": raw,
        "source": "DLQ",
        "ocsf_class": 1001,
        "candidates": [],
        "dlq": True,
        "dlq_error": error,
    }


def _process_one_safe(raw: str) -> dict:
    """Call the pipeline; never raise. Guarantees a result for every record so a
    single poison record can't abort a chunk (spec #12 per-record isolation)."""
    try:
        return _pipeline_process(raw)
    except Exception as exc:  # pragma: no cover - pipeline has its own DLQ fallback
        return _dlq_result(raw, f"engine worker error: {type(exc).__name__}: {exc}")


def _worker_chunk(raws: list[str]) -> list[dict]:
    """Process a whole chunk in one worker call to amortise IPC pickling."""
    return [_process_one_safe(r) for r in raws]


# ── Driver (runs in the main process) ────────────────────────────────────────

# persist_fn(result: dict, record: Record) -> None
PersistFn = Callable[[dict, Record], None]
# progress_fn(done_count: int, last_result: dict, record: Record) -> None
ProgressFn = Callable[[int, dict, Record], None]


def _run_sequential(records: Iterable[Record], persist_fn: PersistFn,
                    progress_fn: Optional[ProgressFn]) -> int:
    done = 0
    for rec in records:
        result = _process_one_safe(rec.raw)
        persist_fn(result, rec)
        done += 1
        if progress_fn is not None:
            progress_fn(done, result, rec)
    return done


def run_parallel(
    records: Iterable[Record],
    persist_fn: PersistFn,
    progress_fn: Optional[ProgressFn] = None,
    n_records: Optional[int] = None,
    config: Optional[EngineConfig] = None,
) -> dict:
    """Drive parsing across the worker pool with deterministic in-order persist.

    Parameters
    ----------
    records      : ordered ``Record`` stream (seq_id ascending).
    persist_fn   : called in the MAIN process, in seq order, once per record.
    progress_fn  : optional live-progress callback (main process).
    n_records    : record count if known (drives auto-sizing / small-batch skip).
    config       : override auto-sizing (tests).

    Returns a small summary dict: {config, processed}.
    """
    cfg = config or autosize(n_records)

    # Small batches (or single-core hosts) run in-process — identical output,
    # no pool spin-up. This is the "keep small-batch sequential fallback" path.
    if cfg.sequential:
        processed = _run_sequential(records, persist_fn, progress_fn)
        return {"config": cfg.__dict__, "processed": processed, "mode": "sequential"}

    chunks: Iterator[Chunk] = iter_chunks(records, cfg.chunk_size)
    ctx = mp.get_context("spawn")
    processed = 0

    from concurrent.futures import ProcessPoolExecutor

    executor = ProcessPoolExecutor(max_workers=cfg.workers, mp_context=ctx)
    # deque of (Chunk, Future) kept in submission (== chunk_id) order. We always
    # wait on the FRONT (lowest chunk_id) future, guaranteeing in-order persist
    # and bounding memory to `max_inflight` chunks.
    pending: deque = deque()
    exhausted = False
    try:
        while True:
            # Fill the in-flight window (backpressure).
            while len(pending) < cfg.max_inflight and not exhausted:
                try:
                    chunk = next(chunks)
                except StopIteration:
                    exhausted = True
                    break
                fut = executor.submit(_worker_chunk, [r.raw for r in chunk.records])
                pending.append((chunk, fut))

            if not pending:
                break

            chunk, fut = pending.popleft()
            try:
                results = fut.result()
            except Exception as exc:
                # Whole-chunk failure (e.g. a worker process died): degrade to
                # per-record DLQ results so nothing is silently dropped and the
                # rest of the run continues.
                results = [_dlq_result(rec.raw, f"chunk failed: {exc}")
                           for rec in chunk.records]

            # Persist strictly in record order within the chunk.
            for rec, result in zip(chunk.records, results):
                persist_fn(result, rec)
                processed += 1
                if progress_fn is not None:
                    progress_fn(processed, result, rec)
    finally:
        executor.shutdown(wait=True)

    return {"config": cfg.__dict__, "processed": processed, "mode": "parallel"}
