"""
Storage façade — two-tier hot/cold split (spec #11).

ULPF keeps a **real** SQLite-for-current + DuckDB-for-historical split:

  * **Hot tier** (``sqlite_store``, SQLite/WAL): every fresh event is written here.
    Fast point writes, safe across the API process and the Kafka consumer process.
  * **Cold tier** (``db``, DuckDB): analytic/historical store. A background worker
    ages rows past ``ULPF_HOT_RETENTION`` out of SQLite into DuckDB, preserving each
    row's ORIGINAL ``ingested_at`` so time-bucketed stats stay honest.

This module is a drop-in replacement for ``import db``: it exposes the same public
surface (``init_db``, ``insert_*``, ``list_*``, ``get_*``, ``get_stats``,
``get_conn``) but routes **writes to the hot tier** and **reads to a union** of hot
+ cold. Because ``sqlite_store`` mirrors ``db``'s return shapes exactly, the union
logic here never special-cases a tier.

Offline-safe by design: the union is computed in Python (no DuckDB SQLite-extension
dependency), so nothing needs network access — important for the SIH air-gapped demo.
"""
from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime, timedelta, timezone

import db  # cold tier (DuckDB)
import sqlite_store  # hot tier (SQLite)

# Rows older than this many seconds are aged hot → cold. Default 24h.
HOT_RETENTION_SECONDS = int(os.getenv("ULPF_HOT_RETENTION", str(24 * 3600)))
# How often the tiering worker wakes up (seconds).
TIER_INTERVAL_SECONDS = int(os.getenv("ULPF_TIER_INTERVAL", "300"))
# Max rows migrated per tick per table — bounds each pass so it never stalls the DB.
TIER_BATCH = int(os.getenv("ULPF_TIER_BATCH", "1000"))

# Re-export the cold-tier connection primitives so any code doing `db.get_conn()`
# keeps working when it switches to `import store as db`. Direct-connection callers
# (Parquet COPY, health probe) operate on the cold tier; use the tier-aware helpers
# below (`count_normalized`, `iter_normalized_for_export`, `export_parquet`) when a
# UNION over both tiers is required.
get_conn = db.get_conn
DUCKDB_WRITER = db.DUCKDB_WRITER


# ── Schema init (both tiers) ──────────────────────────────────────────────────

def init_db():
    sqlite_store.init_db()
    db.init_db()


# ── Writes → hot tier only ────────────────────────────────────────────────────

def insert_raw(event_id: str, source: str, raw_log: str,
               ingested_at: str | None = None):
    sqlite_store.insert_raw(event_id, source, raw_log, ingested_at)


def insert_normalized(event_id: str, parser_id: str, confidence: float,
                      ocsf_class: int, normalized: dict, needs_review: bool,
                      ingested_at: str | None = None):
    sqlite_store.insert_normalized(event_id, parser_id, confidence, ocsf_class,
                                   normalized, needs_review, ingested_at)


def insert_dlq(event_id: str, source: str, raw_log: str, error_message: str,
               attempted_parsers: list[str], ingested_at: str | None = None):
    sqlite_store.insert_dlq(event_id, source, raw_log, error_message,
                            attempted_parsers, ingested_at)


# ── Batched writes (parallel batch/upload path) → hot tier only ───────────────
# Same hot-tier routing as the single-row inserts above; one commit per chunk.

def insert_raw_many(rows: list) -> None:
    sqlite_store.insert_raw_many(rows)


def insert_normalized_many(rows: list) -> None:
    sqlite_store.insert_normalized_many(rows)


def insert_dlq_many(rows: list) -> None:
    sqlite_store.insert_dlq_many(rows)


# ── Reads → union(hot, cold) ──────────────────────────────────────────────────

def get_event(event_id: str) -> dict | None:
    """Tiering moves an event's raw+normalized rows together, so an id lives in
    exactly one tier: check hot first (most events are recent), else cold."""
    return sqlite_store.get_event(event_id) or db.get_event(event_id)


def _merge_paginate(hot: list[dict], cold: list[dict], key, limit: int,
                    offset: int) -> list[dict]:
    """Merge two already-sorted-desc slices into one correctly paginated page.

    Each tier was queried for ``limit + offset`` rows with identical filters, so
    their concatenation is a superset of the true page. Sort by ``key`` desc and
    slice ``[offset : offset+limit]``."""
    merged = hot + cold
    merged.sort(key=key, reverse=True)
    return merged[offset:offset + limit]


def list_events(limit: int = 50, offset: int = 0, source: str | None = None,
                ocsf_class: int | None = None, date_from: str | None = None,
                date_to: str | None = None) -> list[dict]:
    span = limit + offset
    hot = sqlite_store.list_events(span, 0, source, ocsf_class, date_from, date_to)
    cold = db.list_events(span, 0, source, ocsf_class, date_from, date_to)
    return _merge_paginate(hot, cold, lambda e: e.get("ingested_at") or "",
                           limit, offset)


def list_dlq(limit: int = 50, offset: int = 0) -> list[dict]:
    span = limit + offset
    hot = sqlite_store.list_dlq(span, 0)
    cold = db.list_dlq(span, 0)
    return _merge_paginate(hot, cold, lambda e: e.get("ingested_at") or "",
                           limit, offset)


def get_dlq_count() -> int:
    return sqlite_store.get_dlq_count() + db.get_dlq_count()


def _merge_counts(a: list[dict], b: list[dict], key: str, val: str = "count") -> list[dict]:
    """Merge two `[{key: k, count: n}, ...]` lists by summing on ``key``."""
    acc: dict = {}
    for row in list(a) + list(b):
        k = row.get(key)
        acc[k] = acc.get(k, 0) + int(row.get(val, 0))
    out = [{key: k, val: n} for k, n in acc.items()]
    out.sort(key=lambda r: r[val], reverse=True)
    return out


def get_stats() -> dict:
    """Union stats across both tiers: sum scalar totals + coverage buckets, merge
    the grouped lists by key, then recompute all percentages on merged totals."""
    hot = sqlite_store.get_stats()
    cold = db.get_stats()

    hc, cc = hot["coverage"], cold["coverage"]
    ngre_win = hc["ngre_windows"] + cc["ngre_windows"]
    ngre_mac = hc["ngre_macos"] + cc["ngre_macos"]
    ngre_fw = hc["ngre_firewall"] + cc["ngre_firewall"]
    ngre_linux = hc["ngre_linux"] + cc["ngre_linux"]
    ngre_other = hc["ngre_other"] + cc["ngre_other"]
    drain3 = hc["drain3"] + cc["drain3"]
    dlq = hc["dlq"] + cc["dlq"]
    ngre_total = ngre_win + ngre_mac + ngre_fw + ngre_linux + ngre_other
    cov_total = ngre_total + drain3 + dlq

    def pct(n: int) -> float:
        return round(100.0 * n / cov_total, 1) if cov_total else 0.0

    coverage = {
        "total": cov_total,
        "ngre_windows": ngre_win, "ngre_macos": ngre_mac, "ngre_firewall": ngre_fw,
        "ngre_linux": ngre_linux, "ngre_other": ngre_other, "ngre_total": ngre_total,
        "drain3": drain3, "dlq": dlq,
        "pct_ngre": pct(ngre_total), "pct_ngre_windows": pct(ngre_win),
        "pct_ngre_macos": pct(ngre_mac), "pct_ngre_firewall": pct(ngre_fw),
        "pct_ngre_linux": pct(ngre_linux), "pct_drain3": pct(drain3), "pct_dlq": pct(dlq),
    }

    by_day = _merge_counts(hot["by_day"], cold["by_day"], "day")
    by_day.sort(key=lambda r: r["day"], reverse=True)
    return {
        "total_events": hot["total_events"] + cold["total_events"],
        "needs_review": hot["needs_review"] + cold["needs_review"],
        "dlq_count": hot["dlq_count"] + cold["dlq_count"],
        "coverage": coverage,
        "by_parser": _merge_counts(hot["by_parser"], cold["by_parser"], "parser_id"),
        "by_ocsf_class": _merge_counts(hot["by_ocsf_class"], cold["by_ocsf_class"], "class_uid"),
        "by_day": by_day[:14],
        "by_source": _merge_counts(hot["by_source"], cold["by_source"], "source")[:20],
    }


# ── Escape-hatch helpers (tier-aware replacements for raw get_conn() sites) ────

def count_normalized() -> int:
    """Total normalized events across both tiers (health probe)."""
    cold = db.get_conn()
    try:
        cold_n = cold.execute("SELECT COUNT(*) FROM normalized_events").fetchone()[0]
    finally:
        cold.close()
    return sqlite_store.count_normalized() + cold_n


def _cold_export_rows(limit: int) -> list[dict]:
    conn = db.get_conn()
    try:
        rows = conn.execute(
            "SELECT event_id, parser_id, confidence, ocsf_class, needs_review, "
            "ingested_at, normalized FROM normalized_events "
            "ORDER BY ingested_at DESC LIMIT ?", [int(limit)],
        ).fetchall()
    finally:
        conn.close()
    out = []
    for r in rows:
        norm = r[6]
        if isinstance(norm, str):
            try:
                norm = json.loads(norm)
            except json.JSONDecodeError:
                pass
        out.append({
            "event_id": r[0], "parser_id": r[1], "confidence": r[2],
            "ocsf_class": r[3],
            "needs_review": (None if r[4] is None else bool(r[4])),
            "ingested_at": str(r[5]), "normalized": norm,
        })
    return out


def iter_normalized_for_export(limit: int) -> list[dict]:
    """Uniform normalized rows across both tiers for JSON/CSV export, newest first."""
    hot = sqlite_store.export_normalized(limit)
    cold = _cold_export_rows(limit)
    merged = hot + cold
    merged.sort(key=lambda e: e.get("ingested_at") or "", reverse=True)
    return merged[:int(limit)]


def export_parquet(path: str, limit: int) -> None:
    """Write real Parquet for a UNION of both tiers via DuckDB.

    Hot rows are staged into a DuckDB temp table, then COPY writes the union of the
    cold ``normalized_events`` and that temp table to ``path``. Keeps DuckDB as the
    Parquet writer (spec #11) while still exporting recent SQLite-tier events."""
    hot = sqlite_store.export_normalized(limit)
    conn = db.get_conn()
    try:
        conn.execute("DROP TABLE IF EXISTS _export_hot")
        conn.execute(
            "CREATE TEMP TABLE _export_hot (event_id VARCHAR, parser_id VARCHAR, "
            "confidence DOUBLE, ocsf_class INTEGER, needs_review BOOLEAN, "
            "ingested_at VARCHAR, normalized JSON)"
        )
        for r in hot:
            conn.execute(
                "INSERT INTO _export_hot VALUES (?, ?, ?, ?, ?, ?, ?)",
                [r["event_id"], r["parser_id"], r["confidence"], r["ocsf_class"],
                 r["needs_review"], r["ingested_at"],
                 json.dumps(r["normalized"]) if r["normalized"] is not None else None],
            )
        conn.execute(
            f"COPY (SELECT event_id, parser_id, confidence, ocsf_class, needs_review, "
            f"CAST(ingested_at AS VARCHAR) AS ingested_at, normalized FROM ("
            f"  SELECT event_id, parser_id, confidence, ocsf_class, needs_review, "
            f"         ingested_at, normalized FROM normalized_events "
            f"  UNION ALL "
            f"  SELECT event_id, parser_id, confidence, ocsf_class, needs_review, "
            f"         ingested_at, normalized FROM _export_hot"
            f") ORDER BY ingested_at DESC LIMIT {int(limit)}) TO '{path}' (FORMAT PARQUET)"
        )
        conn.execute("DROP TABLE IF EXISTS _export_hot")
    finally:
        conn.close()


# ── Background tiering worker ─────────────────────────────────────────────────

_TIER_THREAD: threading.Thread | None = None
_TIER_STOP = threading.Event()


def _cutoff_string() -> str:
    """Hot-tier ``ingested_at`` is a UTC 'YYYY-MM-DD HH:MM:SS.fff' string (SQLite
    ``strftime('now')``). Produce a comparable cutoff at now-retention (UTC)."""
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=HOT_RETENTION_SECONDS)
    return cutoff.strftime("%Y-%m-%d %H:%M:%S")


def tier_once() -> dict:
    """Age one bounded batch of expired rows hot → cold. Returns counts moved.

    Raw + normalized rows for the same event are migrated together (atomic per
    event id), so ``get_event`` stays a simple "hot else cold" lookup. DLQ rows are
    aged on their own ``ingested_at``. Original timestamps are preserved."""
    if not db.DUCKDB_WRITER:
        return {"events": 0, "dlq": 0}  # only the DuckDB-owning process tiers
    cutoff = _cutoff_string()
    moved_events = 0
    for eid in sqlite_store.expired_event_ids(cutoff, TIER_BATCH):
        raw = sqlite_store.get_raw_row(eid)       # (id, source, raw_log, ingested_at)
        norm = sqlite_store.get_normalized_row(eid)  # (id, parser, conf, class, json, nr, ts)
        if raw is not None:
            db.insert_raw(raw[0], raw[1], raw[2], ingested_at=str(raw[3]))
        if norm is not None:
            try:
                normalized = json.loads(norm[4]) if norm[4] else {}
            except json.JSONDecodeError:
                normalized = {}
            db.insert_normalized(norm[0], norm[1], norm[2], norm[3], normalized,
                                 bool(norm[5]), ingested_at=str(norm[6]))
        sqlite_store.delete_event(eid)
        moved_events += 1

    moved_dlq = 0
    for row in sqlite_store.expired_dlq(cutoff, TIER_BATCH):
        try:
            attempted = json.loads(row[4]) if row[4] else []
        except json.JSONDecodeError:
            attempted = []
        db.insert_dlq(row[0], row[1], row[2], row[3], attempted, ingested_at=str(row[5]))
        sqlite_store.delete_dlq(row[0])
        moved_dlq += 1
    return {"events": moved_events, "dlq": moved_dlq}


def _tier_loop():
    while not _TIER_STOP.is_set():
        try:
            # Drain in bounded batches until this pass has nothing left to age,
            # so a large backlog is cleared over several ticks without blocking.
            while not _TIER_STOP.is_set():
                moved = tier_once()
                if moved["events"] == 0 and moved["dlq"] == 0:
                    break
        except Exception as exc:  # pragma: no cover - worker must never die
            import logging
            logging.getLogger("ulpf").warning("tiering pass failed: %s", exc)
        _TIER_STOP.wait(TIER_INTERVAL_SECONDS)


def start_tiering():
    """Launch the daemon tiering worker (idempotent). Only the DuckDB writer runs
    it — the Kafka consumer process (DUCKDB_WRITER=false) writes hot rows only."""
    global _TIER_THREAD
    if not db.DUCKDB_WRITER:
        return
    if _TIER_THREAD is not None and _TIER_THREAD.is_alive():
        return
    _TIER_STOP.clear()
    _TIER_THREAD = threading.Thread(target=_tier_loop, name="ulpf-tiering",
                                    daemon=True)
    _TIER_THREAD.start()


def stop_tiering():
    _TIER_STOP.set()
