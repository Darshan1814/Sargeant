"""
SQLite hot-tier storage — recent ("current") events.

The storage decision for ULPF is a **two-tier split**: fresh events land here in
SQLite (fast, WAL-mode, concurrent readers + a single writer, safe across the API
process AND the Kafka consumer process via file locks); a background tiering worker
in ``store.py`` ages rows past ``ULPF_HOT_RETENTION`` into the DuckDB cold tier
(``db.py``) for cheap historical/analytic queries.

This module mirrors ``db.py``'s public function signatures and — crucially — its
RETURN SHAPES, so the ``store.py`` façade can union the two tiers without any
per-tier special-casing. It adds a handful of low-level helpers the tiering worker
needs (read expired rows, delete by id) that the DuckDB layer does not require.

Schema is column-for-column identical to ``db.py`` (SQLite types), so a row moved
from hot → cold carries over verbatim, including its original ``ingested_at``.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from pathlib import Path

# Separate file from DuckDB's. Default lives beside the DuckDB db under /data.
SQLITE_PATH = os.getenv("SQLITE_PATH", "/data/ulpf_hot.sqlite")

# Same gate semantics as db.DUCKDB_WRITER: a process that must not own storage
# (never expected for SQLite, but kept symmetric) can opt out.
SQLITE_WRITER = os.getenv("SQLITE_WRITER", "true").lower() != "false"

_LOCK = threading.RLock()
_CONN: sqlite3.Connection | None = None


def get_conn() -> sqlite3.Connection:
    """Process-wide SQLite connection in WAL mode.

    WAL lets many readers run concurrently with one writer and makes cross-process
    access (API + Kafka consumer) safe via SQLite's own file locking. A single
    shared connection guarded by ``_LOCK`` serialises this process's own access.

    Schema is ensured on first connect so ANY writer process is safe even if it
    never called ``init_db()`` (e.g. the Kafka consumer, which does not run the
    API's startup hook).
    """
    global _CONN
    with _LOCK:
        if _CONN is None:
            Path(SQLITE_PATH).parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(SQLITE_PATH, check_same_thread=False)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA busy_timeout=5000")
            _CONN = conn
            _ensure_schema(conn)
        return _CONN


def _ensure_schema(conn: sqlite3.Connection):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS raw_events (
            event_id     TEXT PRIMARY KEY,
            ingested_at  TEXT DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
            source       TEXT,
            raw_log      TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS normalized_events (
            event_id      TEXT PRIMARY KEY,
            parser_id     TEXT,
            confidence    REAL,
            ocsf_class    INTEGER,
            normalized    TEXT,
            needs_review  INTEGER DEFAULT 0,
            ingested_at   TEXT DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now'))
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS dlq_events (
            event_id          TEXT PRIMARY KEY,
            ingested_at       TEXT DEFAULT (strftime('%Y-%m-%d %H:%M:%f','now')),
            source            TEXT,
            raw_log           TEXT,
            error_message     TEXT,
            attempted_parsers TEXT
        )
    """)
    # Index the tiering predicate so aging out old rows is cheap.
    conn.execute("CREATE INDEX IF NOT EXISTS idx_raw_ingested ON raw_events(ingested_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_norm_ingested ON normalized_events(ingested_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_dlq_ingested ON dlq_events(ingested_at)")
    conn.commit()


def _exec(sql: str, params: list | tuple = ()):  # serialised write/read helper
    with _LOCK:
        conn = get_conn()
        cur = conn.execute(sql, params)
        conn.commit()
        return cur


def init_db():
    if not SQLITE_WRITER:
        return
    with _LOCK:
        _ensure_schema(get_conn())


# ── Writes (hot tier only) ────────────────────────────────────────────────────

def insert_raw(event_id: str, source: str, raw_log: str,
               ingested_at: str | None = None):
    if not SQLITE_WRITER:
        return
    if ingested_at is None:
        _exec("INSERT OR REPLACE INTO raw_events (event_id, source, raw_log) VALUES (?, ?, ?)",
              [event_id, source, raw_log])
    else:
        _exec("INSERT OR REPLACE INTO raw_events (event_id, source, raw_log, ingested_at) "
              "VALUES (?, ?, ?, ?)", [event_id, source, raw_log, ingested_at])


def insert_normalized(event_id: str, parser_id: str, confidence: float,
                      ocsf_class: int, normalized: dict, needs_review: bool,
                      ingested_at: str | None = None):
    if not SQLITE_WRITER:
        return
    nr = 1 if needs_review else 0
    if ingested_at is None:
        _exec("""INSERT OR REPLACE INTO normalized_events
                 (event_id, parser_id, confidence, ocsf_class, normalized, needs_review)
                 VALUES (?, ?, ?, ?, ?, ?)""",
              [event_id, parser_id, confidence, ocsf_class, json.dumps(normalized), nr])
    else:
        _exec("""INSERT OR REPLACE INTO normalized_events
                 (event_id, parser_id, confidence, ocsf_class, normalized, needs_review, ingested_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?)""",
              [event_id, parser_id, confidence, ocsf_class, json.dumps(normalized), nr,
               ingested_at])


def insert_dlq(event_id: str, source: str, raw_log: str, error_message: str,
               attempted_parsers: list[str], ingested_at: str | None = None):
    if not SQLITE_WRITER:
        return
    if ingested_at is None:
        _exec("""INSERT OR REPLACE INTO dlq_events
                 (event_id, source, raw_log, error_message, attempted_parsers)
                 VALUES (?, ?, ?, ?, ?)""",
              [event_id, source, raw_log, error_message, json.dumps(attempted_parsers)])
    else:
        _exec("""INSERT OR REPLACE INTO dlq_events
                 (event_id, source, raw_log, error_message, attempted_parsers, ingested_at)
                 VALUES (?, ?, ?, ?, ?, ?)""",
              [event_id, source, raw_log, error_message, json.dumps(attempted_parsers),
               ingested_at])


# ── Batched writes (the parallel batch/upload persist path) ───────────────────
# One ``executemany`` + a SINGLE commit per chunk, instead of a commit per row.
# On a 20K batch this collapses ~40K fsync-bearing commits into ~40, and is the
# hot-tier half of the throughput fix. Row *content* is byte-identical to the
# single-row inserts above (same columns, same ``json.dumps``), so nothing about
# the normalized schema or semantics changes — only how many transactions wrap it.
# ``ingested_at`` is always supplied explicitly here so every row in a chunk is
# stamped consistently rather than relying on SQLite's per-row ``now()`` default.

def insert_raw_many(rows: list[tuple]) -> None:
    """rows: iterable of ``(event_id, source, raw_log, ingested_at)``."""
    if not SQLITE_WRITER or not rows:
        return
    with _LOCK:
        conn = get_conn()
        conn.executemany(
            "INSERT OR REPLACE INTO raw_events (event_id, source, raw_log, ingested_at) "
            "VALUES (?, ?, ?, ?)",
            rows,
        )
        conn.commit()


def insert_normalized_many(rows: list[tuple]) -> None:
    """rows: iterable of ``(event_id, parser_id, confidence, ocsf_class,
    normalized_dict, needs_review, ingested_at)``. ``normalized_dict`` is
    JSON-encoded here so callers hand over the plain dict."""
    if not SQLITE_WRITER or not rows:
        return
    encoded = [
        (eid, pid, conf, cls, json.dumps(norm), 1 if nr else 0, ts)
        for (eid, pid, conf, cls, norm, nr, ts) in rows
    ]
    with _LOCK:
        conn = get_conn()
        conn.executemany(
            """INSERT OR REPLACE INTO normalized_events
               (event_id, parser_id, confidence, ocsf_class, normalized, needs_review, ingested_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            encoded,
        )
        conn.commit()


def insert_dlq_many(rows: list[tuple]) -> None:
    """rows: iterable of ``(event_id, source, raw_log, error_message,
    attempted_parsers_list, ingested_at)``."""
    if not SQLITE_WRITER or not rows:
        return
    encoded = [
        (eid, src, raw, err, json.dumps(att or []), ts)
        for (eid, src, raw, err, att, ts) in rows
    ]
    with _LOCK:
        conn = get_conn()
        conn.executemany(
            """INSERT OR REPLACE INTO dlq_events
               (event_id, source, raw_log, error_message, attempted_parsers, ingested_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            encoded,
        )
        conn.commit()


# ── Reads (same output shapes as db.py) ───────────────────────────────────────

def list_dlq(limit: int = 50, offset: int = 0) -> list[dict]:
    with _LOCK:
        rows = get_conn().execute(
            """SELECT event_id, ingested_at, source, raw_log, error_message, attempted_parsers
               FROM dlq_events ORDER BY ingested_at DESC LIMIT ? OFFSET ?""",
            [limit, offset],
        ).fetchall()
    return [
        {
            "event_id": row[0],
            "ingested_at": str(row[1]),
            "source": row[2],
            "raw_log": row[3],
            "error_message": row[4],
            "attempted_parsers": json.loads(row[5]) if row[5] else [],
        }
        for row in rows
    ]


def get_dlq_count() -> int:
    with _LOCK:
        return get_conn().execute("SELECT COUNT(*) FROM dlq_events").fetchone()[0]


def get_event(event_id: str) -> dict | None:
    with _LOCK:
        conn = get_conn()
        raw_row = conn.execute(
            "SELECT event_id, source, raw_log, ingested_at FROM raw_events WHERE event_id = ?",
            [event_id],
        ).fetchone()
        norm_row = conn.execute(
            "SELECT parser_id, confidence, ocsf_class, normalized, needs_review "
            "FROM normalized_events WHERE event_id = ?",
            [event_id],
        ).fetchone()
    if not raw_row:
        return None
    result = {
        "event_id": raw_row[0],
        "source": raw_row[1],
        "raw_log": raw_row[2],
        "ingested_at": str(raw_row[3]),
    }
    if norm_row:
        result.update({
            "parser_id": norm_row[0],
            "confidence": norm_row[1],
            "ocsf_class": norm_row[2],
            "normalized": json.loads(norm_row[3]),
            "needs_review": bool(norm_row[4]),
        })
    return result


def list_events(limit: int = 50, offset: int = 0, source: str | None = None,
                ocsf_class: int | None = None, date_from: str | None = None,
                date_to: str | None = None) -> list[dict]:
    clauses, params = [], []
    if source:
        clauses.append("r.source = ?"); params.append(source)
    if ocsf_class:
        clauses.append("n.ocsf_class = ?"); params.append(ocsf_class)
    if date_from:
        clauses.append("r.ingested_at >= ?"); params.append(date_from)
    if date_to:
        clauses.append("r.ingested_at <= ?"); params.append(date_to)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    with _LOCK:
        rows = get_conn().execute(
            f"""SELECT r.event_id, r.source, r.ingested_at,
                       n.parser_id, n.confidence, n.ocsf_class, n.needs_review
                FROM raw_events r
                LEFT JOIN normalized_events n ON r.event_id = n.event_id
                {where}
                ORDER BY r.ingested_at DESC
                LIMIT ? OFFSET ?""",
            params + [limit, offset],
        ).fetchall()
    return [
        {
            "event_id": row[0],
            "source": row[1],
            "ingested_at": str(row[2]),
            "parser_id": row[3],
            "confidence": row[4],
            "ocsf_class": row[5],
            "needs_review": (None if row[6] is None else bool(row[6])),
        }
        for row in rows
    ]


def get_stats() -> dict:
    """Return the SAME dict shape as ``db.get_stats`` so ``store`` can merge both
    tiers. Percentages are recomputed by the façade after merging, but we fill
    them here too so the hot tier is independently meaningful."""
    with _LOCK:
        conn = get_conn()
        total = conn.execute("SELECT COUNT(*) FROM raw_events").fetchone()[0]
        by_parser = conn.execute(
            "SELECT parser_id, COUNT(*) FROM normalized_events GROUP BY parser_id ORDER BY 2 DESC"
        ).fetchall()
        by_class = conn.execute(
            "SELECT ocsf_class, COUNT(*) FROM normalized_events GROUP BY ocsf_class"
        ).fetchall()
        needs_review = conn.execute(
            "SELECT COUNT(*) FROM normalized_events WHERE needs_review = 1"
        ).fetchone()[0]
        dlq_count = conn.execute("SELECT COUNT(*) FROM dlq_events").fetchone()[0]
        by_day = conn.execute(
            """SELECT strftime('%Y-%m-%d', ingested_at) AS day, COUNT(*)
               FROM raw_events GROUP BY day ORDER BY day DESC LIMIT 14"""
        ).fetchall()
        by_source = conn.execute(
            "SELECT source, COUNT(*) FROM raw_events GROUP BY source ORDER BY 2 DESC LIMIT 20"
        ).fetchall()
        cov_rows = conn.execute(
            """SELECT
                 CASE
                   WHEN parser_id = 'DRAIN3-FALLBACK'   THEN 'drain3'
                   WHEN parser_id = 'DLQ'               THEN 'dlq'
                   WHEN parser_id LIKE 'FW-%'           THEN 'ngre_firewall'
                   WHEN parser_id LIKE 'WIN-FIREWALL-%' THEN 'ngre_firewall'
                   WHEN parser_id LIKE 'LINUX-%'        THEN 'ngre_linux'
                   WHEN parser_id LIKE 'WIN-%'          THEN 'ngre_windows'
                   WHEN parser_id LIKE 'MAC-%'          THEN 'ngre_macos'
                   ELSE 'ngre_other'
                 END AS bucket,
                 COUNT(*)
               FROM normalized_events GROUP BY bucket"""
        ).fetchall()

    cov = {r[0]: r[1] for r in cov_rows}
    ngre_win = cov.get("ngre_windows", 0)
    ngre_mac = cov.get("ngre_macos", 0)
    ngre_fw = cov.get("ngre_firewall", 0)
    ngre_linux = cov.get("ngre_linux", 0)
    ngre_other = cov.get("ngre_other", 0)
    drain3 = cov.get("drain3", 0)
    dlq = cov.get("dlq", 0)
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
    return {
        "total_events": total,
        "needs_review": needs_review,
        "dlq_count": dlq_count,
        "coverage": coverage,
        "by_parser": [{"parser_id": r[0], "count": r[1]} for r in by_parser],
        "by_ocsf_class": [{"class_uid": r[0], "count": r[1]} for r in by_class],
        "by_day": [{"day": r[0], "count": r[1]} for r in by_day],
        "by_source": [{"source": r[0], "count": r[1]} for r in by_source],
    }


def count_normalized() -> int:
    with _LOCK:
        return get_conn().execute("SELECT COUNT(*) FROM normalized_events").fetchone()[0]


def export_normalized(limit: int) -> list[dict]:
    """Uniform rows for JSON/CSV/Parquet export (event_id, parser_id, confidence,
    ocsf_class, needs_review, ingested_at, normalized-as-dict)."""
    with _LOCK:
        rows = get_conn().execute(
            "SELECT event_id, parser_id, confidence, ocsf_class, needs_review, "
            "ingested_at, normalized FROM normalized_events "
            "ORDER BY ingested_at DESC LIMIT ?", [int(limit)],
        ).fetchall()
    return [
        {
            "event_id": r[0], "parser_id": r[1], "confidence": r[2],
            "ocsf_class": r[3], "needs_review": (None if r[4] is None else bool(r[4])),
            "ingested_at": str(r[5]),
            "normalized": json.loads(r[6]) if r[6] else None,
        }
        for r in rows
    ]


# ── Tiering helpers (read expired rows, delete by id) ─────────────────────────

def expired_event_ids(cutoff: str, limit: int) -> list[str]:
    """event_ids of raw rows older than ``cutoff`` (a 'YYYY-MM-DD HH:MM:SS...' string)."""
    with _LOCK:
        rows = get_conn().execute(
            "SELECT event_id FROM raw_events WHERE ingested_at < ? "
            "ORDER BY ingested_at ASC LIMIT ?", [cutoff, int(limit)],
        ).fetchall()
    return [r[0] for r in rows]


def get_raw_row(event_id: str) -> tuple | None:
    """(event_id, source, raw_log, ingested_at) or None."""
    with _LOCK:
        return get_conn().execute(
            "SELECT event_id, source, raw_log, ingested_at FROM raw_events WHERE event_id = ?",
            [event_id],
        ).fetchone()


def get_normalized_row(event_id: str) -> tuple | None:
    """(event_id, parser_id, confidence, ocsf_class, normalized_json, needs_review,
    ingested_at) or None."""
    with _LOCK:
        return get_conn().execute(
            "SELECT event_id, parser_id, confidence, ocsf_class, normalized, "
            "needs_review, ingested_at FROM normalized_events WHERE event_id = ?",
            [event_id],
        ).fetchone()


def delete_event(event_id: str):
    """Remove a raw+normalized pair from the hot tier (after cold-tier insert)."""
    with _LOCK:
        conn = get_conn()
        conn.execute("DELETE FROM normalized_events WHERE event_id = ?", [event_id])
        conn.execute("DELETE FROM raw_events WHERE event_id = ?", [event_id])
        conn.commit()


def expired_dlq(cutoff: str, limit: int) -> list[tuple]:
    """Rows (event_id, source, raw_log, error_message, attempted_parsers_json,
    ingested_at) older than ``cutoff``."""
    with _LOCK:
        return get_conn().execute(
            "SELECT event_id, source, raw_log, error_message, attempted_parsers, "
            "ingested_at FROM dlq_events WHERE ingested_at < ? "
            "ORDER BY ingested_at ASC LIMIT ?", [cutoff, int(limit)],
        ).fetchall()


def delete_dlq(event_id: str):
    with _LOCK:
        conn = get_conn()
        conn.execute("DELETE FROM dlq_events WHERE event_id = ?", [event_id])
        conn.commit()
