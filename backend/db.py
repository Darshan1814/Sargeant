"""
DuckDB storage layer: raw events, normalized OCSF events, parser registry, and DLQ.
"""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path

import duckdb

DB_PATH = os.getenv("DUCKDB_PATH", "/data/ulpf.db")

# DuckDB allows only ONE connection to attach a given file within a process, and
# is not safe for concurrent writes. We therefore keep a SINGLE shared connection
# per process, guarded by a re-entrant lock so all reads/writes are serialized.
# This eliminates the "Unique file handle conflict: database already attached"
# errors that occur when a connection is opened per-operation under load.
#
# Set DUCKDB_WRITER=false in a process that must NOT own the file (the Kafka
# consumer), so it never opens the DB at all — the API backend owns it.
DUCKDB_WRITER = os.getenv("DUCKDB_WRITER", "true").lower() != "false"

_LOCK = threading.RLock()
_CONN: duckdb.DuckDBPyConnection | None = None


class _SharedConn:
    """Proxy over the process-wide DuckDB connection.

    Exposes the connection's API but makes ``close()`` a no-op so existing call
    sites (which open, use, then close) keep working without each one tearing
    down the shared connection. All access is serialized by ``_LOCK``.
    """

    def __init__(self, conn: duckdb.DuckDBPyConnection):
        self._conn = conn

    def execute(self, *args, **kwargs):
        with _LOCK:
            return self._conn.execute(*args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._conn, name)

    def close(self):  # no-op: keep the shared connection alive
        return None


def get_conn() -> "_SharedConn":
    global _CONN
    with _LOCK:
        if _CONN is None:
            Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
            _CONN = duckdb.connect(DB_PATH)
        return _SharedConn(_CONN)


def init_db():
    if not DUCKDB_WRITER:
        return  # non-writer process relies on the writer having created schema
    conn = get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS raw_events (
            event_id     VARCHAR PRIMARY KEY,
            ingested_at  TIMESTAMP DEFAULT current_timestamp,
            source       VARCHAR,
            raw_log      TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS normalized_events (
            event_id      VARCHAR PRIMARY KEY,
            parser_id     VARCHAR,
            confidence    DOUBLE,
            ocsf_class    INTEGER,
            normalized    JSON,
            needs_review  BOOLEAN DEFAULT FALSE,
            ingested_at   TIMESTAMP DEFAULT current_timestamp
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS dlq_events (
            event_id          VARCHAR PRIMARY KEY,
            ingested_at       TIMESTAMP DEFAULT current_timestamp,
            source            VARCHAR,
            raw_log           TEXT,
            error_message     TEXT,
            attempted_parsers JSON
        )
    """)
    conn.close()


# ── Raw events ────────────────────────────────────────────────────────────────

def insert_raw(event_id: str, source: str, raw_log: str):
    if not DUCKDB_WRITER:
        return  # non-writer process (e.g. Kafka consumer) skips DuckDB
    conn = get_conn()
    conn.execute(
        "INSERT OR REPLACE INTO raw_events (event_id, source, raw_log) VALUES (?, ?, ?)",
        [event_id, source, raw_log],
    )
    conn.close()


# ── Normalized events ─────────────────────────────────────────────────────────

def insert_normalized(
    event_id: str,
    parser_id: str,
    confidence: float,
    ocsf_class: int,
    normalized: dict,
    needs_review: bool,
):
    if not DUCKDB_WRITER:
        return
    conn = get_conn()
    conn.execute(
        """INSERT OR REPLACE INTO normalized_events
           (event_id, parser_id, confidence, ocsf_class, normalized, needs_review)
           VALUES (?, ?, ?, ?, ?, ?)""",
        [event_id, parser_id, confidence, ocsf_class, json.dumps(normalized), needs_review],
    )
    conn.close()


# ── DLQ ───────────────────────────────────────────────────────────────────────

def insert_dlq(
    event_id: str,
    source: str,
    raw_log: str,
    error_message: str,
    attempted_parsers: list[str],
):
    if not DUCKDB_WRITER:
        return
    conn = get_conn()
    conn.execute(
        """INSERT OR REPLACE INTO dlq_events
           (event_id, source, raw_log, error_message, attempted_parsers)
           VALUES (?, ?, ?, ?, ?)""",
        [event_id, source, raw_log, error_message, json.dumps(attempted_parsers)],
    )
    conn.close()


def list_dlq(limit: int = 50, offset: int = 0) -> list[dict]:
    conn = get_conn()
    rows = conn.execute(
        """SELECT event_id, ingested_at, source, raw_log, error_message, attempted_parsers
           FROM dlq_events ORDER BY ingested_at DESC LIMIT ? OFFSET ?""",
        [limit, offset],
    ).fetchall()
    conn.close()
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
    conn = get_conn()
    count = conn.execute("SELECT COUNT(*) FROM dlq_events").fetchone()[0]
    conn.close()
    return count


# ── Query ─────────────────────────────────────────────────────────────────────

def get_event(event_id: str) -> dict | None:
    conn = get_conn()
    raw_row = conn.execute(
        "SELECT event_id, source, raw_log, ingested_at FROM raw_events WHERE event_id = ?",
        [event_id],
    ).fetchone()
    norm_row = conn.execute(
        "SELECT parser_id, confidence, ocsf_class, normalized, needs_review FROM normalized_events WHERE event_id = ?",
        [event_id],
    ).fetchone()
    conn.close()
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
            "needs_review": norm_row[4],
        })
    return result


def list_events(
    limit: int = 50,
    offset: int = 0,
    source: str | None = None,
    ocsf_class: int | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
) -> list[dict]:
    conn = get_conn()
    clauses = []
    params = []
    if source:
        clauses.append("r.source = ?")
        params.append(source)
    if ocsf_class:
        clauses.append("n.ocsf_class = ?")
        params.append(ocsf_class)
    if date_from:
        clauses.append("r.ingested_at >= ?")
        params.append(date_from)
    if date_to:
        clauses.append("r.ingested_at <= ?")
        params.append(date_to)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    rows = conn.execute(
        f"""SELECT r.event_id, r.source, r.ingested_at,
                   n.parser_id, n.confidence, n.ocsf_class, n.needs_review
            FROM raw_events r
            LEFT JOIN normalized_events n ON r.event_id = n.event_id
            {where}
            ORDER BY r.ingested_at DESC
            LIMIT ? OFFSET ?""",
        params + [limit, offset],
    ).fetchall()
    conn.close()
    return [
        {
            "event_id": row[0],
            "source": row[1],
            "ingested_at": str(row[2]),
            "parser_id": row[3],
            "confidence": row[4],
            "ocsf_class": row[5],
            "needs_review": row[6],
        }
        for row in rows
    ]


def get_stats() -> dict:
    conn = get_conn()
    total = conn.execute("SELECT COUNT(*) FROM raw_events").fetchone()[0]
    by_parser = conn.execute(
        "SELECT parser_id, COUNT(*) as cnt FROM normalized_events GROUP BY parser_id ORDER BY cnt DESC"
    ).fetchall()
    by_class = conn.execute(
        "SELECT ocsf_class, COUNT(*) as cnt FROM normalized_events GROUP BY ocsf_class"
    ).fetchall()
    needs_review = conn.execute(
        "SELECT COUNT(*) FROM normalized_events WHERE needs_review = TRUE"
    ).fetchone()[0]
    dlq_count = conn.execute("SELECT COUNT(*) FROM dlq_events").fetchone()[0]
    by_day = conn.execute(
        """SELECT strftime(ingested_at, '%Y-%m-%d') as day, COUNT(*) as cnt
           FROM raw_events GROUP BY day ORDER BY day DESC LIMIT 14"""
    ).fetchall()
    by_source = conn.execute(
        "SELECT source, COUNT(*) as cnt FROM raw_events GROUP BY source ORDER BY cnt DESC LIMIT 20"
    ).fetchall()

    # ── Honest coverage breakdown (derived from parser_id, no schema change) ──
    # NGRE  = matched a real parser (parser_id has an OS prefix)
    # Drain3= structural fallback (DRAIN3-FALLBACK)
    # DLQ   = last-resort minimal event (DLQ)
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
             COUNT(*) AS cnt
           FROM normalized_events GROUP BY bucket"""
    ).fetchall()
    conn.close()

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
        "ngre_windows": ngre_win,
        "ngre_macos": ngre_mac,
        "ngre_firewall": ngre_fw,
        "ngre_linux": ngre_linux,
        "ngre_other": ngre_other,
        "ngre_total": ngre_total,
        "drain3": drain3,
        "dlq": dlq,
        "pct_ngre": pct(ngre_total),
        "pct_ngre_windows": pct(ngre_win),
        "pct_ngre_macos": pct(ngre_mac),
        "pct_ngre_firewall": pct(ngre_fw),
        "pct_ngre_linux": pct(ngre_linux),
        "pct_drain3": pct(drain3),
        "pct_dlq": pct(dlq),
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
