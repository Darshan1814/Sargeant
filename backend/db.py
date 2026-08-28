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

def insert_raw(event_id: str, source: str, raw_log: str,
               ingested_at: str | None = None):
    """Insert a raw event. ``ingested_at`` is normally left to DuckDB's
    ``current_timestamp`` default; the tiering worker passes the ORIGINAL hot-tier
    timestamp so aging a row into the cold tier never rewrites when it arrived."""
    if not DUCKDB_WRITER:
        return  # non-writer process (e.g. Kafka consumer) skips DuckDB
    conn = get_conn()
    if ingested_at is None:
        conn.execute(
            "INSERT OR REPLACE INTO raw_events (event_id, source, raw_log) VALUES (?, ?, ?)",
            [event_id, source, raw_log],
        )
    else:
        conn.execute(
            "INSERT OR REPLACE INTO raw_events (event_id, source, raw_log, ingested_at) "
            "VALUES (?, ?, ?, ?)",
            [event_id, source, raw_log, ingested_at],
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
    ingested_at: str | None = None,
):
    """Insert a normalized OCSF event. ``ingested_at`` preserves the original
    hot-tier arrival time when the tiering worker ages a row into DuckDB."""
    if not DUCKDB_WRITER:
        return
    conn = get_conn()
    if ingested_at is None:
        conn.execute(
            """INSERT OR REPLACE INTO normalized_events
               (event_id, parser_id, confidence, ocsf_class, normalized, needs_review)
               VALUES (?, ?, ?, ?, ?, ?)""",
            [event_id, parser_id, confidence, ocsf_class, json.dumps(normalized), needs_review],
        )
    else:
        conn.execute(
            """INSERT OR REPLACE INTO normalized_events
               (event_id, parser_id, confidence, ocsf_class, normalized, needs_review, ingested_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            [event_id, parser_id, confidence, ocsf_class, json.dumps(normalized),
             needs_review, ingested_at],
        )
    conn.close()


# ── DLQ ───────────────────────────────────────────────────────────────────────

def insert_dlq(
    event_id: str,
    source: str,
    raw_log: str,
    error_message: str,
    attempted_parsers: list[str],
    ingested_at: str | None = None,
):
    """Insert a DLQ event. ``ingested_at`` preserves the original hot-tier arrival
    time when the tiering worker ages a row into DuckDB."""
    if not DUCKDB_WRITER:
        return
    conn = get_conn()
    if ingested_at is None:
        conn.execute(
            """INSERT OR REPLACE INTO dlq_events
               (event_id, source, raw_log, error_message, attempted_parsers)
               VALUES (?, ?, ?, ?, ?)""",
            [event_id, source, raw_log, error_message, json.dumps(attempted_parsers)],
        )
    else:
        conn.execute(
            """INSERT OR REPLACE INTO dlq_events
               (event_id, source, raw_log, error_message, attempted_parsers, ingested_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            [event_id, source, raw_log, error_message,
             json.dumps(attempted_parsers), ingested_at],
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


# ── Evaluator-facing semantic aggregates (cold tier) ──────────────────────────
# Mirrors ``sqlite_store.get_overview`` / ``list_recent`` so ``store`` can merge
# both tiers. Groups by the normalized envelope's own semantic fields rather than
# by parser_id prefix, so a Windows Firewall event is counted as Windows.

_OVERVIEW_PATHS = {
    "by_os_family": "$.device.os.family",
    "by_class": "$.class_uid",
    "by_activity": "$.activity_name",
    "by_severity": "$.severity",
}

_CONFIDENT_CLASSES_SQL = "(1007, 3002, 3005, 4001, 4002, 6003)"

# Backward-compatibility derivation for rows persisted before parse_status /
# ocsf_mapping_status existed. Applies the same deterministic rule as the live
# pipeline to stored inputs, so historical events are classified identically to
# new ones instead of collapsing into a NULL bucket. See sqlite_store for the
# full rationale.
_EFF_PARSE_STATUS = f"""
    CASE
      WHEN json_extract_string(normalized, '$.parse_status') IS NOT NULL
           THEN json_extract_string(normalized, '$.parse_status')
      WHEN parser_id = 'DRAIN3-FALLBACK' THEN 'fallback'
      WHEN parser_id = 'DLQ'             THEN 'failed'
      WHEN ocsf_class IN {_CONFIDENT_CLASSES_SQL} THEN 'parsed'
      WHEN COALESCE(TRY_CAST(json_extract_string(normalized, '$.activity_id') AS INTEGER), 0) > 0
           THEN 'parsed'
      ELSE 'partially_parsed'
    END
"""

_EFF_MAPPING_STATUS = f"""
    CASE
      WHEN json_extract_string(normalized, '$.ocsf_mapping_status') IS NOT NULL
           THEN json_extract_string(normalized, '$.ocsf_mapping_status')
      WHEN parser_id IN ('DRAIN3-FALLBACK', 'DLQ') THEN 'unmapped'
      WHEN ocsf_class IN {_CONFIDENT_CLASSES_SQL} THEN 'mapped'
      WHEN COALESCE(TRY_CAST(json_extract_string(normalized, '$.activity_id') AS INTEGER), 0) > 0
           THEN 'mapped'
      ELSE 'unmapped'
    END
"""


def get_overview() -> dict:
    """Semantic aggregates over the cold tier. Same shape as the hot tier's."""
    conn = get_conn()
    out: dict = {}
    try:
        out["total"] = conn.execute(
            "SELECT COUNT(*) FROM normalized_events").fetchone()[0]
        for name, path in _OVERVIEW_PATHS.items():
            rows = conn.execute(
                "SELECT json_extract_string(normalized, ?) AS k, COUNT(*) AS c "
                "FROM normalized_events GROUP BY k ORDER BY c DESC",
                [path],
            ).fetchall()
            out[name] = [{"key": r[0], "count": r[1]} for r in rows]

        for name, expr in (("by_parse_status", _EFF_PARSE_STATUS),
                           ("by_mapping_status", _EFF_MAPPING_STATUS)):
            rows = conn.execute(
                f"SELECT {expr} AS k, COUNT(*) AS c "
                f"FROM normalized_events GROUP BY k ORDER BY c DESC"
            ).fetchall()
            out[name] = [{"key": r[0], "count": r[1]} for r in rows]

        # Mutually exclusive mapping outcome × review flag (see sqlite_store).
        rows = conn.execute(
            f"""SELECT {_EFF_MAPPING_STATUS} AS m,
                       CASE WHEN needs_review THEN 1 ELSE 0 END AS rev,
                       COUNT(*) AS c
                FROM normalized_events GROUP BY m, rev"""
        ).fetchall()
        out["by_mapping_review"] = [
            {"key": f"{r[0]}|{r[1]}", "count": r[2]} for r in rows
        ]
    finally:
        conn.close()
    return out


def list_recent(limit: int = 10) -> list[dict]:
    """Most recent cold-tier events with semantic fields already extracted."""
    conn = get_conn()
    try:
        rows = conn.execute(
            """SELECT event_id,
                      json_extract_string(normalized, '$.time'),
                      json_extract_string(normalized, '$.device.os.family'),
                      json_extract_string(normalized, '$.class_uid'),
                      json_extract_string(normalized, '$.activity_name'),
                      json_extract_string(normalized, '$.device.hostname'),
                      json_extract_string(normalized, '$.parse_status'),
                      json_extract_string(normalized, '$.ocsf_mapping_status'),
                      json_extract_string(normalized, '$.severity'),
                      json_extract_string(normalized, '$.message'),
                      confidence, ingested_at
               FROM normalized_events
               ORDER BY ingested_at DESC LIMIT ?""",
            [limit],
        ).fetchall()
    finally:
        conn.close()
    return [
        {
            "event_id": r[0], "time": r[1], "os_family": r[2],
            "class_uid": int(r[3]) if str(r[3] or "").isdigit() else r[3],
            "activity_name": r[4], "hostname": r[5],
            "parse_status": r[6], "mapping_status": r[7], "severity": r[8],
            "message": r[9], "confidence": r[10], "ingested_at": str(r[11]),
        }
        for r in rows
    ]
