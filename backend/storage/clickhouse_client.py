"""
ClickHouse normalized-event analytics store.

Holds the flattened, query-optimized view of every normalized OCSF event. The
schema mixes a set of UNIVERSAL columns (the common taxonomy analysts pivot on)
with:
  * `raw_object_id` / `raw_sha256` — pointer back to the immutable MinIO archive
    (enables replay + forensic verification), and
  * `extra_fields` (JSON String) — the COMPLETE normalized envelope, so no
    source-specific field is ever lost even if it has no dedicated column. This
    is the "keep both OCSF and vendor-specific fields" rule from the design.

Gracefully degrades: if `clickhouse-connect` or the server is unavailable, every
function is a no-op. DuckDB stays authoritative.
"""
from __future__ import annotations

import json
import os

try:
    import clickhouse_connect  # type: ignore
    _CH_AVAILABLE = True
except Exception:
    _CH_AVAILABLE = False

CH_HOST = os.getenv("CLICKHOUSE_HOST", "clickhouse")
CH_PORT = int(os.getenv("CLICKHOUSE_PORT", "8123"))
CH_USER = os.getenv("CLICKHOUSE_USER", "default")
CH_PASSWORD = os.getenv("CLICKHOUSE_PASSWORD", "")
CH_DATABASE = os.getenv("CLICKHOUSE_DATABASE", "ulpf")
TABLE = "events"

_client = None
_ready = False


def available() -> bool:
    return _CH_AVAILABLE


def get_client():
    global _client
    if not _CH_AVAILABLE:
        return None
    if _client is None:
        try:
            _client = clickhouse_connect.get_client(
                host=CH_HOST, port=CH_PORT, username=CH_USER,
                password=CH_PASSWORD,
            )
        except Exception:
            _client = None
    return _client


def ensure_schema() -> bool:
    """Create the ULPF database + events table (idempotent)."""
    global _ready
    if _ready:
        return True
    client = get_client()
    if client is None:
        return False
    try:
        client.command(f"CREATE DATABASE IF NOT EXISTS {CH_DATABASE}")
        client.command(f"""
            CREATE TABLE IF NOT EXISTS {CH_DATABASE}.{TABLE} (
                event_id            String,
                event_time          DateTime64(3) DEFAULT now64(3),
                ingestion_time      DateTime64(3) DEFAULT now64(3),
                source_type         LowCardinality(String),
                source_product      LowCardinality(String),
                os_family           LowCardinality(String),
                parser_id           LowCardinality(String),
                parser_confidence   Float32,
                parse_path          LowCardinality(String),
                ocsf_class_uid      UInt32,
                ocsf_class_name     LowCardinality(String),
                category_name       LowCardinality(String),
                activity_name       LowCardinality(String),
                severity            LowCardinality(String),
                severity_id         UInt8,
                status              LowCardinality(String),
                host_name           String,
                user_name           String,
                user_domain         String,
                src_ip              String,
                src_port            UInt32,
                dst_ip              String,
                dst_port            UInt32,
                process_name        String,
                process_pid         UInt32,
                process_cmd_line    String,
                event_code          String,
                message             String,
                needs_review        UInt8,
                raw_object_id       String,
                raw_sha256          String,
                extra_fields        String
            )
            ENGINE = MergeTree()
            ORDER BY (event_time, ocsf_class_uid, parser_id)
        """)
        _ready = True
    except Exception:
        return False
    return _ready


def _dig(d: dict, *path, default=None):
    cur = d
    for p in path:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(p)
        if cur is None:
            return default
    return cur


def _to_int(v, default=0) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def insert_event(event_id: str, normalized: dict, source: str,
                 raw_object_id: str = "", raw_sha256: str = "") -> bool:
    """Flatten a normalized OCSF envelope into the analytics row. The COMPLETE
    envelope is also stored in `extra_fields` so nothing is lost."""
    client = get_client()
    if client is None:
        return False
    if not ensure_schema():
        return False

    md = normalized.get("metadata", {}) or {}
    device = normalized.get("device", {}) or {}
    actor = normalized.get("actor", {}) or {}
    user = actor.get("user", {}) or {}
    proc = actor.get("process", {}) or {}
    src = normalized.get("src_endpoint", {}) or {}
    dst = normalized.get("dst_endpoint", {}) or {}

    row = [
        event_id,
        source or "unknown",
        _dig(md, "product", "name", default="Unknown") or "Unknown",
        _dig(device, "os", "family", default="Unknown") or "Unknown",
        md.get("parser_id", "UNKNOWN"),
        float(normalized.get("confidence", 0.0) or 0.0),
        normalized.get("parse_path", "ngre") or "ngre",
        _to_int(normalized.get("class_uid", 0)),
        normalized.get("class_name", "") or "",
        normalized.get("category_name", "") or "",
        normalized.get("activity_name", "") or "",
        normalized.get("severity", "") or "",
        _to_int(normalized.get("severity_id", 0)),
        normalized.get("status", "") or "",
        str(device.get("hostname") or ""),
        str(user.get("name") or ""),
        str(user.get("domain") or ""),
        str(src.get("ip") or ""),
        _to_int(src.get("port")),
        str(dst.get("ip") or ""),
        _to_int(dst.get("port")),
        str(proc.get("name") or ""),
        _to_int(proc.get("pid")),
        str(proc.get("cmd_line") or ""),
        str(md.get("event_code") or normalized.get("unmapped", {}).get("event_id") or ""),
        str(normalized.get("message") or ""),
        1 if normalized.get("needs_review") else 0,
        raw_object_id or "",
        raw_sha256 or "",
        json.dumps(normalized, default=str),
    ]
    columns = [
        "event_id", "source_type", "source_product", "os_family", "parser_id",
        "parser_confidence", "parse_path", "ocsf_class_uid", "ocsf_class_name",
        "category_name", "activity_name", "severity", "severity_id", "status",
        "host_name", "user_name", "user_domain", "src_ip", "src_port", "dst_ip",
        "dst_port", "process_name", "process_pid", "process_cmd_line",
        "event_code", "message", "needs_review", "raw_object_id", "raw_sha256",
        "extra_fields",
    ]
    try:
        client.insert(f"{CH_DATABASE}.{TABLE}", [row], column_names=columns)
    except Exception:
        return False
    return True


def query(sql: str):
    """Run a read query (for the analytics UI). Returns list[dict] or []."""
    client = get_client()
    if client is None:
        return []
    try:
        res = client.query(sql)
        return [dict(zip(res.column_names, r)) for r in res.result_rows]
    except Exception:
        return []
