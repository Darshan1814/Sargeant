"""
MinIO raw-log archive (immutable evidence store).

Every ingested raw event is written to MinIO under a content-addressed key so it
can be replayed later (e.g. after a parser is fixed) and cross-checked for
forensic integrity. We return a `raw_object_id` + `sha256` that ClickHouse and
the OCSF metadata carry, giving analysts a pivot:

    ClickHouse event → raw_object_id → MinIO → ORIGINAL bytes

Object layout:
    raw/<source>/<yyyy>/<mm>/<dd>/<sha256>.log

Gracefully degrades: if the `minio` library or the server is unavailable, every
function is a no-op that returns None and the pipeline continues on DuckDB alone.
"""
from __future__ import annotations

import hashlib
import io
import os
from datetime import datetime, timezone

try:
    from minio import Minio  # type: ignore
    _MINIO_AVAILABLE = True
except Exception:  # library not installed
    _MINIO_AVAILABLE = False

MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "minio:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "minioadmin")
MINIO_BUCKET = os.getenv("MINIO_BUCKET", "ulpf-raw")
MINIO_SECURE = os.getenv("MINIO_SECURE", "false").lower() == "true"

_client = None
_bucket_ready = False
_bucket_failed = False


def sha256_hex(raw_log: str) -> str:
    """Content hash of the raw log (stable identifier / integrity check)."""
    return hashlib.sha256(raw_log.encode("utf-8", errors="replace")).hexdigest()


def available() -> bool:
    return _MINIO_AVAILABLE


def get_client():
    global _client
    if not _MINIO_AVAILABLE:
        return None
    if _client is None:
        try:
            _client = Minio(
                MINIO_ENDPOINT,
                access_key=MINIO_ACCESS_KEY,
                secret_key=MINIO_SECRET_KEY,
                secure=MINIO_SECURE,
            )
        except Exception:
            _client = None
    return _client


def _ensure_bucket(client) -> bool:
    global _bucket_ready, _bucket_failed
    if _bucket_ready:
        return True
    if _bucket_failed:
        return False
    try:
        if not client.bucket_exists(MINIO_BUCKET):
            client.make_bucket(MINIO_BUCKET)
        _bucket_ready = True
    except Exception:
        _bucket_failed = True
        return False
    return _bucket_ready


def archive_raw(raw_log: str, source: str = "unknown") -> dict | None:
    """Store one raw log immutably. Returns {raw_object_id, raw_sha256, bucket}
    or None if MinIO is unavailable (pipeline continues regardless)."""
    client = get_client()
    if client is None:
        return None
    if not _ensure_bucket(client):
        return None

    digest = sha256_hex(raw_log)
    now = datetime.now(timezone.utc)
    safe_source = (source or "unknown").replace("/", "_").replace(" ", "_")
    key = f"raw/{safe_source}/{now:%Y/%m/%d}/{digest}.log"
    data = raw_log.encode("utf-8", errors="replace")
    try:
        client.put_object(
            MINIO_BUCKET, key, io.BytesIO(data), length=len(data),
            content_type="text/plain",
            metadata={"source": safe_source, "sha256": digest},
        )
    except Exception:
        return None
    return {"raw_object_id": key, "raw_sha256": digest, "bucket": MINIO_BUCKET}


def fetch_raw(raw_object_id: str) -> str | None:
    """Retrieve archived raw bytes by object id (for replay / forensics)."""
    client = get_client()
    if client is None:
        return None
    try:
        resp = client.get_object(MINIO_BUCKET, raw_object_id)
        return resp.read().decode("utf-8", errors="replace")
    except Exception:
        return None
    finally:
        try:
            resp.close(); resp.release_conn()
        except Exception:
            pass
