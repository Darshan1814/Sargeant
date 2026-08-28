"""
OpenSearch client: indexes normalized OCSF events for full-text search.
Gracefully degrades when opensearch-py is not installed (DuckDB is authoritative).

Performance notes (why this file looks the way it does):
  * The client is built **once** (module singleton), not per call. Rebuilding an
    ``OpenSearch`` object per record re-creates a connection pool every time and
    was a major cost on the 20K batch path.
  * A bulk API (:func:`bulk_index`) turns N single-doc HTTP round-trips into ONE
    ``_bulk`` request, which is how the batch persist path indexes a whole chunk.
  * A **circuit breaker** short-circuits all calls for a cooldown window after a
    failure. When OpenSearch is unreachable (e.g. the ``opensearch`` docker host
    doesn't resolve in a local/air-gapped run) this avoids paying a connection
    timeout on every one of 20,000 records — indexing simply no-ops until the
    cooldown lapses, and DuckDB/SQLite remain authoritative.
"""
import os
import time

try:
    from opensearchpy import OpenSearch, RequestsHttpConnection, NotFoundError
    _OPENSEARCH_AVAILABLE = True
except ImportError:
    _OPENSEARCH_AVAILABLE = False

OPENSEARCH_HOST = os.getenv("OPENSEARCH_HOST", "opensearch")
OPENSEARCH_PORT = int(os.getenv("OPENSEARCH_PORT", "9200"))
INDEX_NAME = "ulpf-events"

# After a failed call we stop trying for this many seconds so an unreachable
# cluster can't cost one connect-timeout per record across a large batch.
_BREAKER_COOLDOWN = float(os.getenv("OPENSEARCH_BREAKER_COOLDOWN", "30"))

_client = None            # built lazily, ONCE
_client_built = False
_breaker_until = 0.0      # monotonic deadline; calls no-op until now() passes it


def _breaker_open() -> bool:
    return time.monotonic() < _breaker_until


def _trip_breaker():
    """Open the breaker for the cooldown window (host looks unreachable)."""
    global _breaker_until
    _breaker_until = time.monotonic() + _BREAKER_COOLDOWN


def get_client():
    """Return the shared OpenSearch client (built once), or ``None`` when the
    library is missing or the circuit breaker is currently open."""
    global _client, _client_built
    if not _OPENSEARCH_AVAILABLE or _breaker_open():
        return None
    if not _client_built:
        _client = OpenSearch(
            hosts=[{"host": OPENSEARCH_HOST, "port": OPENSEARCH_PORT}],
            http_compress=True,
            use_ssl=False,
            verify_certs=False,
            connection_class=RequestsHttpConnection,
            # Fail fast when the host is down instead of hanging the persist loop.
            timeout=int(os.getenv("OPENSEARCH_TIMEOUT", "5")),
            max_retries=1,
            retry_on_timeout=False,
        )
        _client_built = True
    return _client


def ensure_index():
    client = get_client()
    if not client:
        return
    try:
        if not client.indices.exists(INDEX_NAME):
            client.indices.create(
                index=INDEX_NAME,
                body={
                    "mappings": {
                        "properties": {
                            "event_id":   {"type": "keyword"},
                            "parser_id":  {"type": "keyword"},
                            "class_uid":  {"type": "integer"},
                            "time":       {"type": "date"},
                            "severity":   {"type": "keyword"},
                            "message":    {"type": "text"},
                            "raw_data":   {"type": "text"},
                            "source":     {"type": "keyword"},
                            "needs_review": {"type": "boolean"},
                        }
                    }
                },
            )
    except Exception:
        _trip_breaker()  # unreachable at startup → don't hammer it per record


def _make_doc(event_id: str, normalized: dict, source: str) -> dict:
    """Build the flat search document indexed for one event. Single source of
    truth shared by the single-doc and bulk paths so they stay identical."""
    return {
        "event_id": event_id,
        "parser_id": normalized.get("metadata", {}).get("parser_id"),
        "class_uid": normalized.get("class_uid"),
        "time": normalized.get("time"),
        "severity": normalized.get("severity"),
        "message": normalized.get("message", ""),
        "raw_data": normalized.get("raw_data", ""),
        "source": source,
        "needs_review": normalized.get("needs_review", False),
    }


def index_event(event_id: str, normalized: dict, source: str):
    """Index a SINGLE event (used by the synchronous /api/ingest path)."""
    client = get_client()
    if not client:
        return
    try:
        client.index(index=INDEX_NAME, id=event_id, body=_make_doc(event_id, normalized, source))
    except Exception:
        _trip_breaker()  # OpenSearch is best-effort; DuckDB is authoritative


def bulk_index(items: list) -> None:
    """Index a batch of events in ONE ``_bulk`` request.

    ``items`` is a list of ``(event_id, normalized, source)`` tuples. Best-effort:
    any failure trips the breaker (so the rest of a large batch skips OpenSearch
    instead of timing out per chunk) and is swallowed — the authoritative copy
    already lives in SQLite/DuckDB.
    """
    if not items:
        return
    client = get_client()
    if not client:
        return
    body = []
    for event_id, normalized, source in items:
        body.append({"index": {"_index": INDEX_NAME, "_id": event_id}})
        body.append(_make_doc(event_id, normalized, source))
    try:
        client.bulk(body=body)
    except Exception:
        _trip_breaker()


def search_events(query: str, size: int = 50) -> list[dict]:
    client = get_client()
    if not client:
        return []
    try:
        resp = client.search(
            index=INDEX_NAME,
            body={"query": {"multi_match": {"query": query, "fields": ["message", "raw_data", "source"]}}, "size": size},
        )
        return [hit["_source"] for hit in resp["hits"]["hits"]]
    except Exception:
        return []
