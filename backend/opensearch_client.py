"""
OpenSearch client: indexes normalized OCSF events for full-text search.
Gracefully degrades when opensearch-py is not installed (DuckDB is authoritative).
"""
import os

try:
    from opensearchpy import OpenSearch, RequestsHttpConnection, NotFoundError
    _OPENSEARCH_AVAILABLE = True
except ImportError:
    _OPENSEARCH_AVAILABLE = False

OPENSEARCH_HOST = os.getenv("OPENSEARCH_HOST", "opensearch")
OPENSEARCH_PORT = int(os.getenv("OPENSEARCH_PORT", "9200"))
INDEX_NAME = "ulpf-events"


def get_client():
    if not _OPENSEARCH_AVAILABLE:
        return None
    return OpenSearch(
        hosts=[{"host": OPENSEARCH_HOST, "port": OPENSEARCH_PORT}],
        http_compress=True,
        use_ssl=False,
        verify_certs=False,
        connection_class=RequestsHttpConnection,
    )


def ensure_index():
    client = get_client()
    if not client:
        return
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


def index_event(event_id: str, normalized: dict, source: str):
    client = get_client()
    if not client:
        return
    doc = {
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
    try:
        client.index(index=INDEX_NAME, id=event_id, body=doc)
    except Exception:
        pass  # OpenSearch is best-effort; DuckDB is authoritative


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
