"""
Big-data storage/streaming clients for the ULPF pipeline.

Each client GRACEFULLY DEGRADES when its backing service (or its Python library)
is unavailable — exactly like the existing OpenSearch client. DuckDB remains the
authoritative source of truth, so the framework runs identically with or without
Kafka / MinIO / ClickHouse present. This keeps the system air-gap-friendly and
lets the same code run in a laptop demo and a full Big-Data deployment.

Roles (per the architecture):
  * Kafka      — raw event bus / transport / buffer / replay (topics)
  * MinIO      — immutable raw log archive (object store) → raw_object_id + sha256
  * ClickHouse — normalized OCSF analytics store (search / correlation / detection)
"""
from . import minio_client, clickhouse_client, kafka_client  # noqa: F401

__all__ = ["minio_client", "clickhouse_client", "kafka_client"]
