"""
Kafka raw event bus (transport / buffer / replay).

Kafka is NOT a database here — it is the streaming backbone that decouples
collectors from the parser engine and enables replay + back-pressure handling.

Topics (per the architecture):
    logs.raw          — every ingested raw event (pre-parse)
    logs.normalized   — successfully normalized OCSF events
    logs.dlq          — events that could not be parsed (dead-letter)

Producing is fire-and-forget and gracefully degrades: if `confluent-kafka`/
`kafka-python` or the broker is unavailable, `publish()` is a no-op returning
False, and the HTTP ingest path still persists to DuckDB. This keeps a laptop
demo working while a full deployment gains streaming.
"""
from __future__ import annotations

import json
import os

_PRODUCER = None
_PRODUCER_FAILED = False  # cache init failure so we don't retry on every call
_KIND = None  # "confluent" | "kafka-python" | None

# Prefer confluent-kafka (librdkafka) if present, else kafka-python, else none.
try:
    from confluent_kafka import Producer as _ConfluentProducer  # type: ignore
    _KIND = "confluent"
except Exception:
    try:
        from kafka import KafkaProducer as _KafkaPythonProducer  # type: ignore
        _KIND = "kafka-python"
    except Exception:
        _KIND = None

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
KAFKA_ENABLED = os.getenv("KAFKA_ENABLED", "true").lower() == "true"

TOPIC_RAW = os.getenv("KAFKA_TOPIC_RAW", "logs.raw")
TOPIC_NORMALIZED = os.getenv("KAFKA_TOPIC_NORMALIZED", "logs.normalized")
TOPIC_DLQ = os.getenv("KAFKA_TOPIC_DLQ", "logs.dlq")


def available() -> bool:
    return _KIND is not None and KAFKA_ENABLED


def _get_producer():
    global _PRODUCER, _PRODUCER_FAILED
    if not available() or _PRODUCER_FAILED:
        return None
    if _PRODUCER is not None:
        return _PRODUCER
    try:
        if _KIND == "confluent":
            _PRODUCER = _ConfluentProducer({
                "bootstrap.servers": KAFKA_BOOTSTRAP,
                "socket.timeout.ms": 3000,
                "message.timeout.ms": 5000,
            })
        elif _KIND == "kafka-python":
            _PRODUCER = _KafkaPythonProducer(
                bootstrap_servers=KAFKA_BOOTSTRAP.split(","),
                value_serializer=lambda v: v.encode("utf-8") if isinstance(v, str) else v,
                request_timeout_ms=5000,
                retries=0,
            )
    except Exception:
        _PRODUCER = None
        _PRODUCER_FAILED = True
    return _PRODUCER


def publish(topic: str, payload: dict | str, key: str | None = None) -> bool:
    """Fire-and-forget publish. Returns True if handed to the producer."""
    producer = _get_producer()
    if producer is None:
        return False
    value = payload if isinstance(payload, str) else json.dumps(payload, default=str)
    try:
        if _KIND == "confluent":
            producer.produce(topic, value=value.encode("utf-8"),
                             key=(key.encode("utf-8") if key else None))
            producer.poll(0)  # serve delivery callbacks without blocking
        else:  # kafka-python
            producer.send(topic, value=value,
                          key=(key.encode("utf-8") if key else None))
        return True
    except Exception:
        return False


def publish_raw(event_id: str, raw_log: str, source: str,
                raw_object_id: str = "", raw_sha256: str = "") -> bool:
    return publish(TOPIC_RAW, {
        "event_id": event_id, "source": source, "raw_log": raw_log,
        "raw_object_id": raw_object_id, "raw_sha256": raw_sha256,
    }, key=event_id)


def publish_normalized(event_id: str, normalized: dict) -> bool:
    return publish(TOPIC_NORMALIZED, {"event_id": event_id, "normalized": normalized},
                   key=event_id)


def publish_dlq(event_id: str, raw_log: str, error: str) -> bool:
    return publish(TOPIC_DLQ, {"event_id": event_id, "raw_log": raw_log, "error": error},
                   key=event_id)


def flush(timeout: float = 2.0):
    producer = _get_producer()
    if producer is None:
        return
    try:
        producer.flush(timeout)
    except Exception:
        pass
