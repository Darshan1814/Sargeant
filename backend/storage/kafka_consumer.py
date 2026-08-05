"""
Kafka consumer worker — the streaming ingest path.

Runs as a separate process/container. Subscribes to `logs.raw`, runs each raw
event through the SAME pipeline (`pipeline.process`) + persistence used by the
HTTP ingest path, so collectors can stream logs to Kafka instead of (or as well
as) POSTing to /api/ingest. This is what makes the framework handle high-volume
streaming without changing the parsing/normalization logic.

Start:  python -m storage.kafka_consumer
Env:    KAFKA_BOOTSTRAP_SERVERS, KAFKA_TOPIC_RAW, KAFKA_GROUP_ID

Gracefully exits with a clear message if no Kafka client library is installed.
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

# Ensure the backend package root is importable when run as a module.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
TOPIC_RAW = os.getenv("KAFKA_TOPIC_RAW", "logs.raw")
GROUP_ID = os.getenv("KAFKA_GROUP_ID", "ulpf-parser-engine")


def _extract_raw(value: bytes) -> tuple[str, str]:
    """Return (raw_log, source) from a raw-topic message. Accepts either a JSON
    envelope {"raw_log": ..., "source": ...} or a bare log line."""
    text = value.decode("utf-8", errors="replace")
    try:
        obj = json.loads(text)
        if isinstance(obj, dict) and "raw_log" in obj:
            return str(obj["raw_log"]), str(obj.get("source", "kafka"))
    except (json.JSONDecodeError, TypeError):
        pass
    return text, "kafka"


def run():
    try:
        from confluent_kafka import Consumer  # type: ignore
        kind = "confluent"
    except Exception:
        try:
            from kafka import KafkaConsumer  # type: ignore
            kind = "kafka-python"
        except Exception:
            print("[kafka-consumer] no Kafka client library installed; exiting.",
                  file=sys.stderr)
            return

    # Import here so a missing pipeline dep doesn't crash the import-time check.
    from main import _process_one  # reuse the exact HTTP ingest processing path

    print(f"[kafka-consumer] connecting to {KAFKA_BOOTSTRAP}, topic={TOPIC_RAW}, "
          f"group={GROUP_ID} via {kind}")

    if kind == "confluent":
        consumer = Consumer({
            "bootstrap.servers": KAFKA_BOOTSTRAP,
            "group.id": GROUP_ID,
            "auto.offset.reset": "earliest",
        })
        consumer.subscribe([TOPIC_RAW])
        try:
            while True:
                msg = consumer.poll(1.0)
                if msg is None:
                    continue
                if msg.error():
                    print(f"[kafka-consumer] error: {msg.error()}", file=sys.stderr)
                    continue
                raw_log, source = _extract_raw(msg.value())
                try:
                    _process_one(raw_log, source)
                except Exception as exc:
                    print(f"[kafka-consumer] process failed: {exc}", file=sys.stderr)
        finally:
            consumer.close()
    else:
        consumer = KafkaConsumer(
            TOPIC_RAW,
            bootstrap_servers=KAFKA_BOOTSTRAP.split(","),
            group_id=GROUP_ID,
            auto_offset_reset="earliest",
        )
        for msg in consumer:
            raw_log, source = _extract_raw(msg.value)
            try:
                _process_one(raw_log, source)
            except Exception as exc:
                print(f"[kafka-consumer] process failed: {exc}", file=sys.stderr)


if __name__ == "__main__":
    while True:
        try:
            run()
        except KeyboardInterrupt:
            break
        except Exception as exc:
            print(f"[kafka-consumer] crashed, retrying in 5s: {exc}", file=sys.stderr)
            time.sleep(5)
