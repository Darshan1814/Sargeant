"""
Kafka consumer worker — the streaming ingest path.

Runs as a separate process/container. Subscribes to `logs.raw` and runs each raw
event through the SAME pipeline (`pipeline.process`) + persistence used by the
HTTP ingest path, so collectors can stream logs to Kafka instead of (or as well
as) POSTing to /api/ingest. This is what makes the framework handle high-volume
streaming without changing the parsing/normalization logic.

Parallelism (spec #12/#13)
--------------------------
Messages are consumed in **micro-batches** and handed to the shared parallel
engine (`engine.parallel.run_parallel`): parsing fans out across a bounded worker
pool while persistence stays in THIS process (single DB writer), exactly like the
HTTP batch path. Auto-sizing keeps small batches sequential (no pool spin-up) and
only spreads large batches across workers — identical output either way (spec #14).

At-least-once delivery
----------------------
Auto-commit is DISABLED. Offsets are committed only AFTER a batch has been fully
persisted. If the worker dies mid-batch, uncommitted messages are re-delivered and
re-processed — records carry stable `raw_sha256` identities so downstream can
dedupe. We never commit ahead of persistence (which would silently drop events).

Start:  python -m storage.kafka_consumer
Env:    KAFKA_BOOTSTRAP_SERVERS, KAFKA_TOPIC_RAW, KAFKA_GROUP_ID,
        KAFKA_BATCH_SIZE (max messages per micro-batch, default 500),
        KAFKA_BATCH_WAIT_MS (max ms to fill a batch before flushing, default 1000)

Gracefully exits with a clear message if no Kafka client library is installed.
"""
from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Ensure the backend package root is importable when run as a module.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
TOPIC_RAW = os.getenv("KAFKA_TOPIC_RAW", "logs.raw")
GROUP_ID = os.getenv("KAFKA_GROUP_ID", "ulpf-parser-engine")


def _env_int(name: str, default: int) -> int:
    try:
        v = int(os.getenv(name, "").strip())
        return v if v > 0 else default
    except (TypeError, ValueError):
        return default


BATCH_SIZE = _env_int("KAFKA_BATCH_SIZE", 500)
BATCH_WAIT_MS = _env_int("KAFKA_BATCH_WAIT_MS", 1000)


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


def _process_batch(batch: list[tuple[str, str]], persist_result, run_parallel,
                   iter_records) -> int:
    """Parse+persist one micro-batch through the parallel engine.

    ``batch`` is a list of (raw_log, source) in consume order. Each Kafka message
    is one logical event (no cross-message grouping — different messages may be
    unrelated events from different sources), so we build one Record per message.

    All records in a batch share one ``ingestion_time`` — the moment ULPF received
    this batch — kept distinct from event_time / processed_time (spec #6).
    """
    if not batch:
        return 0
    ingestion_time = datetime.now(timezone.utc).isoformat()
    # Align a per-record source list with the Record seq_ids. `iter_records`
    # assigns 1-based seq_ids over the non-blank raws it yields; we already
    # dropped blanks below, so sources[rec.seq_id - 1] is this record's source.
    raws = [raw for raw, _ in batch]
    sources = [src for _, src in batch]

    def _persist(result: dict, rec) -> None:
        try:
            persist_result(result, rec.raw, ingestion_time, sources[rec.seq_id - 1])
        except Exception as exc:  # pragma: no cover - defensive persistence guard
            print(f"[kafka-consumer] persist failed seq={rec.seq_id}: {exc}",
                  file=sys.stderr)

    records = iter_records(raws)
    summary = run_parallel(records, persist_fn=_persist, n_records=len(raws))
    return int(summary.get("processed", 0))


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
    # Persistence stays in THIS process; parsing fans out via the shared engine.
    from main import _persist_result  # exact HTTP-ingest persistence path
    from engine.parallel import run_parallel
    from engine.streaming import iter_records

    print(f"[kafka-consumer] connecting to {KAFKA_BOOTSTRAP}, topic={TOPIC_RAW}, "
          f"group={GROUP_ID} via {kind}; batch_size={BATCH_SIZE}, "
          f"batch_wait_ms={BATCH_WAIT_MS}")

    if kind == "confluent":
        consumer = Consumer({
            "bootstrap.servers": KAFKA_BOOTSTRAP,
            "group.id": GROUP_ID,
            "auto.offset.reset": "earliest",
            # At-least-once: we commit only after a batch is persisted.
            "enable.auto.commit": False,
        })
        consumer.subscribe([TOPIC_RAW])
        try:
            while True:
                batch: list[tuple[str, str]] = []
                deadline = time.monotonic() + BATCH_WAIT_MS / 1000.0
                # Accumulate up to BATCH_SIZE messages or until the wait window
                # closes, so latency stays bounded when traffic is sparse.
                while len(batch) < BATCH_SIZE and time.monotonic() < deadline:
                    msg = consumer.poll(0.2)
                    if msg is None:
                        continue
                    if msg.error():
                        print(f"[kafka-consumer] error: {msg.error()}",
                              file=sys.stderr)
                        continue
                    raw_log, source = _extract_raw(msg.value())
                    if raw_log and raw_log.strip():
                        batch.append((raw_log, source))
                if not batch:
                    continue
                try:
                    _process_batch(batch, _persist_result, run_parallel,
                                   iter_records)
                    # Commit only after the whole batch is persisted.
                    consumer.commit(asynchronous=False)
                except Exception as exc:
                    # Do NOT commit — the batch will be re-delivered and retried.
                    print(f"[kafka-consumer] batch failed (will retry): {exc}",
                          file=sys.stderr)
        finally:
            consumer.close()
    else:
        consumer = KafkaConsumer(
            TOPIC_RAW,
            bootstrap_servers=KAFKA_BOOTSTRAP.split(","),
            group_id=GROUP_ID,
            auto_offset_reset="earliest",
            # At-least-once: manual commit after each persisted batch.
            enable_auto_commit=False,
        )
        try:
            while True:
                # poll returns {TopicPartition: [records]}; bound by size + time.
                polled = consumer.poll(timeout_ms=BATCH_WAIT_MS,
                                       max_records=BATCH_SIZE)
                batch: list[tuple[str, str]] = []
                for _tp, msgs in polled.items():
                    for msg in msgs:
                        raw_log, source = _extract_raw(msg.value)
                        if raw_log and raw_log.strip():
                            batch.append((raw_log, source))
                if not batch:
                    continue
                try:
                    _process_batch(batch, _persist_result, run_parallel,
                                   iter_records)
                    consumer.commit()
                except Exception as exc:
                    print(f"[kafka-consumer] batch failed (will retry): {exc}",
                          file=sys.stderr)
        finally:
            consumer.close()


if __name__ == "__main__":
    while True:
        try:
            run()
        except KeyboardInterrupt:
            break
        except Exception as exc:
            print(f"[kafka-consumer] crashed, retrying in 5s: {exc}", file=sys.stderr)
            time.sleep(5)
