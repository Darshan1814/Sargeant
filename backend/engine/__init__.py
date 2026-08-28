"""
ULPF parallel processing engine.

Two pieces, kept deliberately small and dependency-light so worker processes can
import them cheaply under the `spawn` start method:

  * ``streaming`` — the single source of truth for grouping physical log lines
    into logical (possibly multi-line) records, plus a stable ``Record`` type
    that carries a deterministic ``seq_id`` and a content ``raw_sha256``.
  * ``parallel`` — an optimized parallel *chunk* processor that runs the EXACT
    same ``pipeline.process`` per record, only faster: bounded worker pool,
    bounded in-flight backpressure, deterministic in-order persistence.

The engine optimizes throughput WITHOUT changing parsing correctness: a worker
does nothing a sequential run wouldn't do — it calls ``pipeline.process(raw)``.
"""
