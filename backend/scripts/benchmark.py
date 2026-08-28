#!/usr/bin/env python3
"""
WI5 — parallel engine BENCHMARK (throughput, parse-only).

Measures records/sec for the sequential vs. parallel engine over a seeded,
family-mixed corpus at several sizes (1K / 10K / 100K / optional large). It is a
*throughput* harness, not a correctness one — equivalence is proven separately by
tests/test_parallel_equivalence.py. To isolate engine/parse cost from I/O the
persist callback is a no-op counter (this matches the engine's scope: "process
pool, parse-only"; DB writes happen elsewhere and would only add noise here).

Usage
-----
    # defaults: sizes 1000, 10000, 100000
    python scripts/benchmark.py

    # custom sizes (records), e.g. include a 1M "large" run
    python scripts/benchmark.py 1000 10000 100000 1000000

    # env knobs
    SEED=1337                 reproducible corpus (default 1337)
    ULPF_MAX_WORKERS=8        worker ceiling (read by engine.autosize)

Reproducibility: the corpus is seeded, so run-to-run timings compare the SAME
inputs. The reported speedup is parallel_records_per_sec / sequential_...; on a
single-core host autosize may keep both runs sequential (speedup ≈ 1.0) — that is
correct behaviour, not a benchmark failure.
"""
from __future__ import annotations

import os
import random
import sys
import time
from pathlib import Path

_BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_BACKEND))

# Storage paths must exist before workers import `pipeline` (spawn re-imports it).
# We never write through them (no-op persist), but the import graph may open them.
_REPO_ROOT = _BACKEND.parent
os.environ.setdefault("PARSERS_DIR", str(_REPO_ROOT / "parsers" / "registry"))
import tempfile as _tf  # noqa: E402

_TMP = Path(_tf.mkdtemp(prefix="ulpf_bench_"))
os.environ.setdefault("DUCKDB_PATH", str(_TMP / "bench_cold.db"))
os.environ.setdefault("SQLITE_PATH", str(_TMP / "bench_hot.sqlite"))

from engine.parallel import EngineConfig, autosize, run_parallel  # noqa: E402
from engine.streaming import iter_records  # noqa: E402
from testdata.generate_logs import (  # noqa: E402
    g_win_sec_4625, g_mac_appfw, g_fw_generic, g_fw_w3c,
    g_linux_syslog, g_linux_auth,
)

_ANDROID_TAGS = ["ActivityManager", "ConnectivityService", "dumpsys",
                 "WindowManager", "PackageManager", "art"]


def _g_android() -> str:
    """A threadtime logcat line (the generator module has no Android source)."""
    return "%02d-%02d %02d:%02d:%02d.%03d %s/%s(%5d): %s" % (
        random.randint(1, 12), random.randint(1, 28),
        random.randint(0, 23), random.randint(0, 59), random.randint(0, 59),
        random.randint(0, 999), random.choice("VDIWEF"),
        random.choice(_ANDROID_TAGS), random.randint(1000, 9999),
        random.choice(["onResume", "NetworkAgent switched",
                       "serviceName: com.foo.Bar", "GC freed 1234 objects"]),
    )


# Weighted so all three target families (Windows/Linux/Android) + macOS/firewall
# appear, roughly mirroring a heterogeneous SIEM feed.
_GENERATORS = [
    g_linux_syslog, g_linux_auth, g_linux_syslog,     # Linux (heavy)
    _g_android, _g_android,                            # Android
    g_win_sec_4625,                                    # Windows (multi-line)
    g_mac_appfw, g_fw_generic, g_fw_w3c,               # macOS / firewall
]


def build_corpus(n: int, seed: int) -> list[str]:
    """Deterministically generate `n` raw records from the mixed family set."""
    random.seed(seed)
    return [random.choice(_GENERATORS)() for _ in range(n)]


def _run(records, config) -> tuple[int, float]:
    """Run one engine pass; return (processed_count, wall_seconds)."""
    counter = {"n": 0}

    def persist_fn(_result, _record) -> None:
        counter["n"] += 1

    t0 = time.perf_counter()
    summary = run_parallel(records, persist_fn, n_records=len(records),
                           config=config)
    dt = time.perf_counter() - t0
    assert summary["processed"] == counter["n"]
    return counter["n"], dt, summary["mode"]


def _fmt(n: int, dt: float, mode: str) -> str:
    rps = n / dt if dt > 0 else float("inf")
    return f"{mode:10} {n:>9,} recs  {dt:8.3f}s  {rps:>12,.0f} rec/s"


def bench_size(n: int, seed: int) -> None:
    raws = build_corpus(n, seed)

    seq_cfg = EngineConfig(workers=1, chunk_size=1024, max_inflight=2,
                           sequential=True)
    par_cfg = autosize(n)
    # Force the pool on even for small n so the comparison is meaningful; keep
    # autosize's worker/chunk choices (its small-batch skip would otherwise make
    # the "parallel" run identical to sequential).
    if par_cfg.sequential:
        cpu = os.cpu_count() or 2
        par_cfg = EngineConfig(workers=max(2, min(cpu - 1, 8)),
                               chunk_size=max(64, n // 16 or 64),
                               max_inflight=4, sequential=False)

    seq_n, seq_dt, seq_mode = _run(list(iter_records(raws)), seq_cfg)
    par_n, par_dt, par_mode = _run(list(iter_records(raws)), par_cfg)

    assert seq_n == par_n == n, (seq_n, par_n, n)
    speedup = (seq_dt / par_dt) if par_dt > 0 else float("inf")

    print(f"\n── {n:,} records " + "─" * 40)
    print("  " + _fmt(seq_n, seq_dt, seq_mode))
    print("  " + _fmt(par_n, par_dt, par_mode))
    print(f"  speedup (seq/par): {speedup:5.2f}x   "
          f"[workers={par_cfg.workers} chunk={par_cfg.chunk_size} "
          f"inflight={par_cfg.max_inflight}]")


def main(argv: list[str]) -> int:
    seed = int(os.getenv("SEED", "1337"))
    sizes = [int(a) for a in argv[1:]] if len(argv) > 1 else [1_000, 10_000, 100_000]
    print(f"ULPF parallel-engine benchmark  (seed={seed}, cpu={os.cpu_count()})")
    print(f"corpus: mixed families {', '.join(g.__name__ for g in dict.fromkeys(_GENERATORS))}")
    for n in sizes:
        bench_size(n, seed)
    print("\ndone.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
