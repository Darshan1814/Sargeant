"""
WI5 — parallel/sequential EQUIVALENCE.

Spec #14 (verbatim): "The parallel implementation must produce the SAME
normalized schema and semantics as the existing sequential implementation."

This test drives the *same* mixed corpus through ``engine.parallel.run_parallel``
twice:

  * once with ``EngineConfig(sequential=True)``   → in-process, no pool
  * once with a forced-parallel ``EngineConfig``  → spawn ProcessPool, tiny
    chunks, several chunks in flight (so cross-chunk ordering is exercised)

and asserts the two ordered result streams are byte-for-byte identical after
nulling the three genuinely non-deterministic fields:

  * ``event_id``                    (uuid4, per call — pipeline.py)
  * ``metadata.uid``                (== event_id)
  * ``metadata.processed_time``     (datetime.now — ocsf_mapper.py)
  * ``metadata.ingestion_time``     (None here; filled later by the persister)

Everything else — parser_id, ocsf_class, observables, unmapped/OS blocks,
severity, status, needs_review, event_time, raw_sha256 — is deterministic and
IS compared, so any parsing/classification/mapping divergence between the two
engines fails the test.
"""
import copy
import os
import sys
import tempfile
from pathlib import Path

_REPO_ROOT = Path(__file__).parent.parent.parent
os.environ.setdefault("PARSERS_DIR", str(_REPO_ROOT / "parsers" / "registry"))
_TMP = Path(tempfile.mkdtemp())
os.environ.setdefault("DUCKDB_PATH", str(_TMP / "equiv_cold.db"))
os.environ.setdefault("SQLITE_PATH", str(_TMP / "equiv_hot.sqlite"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from engine.parallel import EngineConfig, run_parallel  # noqa: E402
from engine.streaming import iter_records  # noqa: E402


# A deliberately mixed corpus: every family + macOS registry + malformed lines,
# ordered so that consecutive records land in DIFFERENT chunks under chunk_size=2.
_CORPUS = [
    # Windows security auditing (multi-field, real IP)
    ("Log Name: Security\nSource: Microsoft-Windows-Security-Auditing\n"
     "Event ID: 4624\nComputer: DC01\nNew Logon:\n  Account Name: alice\n"
     "  Logon Type: 3\n  Source Network Address: 10.10.1.20"),
    # Windows key=value
    "Provider=Microsoft-Windows-Kernel-General EventID=12 Level=Information",
    # Android logcat threadtime (service_name → android block)
    ("08-10 09:08:13.239 W/dumpsys ( 3974): Thread Pool max thread count is 0. "
     "serviceName: com.foo.Bar"),
    # Android network tag
    "08-10 09:20:19.692 I/ConnectivityService( 1234): NetworkAgent switched",
    # Linux ssh auth success (with ssh2 → auth_protocol)
    ("Aug 01 00:00:05 srv-file-01 sshd[44218]: Accepted publickey for alice "
     "from 203.0.113.9 port 55214 ssh2"),
    # Linux invalid user (failure)
    "Aug 01 00:01:07 srv-file-01 sshd[44219]: Invalid user admin from 198.51.100.7",
    # Linux netfilter/UFW drop
    ("Aug 01 00:02:00 gw kernel: [UFW BLOCK] IN=eth0 SRC=192.0.2.5 DST=10.0.0.1 "
     "PROTO=TCP SPT=4444 DPT=22"),
    # macOS kernel (must route to MAC-ULOG-001 registry, not Linux family)
    ("Jul  1 09:00:55 calvisitor-10-105-160-95 kernel[0]: "
     "IOThunderboltSwitch<0>(0x0)::listenerCallback"),
    # macOS launchd
    ("May  1 12:34:56 MacBook-Pro launchd[1]: (com.apple.xpc.launchd) "
     "Service exited"),
    # Windows CBS version string (must NOT become an IP)
    ("2016-09-29 02:04:40, Info                  CBS    Read out cached package "
     "applicability for package: Package_for_KB2928120~31bf3856ad364e35~amd64~~"
     "6.1.1.2, ApplicableState: 0, CurrentState:0"),
    # Malformed / unknown → DLQ or drain3 fallback, still enveloped
    "!!! not a log line @@@ 12345",
    "",  # blank — dropped by iter_records, must not shift seq alignment
    # Another unknown to keep the tail in its own chunk
    "random free text with no structure whatsoever",
]


def _scrub(result: dict) -> dict:
    """Copy a pipeline result and null the non-deterministic fields so two
    independent runs can be compared for semantic equality."""
    r = copy.deepcopy(result)
    r["event_id"] = None
    norm = r.get("normalized") or {}
    meta = norm.get("metadata")
    if isinstance(meta, dict):
        meta["uid"] = None
        meta["processed_time"] = None
        meta["ingestion_time"] = None
        # `time` is source-derived (deterministic) whenever a source timestamp
        # exists — `metadata.original_time` is then populated. Only when there
        # is NO source timestamp does the mapper fall back to now(), making
        # `time` a wall-clock value that legitimately differs between two runs.
        # So we null `time` ONLY in that synthetic case; for every timestamped
        # record `time` stays in the comparison (spec #6: event vs processing
        # time are distinct and the event time must be reproduced identically).
        if not meta.get("original_time"):
            norm["time"] = None
    return r


def _collect(config: EngineConfig) -> list[tuple[int, dict]]:
    """Run the corpus through run_parallel with the given config, capturing
    (seq_id, scrubbed_result) in the order persist_fn was invoked."""
    out: list[tuple[int, dict]] = []

    def persist_fn(result: dict, record) -> None:
        out.append((record.seq_id, _scrub(result)))

    # Fresh Record stream per run (generators are single-use).
    records = list(iter_records(_CORPUS))
    summary = run_parallel(records, persist_fn, n_records=len(records),
                           config=config)
    return out, summary


def test_parallel_output_equals_sequential():
    seq_cfg = EngineConfig(workers=1, chunk_size=64, max_inflight=2,
                           sequential=True)
    par_cfg = EngineConfig(workers=2, chunk_size=2, max_inflight=2,
                           sequential=False)

    seq_out, seq_summary = _collect(seq_cfg)
    par_out, par_summary = _collect(par_cfg)

    # Both engines actually ran the mode we asked for.
    assert seq_summary["mode"] == "sequential"
    assert par_summary["mode"] == "parallel"

    # Same number of records processed, none dropped.
    assert seq_summary["processed"] == par_summary["processed"] == len(seq_out)
    assert len(seq_out) > 0

    # Persist order is identical and strictly ascending in both engines.
    seq_ids_s = [sid for sid, _ in seq_out]
    seq_ids_p = [sid for sid, _ in par_out]
    assert seq_ids_s == seq_ids_p == sorted(seq_ids_s)

    # Byte-for-byte semantic equality, record by record (clearer diffs than
    # comparing the whole list at once).
    for (sid_s, res_s), (sid_p, res_p) in zip(seq_out, par_out):
        assert sid_s == sid_p
        assert res_s == res_p, f"divergence at seq_id={sid_s}"


def test_parallel_preserves_raw_sha256_and_parser_ids():
    """Cross-check the two invariants the equivalence guarantee rests on:
    stable content hashes and identical routing per record."""
    par_out, _ = _collect(EngineConfig(workers=2, chunk_size=2,
                                       max_inflight=2, sequential=False))
    records = list(iter_records(_CORPUS))
    by_seq = {rec.seq_id: rec for rec in records}
    for sid, res in par_out:
        # raw_sha256 in the envelope == the stable hash computed at ingest.
        meta = res["normalized"]["metadata"]
        assert meta["raw_sha256"] == by_seq[sid].raw_sha256
        # every record carries a concrete parser_id (never blank).
        assert res.get("parser_id")
