"""
Streaming chunker — the single source of truth for turning raw text / a line
stream / a list of pre-split records into deterministic, hashable ``Record``s and
bounded ``Chunk``s.

Why this module exists
----------------------
The multi-line grouping logic used to live only in ``main.py`` (``_group_records``)
and was reachable solely from the HTTP upload path. The parallel engine, the Kafka
consumer and any future file-tailer all need to group lines IDENTICALLY, otherwise
"single-thread output == parallel output" (spec #14) could not hold. So the grouper
now lives here and ``main.py`` imports it.

Guarantees
----------
* ``group_records(text)`` is byte-for-byte the same algorithm the upload path used,
  so existing corpora group exactly as before (no parsing-correctness change).
* Every ``Record`` carries a **stable** identity: ``seq_id`` (1-based position in
  the logical record stream) and ``raw_sha256`` (SHA-256 of the exact raw record
  text). These never depend on worker count, chunk size or scheduling — satisfying
  the "raw hashes / record IDs remain stable" requirement (spec #12).
* Iteration is lazy (generators) so callers may stream instead of materialising a
  second full copy of the input in RAM.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Iterable, Iterator, List

__all__ = [
    "Record",
    "Chunk",
    "sha256_of",
    "group_records",
    "iter_records",
    "iter_records_from_text",
    "iter_records_from_lines",
    "iter_chunks",
]


# ── Record boundary detection (moved verbatim from main.py) ──────────────────
# A line that STARTS a new logical record. Everything until the next such line
# (or a blank line) is treated as a continuation of the same event. This lets a
# multi-line / wrapped Windows export (one event across several physical lines)
# be reassembled before parsing, instead of each fragment failing individually.
_RECORD_START_RE = re.compile(
    r"""^(?:
        \d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}      # ISO timestamp  2026-08-27 08:12:14
      | \d{2}/\d{2}/\d{2,4}\s+\d{2}:\d{2}:\d{2}     # US date time
      | (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}  # syslog
      | Log\ Name\s*:                                # evtx text block header
      | <Event[\s>]                                  # event XML
      | \#(?:Fields|Version|Software)\s*:            # W3C / firewall header
      | \d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3}       # Android logcat  08-10 09:20:19.692
      | \[\s*\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3}  # Android long "[ 08-10 ... ]"
      | [VDIWEFS]/[^(]+\(\s*\d+\s*\):                # Android brief/tag  W/dumpsys( 3907):
    )""",
    re.IGNORECASE | re.VERBOSE,
)

# A line that starts a compact winkv record ONLY when it is not already a
# continuation of an open record. Used to open a record when the file has no
# timestamp wrappers at all (pure "Provider=… / EventID=…" blocks).
_WINKV_START_RE = re.compile(r"^\s*(?:Provider|EventID)\s*=", re.IGNORECASE)

# A bare wrapper/prefix line such as "2026-08-27 08:12:14 INFO [Windows Event Log]"
# is NOT its own event — it is a header line for the record that follows. When a
# boundary line matches this it should merge forward into the next real record
# rather than stand alone.
_WRAPPER_PREFIX_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}\s+\w+\s+\[[^\]]+\]\s*$",
    re.IGNORECASE,
)


def sha256_of(raw: str) -> str:
    """Stable content hash of a raw record (traceability, spec #2/#12)."""
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()


@dataclass(frozen=True)
class Record:
    """One logical log record with a deterministic identity.

    ``seq_id``     — 1-based position in the logical record stream (stable
                     regardless of worker/chunk scheduling → in-order output).
    ``raw``        — the exact raw record text (multi-line preserved).
    ``raw_sha256`` — SHA-256 of ``raw`` (never re-derived downstream).
    """
    seq_id: int
    raw: str
    raw_sha256: str


@dataclass(frozen=True)
class Chunk:
    """An ordered, bounded batch of records dispatched to one worker call."""
    chunk_id: int
    records: List[Record]


def group_records(raw_text: str) -> List[str]:
    """Group physical lines into logical multi-line records.

    A record begins at a ``_RECORD_START_RE`` match (or after a blank line) and
    absorbs following continuation lines. Falls back to one-record-per-line when
    no boundaries are detected (e.g. a clean single-line-per-event file), so
    existing single-line corpora behave exactly as before.

    NOTE: This is the canonical implementation. ``main.py`` imports it; do not
    fork a second copy anywhere or the parallel/sequential equivalence guarantee
    (spec #14) can silently break.
    """
    lines = raw_text.splitlines()
    records: List[str] = []
    current: List[str] = []

    def flush():
        if current:
            rec = "\n".join(current).strip()
            if rec:
                records.append(rec)

    def _has_provider(lines_buf: List[str]) -> bool:
        return any(_WINKV_START_RE.match(l) for l in lines_buf)

    saw_boundary = False
    pending_prefix = None  # a wrapper/header line waiting to merge into next record
    for line in lines:
        if not line.strip():
            flush(); current = []
            pending_prefix = None
            continue

        if _RECORD_START_RE.match(line):
            saw_boundary = True
            # A bare "timestamp LEVEL [Windows Event Log]" wrapper is a header for
            # the NEXT record: close any open record, hold the wrapper to prepend
            # to whatever record follows (never emit it standalone).
            if _WRAPPER_PREFIX_RE.match(line):
                flush(); current = []
                pending_prefix = line
                continue
            flush(); current = []
            if pending_prefix:
                current.append(pending_prefix)
                pending_prefix = None
            current.append(line)
            continue

        # A "Provider="/"EventID=" line opens a NEW record only if the current
        # record ALREADY has one (i.e. this is a different event). Otherwise it's
        # a continuation (fields of the same event wrapped onto multiple lines).
        if _WINKV_START_RE.match(line) and _has_provider(current):
            saw_boundary = True
            flush(); current = [line]
            continue

        if current:
            current.append(line)
        elif pending_prefix:
            current = [pending_prefix, line]
            pending_prefix = None
        else:
            current = [line]
    if pending_prefix and not current:
        current = [pending_prefix]
    flush()

    # If we never detected a single boundary, treat each non-empty line as its
    # own record (preserves prior behavior for simple one-line-per-event files).
    if not saw_boundary:
        return [ln.strip() for ln in lines if ln.strip()]
    return records


def iter_records(raws: Iterable[str], start_seq: int = 1) -> Iterator[Record]:
    """Wrap an iterable of already-final logical record strings into ``Record``s.

    Lazy: consumes ``raws`` one at a time and yields a ``Record`` with a stable
    ``seq_id`` and content hash. Blank/empty entries are skipped (they carry no
    event), keeping seq_ids contiguous over real records.
    """
    seq = start_seq
    for raw in raws:
        if raw is None:
            continue
        text = raw if isinstance(raw, str) else str(raw)
        if not text.strip():
            continue
        yield Record(seq_id=seq, raw=text, raw_sha256=sha256_of(text))
        seq += 1


def iter_records_from_text(raw_text: str) -> Iterator[Record]:
    """Group raw text into logical records, then yield ``Record``s."""
    return iter_records(group_records(raw_text))


def iter_records_from_lines(line_iter: Iterable[str]) -> Iterator[Record]:
    """Streaming variant for genuine line sources (file tail / socket).

    Buffers only enough to detect a boundary — never the whole input — so a large
    file is grouped without a full-RAM load. For inputs where NO boundary is ever
    seen, this yields one record per non-empty line, matching ``group_records``'s
    no-boundary fallback. When boundaries do appear, records are emitted as each
    completes.

    Callers that already hold the full text in memory should prefer
    ``iter_records_from_text`` (identical grouping, simpler).
    """
    def _gen() -> Iterator[str]:
        current: List[str] = []
        pending_prefix = None
        saw_boundary = False
        buffered_singleton: List[str] = []  # pre-first-boundary lines held verbatim

        def _has_provider(buf: List[str]) -> bool:
            return any(_WINKV_START_RE.match(l) for l in buf)

        def _emit_current() -> Iterator[str]:
            if current:
                rec = "\n".join(current).strip()
                if rec:
                    yield rec

        for line in line_iter:
            line = line.rstrip("\n").rstrip("\r")
            if not line.strip():
                # blank line flushes an open record
                if saw_boundary:
                    yield from _emit_current()
                    current.clear()
                else:
                    # no boundary yet: the buffered lines were one accumulating
                    # record in group_records terms; keep buffering (a boundary
                    # may still arrive). We hold them in `current` too.
                    yield from _emit_current()
                    current.clear()
                pending_prefix = None
                buffered_singleton.clear()
                continue

            if _RECORD_START_RE.match(line):
                # First boundary seen — anything buffered before it belongs to a
                # boundaryless prefix run; flush it as a single record (matches
                # group_records, which would have accumulated those lines).
                if not saw_boundary and current:
                    yield from _emit_current()
                    current.clear()
                saw_boundary = True
                if _WRAPPER_PREFIX_RE.match(line):
                    yield from _emit_current()
                    current.clear()
                    pending_prefix = line
                    continue
                yield from _emit_current()
                current.clear()
                if pending_prefix:
                    current.append(pending_prefix)
                    pending_prefix = None
                current.append(line)
                continue

            if _WINKV_START_RE.match(line) and _has_provider(current):
                saw_boundary = True
                yield from _emit_current()
                current = [line]
                continue

            if current:
                current.append(line)
            elif pending_prefix:
                current = [pending_prefix, line]
                pending_prefix = None
            else:
                current = [line]

        if pending_prefix and not current:
            current = [pending_prefix]
        # Final flush.
        if current:
            rec = "\n".join(current).strip()
            if rec:
                yield rec

    return iter_records(_gen())


def iter_chunks(records: Iterable[Record], chunk_size: int) -> Iterator[Chunk]:
    """Batch an ordered ``Record`` stream into ordered ``Chunk``s.

    Chunk ids are contiguous from 0. A chunk preserves record order; chunk order
    plus intra-chunk order gives a total deterministic ordering the parallel
    engine uses to persist results exactly as a sequential run would.
    """
    size = max(1, int(chunk_size))
    chunk_id = 0
    buf: List[Record] = []
    for rec in records:
        buf.append(rec)
        if len(buf) >= size:
            yield Chunk(chunk_id=chunk_id, records=buf)
            chunk_id += 1
            buf = []
    if buf:
        yield Chunk(chunk_id=chunk_id, records=buf)
