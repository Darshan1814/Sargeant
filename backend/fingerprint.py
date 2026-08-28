"""
Parser fingerprinting: scores every registered parser against incoming raw log text,
picks the best match, falls back to Drain3 if confidence < 0.5.
"""
from __future__ import annotations

import re
import json
import os
from pathlib import Path
from dataclasses import dataclass


PARSERS_DIR = Path(os.getenv("PARSERS_DIR", "/app/parsers/registry"))


@dataclass
class ParserCandidate:
    parser_id: str
    score: float


@dataclass
class FingerprintResult:
    detected_parser_id: str | None
    confidence: float
    candidates: list[ParserCandidate]
    use_drain3: bool


def _dir_signature(d: Path) -> tuple:
    """Cheap fingerprint of the registry directory: (name, mtime_ns, size) for
    every ``*.json`` file. Changes iff a parser file is added, removed, or edited
    in place — so the cache below reloads exactly when (and only when) it must.
    ``os.scandir`` gives the stat data C-side in one pass (far cheaper than
    ``pathlib.glob`` + per-file ``read_text``)."""
    entries = []
    try:
        with os.scandir(d) as it:
            for e in it:
                if not e.name.endswith(".json"):
                    continue
                try:
                    st = e.stat()
                except OSError:
                    continue
                entries.append((e.name, st.st_mtime_ns, st.st_size))
    except (FileNotFoundError, NotADirectoryError):
        return ()
    entries.sort()
    return tuple(entries)


# dir → (signature, parsers_list); dir → {parser_id: parser_dict}. Keyed by
# PARSERS_DIR so switching registries (tests, multi-tenant) is still correct.
_CACHE: dict[str, tuple] = {}
_BY_ID: dict[str, dict] = {}


def _load_parsers() -> list[dict]:
    """Load every registry parser JSON, memoized until the directory changes.

    Previously this re-read and re-parsed every ``*.json`` on EVERY call — i.e.
    once per record on the fingerprint path — dominating runtime with redundant
    disk I/O. Now the parsed list is cached and only rebuilt when
    ``_dir_signature`` changes, preserving hot-reload semantics for a long-lived
    server while making steady-state parsing allocation/IO-free.

    The returned list is shared and MUST be treated read-only by callers (the
    scorer only reads). Callers needing a mutable parser use :func:`get_parser`.
    """
    key = str(PARSERS_DIR)
    sig = _dir_signature(PARSERS_DIR)
    cached = _CACHE.get(key)
    if cached is not None and cached[0] == sig:
        return cached[1]

    parsers: list[dict] = []
    by_id: dict[str, dict] = {}
    for name, _mtime, _size in sig:
        try:
            p = json.loads((PARSERS_DIR / name).read_text())
        except Exception:
            continue
        parsers.append(p)
        pid = p.get("parser_id")
        if pid and pid not in by_id:
            by_id[pid] = p
    _CACHE[key] = (sig, parsers)
    _BY_ID[key] = by_id
    return parsers


def get_parser(parser_id: str) -> dict | None:
    """Return a *fresh shallow copy* of a registry parser by id (cache-backed).

    A copy is returned because the NGRE path mutates top-level keys
    (``_confidence``/``_parse_path``); handing back the shared cached object
    would leak those across records. Copying ~10 keys per matched record is
    negligible next to the disk read it replaces."""
    key = str(PARSERS_DIR)
    cached = _CACHE.get(key)
    if cached is None or cached[0] != _dir_signature(PARSERS_DIR):
        _load_parsers()
    p = _BY_ID.get(key, {}).get(parser_id)
    return dict(p) if p is not None else None


def _score_parser(raw_log: str, parser: dict) -> float:
    idents = parser.get("identifiers", {})
    score = 0.0
    weight_total = 0.0

    # Required substrings check (weight 0.4)
    required = idents.get("required_substrings", [])
    if required:
        matched = sum(1 for s in required if s in raw_log)
        score += 0.4 * (matched / len(required))
        weight_total += 0.4

    # Regex signature check (weight 0.5)
    sig = idents.get("regex_signature")
    if sig:
        try:
            if re.search(sig, raw_log, re.MULTILINE):
                score += 0.5
        except re.error:
            pass
        weight_total += 0.5

    # Known processes check (weight 0.1). Scored PROPORTIONALLY to how many
    # distinct known processes appear, so a blob rich in a source's signature
    # processes (e.g. macOS WindowServer/loginwindow/mDNSResponder) outscores a
    # parser that only shares one ambiguous process (e.g. "kernel"). This breaks
    # otherwise-tied catch-all parsers (macOS vs Linux BSD syslog) correctly.
    known_procs = idents.get("known_processes", [])
    if known_procs:
        matched = sum(1 for p in known_procs if p in raw_log)
        if matched:
            score += 0.1 * min(matched / max(len(known_procs) * 0.3, 1), 1.0)
        weight_total += 0.1

    if weight_total == 0:
        return 0.0
    return min(score, 1.0)


def fingerprint(raw_log: str) -> FingerprintResult:
    parsers = _load_parsers()
    if not parsers:
        return FingerprintResult(None, 0.0, [], True)

    # Tie-break by the parser's declared confidence_weight so that when two
    # catch-all parsers score identically on an ambiguous line (e.g. a bare
    # BSD-syslog line matching both macOS and Linux), the more authoritative
    # source wins deterministically instead of relying on filesystem order.
    weights = {
        p["parser_id"]: float(p.get("identifiers", {}).get("confidence_weight", 0.5))
        for p in parsers
    }
    candidates = []
    for parser in parsers:
        s = _score_parser(raw_log, parser)
        candidates.append(ParserCandidate(parser_id=parser["parser_id"], score=round(s, 4)))

    candidates.sort(key=lambda c: (c.score, weights.get(c.parser_id, 0.0)), reverse=True)
    best = candidates[0]

    if best.score >= 0.5:
        return FingerprintResult(
            detected_parser_id=best.parser_id,
            confidence=best.score,
            candidates=candidates,
            use_drain3=False,
        )
    return FingerprintResult(
        detected_parser_id=None,
        confidence=best.score,
        candidates=candidates,
        use_drain3=True,
    )
