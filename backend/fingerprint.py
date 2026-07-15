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


def _load_parsers() -> list[dict]:
    parsers = []
    for f in PARSERS_DIR.glob("*.json"):
        try:
            parsers.append(json.loads(f.read_text()))
        except Exception:
            pass
    return parsers


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
