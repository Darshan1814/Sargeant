"""
macOS Unified Log extractor (Stage 1).

macOS stores its modern logs in a binary tracev3 store that Apple only exposes
through the ``log`` tool on a live macOS host. There is **no** reliable, fully
offline, cross-platform decoder for tracev3 — so this extractor is honest about
its scope:

  * It DOES NOT read .tracev3 / .logarchive binaries. Attempting that would be a
    silent-failure trap. Instead it consumes the *text export* a macOS host
    produces with::

        log show --style ndjson  > unified.ndjson      (one JSON object / line)
        log show --style json    > unified.json         (a JSON array)
        log show --style syslog  > unified.log          (classic BSD syslog text)

  * ndjson / json exports are normalised into single-line JSON records that the
    MAC-ULOG-UNIFIED-JSON parser fingerprints at high confidence.
  * syslog-style text is passed through line-by-line for the BSD-syslog parsers.
  * Anything unparseable is surfaced as an error record, never dropped.

This keeps the pipeline honest: on a non-mac build host we can still exercise
the full parse path using a pre-exported artifact, and we never pretend to have
decoded a binary we cannot decode.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Iterator, List


# The keys the MAC-ULOG-UNIFIED-JSON parser keys off. Order MATTERS: it must
# match the parser's ordered NGRE pattern (timestamp → messageType →
# eventMessage → processImagePath → processID → subsystem → category). Apple's
# real `log show` ndjson emits keys in an arbitrary order, so normalising to
# this fixed order is exactly what makes stage-2 NGRE extraction deterministic.
# Original key names are preserved (lossless); any extra keys are appended.
_CANON_KEYS = ("timestamp", "messageType", "eventMessage", "processImagePath",
               "processID", "subsystem", "category")


@dataclass
class ExtractionResult:
    ok: bool
    records: List[str] = field(default_factory=list)
    errors: List[tuple] = field(default_factory=list)
    reason: str = ""
    style: str = ""

    @property
    def extracted(self) -> int:
        return len(self.records)

    @property
    def failed(self) -> int:
        return len(self.errors)


def _looks_like_json_object(s: str) -> bool:
    s = s.lstrip()
    return s.startswith("{")


def _normalise_json_event(obj: dict) -> str:
    """Emit a compact single-line JSON string with stable key order.

    We keep ALL original keys (lossless) but guarantee the canonical ones are
    present (null when absent) so every extracted macOS event has the identical
    shape — mirroring the OCSF uniformity guarantee one stage earlier.
    """
    out = {k: obj.get(k) for k in _CANON_KEYS}
    for k, v in obj.items():
        if k not in out:
            out[k] = v
    return json.dumps(out, ensure_ascii=False, default=str)


def extract_unified_log(blob: str, style: str = "auto") -> ExtractionResult:
    """Extract events from a pre-exported macOS unified-log artifact.

    ``style`` ∈ {"auto", "ndjson", "json", "syslog"}. ``auto`` sniffs the
    content. Returns an ExtractionResult; ``ok`` is False only when the input
    is empty or the declared style cannot be honoured.
    """
    if not blob or not blob.strip():
        return ExtractionResult(ok=False, reason="empty input")

    stripped = blob.lstrip()

    # ── JSON array (log show --style json) ───────────────────────────────────
    if style in ("auto", "json") and stripped.startswith("["):
        res = ExtractionResult(ok=True, style="json")
        try:
            arr = json.loads(blob)
        except Exception as exc:
            return ExtractionResult(ok=False, reason=f"invalid json array: {exc}")
        for idx, obj in enumerate(arr):
            if isinstance(obj, dict):
                res.records.append(_normalise_json_event(obj))
            else:
                res.errors.append((idx, "array element is not an object"))
        return res

    # ── ndjson (log show --style ndjson) ─────────────────────────────────────
    if style in ("auto", "ndjson") and _looks_like_json_object(stripped):
        res = ExtractionResult(ok=True, style="ndjson")
        for idx, line in enumerate(blob.splitlines()):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    res.records.append(_normalise_json_event(obj))
                else:
                    res.errors.append((idx, "line is not a json object"))
            except Exception as exc:
                res.errors.append((idx, f"{type(exc).__name__}: {exc}"))
        return res

    # ── syslog-style text (log show --style syslog / classic files) ──────────
    res = ExtractionResult(ok=True, style="syslog")
    for line in blob.splitlines():
        if line.strip():
            res.records.append(line.rstrip("\n"))
    return res


def iter_events(blob: str, style: str = "auto") -> Iterator[str]:
    """Convenience generator over successfully extracted records."""
    yield from extract_unified_log(blob, style).records
