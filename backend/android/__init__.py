"""
Android parser family (mirrors the Windows family design).

    android/
      detector.py  — which Android logcat format a line is (threadtime / brief /
                     time / long / process / tag / raw / event / JSON).
      envelope.py  — syntax → common AndroidEvent schema (priority, tag, pid,
                     tid, timestamp, message, extra).
      handlers.py  — taxonomy: tag/priority → OCSF class + severity + activity.
      engine.py    — public entry point: parse(raw) -> AndroidParseResult | None.

Guarantees (same as Windows family):
  * Lossless — every field is preserved; common ones map to OCSF, the rest live
    under `normalized.unmapped.android`.
  * Deterministic runtime — table-driven, no LLM.
  * One family, many formats — every logcat -v format is covered, so any Android
    log (small/large/any type) converts to OCSF.
"""
from .engine import parse, AndroidParseResult, is_android

__all__ = ["parse", "AndroidParseResult", "is_android"]
