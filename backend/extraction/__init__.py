"""
Stage-1 extraction: turn container/binary log artifacts into the flat text
records that the fingerprint + NGRE parsers expect.

Two extractors ship today:
  - windows_evtx_extractor  : binary .evtx  -> evtx-style text blocks
  - macos_unified_extractor : `log show` json/ndjson -> per-event text lines

Honest scope note: extraction is best-effort and offline. Anything that cannot
be extracted is surfaced explicitly (yielded as an error record) rather than
silently dropped — the caller decides whether to route the raw bytes to Drain3.
"""
from .windows_evtx_extractor import extract_evtx, ExtractionResult
from .macos_unified_extractor import extract_unified_log

__all__ = ["extract_evtx", "extract_unified_log", "ExtractionResult"]
