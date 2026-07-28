"""
Windows parser family (Matryoshka-style: syntax → schema → taxonomy).

This package implements a *family* of deterministic Windows parsers rather than a
single regex:

    windows/
      envelope.py   — syntax parsing: any Windows event (evtx-text / XML / W3C /
                      firewall-text) → a common WindowsEvent envelope (schema).
      detector.py   — decides whether a raw log is Windows and which format engine
                      applies (evtx-text, xml, iis-w3c, firewall-text).
      handlers.py   — taxonomy mapping: per-provider / per-Event-ID semantic
                      handlers that name fields and select the OCSF class.
      engine.py     — public entry point: parse(raw) -> WindowsParseResult.

Design guarantees (from the problem statement + Matryoshka paper):
  * Lossless — every field discovered in the raw event is preserved. Common
    fields map to OCSF; everything else is kept verbatim under `windows.*`.
  * Deterministic runtime — no LLM per event. Structure is discovered by
    deterministic parsers; semantic naming is table-driven.
  * One family, many sources — Security / System / Application / Sysmon /
    PowerShell / Defender share the EVTX/XML structural engine; Firewall text
    and IIS W3C use their own syntax engines but belong to the Windows family.
"""
from .engine import parse, WindowsParseResult, is_windows

__all__ = ["parse", "WindowsParseResult", "is_windows"]
