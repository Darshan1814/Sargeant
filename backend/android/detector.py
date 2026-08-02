"""
Android logcat format DETECTOR.

Recognizes the standard `adb logcat -v <format>` layouts plus JSON logcat.
Deterministic, regex-based — no LLM. Returns the format id or None.

Formats (id → example):
  threadtime : 08-10 09:20:19.692  3907  3921 W dumpsys: message
  time/brief : 08-10 09:20:19.692 W/dumpsys( 3907): message
  tag        : W/dumpsys( 3907): message           (no leading timestamp)
  long       : [ 08-10 09:20:19.692  3907: 3921 W/dumpsys ]\n message
  process    : W( 3907) message  (dumpsys)
  event      : 08-10 09:20:19.692  1000  1000 I am_proc_start: [args]
  json       : {"time":"...","pid":...,"priority":"W","tag":"...","message":"..."}
  raw        : (fallback) any line when caller already knows it's Android
"""
from __future__ import annotations

import json
import re

_PRIO = r"[VDIWEFS]"  # Verbose Debug Info Warning Error Fatal Silent

# 08-10 09:20:19.692  3907  3921 W dumpsys : message
_THREADTIME_RE = re.compile(
    rf"^\d{{2}}-\d{{2}}\s+\d{{2}}:\d{{2}}:\d{{2}}\.\d{{3}}\s+\d+\s+\d+\s+{_PRIO}\s+\S")
# 08-10 09:20:19.692 W/dumpsys( 3907): message   (time / brief-with-time)
_TIME_RE = re.compile(
    rf"^\d{{2}}-\d{{2}}\s+\d{{2}}:\d{{2}}:\d{{2}}\.\d{{3}}\s+{_PRIO}/[^(]+\(\s*\d+\s*\):")
# W/dumpsys( 3907): message   (tag / brief, no timestamp)
_TAG_RE = re.compile(rf"^{_PRIO}/[^(]+\(\s*\d+\s*\):")
# [ 08-10 09:20:19.692  3907: 3921 W/dumpsys ]
_LONG_RE = re.compile(
    rf"^\[\s*\d{{2}}-\d{{2}}\s+\d{{2}}:\d{{2}}:\d{{2}}\.\d{{3}}\s+\d+:\s*\d+\s+{_PRIO}/")
# W( 3907) message
_PROCESS_RE = re.compile(rf"^{_PRIO}\(\s*\d+\s*\)\s")


def _looks_like_android_json(raw: str) -> bool:
    s = raw.strip()
    if not (s.startswith("{") and s.endswith("}")):
        return False
    try:
        obj = json.loads(s)
    except (json.JSONDecodeError, ValueError):
        return False
    if not isinstance(obj, dict):
        return False
    keys = {k.lower() for k in obj.keys()}
    # Heuristic: an Android logcat JSON record carries a priority/tag/pid trio.
    return ("tag" in keys and ("priority" in keys or "level" in keys or "pid" in keys))


def detect_format(raw: str) -> str | None:
    if not raw or not raw.strip():
        return None
    first = raw.lstrip().splitlines()[0] if raw.strip() else ""

    if _looks_like_android_json(raw):
        return "json"
    if _LONG_RE.match(first):
        return "long"
    if _THREADTIME_RE.match(first):
        return "threadtime"
    if _TIME_RE.match(first):
        return "time"
    if _TAG_RE.match(first):
        return "tag"
    if _PROCESS_RE.match(first):
        return "process"
    return None


def is_android(raw: str) -> bool:
    return detect_format(raw) is not None
