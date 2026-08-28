"""
Android event ENVELOPE — the common schema every logcat format parses into.

One `AndroidEvent` dataclass regardless of input format. `extra` holds every
additional field losslessly (e.g. event-log args, JSON fields).
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Optional

# Android priority letter → human label (feeds severity mapping downstream).
PRIORITY_LABELS = {
    "V": "Verbose", "D": "Debug", "I": "Info",
    "W": "Warning", "E": "Error", "F": "Fatal", "S": "Silent",
}


@dataclass
class AndroidEvent:
    fmt: str = "unknown"
    timestamp: Optional[str] = None     # raw "MM-DD HH:MM:SS.mmm" as seen
    priority: Optional[str] = None      # single letter V/D/I/W/E/F/S
    tag: Optional[str] = None
    pid: Optional[str] = None
    tid: Optional[str] = None
    message: Optional[str] = None
    extra: dict = field(default_factory=dict)

    def put(self, key: str, value):
        if key and value not in (None, "", "-"):
            self.extra[str(key)] = str(value).strip()


_PRIO = r"[VDIWEFS]"

_RE_THREADTIME = re.compile(
    rf"^(?P<ts>\d{{2}}-\d{{2}}\s+\d{{2}}:\d{{2}}:\d{{2}}\.\d{{3}})\s+"
    rf"(?P<pid>\d+)\s+(?P<tid>\d+)\s+(?P<prio>{_PRIO})\s+(?P<tag>.*?):\s?(?P<msg>.*)$")

_RE_TIME = re.compile(
    rf"^(?P<ts>\d{{2}}-\d{{2}}\s+\d{{2}}:\d{{2}}:\d{{2}}\.\d{{3}})\s+"
    rf"(?P<prio>{_PRIO})/(?P<tag>[^(]+?)\(\s*(?P<pid>\d+)\s*\):\s?(?P<msg>.*)$")

_RE_TAG = re.compile(
    rf"^(?P<prio>{_PRIO})/(?P<tag>[^(]+?)\(\s*(?P<pid>\d+)\s*\):\s?(?P<msg>.*)$")

_RE_PROCESS = re.compile(
    rf"^(?P<prio>{_PRIO})\(\s*(?P<pid>\d+)\s*\)\s(?P<msg>.*?)(?:\s+\((?P<tag>[^)]+)\))?$")

_RE_LONG_HDR = re.compile(
    rf"^\[\s*(?P<ts>\d{{2}}-\d{{2}}\s+\d{{2}}:\d{{2}}:\d{{2}}\.\d{{3}})\s+"
    rf"(?P<pid>\d+):\s*(?P<tid>\d+)\s+(?P<prio>{_PRIO})/(?P<tag>[^\]]+?)\s*\]\s*$")


def _finish(ev: AndroidEvent) -> AndroidEvent:
    # priority_label is surfaced at the android_block top level by the engine —
    # do NOT also store it in `extra` (avoids duplicate/noise per PART 19).
    return ev


def parse_threadtime(raw: str) -> Optional[AndroidEvent]:
    m = _RE_THREADTIME.match(raw.strip())
    if not m:
        return None
    ev = AndroidEvent(fmt="threadtime", timestamp=m["ts"], priority=m["prio"],
                      tag=m["tag"].strip(), pid=m["pid"], tid=m["tid"],
                      message=m["msg"])
    return _finish(ev)


def parse_time(raw: str) -> Optional[AndroidEvent]:
    m = _RE_TIME.match(raw.strip())
    if not m:
        return None
    ev = AndroidEvent(fmt="time", timestamp=m["ts"], priority=m["prio"],
                      tag=m["tag"].strip(), pid=m["pid"], message=m["msg"])
    return _finish(ev)


def parse_tag(raw: str) -> Optional[AndroidEvent]:
    m = _RE_TAG.match(raw.strip())
    if not m:
        return None
    ev = AndroidEvent(fmt="tag", priority=m["prio"], tag=m["tag"].strip(),
                      pid=m["pid"], message=m["msg"])
    return _finish(ev)


def parse_process(raw: str) -> Optional[AndroidEvent]:
    m = _RE_PROCESS.match(raw.strip())
    if not m:
        return None
    ev = AndroidEvent(fmt="process", priority=m["prio"], pid=m["pid"],
                      tag=(m["tag"] or "").strip() or None, message=m["msg"])
    return _finish(ev)


def parse_long(raw: str) -> Optional[AndroidEvent]:
    lines = raw.strip().splitlines()
    if not lines:
        return None
    m = _RE_LONG_HDR.match(lines[0].strip())
    if not m:
        return None
    msg = "\n".join(l for l in lines[1:]).strip()
    ev = AndroidEvent(fmt="long", timestamp=m["ts"], priority=m["prio"],
                      tag=m["tag"].strip(), pid=m["pid"], tid=m["tid"], message=msg)
    return _finish(ev)


def parse_json(raw: str) -> Optional[AndroidEvent]:
    try:
        obj = json.loads(raw.strip())
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(obj, dict):
        return None
    lower = {k.lower(): v for k, v in obj.items()}
    prio = lower.get("priority") or lower.get("level") or lower.get("prio")
    prio = str(prio)[:1].upper() if prio else None
    ev = AndroidEvent(
        fmt="json",
        timestamp=str(lower.get("time") or lower.get("timestamp") or "") or None,
        priority=prio if prio in PRIORITY_LABELS else None,
        tag=str(lower.get("tag") or "") or None,
        pid=str(lower.get("pid") or "") or None,
        tid=str(lower.get("tid") or lower.get("thread") or "") or None,
        message=str(lower.get("message") or lower.get("msg") or "") or None,
    )
    # Preserve every JSON field verbatim.
    for k, v in obj.items():
        ev.put(k, v if not isinstance(v, (dict, list)) else json.dumps(v))
    return _finish(ev)
