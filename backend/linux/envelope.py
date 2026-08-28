"""
Linux event ENVELOPE — the common schema every Linux format parses into.

One `LinuxEvent` dataclass regardless of input format. `extra` holds every
native field losslessly (facility, PRI, msgid, structured-data, audit key=val).
Per-format parsers return a `LinuxEvent` or None.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Optional

# syslog severity (PRI & 7) -> word understood by ocsf_mapper.SEVERITY_MAP.
SYSLOG_SEVERITY_WORD = {
    0: "emergency", 1: "alert", 2: "critical", 3: "error",
    4: "warning", 5: "notice", 6: "informational", 7: "debug",
}


@dataclass
class LinuxEvent:
    fmt: str = "unknown"
    month: Optional[str] = None          # RFC3164 month name, e.g. "Aug"
    day: Optional[str] = None
    time: Optional[str] = None           # "HH:MM:SS"
    timestamp: Optional[str] = None      # ISO-8601 (RFC5424 / journald)
    hostname: Optional[str] = None
    program: Optional[str] = None
    pid: Optional[str] = None
    level: Optional[str] = None          # severity word (from PRI) when known
    message: Optional[str] = None
    extra: dict = field(default_factory=dict)

    def put(self, key: str, value):
        if key and value not in (None, "", "-"):
            self.extra[str(key)] = value if isinstance(value, (int, float)) else str(value).strip()


# ── RFC3164 (workhorse) ───────────────────────────────────────────────────────
# "Mon DD HH:MM:SS host program[pid]: message"  — handles program with or without
# [pid], zero- or space-padded day, optional <PRI> prefix.
_RFC3164 = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?"
    r"(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>[\w.\-]+)\s+"
    r"(?P<program>[\w.\-/]+?)(?:\[(?P<pid>\d+)\])?:\s?(?P<message>.*)$",
    re.DOTALL)

_RFC5424 = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<ver>\d)\s+(?P<ts>\S+)\s+(?P<hostname>\S+)\s+"
    r"(?P<program>\S+)\s+(?P<pid>\S+)\s+(?P<msgid>\S+)\s+(?P<rest>.*)$",
    re.DOTALL)

_DMESG = re.compile(r"^\[\s*(?P<uptime>\d+\.\d+)\]\s+(?P<message>.*)$", re.DOTALL)
# optional "subsystem:" prefix inside a dmesg message
_DMESG_SUBSYS = re.compile(r"^(?P<subsys>[\w.\-]+):\s+(?P<rest>.*)$", re.DOTALL)

_AUDITD = re.compile(
    r"^type=(?P<atype>\w+)\s+(?:msg=)?audit\((?P<epoch>\d+\.\d+):(?P<serial>\d+)\):\s*(?P<rest>.*)$",
    re.DOTALL)
_KV_RE = re.compile(r"(\w+)=(\"[^\"]*\"|'[^']*'|\S+)")


def _pri_to_word(pri: Optional[str]) -> Optional[str]:
    if pri is None:
        return None
    try:
        return SYSLOG_SEVERITY_WORD.get(int(pri) & 7)
    except (TypeError, ValueError):
        return None


def parse_rfc3164(raw: str) -> Optional[LinuxEvent]:
    m = _RFC3164.match(raw.strip())
    if not m:
        return None
    ev = LinuxEvent(
        fmt="rfc3164", month=m["month"], day=m["day"], time=m["time"],
        hostname=m["hostname"], program=m["program"], pid=m["pid"],
        level=_pri_to_word(m["pri"]), message=(m["message"] or "").rstrip("\n"))
    if m["pri"] is not None:
        ev.put("pri", int(m["pri"]))
        ev.put("facility", int(m["pri"]) >> 3)
    return ev


def parse_rfc5424(raw: str) -> Optional[LinuxEvent]:
    m = _RFC5424.match(raw.strip())
    if not m:
        return None
    rest = (m["rest"] or "").strip()
    # Strip a leading structured-data block "[...]" (kept natively in extra).
    sd = None
    if rest.startswith("["):
        depth, i = 0, 0
        for i, ch in enumerate(rest):
            if ch == "[":
                depth += 1
            elif ch == "]":
                depth -= 1
                if depth == 0:
                    break
        sd, rest = rest[:i + 1], rest[i + 1:].strip()
    ev = LinuxEvent(
        fmt="rfc5424", timestamp=m["ts"],
        hostname=None if m["hostname"] == "-" else m["hostname"],
        program=None if m["program"] == "-" else m["program"],
        pid=None if m["pid"] == "-" else m["pid"],
        level=_pri_to_word(m["pri"]), message=rest)
    ev.put("pri", int(m["pri"]))
    ev.put("facility", int(m["pri"]) >> 3)
    ev.put("syslog_version", m["ver"])
    if m["msgid"] and m["msgid"] != "-":
        ev.put("msgid", m["msgid"])
    if sd:
        ev.put("structured_data", sd)
    return ev


def parse_dmesg(raw: str) -> Optional[LinuxEvent]:
    m = _DMESG.match(raw.strip().splitlines()[0])
    if not m:
        return None
    body = (m["message"] or "").strip()
    program = "kernel"
    sm = _DMESG_SUBSYS.match(body)
    if sm and " " not in sm["subsys"]:
        program = sm["subsys"]
    ev = LinuxEvent(fmt="dmesg", program=program, message=body)
    ev.put("uptime", m["uptime"])
    return ev


def parse_auditd(raw: str) -> Optional[LinuxEvent]:
    m = _AUDITD.match(raw.strip())
    if not m:
        return None
    rest = (m["rest"] or "").strip()
    ev = LinuxEvent(fmt="auditd", program="auditd",
                    message=f"{m['atype']} {rest}".strip())
    ev.put("audit_type", m["atype"])
    ev.put("audit_epoch", m["epoch"])
    ev.put("audit_serial", m["serial"])
    # epoch -> ISO timestamp so a real event-time is built downstream.
    try:
        from datetime import datetime, timezone
        ev.timestamp = datetime.fromtimestamp(
            float(m["epoch"]), tz=timezone.utc).isoformat()
    except Exception:
        pass
    for k, v in _KV_RE.findall(rest):
        ev.put(k, v.strip("\"'"))
    return ev


def parse_journald_json(raw: str) -> Optional[LinuxEvent]:
    try:
        obj = json.loads(raw.strip())
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(obj, dict):
        return None
    up = {k.upper(): v for k, v in obj.items()}

    def _s(*keys):
        for k in keys:
            if up.get(k) not in (None, ""):
                return str(up[k])
        return None

    level = None
    pri = _s("PRIORITY")
    if pri is not None:
        level = _pri_to_word(pri)
    ts = None
    rt = _s("__REALTIME_TIMESTAMP")
    if rt and rt.isdigit():
        try:
            from datetime import datetime, timezone
            ts = datetime.fromtimestamp(int(rt) / 1_000_000, tz=timezone.utc).isoformat()
        except Exception:
            ts = None
    ev = LinuxEvent(
        fmt="journald_json", timestamp=ts,
        hostname=_s("_HOSTNAME"),
        program=_s("SYSLOG_IDENTIFIER", "_COMM", "UNIT", "_SYSTEMD_UNIT"),
        pid=_s("_PID", "SYSLOG_PID"),
        level=level, message=_s("MESSAGE"))
    for k, v in obj.items():
        if k.upper() not in ("MESSAGE",):
            ev.put(k, v if not isinstance(v, (dict, list)) else json.dumps(v))
    return ev
