"""
Linux log format DETECTOR.

Deterministic, regex-based (no LLM). Returns a format id or None.

Formats (id -> example):
  rfc3164       : Aug 01 00:00:05 srv-file-01 sshd[44218]: Accepted publickey ...
  rfc5424       : <34>1 2026-08-01T00:00:05Z host app 123 ID1 - message
  dmesg         : [   12.345678] EXT4-fs (sda1): mounted filesystem
  auditd        : type=1400 audit(1756680000.123:45): apparmor="DENIED" ...
  journald_json : {"MESSAGE":"...","PRIORITY":"6","SYSLOG_IDENTIFIER":"sshd", ...}

Only the FIRST non-empty line is examined for the line-oriented formats; JSON is
probed as a whole. `detect_format` returns None for anything that is not a
recognizable Linux record so the pipeline can fall through to the next family.
"""
from __future__ import annotations

import json
import re

# RFC3164: "Mon DD HH:MM:SS host program[pid]: message"  (day zero- or space-padded,
# optional <PRI> prefix, program with or without [pid]).
_RFC3164_RE = re.compile(
    r"^(?:<\d{1,3}>)?"
    r"[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+"
    r"[\w.\-]+\s+"
    r"[\w.\-/]+(?:\[\d+\])?:")

# RFC5424: "<PRI>VERSION ISOTIMESTAMP HOST APP PROCID MSGID ..."
_RFC5424_RE = re.compile(
    r"^<\d{1,3}>\d\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+")

# Kernel dmesg with bracketed monotonic uptime: "[   12.345678] message"
_DMESG_RE = re.compile(r"^\[\s*\d+\.\d+\]\s+\S")

# Native auditd: "type=NAME msg=audit(EPOCH:SERIAL): ..." or "type=NAME audit(EPOCH:SERIAL):"
_AUDITD_RE = re.compile(r"^type=\w+\s+(?:msg=)?audit\(\d+\.\d+:\d+\):")

# macOS emits RFC3164-shaped syslog too ("Mon D HH:MM:SS host program[pid]: …"),
# so a few Apple-only markers must be DECLINED here and left for the macOS
# registry parsers (MAC-ULOG-001, …). These are high-precision — they never
# occur in genuine Linux syslog: `launchd` is the macOS init (Linux uses
# systemd/init), the macOS kernel logs as `kernel[<n>]:` (Linux kernel has no
# pid bracket), and `com.apple.*` is an Apple reverse-DNS identifier.
_MACOS_MARKER_RE = re.compile(
    r"\blaunchd\[\d+\]|\bkernel\[\d+\]:|com\.apple\.")


def _looks_like_journald_json(raw: str) -> bool:
    s = raw.strip()
    if not (s.startswith("{") and s.endswith("}")):
        return False
    try:
        obj = json.loads(s)
    except (json.JSONDecodeError, ValueError):
        return False
    if not isinstance(obj, dict):
        return False
    keys = {k.upper() for k in obj.keys()}
    # A journald export record always carries MESSAGE plus at least one of the
    # journald-native metadata fields.
    return "MESSAGE" in keys and bool(
        keys & {"PRIORITY", "SYSLOG_IDENTIFIER", "_SYSTEMD_UNIT", "_PID",
                "_HOSTNAME", "_COMM", "SYSLOG_FACILITY"})


def detect_format(raw: str) -> str | None:
    if not raw or not raw.strip():
        return None

    if _looks_like_journald_json(raw):
        return "journald_json"

    first = raw.lstrip().splitlines()[0]

    # Apple-origin syslog that shares the RFC3164 shape is declined so the macOS
    # registry parsers claim it (no information loss — just correct routing).
    if _MACOS_MARKER_RE.search(first):
        return None

    if _AUDITD_RE.match(first):
        return "auditd"
    if _RFC5424_RE.match(first):
        return "rfc5424"
    if _RFC3164_RE.match(first):
        return "rfc3164"
    if _DMESG_RE.match(first):
        return "dmesg"
    return None


def is_linux(raw: str) -> bool:
    return detect_format(raw) is not None
