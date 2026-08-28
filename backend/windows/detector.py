"""
Windows format DETECTOR (stage ① entry).

Decides (a) whether a raw log is a Windows log at all, and (b) which structural
format engine applies. Deterministic, substring/regex based — no LLM.

Formats:
  * xml            — raw <Event> … </Event> Windows event XML
  * evtx-text      — wevtutil / Get-WinEvent /f:text block (Log Name:/Event ID:)
  * iis-w3c        — IIS W3C access log (has #Fields: or date time s-ip cs-method)
  * firewall-text  — Windows Firewall pfirewall.log (#Version: / action src dst)
"""
from __future__ import annotations

import re

_XML_RE = re.compile(r"<Event[\s>].*</Event>", re.DOTALL)
# A genuine evtx text block has SEVERAL header fields, each on its own line
# ("Log Name:", "Source:", "Event ID:", "Level:", "Computer:"). We require a
# real "Log Name:" line OR at least TWO distinct evtx header lines so that a
# single spoofed line that merely embeds "Event ID: 4625 …" inline (adversarial
# header wrapping a foreign payload) is NOT claimed as a Windows event.
_EVTX_HEADER_LINE_RE = re.compile(
    r"^\s*(Log Name|Source|Event ID|Level|Computer|Task Category|Keywords)\s*:\s*\S",
    re.MULTILINE,
)
_EVTX_LOGNAME_RE = re.compile(r"^\s*Log Name\s*:\s*\S", re.MULTILINE)
_IIS_FIELDS_RE = re.compile(r"^#Fields:", re.MULTILINE)
_IIS_ROW_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\b",
    re.MULTILINE,
)
# Compact Windows key=value export, e.g.:
#   Provider=Microsoft-Windows-Security-Auditing EventID=4624 Computer=WIN-DEV01
# A very common flattened export style. We require at least a Windows-ish
# Provider/EventID/Channel token so we don't grab arbitrary key=value logs.
_WINKV_RE = re.compile(
    r"(?:^|\s)(?:Provider|EventID|Event_ID|Channel|Computer)\s*=",
    re.IGNORECASE,
)
_WINKV_PROVIDER_HINT_RE = re.compile(
    r"(?:Provider|Channel)\s*=\s*\"?(?:Microsoft-Windows|Windows|Service Control Manager|Sysmon)",
    re.IGNORECASE,
)

_FW_HEADER_RE = re.compile(r"^#(Version|Software|Fields):.*(Windows Firewall|drop|allow)", re.IGNORECASE | re.MULTILINE)
_FW_ROW_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+(ALLOW|DROP|INFO-EVENTS-LOST)\s+(TCP|UDP|ICMP)\b",
    re.IGNORECASE | re.MULTILINE,
)


def detect_format(raw: str) -> str | None:
    """Return the Windows format id, or None if this is not a Windows log."""
    if not raw or not raw.strip():
        return None

    # Raw event XML.
    if "<Event" in raw and _XML_RE.search(raw):
        return "xml"

    # evtx text block — the dominant exported format. Require a real multi-line
    # structure (a "Log Name:" header, or ≥2 distinct evtx header lines) so a
    # single line that merely embeds "Event ID:" inline is not misclaimed.
    header_lines = len(set(m.group(1) for m in _EVTX_HEADER_LINE_RE.finditer(raw)))
    if _EVTX_LOGNAME_RE.search(raw) or header_lines >= 2:
        return "evtx-text"

    # Compact Windows key=value export (single or wrapped lines joined upstream).
    # Needs an EventID/Provider token AND a Windows provider/channel hint OR an
    # explicit EventID=<num> so generic app key=value logs aren't misclaimed.
    if _WINKV_RE.search(raw) and (
        _WINKV_PROVIDER_HINT_RE.search(raw)
        or re.search(r"EventID\s*=\s*\d+", raw, re.IGNORECASE)
    ):
        return "winkv"

    # Windows Firewall pfirewall.log.
    if _FW_HEADER_RE.search(raw) or _FW_ROW_RE.search(raw):
        return "firewall-text"

    # IIS W3C access log.
    if _IIS_FIELDS_RE.search(raw) and ("s-ip" in raw or "cs-method" in raw):
        return "iis-w3c"
    if _IIS_ROW_RE.search(raw):
        return "iis-w3c"

    return None


def is_windows(raw: str) -> bool:
    return detect_format(raw) is not None
