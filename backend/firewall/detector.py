"""
Firewall format DETECTOR (stage ① entry).

Decides (a) whether a raw log is a firewall log at all, and (b) which structural
format engine applies. Deterministic, substring/regex based — no LLM.

Formats:
  * cef           — Common Event Format (CEF:version|vendor|product|...)
  * fortigate     — Fortinet FortiGate key=value syslog (date= time= srcip= ...)
  * cisco_asa     — Cisco ASA syslog (%ASA-severity-msgid:)
  * juniper_srx   — Juniper SRX RT_FLOW structured syslog
  * netscreen     — Juniper NetScreen legacy firewall log

Returns None if the log does not match any known firewall format.
"""
from __future__ import annotations

import re

# ── CEF ───────────────────────────────────────────────────────────────────────
# Matches "CEF:0|" prefix, optional syslog/timestamp prefix allowed.
_CEF_RE = re.compile(r"CEF:\d+\|", re.IGNORECASE)

# ── FortiGate ─────────────────────────────────────────────────────────────────
# FortiGate logs always carry logid= in key=value format, typically combined with
# date=, time=, type=, subtype=, or vd=. Handles traffic, event, utm, and anomaly types.
_FORTIGATE_LOGID_RE = re.compile(r'\blogid\s*=\s*["\d]')
_FORTIGATE_HINT_RE = re.compile(r'\b(?:type\s*=\s*"?\w+"?|vd\s*=\s*"?\w+"?|subtype\s*=\s*"?\w+"?|srcip\s*=)')
_FORTIGATE_DATE_RE = re.compile(r'\bdate\s*=\s*\d{4}-\d{2}-\d{2}\s+time\s*=\s*\d{2}:\d{2}:\d{2}')

# ── Cisco ASA ─────────────────────────────────────────────────────────────────
# Standard syslog tag format: %ASA-severity-msgid:
_CISCO_ASA_RE = re.compile(r"%ASA-\d+-\d+\s*:")

# ── Juniper SRX ───────────────────────────────────────────────────────────────
# RT_FLOW events: RT_FLOW_SESSION_CREATE / CLOSE / DENY
_JUNIPER_SRX_RE = re.compile(r"\bRT_FLOW(?:_SESSION)?(?:_CREATE|_CLOSE|_DENY)\b")
# Also matches plain "RT_FLOW:" prefix
_JUNIPER_SRX2_RE = re.compile(r"\bRT_FLOW\s*:\s*RT_FLOW_")

# ── NetScreen ─────────────────────────────────────────────────────────────────
# NetScreen logs always have "NetScreen:" or "device_id=" followed by action=
_NETSCREEN_RE = re.compile(r"\bNetScreen\b.*\baction\s*=\s*\w+", re.DOTALL)
_NETSCREEN_DEVID_RE = re.compile(r"\bdevice_id\s*=\s*\w+")


def detect_format(raw: str) -> str | None:
    """Return the firewall format id, or None if this is not a recognized firewall log."""
    if not raw or not raw.strip():
        return None

    # CEF: highest specificity — always starts with or contains "CEF:N|"
    if _CEF_RE.search(raw):
        return "cef"

    # FortiGate: requires logid= and FortiOS structure (type=, subtype=, vd=, srcip=, or date+time)
    if _FORTIGATE_LOGID_RE.search(raw) and (_FORTIGATE_HINT_RE.search(raw) or _FORTIGATE_DATE_RE.search(raw)):
        return "fortigate"

    # Cisco ASA: %ASA-severity-msgid: is unmistakable
    if _CISCO_ASA_RE.search(raw):
        return "cisco_asa"

    # Juniper SRX RT_FLOW
    if _JUNIPER_SRX_RE.search(raw) or _JUNIPER_SRX2_RE.search(raw):
        return "juniper_srx"

    # NetScreen: device_id= + action= OR explicit "NetScreen" product name
    if _NETSCREEN_DEVID_RE.search(raw) and "action=" in raw:
        return "netscreen"
    if _NETSCREEN_RE.search(raw):
        return "netscreen"

    return None


def is_firewall(raw: str) -> bool:
    return detect_format(raw) is not None
