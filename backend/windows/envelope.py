"""
Windows event ENVELOPE — the common schema every Windows source is parsed into.

This is stage ① (syntax parsing) + stage ② (schema creation) of the Matryoshka
model. Regardless of input format (evtx-text block, raw event XML, IIS W3C,
firewall pfirewall.log) we normalise into ONE `WindowsEvent` dataclass:

    provider / event_id / channel / computer / timestamp / level / record_id
    process_id / thread_id / event_data{...}   ← ALL remaining fields, lossless

`event_data` is a plain dict holding every remaining field discovered in the
record. Nothing is dropped here — semantic naming and OCSF mapping happen later
in handlers.py, and anything still unmapped is carried into OCSF `unmapped` /
`windows.*` downstream.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional

# Windows event schema XML namespace.
_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

_LEVEL_LABELS = {
    "0": "Information", "1": "Critical", "2": "Error",
    "3": "Warning", "4": "Information", "5": "Verbose",
}


@dataclass
class WindowsEvent:
    """Common Windows envelope. `event_data` holds every extra field, losslessly."""
    fmt: str = "unknown"                     # evtx-text | xml | iis-w3c | firewall-text
    provider: Optional[str] = None
    event_id: Optional[str] = None
    channel: Optional[str] = None            # Log Name / Channel
    computer: Optional[str] = None
    timestamp: Optional[str] = None          # raw string as seen in the log
    level: Optional[str] = None
    keywords: Optional[str] = None
    record_id: Optional[str] = None
    task: Optional[str] = None
    process_id: Optional[str] = None
    thread_id: Optional[str] = None
    security_user_id: Optional[str] = None   # System-level SID (Subject)
    event_data: dict = field(default_factory=dict)

    def put(self, key: str, value):
        """Store an extra field iff it carries information (non-empty)."""
        if key is None:
            return
        if value is None:
            return
        v = str(value).strip()
        if v == "" or v == "-":
            return
        # Do not clobber a real value with a placeholder from a later section.
        if key in self.event_data and self.event_data[key] not in ("", "-", None):
            return
        self.event_data[key] = v


# ── evtx-text block parser (wevtutil / Get-WinEvent /f:text) ──────────────────
# Header "Key:  value" pairs plus indented "  Key:  value" EventData lines. This
# is the dominant format for exported Windows logs and what the fixtures use.

_HEADER_KEYS = {
    "log name": "channel",
    "source": "provider",
    "event id": "event_id",
    "level": "level",
    "computer": "computer",
    "keywords": "keywords",
    "task category": "task",
    "date": "timestamp",
}

# Lines like "Key:   value" (any indentation). Value may be empty.
_KV_RE = re.compile(r"^[ \t]*([A-Za-z0-9 /_\-\.]+?):[ \t]*(.*?)[ \t]*$")


# Section headers in the rendered message body (e.g. "Subject:", "New Logon:").
# A line that is a bare "Word Word:" with NO value starts a new section, so we
# can disambiguate the repeated "Account Name" fields Windows emits per section.
_SECTION_RE = re.compile(r"^([A-Za-z][A-Za-z ]+):\s*$")

# Section labels whose fields describe the ACTING principal (as opposed to the
# subject/caller). Handlers prefer these for the real user on logon events.
_PRIMARY_SECTIONS = {"new logon", "target account", "account that was locked out"}


def parse_evtx_text(raw: str) -> WindowsEvent:
    ev = WindowsEvent(fmt="evtx-text")
    section = ""  # current message-body section, lower-cased
    for line in raw.splitlines():
        # Section header? (bare "Something:" with no value)
        sm = _SECTION_RE.match(line.strip())
        if sm and sm.group(1).lower() not in _HEADER_KEYS:
            section = sm.group(1).strip().lower()
            continue

        m = _KV_RE.match(line)
        if not m:
            continue
        key_raw, val = m.group(1).strip(), m.group(2).strip()
        key_low = key_raw.lower()
        if key_low in _HEADER_KEYS and getattr(ev, _HEADER_KEYS[key_low]) in (None, ""):
            setattr(ev, _HEADER_KEYS[key_low], val)
            continue
        if not val or val == "-":
            continue
        # Keep the plain-label field (first-seen wins, lossless).
        ev.put(key_raw, val)
        # Also keep a section-qualified copy so repeated labels (Account Name in
        # Subject vs New Logon) are BOTH preserved and disambiguable.
        if section:
            ev.put(f"{section}::{key_raw}", val)
            if section in _PRIMARY_SECTIONS:
                # Promote the acting-principal value under a stable primary key.
                ev.event_data[f"primary::{key_raw}"] = val
    if ev.level and ev.level.isdigit():
        ev.level = _LEVEL_LABELS.get(ev.level, ev.level)
    return ev


# ── compact key=value parser (Provider=… EventID=… Computer=… …) ──────────────
# Splits on "Key=" boundaries so a value may contain spaces (e.g.
# Message=The operating system started). Header-ish keys map onto the envelope;
# everything else is preserved in event_data (keyed by the raw attribute name,
# so semantic handlers keyed on raw XML attrs like TargetUserName still match).

_WINKV_HEADER_MAP = {
    "provider": "provider",
    "source": "provider",
    "eventid": "event_id",
    "event_id": "event_id",
    "channel": "channel",
    "logname": "channel",
    "computer": "computer",
    "level": "level",
    "keywords": "keywords",
    "task": "task",
    "recordid": "record_id",
    "eventrecordid": "record_id",
    "processid": "process_id",
    "threadid": "thread_id",
}

# Match "Key=" tokens. A key must be at the start or preceded by whitespace, so
# "=" characters INSIDE a value (e.g. an LDAP DN "CN=analyst,OU=Users,DC=x")
# are not mistaken for new keys. LDAP RDN prefixes (CN/OU/DC/O/UID…) that appear
# mid-value are additionally excluded below.
_KV_TOKEN_RE = re.compile(r"(?:^|\s)([A-Za-z_][\w()./\-]*)=")

# Short LDAP relative-distinguished-name prefixes that commonly appear INSIDE a
# value (a distinguished name). These are never top-level Windows event keys, so
# we don't split on them — the whole DN stays as one value.
_LDAP_RDN_KEYS = {"cn", "ou", "dc", "o", "uid", "l", "st", "c"}


def parse_winkv(raw: str) -> WindowsEvent | None:
    # Collapse newlines so a wrapped multi-line record parses as one event.
    text = " ".join(line.strip() for line in raw.splitlines() if line.strip())
    matches = list(_KV_TOKEN_RE.finditer(text))
    if not matches:
        return None

    # Drop matches whose key is an LDAP RDN prefix appearing inside a value, so a
    # distinguished name is kept whole instead of being split into CN/OU/DC keys.
    matches = [m for m in matches if m.group(1).lower() not in _LDAP_RDN_KEYS]
    if not matches:
        return None

    ev = WindowsEvent(fmt="winkv")
    for i, m in enumerate(matches):
        key = m.group(1)
        val_start = m.end()
        val_end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        raw_val = text[val_start:val_end].strip()
        # A trailing "NextKey" token was consumed as part of the boundary; the
        # regex boundary already excludes it, but strip a dangling word that is
        # actually the next key (defensive) and surrounding quotes.
        val = raw_val.strip().strip('"').strip()
        if not val or val == "-":
            continue
        klow = key.lower()
        hdr = _WINKV_HEADER_MAP.get(klow)
        if hdr and getattr(ev, hdr) in (None, ""):
            setattr(ev, hdr, val)
        # Always also keep the raw key in event_data (lossless + handler lookup).
        ev.put(key, val)

    if ev.level and ev.level.isdigit():
        ev.level = _LEVEL_LABELS.get(ev.level, ev.level)
    # Not a Windows event unless we at least learned a provider or event id.
    if not (ev.provider or ev.event_id):
        return None
    return ev


# ── raw event XML parser (<Event>…</Event>) ───────────────────────────────────

def parse_event_xml(raw: str) -> Optional[WindowsEvent]:
    try:
        root = ET.fromstring(raw.strip())
    except ET.ParseError:
        return None

    def _ns_find(parent, tag):
        # Support both namespaced and non-namespaced documents.
        el = parent.find(f"{_NS}{tag}")
        if el is None:
            el = parent.find(tag)
        return el

    system = _ns_find(root, "System")
    if system is None:
        return None
    ev = WindowsEvent(fmt="xml")

    def sysval(tag):
        el = _ns_find(system, tag)
        return (el.text or "").strip() if el is not None and el.text else ""

    prov = _ns_find(system, "Provider")
    if prov is not None:
        ev.provider = prov.get("Name") or prov.get("EventSourceName")
    ev.event_id = sysval("EventID") or None
    ev.channel = sysval("Channel") or None
    ev.computer = sysval("Computer") or None
    ev.task = sysval("Task") or None
    ev.record_id = sysval("EventRecordID") or None
    lvl = sysval("Level")
    ev.level = _LEVEL_LABELS.get(lvl, lvl) if lvl else None
    kw = sysval("Keywords")
    ev.keywords = kw or None

    tc = _ns_find(system, "TimeCreated")
    if tc is not None:
        ev.timestamp = tc.get("SystemTime")
    exe = _ns_find(system, "Execution")
    if exe is not None:
        ev.process_id = exe.get("ProcessID")
        ev.thread_id = exe.get("ThreadID")
    sec = _ns_find(system, "Security")
    if sec is not None:
        ev.security_user_id = sec.get("UserID")

    # EventData / UserData — keep every Data Name="X" losslessly.
    for container in ("EventData", "UserData"):
        cont = _ns_find(root, container)
        if cont is None:
            continue
        for child in cont.iter():
            name = child.get("Name")
            val = (child.text or "").strip()
            if name and val:
                ev.put(name, val)
    return ev
