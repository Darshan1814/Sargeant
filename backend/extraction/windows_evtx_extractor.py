"""
Windows EVTX extractor (Stage 1).

Converts a binary Windows Event Log (.evtx) into the plain-text "evtx-style"
blocks that the WIN-* NGRE parsers understand, e.g.::

    Log Name:      Security
    Source:        Microsoft-Windows-Security-Auditing
    Event ID:      4624
    Level:         Information
    Computer:      DC01.corp.local
    <rendered message + EventData key: value lines>

Design constraints (honest):
  * Fully offline. Uses the pure-python ``python-evtx`` library if present.
    If it is not installed we DO NOT fake success — we raise/return an
    explicit ExtractionResult with ok=False so the caller can fall back.
  * We do not attempt to reproduce the exact Windows Event Viewer rendering.
    We emit the canonical header fields (which the parsers key off) plus a
    flattened EventData/UserData dump so no field is lost — unmapped keys are
    still carried into OCSF ``unmapped`` downstream.
  * A record that cannot be parsed is yielded as an error block, never dropped.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as _ET  # stdlib — always available
from dataclasses import dataclass, field
from typing import Iterator, List

try:  # optional, offline-installable dependency (binary .evtx decoding only)
    from Evtx.Evtx import Evtx  # type: ignore
    _HAVE_EVTX = True
except Exception:  # pragma: no cover - depends on host env
    _HAVE_EVTX = False


# Windows system XML namespace used by the event schema.
_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

# Human-readable Level id -> label (matches Event Viewer wording the parsers expect).
_LEVEL_LABELS = {
    "0": "Information",
    "1": "Critical",
    "2": "Error",
    "3": "Warning",
    "4": "Information",
    "5": "Verbose",
}

# Raw EVTX EventData attribute names -> the Event-Viewer-rendered labels the
# WIN-SEC-* / WIN-SYSMON-* parsers key off. Binary .evtx stores machine names
# (TargetUserName); the parsers (built against `wevtutil /f:text` output) expect
# the rendered labels (Account Name). Translating here is what lets a decoded
# binary record reach its specialized parser instead of the generic catch-all.
# Anything not in this map is still emitted under its raw name (lossless).
_EVENTDATA_LABELS = {
    "TargetUserName": "Account Name",
    "SubjectUserName": "Account Name",
    "TargetDomainName": "Account Domain",
    "SubjectDomainName": "Account Domain",
    "LogonType": "Logon Type",
    "IpAddress": "Source Network Address",
    "IpPort": "Source Port",
    "WorkstationName": "Workstation Name",
    "Status": "Failure Reason",
    "FailureReason": "Failure Reason",
    "NewProcessId": "New Process ID",
    "NewProcessName": "New Process Name",
    "ProcessName": "Process Name",
    "ProcessId": "Process ID",
    "ParentProcessName": "Creator Process Name",
    "Image": "Image",
    "CommandLine": "CommandLine",
    "ServiceName": "Service Name",
}


@dataclass
class ExtractionResult:
    """Outcome of an extraction run.

    ``records`` holds successfully rendered text blocks. ``errors`` holds
    (index, reason) pairs for records we could not render. ``ok`` is True only
    when the extractor could actually run (dependency present + file opened).
    """

    ok: bool
    records: List[str] = field(default_factory=list)
    errors: List[tuple] = field(default_factory=list)
    reason: str = ""

    @property
    def extracted(self) -> int:
        return len(self.records)

    @property
    def failed(self) -> int:
        return len(self.errors)


def dependency_available() -> bool:
    """True when python-evtx is importable in this environment."""
    return _HAVE_EVTX


def _text(elem, default: str = "") -> str:
    return (elem.text or default).strip() if elem is not None else default


def _render_record(xml_str: str) -> str:
    """Turn one event's XML into an evtx-style text block.

    Never raises for content reasons — malformed XML is the caller's concern
    (it is caught in :func:`extract_evtx` and recorded as an error).
    """
    root = _ET.fromstring(xml_str)
    system = root.find(f"{_NS}System")

    def sysval(tag: str) -> str:
        return _text(system.find(f"{_NS}{tag}")) if system is not None else ""

    provider_el = system.find(f"{_NS}Provider") if system is not None else None
    source = ""
    if provider_el is not None:
        source = provider_el.get("Name") or provider_el.get("EventSourceName") or ""

    channel = sysval("Channel")
    event_id = sysval("EventID")
    computer = sysval("Computer")

    level_raw = sysval("Level")
    level = _LEVEL_LABELS.get(level_raw, level_raw or "Information")

    time_el = system.find(f"{_NS}TimeCreated") if system is not None else None
    time_created = time_el.get("SystemTime") if time_el is not None else ""

    lines = [
        f"Log Name:      {channel}",
        f"Source:        {source}",
        f"Event ID:      {event_id}",
        f"Level:         {level}",
        f"Date:          {time_created}",
        f"Computer:      {computer}",
    ]

    # Flatten EventData / UserData so nothing is lost. Raw attribute names are
    # translated to Event-Viewer labels where known so specialized parsers match;
    # unknown names pass through verbatim (still captured into OCSF `unmapped`).
    for container in ("EventData", "UserData"):
        cont_el = root.find(f"{_NS}{container}")
        if cont_el is None:
            continue
        for child in cont_el.iter():
            name = child.get("Name")
            val = (child.text or "").strip()
            if name and val:
                label = _EVENTDATA_LABELS.get(name, name)
                # "  Account Name:  jsmith" style — matches WIN-SEC-* patterns.
                lines.append(f"  {label}:  {val}")
    return "\n".join(lines)


def extract_evtx(path: str) -> ExtractionResult:
    """Extract every record from a .evtx file into text blocks.

    Returns an ExtractionResult. When python-evtx is unavailable, ``ok`` is
    False and ``reason`` explains why — the caller should then route raw bytes
    to Drain3 rather than assume coverage.
    """
    if not _HAVE_EVTX:
        return ExtractionResult(
            ok=False,
            reason="python-evtx not installed; cannot decode binary .evtx offline. "
            "Install 'python-evtx' or pre-export to text.",
        )

    result = ExtractionResult(ok=True)
    try:
        with Evtx(path) as log:
            for idx, record in enumerate(log.records()):
                try:
                    result.records.append(_render_record(record.xml()))
                except Exception as exc:  # malformed single record — keep going
                    result.errors.append((idx, f"{type(exc).__name__}: {exc}"))
    except Exception as exc:
        return ExtractionResult(ok=False, reason=f"failed to open {path}: {exc}")
    return result


def extract_evtx_text(blob: str) -> Iterator[str]:
    """Split an already-textual evtx export into individual event blocks.

    Useful when logs were exported with ``wevtutil qe ... /f:text`` (no binary
    dependency). Blocks are separated by blank lines and each must contain a
    ``Log Name:`` or ``Event ID:`` header to count as an event.
    """
    block: list[str] = []
    for line in blob.splitlines():
        if not line.strip():
            if block:
                joined = "\n".join(block)
                if re.search(r"^(Log Name:|Event ID:)", joined, re.MULTILINE):
                    yield joined
                block = []
            continue
        block.append(line)
    if block:
        joined = "\n".join(block)
        if re.search(r"^(Log Name:|Event ID:)", joined, re.MULTILINE):
            yield joined
