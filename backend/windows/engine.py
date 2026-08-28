"""
Windows parser family ENGINE — public entry point.

    parse(raw_log) -> WindowsParseResult | None

Pipeline (deterministic, no LLM at runtime):
    detect_format ──► syntax parse (envelope) ──► classify (taxonomy) ──►
    build {fields, field_mapping, parser meta} ready for backend.ocsf_mapper.

Returns None when the log is not a Windows log, so the caller can fall through
to other parsers / Drain3.

The result gives the pipeline everything `map_to_ocsf` needs:
  * `fields`        — flat dict of every discovered value (promoted + raw)
  * `parser`        — a synthetic parser config (parser_id, class, mapping,
                      static_fields) so the SAME ocsf_mapper builds the envelope
  * `windows_block` — the complete Windows-native view, preserved under
                      `windows.*` so NO field is ever lost.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

import confidence as _confidence_mod

from .detector import detect_format, is_windows
from .envelope import WindowsEvent, parse_evtx_text, parse_event_xml, parse_winkv
from .handlers import classify, CLS_NETWORK, CLS_HTTP, SemanticResult

# Emitting providers/channels we consider unresolved → lowers the `source` sub-score.
_GENERIC_SOURCES = {"", "unknown", "generic", "generic log", "windows", "eventlog"}


@dataclass
class WindowsParseResult:
    parser_id: str
    fields: dict
    parser_config: dict
    windows_block: dict
    confidence: float
    summary: str = ""


# ── IIS W3C access-log engine ─────────────────────────────────────────────────

def _parse_iis_w3c(raw: str) -> Optional[WindowsEvent]:
    """Parse a single IIS W3C row using the most recent #Fields: header if present,
    else a common default field order."""
    fields_order = None
    row = None
    for line in raw.splitlines():
        line = line.rstrip("\r")
        if line.startswith("#Fields:"):
            fields_order = line[len("#Fields:"):].split()
        elif line and not line.startswith("#"):
            row = line
            break
    if row is None:
        return None
    values = row.split()
    if not fields_order:
        fields_order = ["date", "time", "s-ip", "cs-method", "cs-uri-stem",
                        "cs-uri-query", "s-port", "cs-username", "c-ip",
                        "cs(User-Agent)", "sc-status", "sc-substatus",
                        "sc-win32-status", "time-taken"][:len(values)]
    ev = WindowsEvent(fmt="iis-w3c", provider="IIS", channel="IIS")
    pairs = dict(zip(fields_order, values))
    date_v, time_v = pairs.get("date"), pairs.get("time")
    if date_v and time_v:
        ev.timestamp = f"{date_v} {time_v}"
    for k, v in pairs.items():
        ev.put(k, v)
    ev.event_id = "iis-request"
    return ev


def _parse_firewall_text(raw: str) -> Optional[WindowsEvent]:
    """Parse a Windows Firewall pfirewall.log row (space-separated W3C-ish)."""
    fields_order = None
    row = None
    for line in raw.splitlines():
        line = line.rstrip("\r")
        if line.startswith("#Fields:"):
            fields_order = line[len("#Fields:"):].split()
        elif line and not line.startswith("#"):
            row = line
            break
    if row is None:
        return None
    values = row.split()
    if not fields_order:
        fields_order = ["date", "time", "action", "protocol", "src-ip", "dst-ip",
                        "src-port", "dst-port", "size", "tcpflags", "tcpsyn",
                        "tcpack", "tcpwin", "icmptype", "icmpcode", "info",
                        "path"][:len(values)]
    ev = WindowsEvent(fmt="firewall-text", provider="Windows Firewall",
                      channel="Windows Firewall")
    pairs = dict(zip(fields_order, values))
    date_v, time_v = pairs.get("date"), pairs.get("time")
    if date_v and time_v:
        ev.timestamp = f"{date_v} {time_v}"
    for k, v in pairs.items():
        ev.put(k, v)
    ev.event_id = pairs.get("action", "firewall")
    return ev


def _build_envelope(raw: str, fmt: str) -> Optional[WindowsEvent]:
    if fmt == "xml":
        return parse_event_xml(raw)
    if fmt == "evtx-text":
        return parse_evtx_text(raw)
    if fmt == "winkv":
        return parse_winkv(raw)
    if fmt == "iis-w3c":
        return _parse_iis_w3c(raw)
    if fmt == "firewall-text":
        return _parse_firewall_text(raw)
    return None


def _iis_semantic(ev: WindowsEvent) -> SemanticResult:
    return SemanticResult(
        ocsf_class_uid=CLS_HTTP, activity=(0, "HTTP Request"),
        category="Network Activity", source_name="IIS",
        summary=f"IIS {ev.event_data.get('cs-method', 'request')} "
                f"{ev.event_data.get('cs-uri-stem', '')}",
        mapping={k: v for k, v in {
            "c-ip": "src_endpoint.ip", "s-ip": "dst_endpoint.ip",
            "s-port": "dst_endpoint.port", "cs-method": "http_request.http_method",
            "cs-uri-stem": "http_request.url.path", "sc-status": "http_response.code",
            "cs-username": "actor.user.name",
        }.items() if k in ev.event_data},
    )


def _firewall_semantic(ev: WindowsEvent) -> SemanticResult:
    action = str(ev.event_data.get("action", "")).upper()
    return SemanticResult(
        ocsf_class_uid=CLS_NETWORK, activity=(6, "Traffic"),
        category="Network Activity", source_name="Windows Firewall",
        status="Success" if action == "ALLOW" else ("Failure" if action == "DROP" else None),
        summary=f"Firewall {action or 'event'} "
                f"{ev.event_data.get('src-ip', '')} → {ev.event_data.get('dst-ip', '')}",
        mapping={k: v for k, v in {
            "src-ip": "src_endpoint.ip", "dst-ip": "dst_endpoint.ip",
            "src-port": "src_endpoint.port", "dst-port": "dst_endpoint.port",
            "protocol": "connection_info.protocol_name",
        }.items() if k in ev.event_data},
    )


def _parser_id_for(ev: WindowsEvent, sem: SemanticResult) -> str:
    """Stable parser_id for the family, aligned with the registry ID convention
    so coverage/telemetry group Windows sub-parsers consistently."""
    if ev.fmt == "iis-w3c":
        return "WIN-IIS-W3C"
    if ev.fmt == "firewall-text":
        return "WIN-FIREWALL-001"
    prov = (ev.provider or "").lower()
    chan = (ev.channel or "").lower()
    eid = str(ev.event_id or "").strip()
    if "sysmon" in prov or "sysmon" in chan:
        return "WIN-SYSMON-001"
    if "powershell" in prov or "powershell" in chan:
        # PowerShell script-block logging is Event ID 4104.
        return f"WIN-PWSH-{eid}" if eid in ("4103", "4104", "4105", "4106") else "WIN-PWSH-4104"
    if "defender" in prov or "defender" in chan:
        return "WIN-DEFENDER-001"
    if "service control manager" in prov:
        return "WIN-SYS-SVC"
    if "security-auditing" in prov or chan == "security":
        return f"WIN-SEC-{eid or 'X'}"
    # Any other Windows Event Log block → the generic catch-all registry id.
    return "WIN-EVTLOG-001"


def parse(raw_log: str) -> Optional[WindowsParseResult]:
    """Parse any Windows log into an OCSF-ready result, or None if not Windows."""
    fmt = detect_format(raw_log)
    if fmt is None:
        return None
    ev = _build_envelope(raw_log, fmt)
    if ev is None:
        return None

    # Taxonomy stage — pick semantic handler by format/provider/event id.
    if fmt == "iis-w3c":
        sem = _iis_semantic(ev)
    elif fmt == "firewall-text":
        sem = _firewall_semantic(ev)
    else:
        sem = classify(ev)

    parser_id = _parser_id_for(ev, sem)

    # ── Flatten envelope → fields dict for ocsf_mapper. ──
    # Header fields ocsf_mapper understands directly (timestamp/level/computer),
    # plus every EventData field keyed by its label. Promoted keys get their
    # OCSF path via field_mapping; everything else is preserved (unmapped +
    # windows_block).
    fields: dict = {}
    if ev.timestamp:
        fields["timestamp"] = ev.timestamp
    if ev.level:
        fields["level"] = ev.level
    if ev.computer:
        fields["Computer"] = ev.computer
    for k, v in ev.event_data.items():
        fields[k] = v
    # Promote taxonomy-derived semantic fields (e.g. logon_type) — spec #4.
    for k, v in sem.fields.items():
        if v not in (None, ""):
            fields[k] = v
    if sem.summary:
        fields["message"] = sem.summary

    field_mapping = dict(sem.mapping)

    # ── Promote source-native identifiers to canonical OCSF metadata homes ──
    # The EventID and Provider are the two fields an operator most needs to see,
    # but they previously had no canonical home and were only reachable inside
    # the `unmapped` leftovers dict. Mapping them here means a user-facing screen
    # can show "Event ID 12 / Microsoft-Windows-Kernel-General" from real
    # canonical fields instead of digging through internal structures.
    if ev.event_id not in (None, ""):
        fields["event_code"] = str(ev.event_id)
        field_mapping["event_code"] = "metadata.event_code"
        # Route the raw label carrying the same value to the same target so the
        # promotion does not leave a duplicate copy behind in `unmapped`.
        for dup in ("EventID", "Event ID", "EventId"):
            if str(fields.get(dup, "")).strip() == str(ev.event_id).strip() and dup in fields:
                field_mapping[dup] = "metadata.event_code"
    if ev.provider not in (None, ""):
        # log_provider is already populated from sem.source_name; mapping the raw
        # key to the same destination consumes it losslessly (same value, no dup).
        for dup in ("Provider", "ProviderName"):
            if dup in fields:
                field_mapping[dup] = "metadata.log_provider"

    static_fields: dict = {
        "activity_id": sem.activity[0],
        "activity_name": sem.activity[1],
    }
    if sem.status:
        static_fields["status"] = sem.status
        static_fields["status_id"] = 1 if sem.status == "Success" else 2
    if sem.severity:
        static_fields["severity_id"] = sem.severity[0]
        static_fields["severity"] = sem.severity[1]

    # ── Complete Windows-native view — guarantees zero information loss. ──
    windows_block = {
        "format": ev.fmt,
        "provider": ev.provider,
        "channel": ev.channel,
        "event_id": ev.event_id,
        "computer": ev.computer,
        "record_id": ev.record_id,
        "level": ev.level,
        "keywords": ev.keywords,
        "task": ev.task,
        "process_id": ev.process_id,
        "thread_id": ev.thread_id,
        "security_user_id": ev.security_user_id,
        "event_data": dict(ev.event_data),
    }
    windows_block = {k: v for k, v in windows_block.items() if v not in (None, "", {})} \
        or {"format": ev.fmt}
    windows_block["event_data"] = dict(ev.event_data)

    # ── Dynamic confidence (spec #9): calculated per stage, never hardcoded. ──
    # Structural core an evtx/xml/winkv record is expected to carry.
    _core = (ev.timestamp, ev.provider, ev.channel, ev.event_id, ev.computer, ev.level)
    structural_present = sum(1 for v in _core if v not in (None, "", False))
    source_known = (sem.source_name or "").strip().lower() not in _GENERIC_SOURCES
    cb = _confidence_mod.score(
        format_matched=True,
        structural_present=structural_present,
        structural_expected=len(_core),
        extracted_fields=len(fields),
        source_known=source_known,
        ocsf_class_uid=sem.ocsf_class_uid,
    )
    conf = cb.pop("_aggregate")

    parser_config = {
        "parser_id": parser_id,
        "source_name": sem.source_name,
        "os_family": "Windows",
        "category": sem.category,
        "ocsf_class_uid": sem.ocsf_class_uid,
        "field_mapping": field_mapping,
        "static_fields": static_fields,
        "_confidence": conf,
        "_confidence_breakdown": cb,
        "_parse_path": "windows-family",
    }

    return WindowsParseResult(
        parser_id=parser_id,
        fields=fields,
        parser_config=parser_config,
        windows_block=windows_block,
        confidence=conf,
        summary=sem.summary or "",
    )
