"""
Linux parser family ENGINE — public entry point.

    parse(raw_log) -> LinuxParseResult | None

detect_format → syntax parse (envelope) → classify (taxonomy) → build
{fields, parser_config, linux_block} for the shared ocsf_mapper.

Returns None when the log is not Linux (or belongs to another family that only
*looks* syslog-ish), so the pipeline falls through to fingerprint/registry.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import confidence as _confidence_mod

from .detector import detect_format
from .envelope import (
    LinuxEvent, parse_rfc3164, parse_rfc5424, parse_dmesg, parse_auditd,
    parse_journald_json,
)
from .handlers import classify

# Emitting products/services we consider unresolved → lowers the `source` sub-score.
_GENERIC_SOURCES = {"", "unknown", "generic", "generic log", "syslog"}

# Native promotion always available regardless of class.
BASE_MAPPING = {
    "hostname": "device.hostname",
    "program": "actor.process.name",
    "pid": "actor.process.pid",
}

_PARSERS = {
    "rfc3164": parse_rfc3164,
    "rfc5424": parse_rfc5424,
    "dmesg": parse_dmesg,
    "auditd": parse_auditd,
    "journald_json": parse_journald_json,
}

_PARSER_IDS = {
    "rfc3164": "LINUX-SYSLOG-RFC3164",
    "rfc5424": "LINUX-SYSLOG-RFC5424",
    "dmesg": "LINUX-KERNEL-DMESG",
    "auditd": "LINUX-AUDITD",
    "journald_json": "LINUX-JOURNALD-JSON",
}


@dataclass
class LinuxParseResult:
    parser_id: str
    fields: dict
    parser_config: dict
    linux_block: dict
    confidence: float
    summary: str = ""


def is_linux(raw: str) -> bool:
    return detect_format(raw) is not None


def _should_decline(raw: str, ev: LinuxEvent) -> bool:
    """Yield adversarial / foreign-payload lines back to the pipeline.

    These are RFC3164-shaped but wrap another product's payload; letting the
    generic fingerprint/registry + review flagging handle them keeps the
    adversarial-detection guarantees intact (never auto-claim a confident class
    for a mismatched header/body).
    """
    low = raw.lower()
    # macOS / pfSense / NetScreen / Juniper / Cisco ASA firewall products own these payloads.
    if ("filterlog" in low or "socketfilterfw" in low or "rt_flow" in low
            or "netscreen" in low or "%asa-" in low or "cef:" in low):
        return True
    prog = (ev.program or "").lower()
    msg = ev.message or ""
    # sshd program name but an iptables-style packet body = wrapped payload.
    if prog == "sshd" and ("SRC=" in msg and "DST=" in msg):
        return True
    return False


def parse(raw_log: str) -> Optional[LinuxParseResult]:
    if not raw_log or not raw_log.strip():
        return None
    fmt = detect_format(raw_log)
    if fmt is None:
        return None
    fn = _PARSERS.get(fmt)
    if fn is None:
        return None
    ev = fn(raw_log)
    if ev is None:
        return None
    if _should_decline(raw_log, ev):
        return None

    sem = classify(ev)
    parser_id = _PARSER_IDS.get(fmt, "LINUX-SYSLOG-001")

    # ── Flatten envelope → fields for ocsf_mapper. ──
    fields: dict = {}
    if ev.month and ev.day and ev.time:
        fields["month"] = ev.month
        fields["day"] = ev.day
        fields["time"] = ev.time
    elif ev.timestamp:
        fields["timestamp"] = ev.timestamp
    if ev.level:
        fields["level"] = ev.level
    if ev.hostname:
        fields["hostname"] = ev.hostname
    if ev.program:
        fields["program"] = ev.program
    if ev.pid:
        fields["pid"] = ev.pid
    if ev.message is not None:
        fields["message"] = ev.message
    # Promote taxonomy-extracted values (user/ips/ports/command/http/...).
    for k, v in sem.fields.items():
        if v not in (None, ""):
            fields[k] = v

    static_fields = {"activity_id": sem.activity[0], "activity_name": sem.activity[1]}
    if sem.severity is not None:
        static_fields["severity_id"] = sem.severity[0]
        static_fields["severity"] = sem.severity[1]
    if sem.status is not None:
        static_fields["status"] = sem.status[0]
        static_fields["status_id"] = sem.status[1]

    field_mapping = {**BASE_MAPPING, **sem.mapping}

    # ── Native block: EVERYTHING the mapper won't promote, losslessly. ──
    linux_block = {
        "format": ev.fmt,
        "facility": ev.extra.get("facility"),
        "priority": ev.extra.get("priority"),
        "hostname": ev.hostname,
        "program": ev.program,
        "pid": ev.pid,
        "level": ev.level,
        "timestamp": ev.timestamp,
        "message": ev.message,
    }
    linux_block = {k: v for k, v in linux_block.items() if v not in (None, "", {})}
    # everything the format parser captured natively (audit key=vals, msgid,
    # structured_data, uptime, unit, …) lives here and only here.
    linux_block["native"] = dict(ev.extra)

    # ── Dynamic confidence (spec #9): calculated per stage, never hardcoded. ──
    # Structural core the syslog/kernel/audit envelope is expected to fill.
    _core = (ev.timestamp or (ev.month and ev.day and ev.time), ev.hostname,
             ev.program, ev.pid, ev.level, ev.message)
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
        "os_family": "Linux",
        "category": sem.category,
        "ocsf_class_uid": sem.ocsf_class_uid,
        "field_mapping": field_mapping,
        "static_fields": static_fields,
        "_confidence": conf,
        "_confidence_breakdown": cb,
        "_parse_path": "linux-family",
    }

    return LinuxParseResult(
        parser_id=parser_id,
        fields=fields,
        parser_config=parser_config,
        linux_block=linux_block,
        confidence=conf,
        summary=sem.summary or "",
    )
