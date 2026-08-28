"""
Android parser family ENGINE — public entry point.

    parse(raw_log) -> AndroidParseResult | None

detect_format → syntax parse (envelope) → classify (taxonomy) → build
{fields, parser_config, android_block} for the shared ocsf_mapper.

Returns None when the log is not Android, so the pipeline falls through.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import confidence as _confidence_mod

from .detector import detect_format, is_android
from .envelope import (
    AndroidEvent, PRIORITY_LABELS,
    parse_threadtime, parse_time, parse_tag, parse_process, parse_long, parse_json,
)
from .handlers import classify

# Emitting apps/tags we consider unresolved → lowers the `source` sub-score.
_GENERIC_SOURCES = {"", "unknown", "generic", "generic log", "logcat"}


@dataclass
class AndroidParseResult:
    parser_id: str
    fields: dict
    parser_config: dict
    android_block: dict
    confidence: float
    summary: str = ""


_PARSERS = {
    "threadtime": parse_threadtime,
    "time": parse_time,
    "tag": parse_tag,
    "process": parse_process,
    "long": parse_long,
    "json": parse_json,
}


def _build_envelope(raw: str, fmt: str) -> Optional[AndroidEvent]:
    fn = _PARSERS.get(fmt)
    return fn(raw) if fn else None


def _parser_id_for(ev: AndroidEvent) -> str:
    return {
        "threadtime": "ANDROID-LOGCAT-THREADTIME",
        "time":       "ANDROID-LOGCAT-TIME",
        "tag":        "ANDROID-LOGCAT-BRIEF",
        "process":    "ANDROID-LOGCAT-PROCESS",
        "long":       "ANDROID-LOGCAT-LONG",
        "json":       "ANDROID-LOGCAT-JSON",
    }.get(ev.fmt, "ANDROID-LOGCAT-001")


def parse(raw_log: str) -> Optional[AndroidParseResult]:
    fmt = detect_format(raw_log)
    if fmt is None:
        return None
    ev = _build_envelope(raw_log, fmt)
    if ev is None:
        return None

    sem = classify(ev)
    parser_id = _parser_id_for(ev)

    # ── Flatten envelope → fields for ocsf_mapper. ──
    fields: dict = {}
    if ev.timestamp:
        # Android time is "MM-DD HH:MM:SS.mmm"; feed as month/day/time so the
        # mapper's numeric MM-DD branch builds a real event_time (not now()).
        parts = ev.timestamp.split()
        if len(parts) == 2 and "-" in parts[0]:
            mm, dd = parts[0].split("-", 1)
            fields["month"] = mm
            fields["day"] = dd
            fields["time"] = parts[1]
        else:
            fields["timestamp"] = ev.timestamp
    if ev.priority:
        # Single-letter priority → level so SEVERITY_MAP resolves it.
        fields["level"] = ev.priority
    if ev.tag:
        fields["tag"] = ev.tag
    if ev.pid:
        fields["pid"] = ev.pid
    if ev.tid:
        fields["tid"] = ev.tid
    if ev.message is not None:
        fields["message"] = ev.message
    for k, v in ev.extra.items():
        fields.setdefault(k, v)

    static_fields = {"activity_id": sem.activity[0], "activity_name": sem.activity[1]}

    android_block = {
        "format": ev.fmt,
        "priority": ev.priority,
        "priority_label": PRIORITY_LABELS.get(ev.priority or "", None),
        "tag": ev.tag,
        "pid": ev.pid,
        "tid": ev.tid,
        "timestamp": ev.timestamp,
        "message": ev.message,
        "extra": dict(ev.extra),
    }
    android_block = {k: v for k, v in android_block.items() if v not in (None, "", {})}
    android_block["extra"] = dict(ev.extra)
    # #4: preserve taxonomy-derived semantic fields (e.g. service_name) INSIDE
    # the android block — the value is kept losslessly under `unmapped.android`
    # (PART 19: top-level `unmapped` stays clean, no new envelope key is added).
    for k, v in sem.fields.items():
        if v not in (None, ""):
            android_block.setdefault(k, v)

    # ── Dynamic confidence (spec #9): calculated per stage, never hardcoded. ──
    # Structural core a logcat line is expected to carry.
    _core = (ev.timestamp, ev.priority, ev.tag, ev.pid, ev.message)
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
        "os_family": "Android",
        "category": sem.category,
        "ocsf_class_uid": sem.ocsf_class_uid,
        "field_mapping": dict(sem.mapping),
        "static_fields": static_fields,
        "_confidence": conf,
        "_confidence_breakdown": cb,
        "_parse_path": "android-family",
    }

    return AndroidParseResult(
        parser_id=parser_id,
        fields=fields,
        parser_config=parser_config,
        android_block=android_block,
        confidence=conf,
        summary=sem.summary or "",
    )
