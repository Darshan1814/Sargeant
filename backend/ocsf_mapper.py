"""
OCSF field mapping.

Produces a *canonical, uniform* OCSF envelope so that a Windows event and a macOS
event have the EXACT SAME top-level structure — every key is always present (null
when a source has no value for it). This is what makes cross-platform events "look
the same".

Two guarantees:
  1. Uniform shape — the skeleton in `_canonical_envelope()` is identical for every
     parser/OS. Absent values are explicit nulls, never missing keys.
  2. No field is ever dropped — every NGRE named group is either mapped to an OCSF
     path (via the parser's `field_mapping`) OR preserved verbatim under `unmapped`.
     Nothing the parser captured is silently discarded.
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone

# ── OCSF class / category / activity lookup tables ────────────────────────────
# class_uid → (class_name, category_uid, category_name)
CLASS_INFO = {
    1001: ("System Activity", 1, "System Activity"),
    1007: ("Process Activity", 1, "System Activity"),
    3002: ("Authentication", 3, "Identity & Access Management"),
    3005: ("Entity Management", 3, "Identity & Access Management"),
    4001: ("Network Activity", 4, "Network Activity"),
    4002: ("HTTP Activity", 4, "Network Activity"),
    6003: ("API Activity", 6, "Application Activity"),
    6005: ("Application Lifecycle", 6, "Application Activity"),
}

SEVERITY_MAP = {
    "information": (1, "Informational"),
    "informational": (1, "Informational"),
    "info": (1, "Informational"),
    "notice": (1, "Informational"),
    "default": (1, "Informational"),
    "verbose": (0, "Unknown"),
    "debug": (0, "Unknown"),
    "trace": (0, "Unknown"),
    "low": (2, "Low"),
    "warning": (3, "Medium"),
    "warn": (3, "Medium"),
    "medium": (3, "Medium"),
    "error": (4, "High"),
    "err": (4, "High"),
    "high": (4, "High"),
    "fault": (4, "High"),
    "critical": (5, "Critical"),
    "crit": (5, "Critical"),
    "fatal": (5, "Critical"),
    "emergency": (5, "Critical"),
    "alert": (5, "Critical"),
    "audit success": (1, "Informational"),
    "audit failure": (4, "High"),
    "success": (1, "Informational"),
    "failure": (4, "High"),
    # Android logcat single-letter priorities.
    "v": (0, "Unknown"),       # Verbose
    "d": (0, "Unknown"),       # Debug
    "i": (1, "Informational"), # Info
    "w": (3, "Medium"),        # Warning
    "e": (4, "High"),          # Error
    "f": (5, "Critical"),      # Fatal
}

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

# Candidate IPv4 finder. We DON'T trust a bare 4-dotted-number match — many
# non-IP tokens look like one (package/build versions "6.1.1.2", dotted ids).
# Each candidate is validated by _valid_ipv4() below (octet range + surrounding
# context) so version strings are never mis-tagged as IP observables.
_IP_CANDIDATE_RE = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?![\w.])")
# A version/identifier context: the token sits inside a longer dotted or
# tilde/underscore-delimited run (e.g. "~~6.1.1.2", "v1.2.3.4-build").
_VERSION_HINT_RE = re.compile(r"(?:version|ver|build|kb|package|v)\b", re.IGNORECASE)


def _valid_ipv4(candidate: str, raw: str, start: int, end: int) -> bool:
    """True only if `candidate` is a real IPv4 address, not a version/id string.

    Rules (context-aware, fixes the "6.1.1.2 → IP" false positive at the root):
      * every octet must be 0-255 (rejects 999.1.1.1, and 6.1.1.2 passes range
        but is caught by the context checks below);
      * the char immediately before/after must NOT be '.' , '~' or a digit —
        that would mean the token is part of a longer dotted/versioned run
        (e.g. "…~~6.1.1.2" or "1.2.3.4.5");
      * a nearby version/package keyword downgrades it to non-IP.
    """
    parts = candidate.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit() or not (0 <= int(p) <= 255):
            return False
    # Immediate neighbours: '~' or '.' adjacency means it's inside a version run.
    # (Guard against empty-string neighbours, since "" in ".~" is True.)
    before = raw[start - 1] if start > 0 else ""
    after = raw[end] if end < len(raw) else ""
    if (before and before in ".~") or (after and after in ".~"):
        return False
    # Version/package keyword within a small window before the candidate.
    window = raw[max(0, start - 24):start]
    if _VERSION_HINT_RE.search(window):
        return False
    return True


def _resolve_severity(raw_level) -> tuple[int, str]:
    if not raw_level:
        return (1, "Informational")
    key = str(raw_level).strip().lower()
    return SEVERITY_MAP.get(key, (1, "Informational"))


def _build_timestamp(fields: dict) -> tuple[str, str | None]:
    """Return (iso8601_time, original_raw_time_string)."""
    # 1. Full datetime field: "YYYY-MM-DD HH:MM:SS" (Windows CBS / evtx export)
    dt_str = fields.get("datetime") or fields.get("date_time")
    if dt_str:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S",
                    "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%d %H:%M:%S.%f"):
            try:
                dt = datetime.strptime(dt_str.strip(), fmt)
                return dt.replace(tzinfo=timezone.utc).isoformat(), dt_str.strip()
            except ValueError:
                pass

    # 2. Separate date + time (IIS W3C / firewall: "2024-05-01" + "12:00:00")
    date_f = fields.get("date")
    time_f = fields.get("time")
    if date_f and time_f and "-" in str(date_f):
        try:
            dt = datetime.strptime(f"{date_f} {time_f}", "%Y-%m-%d %H:%M:%S")
            return dt.replace(tzinfo=timezone.utc).isoformat(), f"{date_f} {time_f}"
        except ValueError:
            pass

    # 3. Month / day / time — year assumed current. Handles BOTH:
    #      BSD syslog  "Jul  1 09:00:55"        (month = 3-letter name)
    #      Android     "08-10 09:20:19.692"     (month = numeric, time has .mmm)
    month = fields.get("month")
    day = fields.get("day")
    if month and day and time_f:
        year = datetime.now(timezone.utc).year
        try:
            m_str = str(month).strip()
            mm = int(m_str) if m_str.isdigit() else _MONTHS.get(m_str[:3], 1)
            # Split time into H, M, S and optional fractional seconds.
            t = str(time_f).strip()
            hh, mi, sec = (t.split(":") + ["0", "0", "0"])[:3]
            if "." in sec:
                ss, frac = sec.split(".", 1)
                micro = int((frac + "000000")[:6])
            else:
                ss, micro = sec, 0
            dt = datetime(year, mm, int(day), int(hh), int(mi), int(ss),
                          micro, tzinfo=timezone.utc)
            return dt.isoformat(), f"{month}-{day} {time_f}" if m_str.isdigit() \
                else f"{month} {day} {time_f}"
        except (ValueError, KeyError):
            pass

    # 4. ISO timestamp field (unified-log JSON, crash reports)
    ts = fields.get("timestamp") or fields.get("time_iso")
    if ts:
        try:
            dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
            return dt.isoformat(), str(ts)
        except (ValueError, AttributeError):
            # Un-parseable but real — keep the raw string for traceability.
            return datetime.now(timezone.utc).isoformat(), str(ts)

    # 5. Nothing structured parsed — preserve any raw datetime-ish field we saw.
    raw_candidate = (
        dt_str
        or (f"{month} {day} {time_f}" if (month and day and time_f) else None)
    )
    return datetime.now(timezone.utc).isoformat(), (
        raw_candidate.strip() if isinstance(raw_candidate, str) else None
    )


def _set_nested(obj: dict, dotted_key: str, value):
    parts = dotted_key.split(".")
    for part in parts[:-1]:
        nxt = obj.get(part)
        if not isinstance(nxt, dict):
            nxt = {}
            obj[part] = nxt
        obj = nxt
    obj[parts[-1]] = value


def _coerce(value):
    """Turn numeric-looking strings into ints for cleaner OCSF (pids, ports, ids)."""
    if isinstance(value, str) and value.isdigit():
        try:
            return int(value)
        except ValueError:
            return value
    return value


def _os_name(os_family: str) -> str:
    fam = (os_family or "").lower()
    if "win" in fam:
        return "Windows"
    if "android" in fam:
        return "Android"
    if "mac" in fam or "darwin" in fam or "osx" in fam:
        return "macOS"
    if "linux" in fam:
        return "Linux"
    return os_family or "Unknown"


def _canonical_envelope(class_uid: int, event_id: str, parser: dict) -> dict:
    """The fixed skeleton — identical for EVERY OS/parser. Absent = explicit null."""
    class_name, category_uid, category_name = CLASS_INFO.get(
        class_uid, ("System Activity", 1, "System Activity")
    )
    os_family = parser.get("os_family", "Unknown")
    return {
        # ── classification ──
        "class_uid": class_uid,
        "class_name": class_name,
        "category_uid": category_uid,
        "category_name": category_name,
        "activity_id": 0,
        "activity_name": "Unknown",
        "type_uid": class_uid * 100,
        # ── time ──
        "time": None,
        "timezone_offset": 0,
        # ── severity / status ──
        "severity_id": 1,
        "severity": "Informational",
        "status": "Unknown",
        "status_id": 0,
        # ── human message ──
        "message": None,
        # ── device (host) ──
        "device": {
            "hostname": None,
            "type": "Unknown",
            "os": {
                "name": _os_name(os_family),
                "family": os_family,
                "type": os_family,
            },
        },
        # ── actor (who/what) ──
        "actor": {
            "process": {"name": None, "pid": None, "cmd_line": None},
            "user": {"name": None, "uid": None, "domain": None},
        },
        # ── network endpoints (null for non-network events, but always present) ──
        "src_endpoint": {"ip": None, "port": None, "hostname": None},
        "dst_endpoint": {"ip": None, "port": None, "hostname": None},
        # ── network connection (null for non-network events, but always present) ──
        "connection_info": {
            "protocol_name": None,
            "direction": None,
            "protocol_num": None,
        },
        # ── authentication (null for non-auth events, but always present) ──
        "auth_protocol": None,
        # ── traceability metadata ──
        "metadata": {
            "version": "1.1.0",
            "uid": event_id,
            "parser_id": parser.get("parser_id", "UNKNOWN"),
            "product": {
                "name": parser.get("source_name", "Unknown"),
                "vendor_name": os_family,
                "feature": {"name": parser.get("category", "Unknown")},
            },
            "log_provider": parser.get("source_name", "Unknown"),
            # Three distinct time axes are kept separate (spec #6): when the
            # event happened (original_time / ev["time"]), when we ingested it
            # (ingestion_time — filled by main._persist_result), and when we
            # normalized it (processed_time). They are never conflated.
            "original_time": None,
            "ingestion_time": None,
            "processed_time": datetime.now(timezone.utc).isoformat(),
            # Always-on integrity hash of the exact raw payload (spec #2). Filled
            # in map_to_ocsf so EVERY path carries it, regardless of archival.
            "raw_sha256": None,
        },
        # ── enrichment / lossless capture ──
        "observables": [],
        "unmapped": {},
        # ── provenance ──
        "raw_data": None,
        "confidence": parser.get("_confidence", 1.0),
        # Multi-dimensional confidence (PART 22) — tells the truth about WHICH
        # stage we are sure of. Populated by _apply_provenance() below.
        "confidence_breakdown": {
            "format": None, "pattern": None, "source": None,
            "parser": None, "semantic": None, "ocsf": None,
            "field_coverage": None,
        },
        # Human-readable pipeline stages (PART 26) instead of an opaque "ngre".
        "parse_path": parser.get("_parse_path", "ngre"),
        "parse_stages": [],
        # PART 23 — parsed | partially_parsed | fallback | failed.
        "parse_status": "parsed",
        # PART 20/21 — whether we confidently mapped an OCSF semantic class.
        "ocsf_mapping_status": "mapped",
        "needs_review": False,
    }


# Known-confident OCSF classes: when a parser lands here we consider the OCSF
# semantic mapping trustworthy. A generic/log-only landing (System Activity or
# Application "Log") means the format is parsed but the high-level OCSF class is
# not confidently determined → ocsf_mapping_status = "unmapped" (PART 20/21).
_CONFIDENT_OCSF_CLASSES = {1007, 3002, 3005, 4001, 4002, 6003}


def _validate_class_uid(class_uid) -> tuple[int, str | None]:
    """Validate a proposed OCSF class_uid against the configured schema (``CLASS_INFO``).

    Spec #8: we NEVER force a wrong class. If a parser proposes a class_uid the
    framework does not recognise (not in the configured OCSF class table), we do
    NOT silently keep the bad uid with a mismatched name — we downgrade to the
    generic 1001 "System Activity" landing (which the confident-class gate then
    flags needs_review + ocsf_mapping_status="unmapped") and return a note so the
    original, rejected uid is preserved in metadata for transparency.

    Returns ``(effective_class_uid, downgrade_note_or_None)``.
    """
    try:
        uid = int(class_uid)
    except (TypeError, ValueError):
        return 1001, f"non-numeric class_uid {class_uid!r} → downgraded to 1001"
    if uid in CLASS_INFO:
        return uid, None
    return 1001, f"unrecognized class_uid {uid} not in OCSF schema → downgraded to 1001"


def _human_parse_path(parse_path: str) -> list:
    """Map the internal parse_path token to the explainable stage list (PART 26)."""
    if parse_path in ("drain3",):
        return ["format_detection", "pattern_detection", "generic_parser",
                "drain3_fallback"]
    if parse_path == "dlq":
        return ["format_detection", "pattern_detection", "parser_identification",
                "failed", "dlq"]
    # deterministic paths: ngre / windows-family / android-family
    return ["format_detection", "pattern_detection", "source_detection",
            "parser_identification", "syntax_parsing", "normalization",
            "ocsf_mapping"]


def map_to_ocsf(
    fields: dict,
    parser: dict,
    event_id: str,
    raw_log: str,
    drain3_template: str | None = None,
) -> dict:
    requested_class_uid = parser.get("ocsf_class_uid", 1001)
    # Spec #8: validate the proposed OCSF class against the configured schema.
    # An unrecognized class is downgraded to the generic landing rather than
    # forced through with a mismatched class_name; the confident-OCSF gate then
    # marks it unmapped + needs_review. The original request is preserved below.
    class_uid, _class_downgrade_note = _validate_class_uid(requested_class_uid)
    field_mapping: dict = parser.get("field_mapping", {})

    ev = _canonical_envelope(class_uid, event_id, parser)
    if _class_downgrade_note:
        ev["metadata"]["ocsf_class_requested"] = requested_class_uid
        ev["metadata"]["ocsf_class_note"] = _class_downgrade_note
        ev["needs_review"] = True

    # timestamp
    iso_time, original_time = _build_timestamp(fields)
    ev["time"] = iso_time
    ev["metadata"]["original_time"] = original_time

    # severity (level / severity / messageType / status)
    severity_raw = (
        fields.get("level")
        or fields.get("severity")
        or fields.get("messageType")
        or fields.get("message_type")
        or fields.get("status")
        or ""
    )
    sev_id, sev_name = _resolve_severity(severity_raw)
    ev["severity_id"] = sev_id
    ev["severity"] = sev_name

    # activity name/id override from parser (optional)
    if "activity_id" in parser:
        ev["activity_id"] = parser["activity_id"]
    if "activity_name" in parser:
        ev["activity_name"] = parser["activity_name"]

    # static_fields: constant OCSF values the parser knows a priori
    # (e.g. status="Failure" for a 4625 logon-failure parser). Applied before
    # dynamic field_mapping so extracted values can still override if needed.
    for path, const_val in parser.get("static_fields", {}).items():
        if str(path).startswith("_"):
            continue
        _set_nested(ev, path, const_val)

    raw_data = raw_log if raw_log is not None else ""
    ev["raw_data"] = raw_data
    # Always-on integrity hash of the exact raw payload (spec #2). Computed here
    # so it is present on EVERY code path — deterministic, drain3, and DLQ alike
    # — independent of whether the MinIO archive step later runs.
    ev["metadata"]["raw_sha256"] = hashlib.sha256(
        raw_data.encode("utf-8", "replace")
    ).hexdigest()

    # ── Apply explicit field_mapping (extracted field → OCSF dotted path) ──
    mapped_src_keys: set[str] = set()
    mapped_count = 0  # source fields that found a real OCSF home (for field_coverage)
    for src_field, ocsf_path in field_mapping.items():
        # keys/targets beginning with "_" are pipeline-internal (e.g. _datetime, _month)
        mapped_src_keys.add(src_field)
        if src_field.startswith("_") or str(ocsf_path).startswith("_"):
            continue
        value = fields.get(src_field)
        if value is not None and value != "":
            _set_nested(ev, ocsf_path, _coerce(value))
            mapped_count += 1

    # ── Lossless capture: named groups not explicitly mapped are preserved,
    # EXCEPT fields already CONSUMED by normalization (timestamp components,
    # severity source) — those are represented in `time`/`severity`/`metadata`
    # and in the source-specific block (android.*/windows.*), so echoing them
    # into `unmapped` would make it a dumping ground (PART 19). ──
    _CONSUMED = {
        "drain3_template",
        # timestamp components → represented in ev["time"] + metadata.original_time
        "datetime", "date_time", "date", "time", "month", "day",
        "timestamp", "time_iso", "time_created",
        # severity sources → represented in ev["severity"]/severity_id
        "level", "severity", "messageType", "message_type",
        "priority", "priority_label",
        # message → represented in ev["message"]
        "message",
    }
    for key, value in fields.items():
        if key in _CONSUMED or key in mapped_src_keys:
            continue
        if value is None or value == "":
            continue
        ev["unmapped"][key] = value

    # message fallback
    if ev["message"] is None:
        ev["message"] = fields.get("message") or raw_data

    # ── Observables: pull VALIDATED IPs out of the raw line for pivoting ──
    # Each 4-dotted candidate is range- and context-checked so version/build
    # strings (e.g. "6.1.1.2" in a KB package name) are never tagged as IPs.
    seen_ips: set[str] = set()
    for m in _IP_CANDIDATE_RE.finditer(raw_data):
        cand = m.group(1)
        if cand in seen_ips:
            continue
        if _valid_ipv4(cand, raw_data, m.start(1), m.end(1)):
            seen_ips.add(cand)
            ev["observables"].append({"name": "ip", "type": "IP Address", "value": cand})

    # ── Drain3 fallback annotation ──
    if drain3_template:
        ev["needs_review"] = True
        ev["parse_path"] = "drain3"
        ev["metadata"]["drain3_template"] = drain3_template
        ev["unmapped"]["drain3_template"] = drain3_template

    # ── Timestamp inference metadata (PART 8) ──
    # Sources like Android logcat/BSD syslog carry no year or timezone. When we
    # supplied them, mark them as inferred so downstream never treats them as
    # authoritative source values.
    orig = ev["metadata"].get("original_time") or ""
    has_year = bool(re.search(r"\b\d{4}\b", str(orig)))
    has_tz = bool(re.search(r"(?:[Zz]|[+-]\d{2}:?\d{2})\s*$", str(orig)))
    ev["metadata"]["timestamp_year_source"] = "source" if has_year else "inferred"
    ev["metadata"]["timestamp_timezone_source"] = (
        "source" if has_tz else "collector/system configuration"
    )

    # ── field_coverage (spec #9): how much of what we extracted found an OCSF
    # home vs. was preserved under `unmapped`. Computed here because only now do
    # we know the mapped-vs-unmapped split. ──
    unmapped_count = len(ev["unmapped"])
    denom = mapped_count + unmapped_count
    field_coverage = round(mapped_count / denom, 3) if denom else 0.0

    # ── Provenance: parse_status, confidence breakdown, readable path (PART 20-26) ──
    _apply_provenance(ev, parser, class_uid, drain3_template is not None, field_coverage)

    return ev


def _apply_provenance(ev: dict, parser: dict, class_uid: int, is_drain3: bool,
                      field_coverage: float = 0.0):
    """Populate parse_status, confidence_breakdown, parse_stages, ocsf_mapping_status.

    These are honest, derived signals — never a blanket confidence=1. They tell an
    evaluator exactly which pipeline stage we are sure of. When a deterministic
    family engine supplied its own per-stage breakdown (``_confidence_breakdown``),
    we honor those calculated sub-scores; otherwise we derive a breakdown from the
    single ``_confidence`` scalar (fingerprint/registry paths). The confident-OCSF
    gate stays authoritative either way (a generic landing is forced to ocsf=0.0 +
    needs_review), and ``field_coverage`` is always appended from the mapper.
    """
    parse_path = ev.get("parse_path", "ngre")
    conf = float(parser.get("_confidence", 1.0) or 0.0)
    ev["parse_stages"] = _human_parse_path(parse_path)

    if is_drain3 or parse_path == "drain3":
        ev["parse_status"] = "fallback"
        ev["ocsf_mapping_status"] = "unmapped"
        ev["needs_review"] = True
        ev["confidence_breakdown"] = {
            "format": 0.5, "pattern": 0.3, "source": 0.0,
            "parser": 0.0, "semantic": 0.0, "ocsf": 0.0,
            "field_coverage": field_coverage,
        }
        return
    if parser.get("parser_id") == "DLQ":
        ev["parse_status"] = "failed"
        ev["ocsf_mapping_status"] = "unmapped"
        ev["needs_review"] = True
        ev["confidence_breakdown"] = {
            k: 0.0 for k in ("format", "pattern", "source", "parser", "semantic", "ocsf")
        }
        ev["confidence_breakdown"]["field_coverage"] = field_coverage
        return

    # Deterministic parse. Is the OCSF class a confident semantic class, or a
    # generic "we parsed it but don't know the high-level class" landing?
    confident_ocsf = class_uid in _CONFIDENT_OCSF_CLASSES
    ev["ocsf_mapping_status"] = "mapped" if confident_ocsf else "unmapped"
    ev["parse_status"] = "parsed" if confident_ocsf else "partially_parsed"
    if not confident_ocsf:
        ev["needs_review"] = True

    supplied = parser.get("_confidence_breakdown")
    if isinstance(supplied, dict) and supplied:
        # Engine-calculated per-stage sub-scores (spec #9). Copy them through, but
        # keep the confident-OCSF gate authoritative for the ocsf/semantic stages.
        breakdown = {
            "format": round(float(supplied.get("format", 1.0) or 0.0), 2),
            "pattern": round(float(supplied.get("pattern", conf) or 0.0), 2),
            "source": round(float(supplied.get("source", 1.0) or 0.0), 2),
            "parser": round(float(supplied.get("parser", conf) or 0.0), 2),
            "semantic": round(float(supplied.get("semantic", conf) or 0.0), 2),
            "ocsf": round(float(supplied.get("ocsf", 0.0) or 0.0), 2),
        }
        if not confident_ocsf:
            breakdown["ocsf"] = 0.0
    else:
        # Non-family deterministic path (fingerprint/registry): derive from the
        # single scalar, as before.
        breakdown = {
            "format": 1.0,
            "pattern": round(min(conf + 0.05, 1.0), 2),
            "source": 1.0,
            "parser": round(conf, 2),
            "semantic": round(conf if confident_ocsf else conf * 0.6, 2),
            "ocsf": round(conf, 2) if confident_ocsf else 0.0,
        }
    breakdown["field_coverage"] = field_coverage
    ev["confidence_breakdown"] = breakdown
