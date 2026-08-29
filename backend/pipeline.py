"""
Core parsing pipeline: fingerprint → NGRE or Drain3 → OCSF mapping → DLQ fallback.
100% coverage guarantee: every event produces an OCSF record; failures go to DLQ.
"""
from __future__ import annotations

import json
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from drain3 import TemplateMiner

from fingerprint import fingerprint, FingerprintResult, get_parser
from ocsf_mapper import map_to_ocsf

try:
    from windows import parse as _windows_parse  # Windows parser family (Phase 1)
except Exception:  # pragma: no cover - defensive: never break the pipeline
    _windows_parse = None

try:
    from android import parse as _android_parse  # Android logcat parser family
except Exception:  # pragma: no cover
    _android_parse = None

try:
    from linux import parse as _linux_parse  # Linux syslog/journald/auditd/dmesg family
except Exception:  # pragma: no cover
    _linux_parse = None

try:
    from firewall import parse as _firewall_parse  # Firewall family (CEF/FortiGate/Cisco ASA/Juniper/NetScreen)
except Exception:  # pragma: no cover
    _firewall_parse = None

PARSERS_DIR = Path(os.getenv("PARSERS_DIR", "/app/parsers/registry"))

# Drain3 with in-memory state — no load_defaults() needed (removed in drain3 0.9.x)
_drain3_miner = TemplateMiner()


def _load_parser(parser_id: str) -> dict | None:
    """Fetch a registry parser by id from the shared cache (see
    ``fingerprint.get_parser``). Returns a fresh, safe-to-mutate copy. Replaces
    the previous per-record full-directory rescan, which re-read every JSON file
    from disk on every NGRE match."""
    return get_parser(parser_id)


def _apply_ngre(raw_log: str, parser: dict) -> dict:
    pattern = parser.get("ngre_pattern", "")
    m = re.search(pattern, raw_log, re.MULTILINE | re.DOTALL)
    if m:
        return m.groupdict()
    return {}


# CBS package descriptor, e.g.:
#   Package_for_KB2928120~31bf3856ad364e35~amd64~~6.1.1.2
# Fields are '~'-separated: <name>~<pubkeytoken>~<arch>~<culture>~<version>.
_CBS_PACKAGE_RE = re.compile(
    r"(?P<package>Package(?:_for_)?[A-Za-z0-9_.]*"
    r"~[0-9a-fA-F]+~(?P<arch>[a-zA-Z0-9]+)~[^~]*~(?P<version>[\d.]+))"
)
_CBS_KB_RE = re.compile(r"(KB\d{5,})")
_CBS_STATE_RE = re.compile(
    r"ApplicableState:\s*(?P<applicable>\d+).*?CurrentState:\s*(?P<current>\d+)",
    re.IGNORECASE | re.DOTALL,
)


def _enrich_cbs(normalized: dict, raw_log: str) -> None:
    """Source-specific semantic enrichment for Windows CBS lines (PART 34).

    Pulls package / KB / architecture / version / servicing-state fields out of
    the message and stores them under the windows.* namespace, WITHOUT touching
    the raw message and without affecting lines that carry no package. This is a
    deterministic, offline enricher — no false IPs because 6.1.1.2 is captured
    explicitly as windows.package.version here (context-aware typing)."""
    win = normalized.setdefault("unmapped", {}).setdefault("windows", {})
    pkg = {}
    m = _CBS_PACKAGE_RE.search(raw_log)
    if m:
        pkg["name"] = m.group("package")
        pkg["architecture"] = m.group("arch")
        pkg["version"] = m.group("version")
    kb = _CBS_KB_RE.search(raw_log)
    if kb:
        pkg["kb"] = kb.group(1)
    if pkg:
        win["package"] = pkg
    st = _CBS_STATE_RE.search(raw_log)
    if st:
        win["applicable_state"] = int(st.group("applicable"))
        win["current_state"] = int(st.group("current"))
    # component is already actor.process.name; also record it natively.
    win.setdefault("component", "CBS" if "CBS" in raw_log else
                   ("CSI" if "CSI" in raw_log else None))


def _apply_drain3(raw_log: str) -> tuple[dict, str]:
    try:
        result = _drain3_miner.add_log_message(raw_log)
        template = result["template_mined"] if result else raw_log
    except Exception:
        template = raw_log
    fields = {"message": raw_log, "drain3_template": template}
    return fields, template


def _minimal_ocsf(event_id: str, raw_log: str, error: str, candidates: list) -> dict:
    """
    Fallback OCSF event used when everything else fails (DLQ path).
    Flows through the SAME canonical mapper so a DLQ event has the identical
    uniform skeleton as a fully-parsed Windows/Mac event.
    """
    dlq_parser = {
        "parser_id": "DLQ",
        "source_name": "Dead Letter Queue",
        "os_family": "Unknown",
        "category": "Unclassified",
        "ocsf_class_uid": 1001,
        "field_mapping": {},
        "_confidence": 0.0,
        "_parse_path": "dlq",
    }
    ev = map_to_ocsf({"message": raw_log}, dlq_parser, event_id, raw_log)
    ev["needs_review"] = True
    ev["severity_id"], ev["severity"] = 0, "Unknown"
    ev["status"] = "Failure"
    ev["metadata"]["dlq_error"] = error
    ev["metadata"]["attempted_parsers"] = [c.get("parser_id") for c in candidates]
    ev["unmapped"]["dlq_error"] = error
    return ev


def process(raw_log: str) -> dict:
    """
    Full pipeline for a single raw log string.
    Guaranteed to return a result dict with a valid OCSF event.
    Path: ngre → drain3 → dlq (last resort).
    """
    event_id = str(uuid.uuid4())

    # ── Windows parser family path (highest priority) ───────────────────────────
    # A deterministic structural engine (syntax → schema → taxonomy) that handles
    # ANY Windows log format (evtx-text / event XML / IIS W3C / firewall text) and
    # every provider/Event-ID, promoting common fields to OCSF while preserving
    # every Windows-native field under `normalized.windows`. Runs before the
    # generic JSON-regex registry so specialized Windows semantics always win.
    if _windows_parse is not None:
        try:
            wr = _windows_parse(raw_log)
        except Exception:
            wr = None
        if wr is not None:
            try:
                normalized = map_to_ocsf(wr.fields, wr.parser_config, event_id, raw_log)
                # Zero-loss guarantee: attach the complete Windows-native view
                # under `unmapped` (always present in the canonical envelope), so
                # the top-level OCSF shape stays IDENTICAL across every OS while
                # no Windows-specific field is ever dropped.
                normalized["unmapped"]["windows"] = wr.windows_block
                return {
                    "event_id": event_id,
                    "parser_id": wr.parser_id,
                    "confidence": wr.confidence,
                    "path": "ngre",
                    "needs_review": normalized.get("needs_review", False),
                    "normalized": normalized,
                    "raw_log": raw_log,
                    "source": wr.parser_config.get("source_name", "Windows"),
                    "ocsf_class": normalized.get("class_uid", 1001),
                    "candidates": [{"parser_id": wr.parser_id, "score": wr.confidence}],
                }
            except Exception:
                pass  # fall through to the registry / drain3 paths

    # ── Android logcat family path ─────────────────────────────────────────────
    # Deterministic engine covering every logcat -v format (threadtime / time /
    # brief / long / process / json). Promotes tag/pid/priority/message to OCSF
    # and preserves the full Android-native view under `normalized.unmapped.android`.
    if _android_parse is not None:
        try:
            ar = _android_parse(raw_log)
        except Exception:
            ar = None
        if ar is not None:
            try:
                normalized = map_to_ocsf(ar.fields, ar.parser_config, event_id, raw_log)
                normalized["unmapped"]["android"] = ar.android_block
                return {
                    "event_id": event_id,
                    "parser_id": ar.parser_id,
                    "confidence": ar.confidence,
                    "path": "ngre",
                    "needs_review": normalized.get("needs_review", False),
                    "normalized": normalized,
                    "raw_log": raw_log,
                    "source": ar.parser_config.get("source_name", "Android"),
                    "ocsf_class": normalized.get("class_uid", 6005),
                    "candidates": [{"parser_id": ar.parser_id, "score": ar.confidence}],
                }
            except Exception:
                pass

    # ── Firewall family path ───────────────────────────────────────────────────
    # Deterministic engine covering CEF (generic), FortiGate key=value, Cisco ASA
    # syslog (%ASA-N-MSGID), Juniper SRX RT_FLOW, and NetScreen legacy logs.
    # All formats normalize to OCSF class 4001 (Network Activity). Runs before generic
    # OS syslog so network telemetry with syslog wrappers is cleanly claimed here.
    if _firewall_parse is not None:
        try:
            fr = _firewall_parse(raw_log)
        except Exception:
            fr = None
        if fr is not None:
            try:
                normalized = map_to_ocsf(fr.fields, fr.parser_config, event_id, raw_log)
                normalized["unmapped"]["firewall"] = fr.firewall_block
                return {
                    "event_id": event_id,
                    "parser_id": fr.parser_id,
                    "confidence": fr.confidence,
                    "path": "ngre",
                    "needs_review": normalized.get("needs_review", False),
                    "normalized": normalized,
                    "raw_log": raw_log,
                    "source": fr.parser_config.get("source_name", "Firewall"),
                    "ocsf_class": normalized.get("class_uid", 4001),
                    "candidates": [{"parser_id": fr.parser_id, "score": fr.confidence}],
                }
            except Exception:
                pass  # fall through

    # ── Linux family path ──────────────────────────────────────────────────────
    # Deterministic engine covering RFC3164/RFC5424 syslog, journald JSON, auditd
    # and kernel dmesg. Content-based OCSF classification (auth/process/network/
    # http/account/system); full native view preserved under `unmapped.linux`.
    if _linux_parse is not None:
        try:
            lr = _linux_parse(raw_log)
        except Exception:
            lr = None
        if lr is not None:
            try:
                normalized = map_to_ocsf(lr.fields, lr.parser_config, event_id, raw_log)
                normalized["unmapped"]["linux"] = lr.linux_block
                return {
                    "event_id": event_id,
                    "parser_id": lr.parser_id,
                    "confidence": lr.confidence,
                    "path": "ngre",
                    "needs_review": normalized.get("needs_review", False),
                    "normalized": normalized,
                    "raw_log": raw_log,
                    "source": lr.parser_config.get("source_name", "Linux"),
                    "ocsf_class": normalized.get("class_uid", 1001),
                    "candidates": [{"parser_id": lr.parser_id, "score": lr.confidence}],
                }
            except Exception:
                pass

    fp: FingerprintResult = fingerprint(raw_log)
    candidates_list = [{"parser_id": c.parser_id, "score": c.score} for c in fp.candidates]

    # ── NGRE path ──────────────────────────────────────────────────────────────
    if not fp.use_drain3 and fp.detected_parser_id:
        try:
            parser = _load_parser(fp.detected_parser_id)
            if parser:
                fields = _apply_ngre(raw_log, parser)
                if fields:
                    parser["_confidence"] = fp.confidence
                    parser["_parse_path"] = "ngre"
                    normalized = map_to_ocsf(fields, parser, event_id, raw_log)
                    # Source-specific semantic enrichment for CBS (PART 34):
                    # extract package/KB/arch/version/state under windows.*.
                    if fp.detected_parser_id == "WIN-CBS-001":
                        try:
                            _enrich_cbs(normalized, raw_log)
                        except Exception:
                            pass
                    # A match resting solely on a generic catch-all regex (no
                    # corroborating substrings/known-process signal → confidence
                    # at/below the 0.5 NGRE floor) is weak: flag it for analyst
                    # review. This catches adversarial header-wrapped payloads
                    # that superficially satisfy a broad syslog signature.
                    low_conf = fp.confidence <= 0.5
                    needs_review = normalized.get("needs_review", False) or low_conf
                    if low_conf:
                        normalized["needs_review"] = True
                    return {
                        "event_id": event_id,
                        "parser_id": fp.detected_parser_id,
                        "confidence": fp.confidence,
                        "path": "ngre",
                        "needs_review": needs_review,
                        "normalized": normalized,
                        "raw_log": raw_log,
                        "source": parser.get("source_name", "Unknown"),
                        "ocsf_class": normalized.get("class_uid", 1001),
                        "candidates": candidates_list,
                    }
        except Exception as exc:
            pass  # fall through to drain3

    # ── Drain3 path ────────────────────────────────────────────────────────────
    try:
        fields, drain3_template = _apply_drain3(raw_log)
        unknown_parser = {
            "parser_id": "DRAIN3-FALLBACK",
            "source_name": "Drain3 Template Miner",
            "os_family": "Unknown",
            "category": "Unclassified",
            "ocsf_class_uid": 1001,
            "field_mapping": {},
            "_confidence": fp.confidence,
            "_parse_path": "drain3",
        }
        normalized = map_to_ocsf(fields, unknown_parser, event_id, raw_log, drain3_template)
        normalized["needs_review"] = True
        return {
            "event_id": event_id,
            "parser_id": "DRAIN3-FALLBACK",
            "confidence": fp.confidence,
            "path": "drain3",
            "needs_review": True,
            "normalized": normalized,
            "raw_log": raw_log,
            "source": "Unknown",
            "ocsf_class": 1001,
            "candidates": candidates_list,
            "drain3_template": drain3_template,
        }
    except Exception as drain_exc:
        pass

    # ── DLQ path (last resort — 100% coverage guarantee) ──────────────────────
    error_msg = f"All parse paths failed for log of length {len(raw_log)}"
    normalized = _minimal_ocsf(event_id, raw_log, error_msg, candidates_list)
    return {
        "event_id": event_id,
        "parser_id": "DLQ",
        "confidence": 0.0,
        "path": "dlq",
        "needs_review": True,
        "normalized": normalized,
        "raw_log": raw_log,
        "source": "DLQ",
        "ocsf_class": 1001,
        "candidates": candidates_list,
        "dlq": True,
        "dlq_error": error_msg,
    }
