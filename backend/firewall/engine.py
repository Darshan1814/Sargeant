"""
Firewall parser family ENGINE — public entry point.

    parse(raw_log) -> FirewallParseResult | None

Pipeline (deterministic, no LLM at runtime):
    detect_format ──► syntax parse (envelope) ──► classify (taxonomy) ──►
    build {fields, field_mapping, parser meta} ready for backend.ocsf_mapper.

Returns None when the log is not a recognized firewall log, so the caller
can fall through to NGRE registry / Drain3.

The result gives the pipeline everything `map_to_ocsf` needs:
  * `fields`         — flat dict of every discovered value (promoted + raw)
  * `parser_config`  — synthetic parser config (parser_id, class, mapping,
                        static_fields) consumed by the SAME ocsf_mapper
  * `firewall_block` — complete vendor-native view stored under
                        `unmapped.firewall` — zero information loss
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import confidence as _confidence_mod

from .detector import detect_format
from .envelope import (
    FirewallEvent,
    parse_cef, parse_fortigate, parse_cisco_asa,
    parse_juniper_srx, parse_netscreen,
)
from .handlers import classify, FirewallSemanticResult

_GENERIC_SOURCES = {"", "unknown", "generic", "firewall", "unknown firewall"}

# ── format → (envelope_parser, stable_parser_id) ─────────────────────────────
_PARSERS = {
    "cef":         (parse_cef,         "FW-CEF-GENERIC"),
    "fortigate":   (parse_fortigate,   "FW-FORTIGATE-001"),
    "cisco_asa":   (parse_cisco_asa,   "FW-CISCO-ASA-001"),
    "juniper_srx": (parse_juniper_srx, "FW-JUNIPER-SRX-001"),
    "netscreen":   (parse_netscreen,   "FW-NETSCREEN-001"),
}

# BASE field mapping — always present for every firewall format
# Keys match what the envelope promotes and handlers.fields may inject.
BASE_MAPPING = {
    "src_ip":    "src_endpoint.ip",
    "src_port":  "src_endpoint.port",
    "dst_ip":    "dst_endpoint.ip",
    "dst_port":  "dst_endpoint.port",
    "protocol":  "connection_info.protocol_name",
    "direction": "connection_info.direction",
    "hostname":  "device.hostname",
}


@dataclass
class FirewallParseResult:
    parser_id: str
    fields: dict
    parser_config: dict
    firewall_block: dict
    confidence: float
    summary: str = ""


def parse(raw_log: str) -> Optional[FirewallParseResult]:
    """Parse any firewall log into an OCSF-ready result, or None if not firewall."""
    if not raw_log or not raw_log.strip():
        return None

    fmt = detect_format(raw_log)
    if fmt is None:
        return None

    parse_fn, parser_id = _PARSERS[fmt]
    ev: Optional[FirewallEvent] = parse_fn(raw_log)
    if ev is None:
        return None

    sem: FirewallSemanticResult = classify(ev)

    # ── Refine parser_id for CEF based on vendor ──────────────────────────────
    if fmt == "cef":
        vendor = (ev.vendor_data.get("device_vendor") or "").strip().upper()
        product = (ev.vendor_data.get("device_product") or "").strip().upper()
        if "PALO ALTO" in vendor or "PAN" in product:
            parser_id = "FW-CEF-PALO-ALTO"
        elif "CHECK POINT" in vendor or "CHECKPOINT" in vendor:
            parser_id = "FW-CEF-CHECKPOINT"
        elif "CISCO" in vendor:
            parser_id = "FW-CEF-CISCO"
        elif "FORTINET" in vendor or "FORTIGATE" in product:
            parser_id = "FW-CEF-FORTIGATE"
        # else keep generic FW-CEF-GENERIC

    # ── Refine Cisco ASA parser_id based on message ID ───────────────────────
    if fmt == "cisco_asa":
        msgid = ev.vendor_data.get("asa_msgid", "")
        if msgid:
            # Group into families for telemetry aggregation
            if msgid.startswith("106"):
                parser_id = f"FW-CISCO-ASA-ACL"
            elif msgid.startswith("302"):
                parser_id = f"FW-CISCO-ASA-CONN"
            elif msgid.startswith("710"):
                parser_id = f"FW-CISCO-ASA-IFACE"

    # ── Flatten envelope + taxonomy → fields dict for ocsf_mapper ─────────────
    fields: dict = {}

    # Timestamp components (consumed by ocsf_mapper._build_timestamp)
    if ev.date and ev.time:
        fields["date"] = ev.date
        fields["time"] = ev.time
    elif ev.month and ev.day and ev.time:
        fields["month"] = ev.month
        fields["day"] = ev.day
        fields["time"] = ev.time
    elif ev.timestamp:
        fields["timestamp"] = ev.timestamp

    # Severity (consumed by ocsf_mapper._resolve_severity)
    if ev.level:
        fields["level"] = ev.level

    # Core network fields
    if ev.src_ip:
        fields["src_ip"] = ev.src_ip
    if ev.src_port:
        fields["src_port"] = ev.src_port
    if ev.dst_ip:
        fields["dst_ip"] = ev.dst_ip
    if ev.dst_port:
        fields["dst_port"] = ev.dst_port
    if ev.protocol:
        fields["protocol"] = ev.protocol
    if ev.action:
        fields["action"] = ev.action
    if ev.hostname:
        fields["hostname"] = ev.hostname

    # All vendor_data goes into fields too (preserved in unmapped by ocsf_mapper)
    for k, v in ev.vendor_data.items():
        if k not in fields and v not in (None, "", {}):
            fields[k] = v

    # Taxonomy-promoted extra fields
    for k, v in sem.fields.items():
        if v not in (None, ""):
            fields[k] = v

    if sem.summary:
        fields["message"] = sem.summary

    # ── Field mapping ─────────────────────────────────────────────────────────
    field_mapping = {**BASE_MAPPING, **sem.mapping}

    # ── Static fields ─────────────────────────────────────────────────────────
    static_fields: dict = {
        "activity_id": sem.activity[0],
        "activity_name": sem.activity[1],
    }
    if sem.status is not None:
        static_fields["status"] = sem.status[0]
        static_fields["status_id"] = sem.status[1]
    if sem.severity is not None:
        static_fields["severity_id"] = sem.severity[0]
        static_fields["severity"] = sem.severity[1]

    # ── Native firewall block (zero information loss) ─────────────────────────
    firewall_block: dict = {
        "format": ev.fmt,
        "parser_id": parser_id,
        "hostname": ev.hostname,
        "src_ip": ev.src_ip,
        "src_port": ev.src_port,
        "dst_ip": ev.dst_ip,
        "dst_port": ev.dst_port,
        "protocol": ev.protocol,
        "action": ev.action,
        "level": ev.level,
        "vendor_data": dict(ev.vendor_data),
    }
    firewall_block = {k: v for k, v in firewall_block.items()
                      if v not in (None, "", {})}

    # ── Dynamic confidence ────────────────────────────────────────────────────
    _core = (
        ev.src_ip, ev.dst_ip, ev.src_port, ev.dst_port,
        ev.protocol, ev.action, ev.hostname,
        (ev.date and ev.time) or ev.timestamp or (ev.month and ev.day),
    )
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
        "os_family": "Network",
        "category": sem.category,
        "ocsf_class_uid": sem.ocsf_class_uid,
        "field_mapping": field_mapping,
        "static_fields": static_fields,
        "_confidence": conf,
        "_confidence_breakdown": cb,
        "_parse_path": "firewall-family",
    }

    return FirewallParseResult(
        parser_id=parser_id,
        fields=fields,
        parser_config=parser_config,
        firewall_block=firewall_block,
        confidence=conf,
        summary=sem.summary or "",
    )
