"""
Firewall TAXONOMY mapping (stage ③).

Given a FirewallEvent, choose the OCSF class + activity + severity + status and
extract the fields that should be PROMOTED to OCSF paths.

All formats map to:
    ocsf_class_uid = 4001  (Network Activity)
    activity       = (6, "Traffic")

The key semantic work here is:
  - Normalizing vendor action strings → OCSF status (Success / Failure)
  - Mapping vendor protocol names/numbers → standard names
  - Mapping CEF numeric severity (0-10) → OCSF severity scale

Design rule: handlers only PROMOTE common fields to OCSF paths. They NEVER discard
vendor-specific fields — those are preserved verbatim under `unmapped.firewall` by
the engine. OCSF gives cross-source uniformity; firewall_block guarantees completeness.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .envelope import FirewallEvent

# OCSF class used for all firewall events
CLS_NETWORK = 4001   # Network Activity


@dataclass
class FirewallSemanticResult:
    ocsf_class_uid: int = CLS_NETWORK
    activity: tuple = (6, "Traffic")
    category: str = "Network Activity"
    source_name: str = "Firewall"
    status: Optional[tuple] = None       # ("Success"|"Failure", 1|2)
    severity: Optional[tuple] = None     # (severity_id, "Name")
    summary: Optional[str] = None
    mapping: dict = field(default_factory=dict)
    fields: dict = field(default_factory=dict)


# ── Standard field mapping (same for all firewall formats) ────────────────────
# These keys MUST match what FirewallEvent fields and vendor_data keys we populate.
BASE_FIREWALL_MAPPING = {
    "src_ip":    "src_endpoint.ip",
    "src_port":  "src_endpoint.port",
    "dst_ip":    "dst_endpoint.ip",
    "dst_port":  "dst_endpoint.port",
    "protocol":  "connection_info.protocol_name",
    "direction": "connection_info.direction",
    "hostname":  "device.hostname",
}

# ── Action → OCSF status normalization ────────────────────────────────────────
_DENY_ACTIONS = frozenset([
    "block", "blocked", "deny", "denied", "drop", "dropped",
    "reject", "rejected", "discard", "discarded",
])
_ALLOW_ACTIONS = frozenset([
    "allow", "allowed", "permit", "permitted", "accept", "accepted",
    "pass", "passed", "forward", "built",   # Cisco ASA "Built" = connection established
    "close",        # FortiGate session close = completed
    "server-rst",   # FortiGate / SRX session end RST = completed
    "client-rst",
    "create",       # Juniper SRX session create = allowed
])

def _normalize_action(action: str | None) -> Optional[tuple]:
    """Return (status_label, status_id) or None if action is ambiguous."""
    if not action:
        return None
    a = action.strip().lower()
    if a in _ALLOW_ACTIONS:
        return ("Success", 1)
    if a in _DENY_ACTIONS:
        return ("Failure", 2)
    # Partial matches for explicit security decisions
    if any(d in a for d in ["deny", "block", "drop", "reject", "discard"]):
        return ("Failure", 2)
    if any(al in a for al in ["allow", "permit", "accept", "pass"]):
        return ("Success", 1)
    # Teardown / session ends without denial are normal completions
    if "teardown" in a or "built" in a:
        return ("Success", 1)
    return None   # unknown action — leave status as Unknown

# ── CEF severity (0-10) → OCSF severity ──────────────────────────────────────
_CEF_SEV_MAP = {
    "0": (0, "Unknown"),
    "1": (2, "Low"), "2": (2, "Low"), "3": (2, "Low"),
    "4": (3, "Medium"), "5": (3, "Medium"), "6": (3, "Medium"),
    "7": (4, "High"), "8": (4, "High"),
    "9": (5, "Critical"), "10": (5, "Critical"),
    # Text variants
    "low": (2, "Low"), "medium": (3, "Medium"), "high": (4, "High"),
    "very-high": (5, "Critical"), "very high": (5, "Critical"),
    "unknown": (0, "Unknown"),
}

# Cisco ASA severity number → OCSF
_ASA_SEV_MAP = {
    "1": (5, "Critical"), "2": (4, "High"), "3": (4, "High"),
    "4": (3, "Medium"), "5": (1, "Informational"),
    "6": (1, "Informational"), "7": (0, "Unknown"),
}

# FortiGate / NetScreen level text → OCSF severity
_TEXT_SEV_MAP = {
    "emergency": (5, "Critical"), "alert": (5, "Critical"),
    "critical": (5, "Critical"), "crit": (5, "Critical"),
    "error": (4, "High"), "err": (4, "High"),
    "warning": (3, "Medium"), "warn": (3, "Medium"),
    "notice": (1, "Informational"), "information": (1, "Informational"),
    "informational": (1, "Informational"), "info": (1, "Informational"),
    "debug": (0, "Unknown"),
}


def _resolve_firewall_severity(ev: FirewallEvent) -> Optional[tuple]:
    """Return (severity_id, severity_name) or None to let ocsf_mapper decide."""
    level = (ev.level or "").strip().lower()
    if not level:
        return None
    # CEF numeric severity
    if level.isdigit():
        cef_sev = _CEF_SEV_MAP.get(level)
        if cef_sev:
            return cef_sev
    cef_sev = _CEF_SEV_MAP.get(level)
    if cef_sev:
        return cef_sev
    return _TEXT_SEV_MAP.get(level)


# ── Per-format semantic handlers ───────────────────────────────────────────────

def _cef_classify(ev: FirewallEvent) -> FirewallSemanticResult:
    vendor = ev.vendor_data.get("device_vendor", "")
    product = ev.vendor_data.get("device_product", "")
    name = ev.vendor_data.get("name", "")
    sev = _resolve_firewall_severity(ev)

    # CEF severity number as ASA-sev if vendor is Cisco
    if sev is None:
        cef_sev_raw = str(ev.vendor_data.get("cef_severity", "")).strip()
        sev = _CEF_SEV_MAP.get(cef_sev_raw)

    status = _normalize_action(ev.action)
    # CEF "outcome" extension can also carry status
    if status is None:
        outcome = ev.vendor_data.get("extensions", {}).get("outcome", "")
        status = _normalize_action(outcome)

    source_name = f"{vendor} {product}".strip() or "CEF Device"
    summary = name or (
        f"CEF event: {ev.src_ip} → {ev.dst_ip}" if ev.src_ip else "CEF event"
    )

    return FirewallSemanticResult(
        ocsf_class_uid=CLS_NETWORK,
        activity=(6, "Traffic"),
        category="Network Activity",
        source_name=source_name,
        status=status,
        severity=sev,
        summary=summary,
        mapping=dict(BASE_FIREWALL_MAPPING),
    )


def _fortigate_classify(ev: FirewallEvent) -> FirewallSemanticResult:
    sev = _resolve_firewall_severity(ev)
    status = _normalize_action(ev.action)
    logtype = ev.vendor_data.get("type", "traffic")
    subtype = ev.vendor_data.get("subtype", "")

    summary = (
        f"FortiGate {logtype}/{subtype} {ev.action or ''}: "
        f"{ev.src_ip or '?'} → {ev.dst_ip or '?'}"
    ).strip()

    return FirewallSemanticResult(
        ocsf_class_uid=CLS_NETWORK,
        activity=(6, "Traffic"),
        category="Network Activity",
        source_name="Fortinet FortiGate",
        status=status,
        severity=sev,
        summary=summary,
        mapping=dict(BASE_FIREWALL_MAPPING),
    )


def _cisco_asa_classify(ev: FirewallEvent) -> FirewallSemanticResult:
    asa_sev = ev.vendor_data.get("asa_severity", "")
    sev = _ASA_SEV_MAP.get(asa_sev) or _resolve_firewall_severity(ev)
    status = _normalize_action(ev.action)
    msgid = ev.vendor_data.get("asa_msgid", "")

    summary = (
        f"Cisco ASA {msgid}: {ev.action or ''} "
        f"{ev.protocol or ''} {ev.src_ip or '?'}/{ev.src_port or '?'}"
        f" → {ev.dst_ip or '?'}/{ev.dst_port or '?'}"
    ).strip()

    return FirewallSemanticResult(
        ocsf_class_uid=CLS_NETWORK,
        activity=(6, "Traffic"),
        category="Network Activity",
        source_name="Cisco ASA",
        status=status,
        severity=sev,
        summary=summary,
        mapping=dict(BASE_FIREWALL_MAPPING),
    )


def _juniper_srx_classify(ev: FirewallEvent) -> FirewallSemanticResult:
    sev = _resolve_firewall_severity(ev)
    status = _normalize_action(ev.action)
    event_type = ev.vendor_data.get("srx_event_type", "")

    summary = (
        f"Juniper SRX RT_FLOW_{event_type}: "
        f"{ev.src_ip or '?'}/{ev.src_port or '?'} → "
        f"{ev.dst_ip or '?'}/{ev.dst_port or '?'}"
    ).strip()

    return FirewallSemanticResult(
        ocsf_class_uid=CLS_NETWORK,
        activity=(6, "Traffic"),
        category="Network Activity",
        source_name="Juniper SRX",
        status=status,
        severity=sev,
        summary=summary,
        mapping=dict(BASE_FIREWALL_MAPPING),
    )


def _netscreen_classify(ev: FirewallEvent) -> FirewallSemanticResult:
    sev = _resolve_firewall_severity(ev)
    status = _normalize_action(ev.action)

    summary = (
        f"NetScreen {ev.action or ''}: "
        f"{ev.src_ip or '?'} → {ev.dst_ip or '?'}"
    ).strip()

    return FirewallSemanticResult(
        ocsf_class_uid=CLS_NETWORK,
        activity=(6, "Traffic"),
        category="Network Activity",
        source_name="Juniper NetScreen",
        status=status,
        severity=sev,
        summary=summary,
        mapping=dict(BASE_FIREWALL_MAPPING),
    )


# ── Dispatcher ────────────────────────────────────────────────────────────────

_HANDLERS = {
    "cef":         _cef_classify,
    "fortigate":   _fortigate_classify,
    "cisco_asa":   _cisco_asa_classify,
    "juniper_srx": _juniper_srx_classify,
    "netscreen":   _netscreen_classify,
}


def classify(ev: FirewallEvent) -> FirewallSemanticResult:
    """Choose the semantic handler for a FirewallEvent (deterministic dispatch)."""
    handler = _HANDLERS.get(ev.fmt)
    if handler:
        return handler(ev)
    # Fallback: still produce a valid network event
    return FirewallSemanticResult(
        source_name="Unknown Firewall",
        summary="Unknown firewall event",
        mapping=dict(BASE_FIREWALL_MAPPING),
    )
