"""
Windows TAXONOMY mapping (stage ③).

Per-provider / per-Event-ID semantic handlers. Each handler receives the common
`WindowsEvent` envelope and returns a `SemanticResult`:

    ocsf_class_uid   — which OCSF class this event belongs to
    activity          — (id, name) OCSF activity
    status            — "Success" | "Failure" | None
    severity          — optional (id, name) override
    mapping           — {envelope_field_name: "ocsf.dotted.path"} for COMMON fields
    summary           — short human message

CRITICAL design rule (per the Matryoshka paper + PS "no information loss"):
handlers only *promote* common fields to OCSF paths. They NEVER discard the
Windows-specific fields — every envelope field that is not promoted is preserved
verbatim under the `windows.*` block by the engine. So OCSF gives cross-source
uniformity while `windows.*` guarantees completeness.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from .envelope import WindowsEvent

# OCSF classes we use.
CLS_SYSTEM = 1001        # System Activity
CLS_PROCESS = 1007       # Process Activity
CLS_AUTH = 3002          # Authentication
CLS_ACCOUNT = 3005       # Entity/Account Management
CLS_NETWORK = 4001       # Network Activity
CLS_HTTP = 4002          # HTTP Activity
CLS_APP = 6005           # Application Lifecycle


@dataclass
class SemanticResult:
    ocsf_class_uid: int = CLS_SYSTEM
    activity: tuple = (0, "Unknown")
    status: Optional[str] = None
    severity: Optional[tuple] = None
    mapping: dict = field(default_factory=dict)
    summary: Optional[str] = None
    category: str = "System Activity"
    source_name: str = "Windows Event Log"
    fields: dict = field(default_factory=dict)   # extracted/derived src_key -> value


# Common EventData label aliases → the envelope keys we look them up by. The
# evtx-text engine keys by Event-Viewer label ("Account Name"); the XML engine
# keys by raw attribute ("TargetUserName"). We resolve either.
def _first(ev: WindowsEvent, *keys, default=None):
    for k in keys:
        if k in ev.event_data and ev.event_data[k] not in ("", "-", None):
            return ev.event_data[k]
    return default


# ── Security channel — authentication & account handlers ──────────────────────

_LOGON_TYPE_NAMES = {
    "2": "Interactive", "3": "Network", "4": "Batch", "5": "Service",
    "7": "Unlock", "8": "NetworkCleartext", "9": "NewCredentials",
    "10": "RemoteInteractive", "11": "CachedInteractive",
}


def _logon(ev: WindowsEvent, success: bool) -> SemanticResult:
    # "New Logon" account is the real principal on 4624/4625 — prefer the
    # section-qualified primary::* key set by the envelope parser, then fall
    # back to the plain label, then the raw XML attribute.
    user = _first(ev, "primary::Account Name", "Account Name",
                  "TargetUserName", "SubjectUserName", "AccountName", "User")
    mapping = {
        k: v for k, v in {
            _key_for(ev, "primary::Account Name", "Account Name", "TargetUserName", "AccountName", "User"): "actor.user.name",
            _key_for(ev, "primary::Account Domain", "Account Domain", "TargetDomainName", "AccountDomain"): "actor.user.domain",
            _key_for(ev, "Source Network Address", "IpAddress", "SourceAddress", "SourceIp"): "src_endpoint.ip",
            _key_for(ev, "Source Port", "IpPort", "SourcePort"): "src_endpoint.port",
            "Computer": "device.hostname",
        }.items() if k
    }
    # #4: promote the logon type — a confidently-present audit field. Keep the
    # raw id AND the human name (translated from the fixed OCSF-independent
    # Windows table); only when the value is actually present (no fabrication).
    # Neither has a canonical top-level OCSF home in this framework's uniform
    # skeleton, so they are preserved losslessly under `unmapped` rather than
    # promoted — the envelope shape stays identical across every family.
    extra_fields: dict = {}
    lt_raw = _first(ev, "Logon Type", "LogonType")
    if lt_raw not in (None, "", "-"):
        extra_fields["logon_type_id"] = lt_raw
        lt_name = _LOGON_TYPE_NAMES.get(str(lt_raw).strip())
        if lt_name:
            extra_fields["logon_type"] = lt_name
    return SemanticResult(
        ocsf_class_uid=CLS_AUTH,
        activity=(1, "Logon"),
        status="Success" if success else "Failure",
        severity=None if success else (3, "Medium"),
        category="Authentication",
        source_name="Windows Security Auditing",
        summary=("Successful logon" if success else "Failed logon")
                + (f" for {user}" if user else ""),
        mapping=mapping,
        fields=extra_fields,
    )


def _key_for(ev: WindowsEvent, *candidates) -> Optional[str]:
    """Return the first candidate key actually present in the envelope."""
    for k in candidates:
        if k in ev.event_data and ev.event_data[k] not in ("", "-", None):
            return k
    return None


def _special_privileges(ev: WindowsEvent) -> SemanticResult:
    return SemanticResult(
        ocsf_class_uid=CLS_AUTH, activity=(1, "Logon"),
        category="Authentication", source_name="Windows Security Auditing",
        summary="Special privileges assigned to new logon",
        mapping={k: v for k, v in {
            _key_for(ev, "Account Name", "SubjectUserName"): "actor.user.name",
            _key_for(ev, "Account Domain", "SubjectDomainName"): "actor.user.domain",
            "Computer": "device.hostname",
        }.items() if k},
    )


def _process_creation(ev: WindowsEvent) -> SemanticResult:
    return SemanticResult(
        ocsf_class_uid=CLS_PROCESS, activity=(1, "Launch"),
        category="Process Activity", source_name="Windows Security Auditing",
        summary="A new process has been created",
        mapping={k: v for k, v in {
            _key_for(ev, "New Process Name", "NewProcessName"): "actor.process.name",
            _key_for(ev, "New Process ID", "NewProcessId"): "actor.process.pid",
            _key_for(ev, "Process Command Line", "CommandLine"): "actor.process.cmd_line",
            _key_for(ev, "Account Name", "SubjectUserName", "User"): "actor.user.name",
            _key_for(ev, "Creator Process Name", "ParentProcessName"): "actor.process.parent_process.name",
            "Computer": "device.hostname",
        }.items() if k},
    )


def _account_mgmt(ev: WindowsEvent, activity_name: str, summary: str) -> SemanticResult:
    return SemanticResult(
        ocsf_class_uid=CLS_ACCOUNT, activity=(1, activity_name),
        category="Identity & Access Management", source_name="Windows Security Auditing",
        summary=summary,
        mapping={k: v for k, v in {
            _key_for(ev, "Account Name", "TargetUserName", "User"): "actor.user.name",
            _key_for(ev, "Account Domain", "TargetDomainName"): "actor.user.domain",
            "Computer": "device.hostname",
        }.items() if k},
    )


def _account_lockout(ev: WindowsEvent) -> SemanticResult:
    r = _account_mgmt(ev, "Lockout", "A user account was locked out")
    r.severity = (3, "Medium")
    return r


# ── Sysmon handlers ───────────────────────────────────────────────────────────

def _sysmon_process(ev: WindowsEvent) -> SemanticResult:
    return SemanticResult(
        ocsf_class_uid=CLS_PROCESS, activity=(1, "Launch"),
        category="Process Activity", source_name="Microsoft-Windows-Sysmon",
        summary="Sysmon process creation",
        mapping={k: v for k, v in {
            "Image": "actor.process.name",
            "CommandLine": "actor.process.cmd_line",
            _key_for(ev, "ProcessId", "PID"): "actor.process.pid",
            "User": "actor.user.name",
            "ParentImage": "actor.process.parent_process.name",
            "ParentCommandLine": "actor.process.parent_process.cmd_line",
            "Computer": "device.hostname",
        }.items() if k},
    )


def _sysmon_network(ev: WindowsEvent) -> SemanticResult:
    return SemanticResult(
        ocsf_class_uid=CLS_NETWORK, activity=(6, "Traffic"),
        category="Network Activity", source_name="Microsoft-Windows-Sysmon",
        summary="Sysmon network connection",
        mapping={k: v for k, v in {
            "SourceIp": "src_endpoint.ip",
            "SourcePort": "src_endpoint.port",
            "DestinationIp": "dst_endpoint.ip",
            "DestinationPort": "dst_endpoint.port",
            "Protocol": "connection_info.protocol_name",
            "Image": "actor.process.name",
            "Computer": "device.hostname",
        }.items() if k},
    )


# ── PowerShell / Defender ─────────────────────────────────────────────────────

def _powershell(ev: WindowsEvent) -> SemanticResult:
    return SemanticResult(
        ocsf_class_uid=CLS_PROCESS, activity=(1, "Launch"),
        category="Process Activity", source_name="Microsoft-Windows-PowerShell",
        summary="PowerShell script block executed",
        mapping={k: v for k, v in {
            _key_for(ev, "ScriptBlockText", "CommandLine"): "actor.process.cmd_line",
            "Path": "actor.process.file.path",
            _key_for(ev, "UserId", "User"): "actor.user.name",
            "Computer": "device.hostname",
        }.items() if k},
    )


def _defender(ev: WindowsEvent) -> SemanticResult:
    r = SemanticResult(
        ocsf_class_uid=CLS_SYSTEM, activity=(0, "Detection"),
        category="Security Finding", source_name="Microsoft-Windows-Windows Defender",
        summary="Windows Defender detection",
        severity=(4, "High"),
        mapping={k: v for k, v in {
            _key_for(ev, "Threat Name", "ThreatName"): "finding.title",
            "Path": "actor.process.file.path",
            "User": "actor.user.name",
            "Computer": "device.hostname",
        }.items() if k},
    )
    return r


# ── Generic Windows event fallback (still lossless) ───────────────────────────

def _generic(ev: WindowsEvent) -> SemanticResult:
    return SemanticResult(
        ocsf_class_uid=CLS_SYSTEM, activity=(0, "Unknown"),
        category="System Activity",
        source_name=ev.provider or "Windows Event Log",
        summary=_first(ev, "Description", "Message") or f"Windows event {ev.event_id}",
        mapping={k: v for k, v in {
            _key_for(ev, "Account Name", "User", "SubjectUserName"): "actor.user.name",
            "Computer": "device.hostname",
        }.items() if k},
    )


# ── Security Event-ID dispatch table ──────────────────────────────────────────

_SECURITY_HANDLERS: dict[str, Callable[[WindowsEvent], SemanticResult]] = {
    "4624": lambda ev: _logon(ev, True),
    "4625": lambda ev: _logon(ev, False),
    "4634": lambda ev: _logon(ev, True),   # logoff
    "4647": lambda ev: _logon(ev, True),   # user-initiated logoff
    "4648": lambda ev: _logon(ev, True),   # explicit-cred logon
    "4672": _special_privileges,
    "4688": _process_creation,
    "4720": lambda ev: _account_mgmt(ev, "Create", "A user account was created"),
    "4722": lambda ev: _account_mgmt(ev, "Enable", "A user account was enabled"),
    "4725": lambda ev: _account_mgmt(ev, "Disable", "A user account was disabled"),
    "4726": lambda ev: _account_mgmt(ev, "Delete", "A user account was deleted"),
    "4728": lambda ev: _account_mgmt(ev, "Modify", "Member added to a security-enabled global group"),
    "4732": lambda ev: _account_mgmt(ev, "Modify", "Member added to a security-enabled local group"),
    "4740": _account_lockout,
    "4756": lambda ev: _account_mgmt(ev, "Modify", "Member added to a universal group"),
}

_SYSMON_HANDLERS: dict[str, Callable[[WindowsEvent], SemanticResult]] = {
    "1": _sysmon_process,
    "3": _sysmon_network,
    "11": lambda ev: SemanticResult(
        ocsf_class_uid=CLS_SYSTEM, activity=(0, "File Create"),
        category="File Activity", source_name="Microsoft-Windows-Sysmon",
        summary="Sysmon file created",
        mapping={k: v for k, v in {
            "TargetFilename": "actor.process.file.path",
            "Image": "actor.process.name", "Computer": "device.hostname",
        }.items() if k}),
}


def classify(ev: WindowsEvent) -> SemanticResult:
    """Choose the semantic handler for a WindowsEvent (deterministic dispatch)."""
    provider = (ev.provider or "").lower()
    channel = (ev.channel or "").lower()
    eid = str(ev.event_id or "").strip()

    if "sysmon" in provider or "sysmon" in channel:
        return _SYSMON_HANDLERS.get(eid, _sysmon_process if eid == "1" else _generic)(ev)

    if "powershell" in provider or "powershell" in channel:
        return _powershell(ev)

    if "defender" in provider or "defender" in channel:
        return _defender(ev)

    if "security-auditing" in provider or channel == "security":
        h = _SECURITY_HANDLERS.get(eid)
        if h:
            return h(ev)

    return _generic(ev)
