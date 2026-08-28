"""
Linux TAXONOMY mapping.

Given a LinuxEvent, choose the OCSF class + activity + severity and extract the
fields that should be PROMOTED to OCSF (user, ips, ports, command, http, ...).
Everything is content-based and table-driven; native detail the engine does not
promote is preserved under `linux.*` losslessly.

Scoping note (must not regress the seeded pipeline tests):
  * The generic RFC3164 generator (LINUX-SYSLOG-001) emits systemd lifecycle /
    pam_unix(cron:session) / promiscuous-mode / "Reached target" lines that MUST
    stay class 1001 — so auth is matched by CONTENT (Accepted/Failed ... for,
    Invalid user, pam_unix(sshd:session)) and never by program name, and the
    network matcher never claims "promiscuous mode".
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from .envelope import LinuxEvent

# OCSF classes reused across the framework.
CLS_SYSTEM = 1001     # System Activity
CLS_PROCESS = 1007    # Process Activity
CLS_AUTH = 3002       # Authentication
CLS_ACCOUNT = 3005    # Account Change
CLS_NETWORK = 4001    # Network Activity
CLS_HTTP = 4002       # HTTP Activity

# status_id conventions (OCSF): 1 Success, 2 Failure.
SEV_INFO = (1, "Informational")
SEV_MEDIUM = (3, "Medium")
SEV_HIGH = (4, "High")


@dataclass
class SemanticResult:
    ocsf_class_uid: int = CLS_SYSTEM
    activity: tuple = (0, "Unknown")
    category: str = "System Activity"
    source_name: str = "Linux syslog"
    severity: Optional[tuple] = None          # (id, label) override; None -> from level
    status: Optional[tuple] = None            # (label, id) override
    summary: Optional[str] = None
    mapping: dict = field(default_factory=dict)   # extra src_key -> OCSF dotted path
    fields: dict = field(default_factory=dict)    # extracted src_key -> value


# ── promotion mappings (merged with BASE_MAPPING in the engine) ───────────────
USER_MAP = {"user": "actor.user.name", "uid": "actor.user.uid"}
NET_MAP = {
    "src_ip": "src_endpoint.ip", "src_port": "src_endpoint.port",
    "dst_ip": "dst_endpoint.ip", "dst_port": "dst_endpoint.port",
    "protocol": "connection_info.protocol_name",
}
CMD_MAP = {"command": "actor.process.cmd_line"}
HTTP_MAP = {
    "src_ip": "src_endpoint.ip",
    "http_method": "http_request.http_method",
    "http_uri": "http_request.url.path",
    "http_status": "http_response.code",
}

# ── content regexes ───────────────────────────────────────────────────────────
_SSH_AUTH = re.compile(
    r"\b(?P<result>Accepted|Failed)\s+(?P<method>password|publickey|keyboard-interactive|none)\s+"
    r"for\s+(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<src_ip>[\da-fA-F.:]+)\s+port\s+(?P<src_port>\d+)"
    r"(?:\s+(?P<ssh_version>ssh\d))?")
_INVALID_USER = re.compile(
    r"[Ii]nvalid user\s+(?P<user>\S+)\s+from\s+(?P<src_ip>[\da-fA-F.:]+)(?:\s+port\s+(?P<src_port>\d+))?")
_PAM_SSHD = re.compile(
    r"pam_unix\(sshd:session\):\s+session\s+(?P<pam_action>opened|closed)\s+for\s+user\s+(?P<user>[\w.\-]+)")
_PG_AUTHZ = re.compile(
    r"connection authorized:\s+user=(?P<user>[\w.\-]+)\s+database=(?P<database>[\w.\-]+)(?:\s+client=(?P<src_ip>[\d.]+))?")
_PG_AUTHFAIL = re.compile(r'password authentication failed for user\s+"(?P<user>[^"]+)"')
_AUDIT_LOGIN = re.compile(
    r"USER_LOGIN\b.*?(?:\buid=(?P<uid>\d+))?.*?(?:\bid=(?P<user>[\w.\-]+))?.*?(?:\baddr=(?P<src_ip>[\d.]+))?",
    re.DOTALL)

_ACCOUNT = re.compile(
    r"\b(useradd|userdel|usermod|groupadd|groupdel|gpasswd|chpasswd|passwd)\b"
    r"|new user:|new group:|password changed for")

_SUDO_CMD = re.compile(r"USER=(?P<target>\S+)\s*;\s*COMMAND=(?P<command>.+)$", re.DOTALL)
_CRON_CMD = re.compile(r"CMD\s+\((?P<command>.+)\)\s*$", re.DOTALL)
_EXECVE = re.compile(r"\bEXECVE\b.*?\ba0=\"?(?P<command>[^\"\s]+)\"?", re.DOTALL)
_SYSCALL_EXE = re.compile(r"\bSYSCALL\b.*?\bexe=(?P<command>\"?[^\"\s]+\"?)", re.DOTALL)
_OOM = re.compile(r"(?:Out of memory|Memory cgroup out of memory|oom-kill).*?"
                  r"Killed process\s+\d+\s+\((?P<proc>[^)]+)\)", re.DOTALL)
_OOM_SIMPLE = re.compile(r"\boom-kill\b|Out of memory")
_CONTAINER = re.compile(r"\bcontainer\s+(?P<container>\S+)\s+(?P<cstate>started|exited|created|died)")
_SEGFAULT = re.compile(r"\bsegfault at\b|\btraps:\s")

_HTTP_ACCESS = re.compile(
    r'^(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+\S+\s+.*?"(?P<http_method>[A-Z]+)\s+'
    r'(?P<http_uri>\S+)\s+HTTP/[\d.]+"\s+(?P<http_status>\d{3})')
_HTTP_ERR = re.compile(r"\[error\]\s+client\s+(?P<src_ip>[\d.]+)")

_NETFILTER = re.compile(
    r"SRC=(?P<src_ip>[\d.]+).*?DST=(?P<dst_ip>[\d.]+)(?:.*?PROTO=(?P<protocol>\w+))?"
    r"(?:.*?SPT=(?P<src_port>\d+))?(?:.*?DPT=(?P<dst_port>\d+))?", re.DOTALL)
_UFW_ACTION = re.compile(r"\[UFW\s+(?P<action>[A-Z]+)\]|\b(?P<a2>BLOCK|DROP|REJECT|ACCEPT|ALLOW)\b")
_SYN_FLOOD = re.compile(r"TCP:\s+Possible SYN flooding")
_FAIL2BAN = re.compile(r"\b(?P<action>Ban|Unban)\s+(?P<src_ip>[\d.]+)")
_DHCP = re.compile(r"DHCPACK of\s+(?P<ip>[\d.]+)|DHCPACK|DHCPREQUEST|DHCPOFFER")


def _clean(d: dict) -> dict:
    return {k: v for k, v in d.items() if v not in (None, "")}


def classify(ev: LinuxEvent) -> SemanticResult:
    msg = ev.message or ""
    prog = (ev.program or "").lower()

    # ── HTTP access / error (nginx / apache) ─────────────────────────────────
    if prog in ("nginx", "apache2", "httpd", "apache"):
        m = _HTTP_ACCESS.search(msg)
        if m:
            code = m["http_status"]
            sev = SEV_MEDIUM if code and code[0] in ("4", "5") else None
            return SemanticResult(
                CLS_HTTP, (0, "HTTP Request"), "HTTP Activity", "Linux web",
                severity=sev, mapping=dict(HTTP_MAP), fields=_clean(m.groupdict()),
                summary=msg)
        me = _HTTP_ERR.search(msg)
        if me:
            return SemanticResult(
                CLS_HTTP, (0, "HTTP Request"), "HTTP Activity", "Linux web",
                severity=SEV_MEDIUM, mapping={"src_ip": "src_endpoint.ip"},
                fields=_clean(me.groupdict()), summary=msg)

    # ── Authentication (content-based only) ──────────────────────────────────
    m = _SSH_AUTH.search(msg)
    if m:
        failed = m["result"] == "Failed"
        # #4: the auth method (password/publickey/…) and — when the trailing
        # "ssh2" token is present — the SSH protocol version are confidently in
        # the message. Promote them as evidence-based semantic fields (never
        # fabricated: only set when the regex actually matched them).
        # auth_protocol maps to the canonical top-level OCSF field; auth_method
        # has no canonical home, so it is preserved losslessly under `unmapped`
        # (keeping the uniform envelope skeleton unchanged — spec: same schema).
        auth_fields = {"user": m["user"], "src_ip": m["src_ip"],
                       "src_port": m["src_port"], "auth_method": m["method"]}
        auth_map = {**USER_MAP, "src_ip": "src_endpoint.ip",
                    "src_port": "src_endpoint.port"}
        if m.groupdict().get("ssh_version"):
            auth_fields["auth_protocol"] = m["ssh_version"].upper()
            auth_map["auth_protocol"] = "auth_protocol"
        return SemanticResult(
            CLS_AUTH, (1, "Logon"), "Authentication", "Linux auth",
            severity=SEV_MEDIUM if failed else None,
            status=("Failure", 2) if failed else ("Success", 1),
            mapping=auth_map,
            fields=_clean(auth_fields),
            summary=msg)
    m = _INVALID_USER.search(msg)
    if m:
        return SemanticResult(
            CLS_AUTH, (1, "Logon"), "Authentication", "Linux auth",
            severity=SEV_MEDIUM, status=("Failure", 2),
            mapping={**USER_MAP, "src_ip": "src_endpoint.ip", "src_port": "src_endpoint.port"},
            fields=_clean(m.groupdict()), summary=msg)
    m = _PAM_SSHD.search(msg)
    if m:
        return SemanticResult(
            CLS_AUTH, (1, "Logon"), "Authentication", "Linux auth",
            status=("Success", 1),
            mapping=dict(USER_MAP), fields=_clean({"user": m["user"]}), summary=msg)
    m = _PG_AUTHZ.search(msg)
    if m:
        return SemanticResult(
            CLS_AUTH, (1, "Logon"), "Authentication", "Linux database",
            status=("Success", 1),
            mapping={**USER_MAP, "src_ip": "src_endpoint.ip"},
            fields=_clean({"user": m["user"], "src_ip": m["src_ip"]}), summary=msg)
    m = _PG_AUTHFAIL.search(msg)
    if m:
        return SemanticResult(
            CLS_AUTH, (1, "Logon"), "Authentication", "Linux database",
            severity=SEV_MEDIUM, status=("Failure", 2),
            mapping=dict(USER_MAP), fields=_clean({"user": m["user"]}), summary=msg)
    if "USER_LOGIN" in msg:
        m = _AUDIT_LOGIN.search(msg)
        gd = _clean(m.groupdict()) if m else {}
        return SemanticResult(
            CLS_AUTH, (1, "Logon"), "Authentication", "Linux auditd",
            mapping={**USER_MAP, "src_ip": "src_endpoint.ip"}, fields=gd, summary=msg)

    # ── Account management ───────────────────────────────────────────────────
    if _ACCOUNT.search(msg):
        return SemanticResult(
            CLS_ACCOUNT, (0, "Account Change"), "Identity & Access Management",
            "Linux account", summary=msg)

    # ── Process activity ─────────────────────────────────────────────────────
    m = _SUDO_CMD.search(msg)
    if m:
        return SemanticResult(
            CLS_PROCESS, (1, "Launch"), "Process Activity", "Linux sudo",
            mapping=dict(CMD_MAP), fields=_clean({"command": (m["command"] or "").strip()}),
            summary=msg)
    m = _CRON_CMD.search(msg)
    if m:
        return SemanticResult(
            CLS_PROCESS, (1, "Launch"), "Process Activity", "Linux cron",
            mapping=dict(CMD_MAP), fields=_clean({"command": (m["command"] or "").strip()}),
            summary=msg)
    m = _EXECVE.search(msg) or _SYSCALL_EXE.search(msg)
    if m:
        return SemanticResult(
            CLS_PROCESS, (1, "Launch"), "Process Activity", "Linux auditd",
            mapping=dict(CMD_MAP),
            fields=_clean({"command": (m.groupdict().get("command") or "").strip('"')}),
            summary=msg)
    m = _OOM.search(msg)
    if m:
        return SemanticResult(
            CLS_PROCESS, (4, "Terminate"), "Process Activity", "Linux kernel",
            severity=SEV_HIGH, mapping={"proc": "actor.process.name"},
            fields=_clean({"proc": m["proc"]}), summary=msg)
    if _OOM_SIMPLE.search(msg):
        return SemanticResult(
            CLS_PROCESS, (4, "Terminate"), "Process Activity", "Linux kernel",
            severity=SEV_HIGH, summary=msg)
    m = _CONTAINER.search(msg)
    if m:
        term = m["cstate"] in ("exited", "died")
        return SemanticResult(
            CLS_PROCESS, (4 if term else 1, "Terminate" if term else "Launch"),
            "Process Activity", "Linux container",
            mapping={"container": "actor.process.name"},
            fields=_clean({"container": m["container"]}), summary=msg)
    if _SEGFAULT.search(msg):
        return SemanticResult(
            CLS_PROCESS, (4, "Terminate"), "Process Activity", "Linux kernel",
            severity=SEV_HIGH, summary=msg)

    # ── Network activity ─────────────────────────────────────────────────────
    # kernel netfilter / UFW packet log (scoped to kernel-origin SRC=/DST= lines)
    if prog == "kernel" and "SRC=" in msg and "DST=" in msg:
        m = _NETFILTER.search(msg)
        if m:
            act = _UFW_ACTION.search(msg)
            action = (act.group("action") or act.group("a2")) if act else None
            blocked = action in ("BLOCK", "DROP", "REJECT")
            sr = SemanticResult(
                CLS_NETWORK, (6, "Traffic"), "Network Activity", "Linux netfilter",
                severity=SEV_MEDIUM if blocked else None,
                status=("Failure", 2) if blocked else None,
                mapping=dict(NET_MAP), fields=_clean(m.groupdict()), summary=msg)
            if action:
                sr.fields["fw_action"] = action  # native-only (not mapped)
            return sr
    if _SYN_FLOOD.search(msg):
        return SemanticResult(
            CLS_NETWORK, (6, "Traffic"), "Network Activity", "Linux kernel",
            severity=SEV_HIGH, summary=msg)
    m = _FAIL2BAN.search(msg)
    if m:
        banned = m["action"] == "Ban"
        return SemanticResult(
            CLS_NETWORK, (6, "Traffic"), "Network Activity", "Linux fail2ban",
            severity=SEV_MEDIUM if banned else None,
            mapping={"src_ip": "src_endpoint.ip"},
            fields=_clean({"src_ip": m["src_ip"]}), summary=msg)
    if _DHCP.search(msg):
        m = _DHCP.search(msg)
        return SemanticResult(
            CLS_NETWORK, (6, "Traffic"), "Network Activity", "Linux dhcp",
            mapping={"ip": "dst_endpoint.ip"},
            fields=_clean({"ip": m.groupdict().get("ip")}), summary=msg)

    # ── System (catch-all) ───────────────────────────────────────────────────
    # apparmor / SELinux denials and I/O errors are noteworthy but stay System.
    sev = None
    low = msg.lower()
    if 'apparmor="denied"' in low or "apparmor=denied" in low or "denied" in low and "apparmor" in low:
        sev = SEV_HIGH
    elif "i/o error" in low or "blk_update_request" in low:
        sev = SEV_HIGH
    return SemanticResult(
        CLS_SYSTEM, (0, "System Activity"), "System Activity", "Linux syslog",
        severity=sev, summary=msg)
