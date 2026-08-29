"""
Firewall event ENVELOPE — the common schema every firewall source is parsed into.

Stage ① (syntax parsing) + Stage ② (schema normalization) of the Matryoshka model.
Regardless of input format (CEF / FortiGate kv / Cisco ASA syslog / Juniper SRX /
NetScreen) we normalise into ONE `FirewallEvent` dataclass:

    hostname / timestamp components / level
    src_ip / src_port / dst_ip / dst_port / protocol / action
    vendor_data{...}  ← ALL remaining fields, losslessly (nothing dropped)

vendor_data is a plain dict holding every extra field. Semantic naming and OCSF
mapping happen later in handlers.py; anything still unmapped is carried under
`unmapped.firewall` downstream.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class FirewallEvent:
    """Common firewall envelope.  vendor_data holds every extra field, losslessly."""
    fmt: str = "unknown"              # cef | fortigate | cisco_asa | juniper_srx | netscreen

    # Timestamp — depends on format
    date: Optional[str] = None        # YYYY-MM-DD (FortiGate, Win-FW)
    time: Optional[str] = None        # HH:MM:SS
    month: Optional[str] = None       # Jan/Feb/... (syslog-wrapped formats)
    day: Optional[str] = None         # 1–31
    timestamp: Optional[str] = None   # ISO or epoch (CEF rt=)

    hostname: Optional[str] = None    # reporting device hostname
    level: Optional[str] = None       # severity label (notice, warning, alert …)

    # Core network fields (promoted from every format)
    src_ip: Optional[str] = None
    src_port: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[str] = None
    protocol: Optional[str] = None    # name or number
    action: Optional[str] = None      # raw vendor action string

    # Vendor-specific bag (lossless)
    vendor_data: dict = field(default_factory=dict)

    def put(self, key: str, value):
        """Store an extra field iff it carries information (non-empty)."""
        if key is None or value is None:
            return
        v = str(value).strip()
        if v in ("", "-", "N/A", "n/a"):
            return
        if key not in self.vendor_data or self.vendor_data[key] in ("", "-", None):
            self.vendor_data[key] = v


# ═════════════════════════════════════════════════════════════════════════════
# CEF parser
# ═════════════════════════════════════════════════════════════════════════════

# Syslog/timestamp prefix patterns that may precede the CEF: prefix.
# e.g. "1493738863000 hostname.example.com CEF:0|..."
# e.g. "May  4 10:00:00 host CEF:0|..."
_CEF_PREFIX_RFC3164_RE = re.compile(
    r"^(?:<\d+>\s*)?(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s*$",
    re.IGNORECASE,
)
_CEF_PREFIX_EPOCH_RE = re.compile(
    r"^(?:<\d+>\s*)?(?:(?P<epoch>\d{10,13})\s+)?(?P<host>\S+)\s*$",
    re.IGNORECASE,
)


def _split_cef_header(s: str) -> list[str]:
    """Split a CEF header on unescaped '|' characters."""
    parts: list[str] = []
    current: list[str] = []
    i = 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s) and s[i + 1] == "|":
            current.append("|")
            i += 2
        elif s[i] == "|":
            parts.append("".join(current))
            current = []
            i += 1
        else:
            current.append(s[i])
            i += 1
    if current:
        parts.append("".join(current))
    return parts


# Key= boundary: word chars preceded by start-of-string OR a space.
# This correctly handles multi-word values like "cs2=Current Value cnt=1".
_CEF_EXT_KEY_RE = re.compile(r"(?:^|(?<= ))(\w+)=")


def _parse_cef_extensions(ext_str: str) -> dict:
    """Parse CEF extension key=value pairs.  Values may contain spaces."""
    result: dict = {}
    if not ext_str:
        return result
    matches = list(_CEF_EXT_KEY_RE.finditer(ext_str))
    for i, m in enumerate(matches):
        key = m.group(1)
        val_start = m.end()
        val_end = matches[i + 1].start() if i + 1 < len(matches) else len(ext_str)
        value = ext_str[val_start:val_end].rstrip(" ")
        # CEF backslash escapes
        value = (
            value.replace("\\\\", "\x00BSLASH\x00")
                 .replace("\\n", "\n")
                 .replace("\\r", "\r")
                 .replace("\\=", "=")
                 .replace("\\|", "|")
                 .replace("\x00BSLASH\x00", "\\")
        )
        result[key] = value
    return result


def parse_cef(raw: str) -> Optional[FirewallEvent]:
    """Parse a CEF log line (with or without syslog prefix)."""
    raw = raw.strip()
    ev = FirewallEvent(fmt="cef")

    # Locate "CEF:" token — strip any prefix before it
    cef_idx = raw.upper().find("CEF:")
    if cef_idx < 0:
        return None

    prefix = raw[:cef_idx].rstrip()
    cef_str = raw[cef_idx:]

    # Try to extract syslog prefix metadata
    if prefix:
        m2 = _CEF_PREFIX_RFC3164_RE.match(prefix)
        if m2:
            ev.month = m2.group("month")
            ev.day = m2.group("day")
            ev.time = m2.group("time")
            ev.hostname = m2.group("host")
        else:
            m1 = _CEF_PREFIX_EPOCH_RE.match(prefix)
            if m1:
                ev.hostname = m1.group("host")
                epoch = m1.group("epoch")
                if epoch:
                    ev.vendor_data["cef_epoch_ms"] = epoch

    # Split "CEF:N|vendor|product|ver|classId|name|severity|extensions"
    parts = _split_cef_header(cef_str)
    if len(parts) < 7:
        return None  # malformed CEF

    # parts[0] = "CEF:N"
    try:
        ev.vendor_data["cef_version"] = int(parts[0].split(":")[1])
    except (IndexError, ValueError):
        ev.vendor_data["cef_version"] = 0

    ev.vendor_data["device_vendor"] = parts[1]
    ev.vendor_data["device_product"] = parts[2]
    ev.vendor_data["device_version"] = parts[3]
    ev.vendor_data["device_event_class_id"] = parts[4]
    ev.vendor_data["name"] = parts[5]
    ev.vendor_data["cef_severity"] = parts[6]
    ev.level = parts[6]  # used by severity resolver

    # Extensions (index 7 onward joined back with "|" in case of edge case splits)
    ext_raw = "|".join(parts[7:]) if len(parts) > 7 else ""
    extensions = _parse_cef_extensions(ext_raw)
    ev.vendor_data["extensions"] = extensions

    # Promote standard extension fields → envelope
    ev.src_ip = extensions.get("src") or extensions.get("sourceAddress")
    ev.dst_ip = extensions.get("dst") or extensions.get("destinationAddress")
    ev.src_port = extensions.get("spt") or extensions.get("sourcePort")
    ev.dst_port = extensions.get("dpt") or extensions.get("destinationPort")
    ev.protocol = extensions.get("proto") or extensions.get("transportProtocol")
    ev.action = extensions.get("act") or extensions.get("outcome")
    if not ev.hostname:
        ev.hostname = extensions.get("dvc") or extensions.get("deviceAddress")

    # CEF rt= is epoch milliseconds
    rt = extensions.get("rt")
    if rt and rt.isdigit():
        ev.vendor_data["cef_epoch_ms"] = rt

    # Message field
    msg = extensions.get("msg") or extensions.get("message")
    if msg:
        ev.vendor_data["message"] = msg

    return ev


# ═════════════════════════════════════════════════════════════════════════════
# FortiGate key=value parser
# ═════════════════════════════════════════════════════════════════════════════

# FortiGate uses both quoted and unquoted values:
#   key="value with spaces"   key=value_no_spaces
_FGT_KV_RE = re.compile(r'(\w+)=(?:"([^"]*)"|([\S]*))')

# Protocol number → name mapping (common ones)
_PROTO_NUM = {
    "1": "icmp", "6": "tcp", "17": "udp", "47": "gre",
    "50": "esp", "51": "ah", "58": "ipv6-icmp", "89": "ospf",
}

# Actions that mean TRAFFIC BLOCKED/DENIED
_DENY_ACTIONS = frozenset(
    ["block", "blocked", "deny", "denied", "drop", "dropped", "reject", "rejected"]
)


def parse_fortigate(raw: str) -> Optional[FirewallEvent]:
    """Parse a FortiGate key=value log line."""
    if "logid=" not in raw and "logid =" not in raw:
        return None

    ev = FirewallEvent(fmt="fortigate")
    kv: dict = {}
    for m in _FGT_KV_RE.finditer(raw):
        key = m.group(1)
        value = m.group(2) if m.group(2) is not None else m.group(3)
        kv[key] = value

    if not kv:
        return None

    # Timestamp (date + time are consumed by ocsf_mapper._build_timestamp)
    ev.date = kv.get("date")
    ev.time = kv.get("time")

    # Device / level
    ev.hostname = kv.get("devname") or kv.get("hostname")
    ev.level = kv.get("level")

    # Core network fields
    ev.src_ip = kv.get("srcip")
    ev.dst_ip = kv.get("dstip")
    ev.src_port = kv.get("srcport")
    ev.dst_port = kv.get("dstport")

    # Protocol: FortiGate emits numeric (proto=6) or service name
    proto_raw = kv.get("proto", "")
    ev.protocol = _PROTO_NUM.get(proto_raw, proto_raw) or kv.get("service", "")
    ev.action = kv.get("action")

    # Preserve every field in vendor_data
    for k, v in kv.items():
        ev.put(k, v)

    return ev


# ═════════════════════════════════════════════════════════════════════════════
# Cisco ASA parser
# ═════════════════════════════════════════════════════════════════════════════

# Top-level syslog wrapper (optional):  <priority>Month Day HH:MM:SS host %ASA-N-ID:
_ASA_SYSLOG_PREFIX_RE = re.compile(
    r"^(?:<\d+>)?\s*"
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+",
    re.IGNORECASE,
)
# Core tag: %ASA-severity-msgid:
_ASA_TAG_RE = re.compile(r"%ASA-(?P<sev>\d+)-(?P<msgid>\d+)\s*:")

# Per-message-ID patterns for the most common firewall/connection events.
# Named groups follow our standard: src_ip, src_port, dst_ip, dst_port, protocol, action
_ASA_MSG_PATTERNS: dict[str, re.Pattern] = {
    # ASA-2-106001: Inbound/Outbound TCP connection denied from src/sport to dst/dport
    "106001": re.compile(
        r"(?P<action>[\w ]+)\s+(?P<protocol>\w+)\s+connection\s+(?:denied\s+)?from\s+"
        r"(?P<src_ip>[\d.]+)/(?P<src_port>\d+)\s+to\s+(?P<dst_ip>[\d.]+)/(?P<dst_port>\d+)"
        r"(?:.*?on\s+interface\s+(?P<in_iface>\S+))?",
        re.IGNORECASE | re.DOTALL,
    ),
    # ASA-2-106006/106007/106010: action direction proto from src/sport to dst/dport
    "106006": re.compile(
        r"(?P<action>[\w]+)\s+(?P<direction>\w+)\s+(?P<protocol>\w+)\s+"
        r"(?:from|src)\s+(?P<src_ip>[\d.]+)/(?P<src_port>\d+)"
        r"(?:\s*\([^)]*\))?\s+(?:to|dst)\s+(?P<dst_ip>[\d.]+)/(?P<dst_port>\d+)",
        re.IGNORECASE | re.DOTALL,
    ),
    # ASA-6-106015: action proto (rule) from src/sport to dst/dport
    "106015": re.compile(
        r"(?P<action>\w+)\s+(?P<protocol>\w+)\s+(?:\((?P<rule>[^)]+)\)\s+)?from\s+"
        r"(?P<src_ip>[\d.]+)/(?P<src_port>\d+)\s+to\s+(?P<dst_ip>[\d.]+)/(?P<dst_port>\d+)"
        r"(?:.*?on\s+interface\s+(?P<in_iface>\S+))?",
        re.IGNORECASE | re.DOTALL,
    ),
    # ASA-4-106023: action proto src iface:ip/port dst iface:ip/port by access-group "rule"
    "106023": re.compile(
        r"(?P<action>\w+)(?:\s+protocol)?\s+(?P<protocol>\w+)\s+src\s+"
        r"(?P<src_iface>\S+):(?P<src_ip>[\d.]+)/(?P<src_port>\d+)"
        r"(?:\s*\([^)]*\))?\s+dst\s+(?P<dst_iface>\S+):(?P<dst_ip>[\d.]+)/(?P<dst_port>\d+)"
        r"(?:.*?by\s+access-group\s+[\"']?(?P<rule>[^\"'\[\s]+))?",
        re.IGNORECASE | re.DOTALL,
    ),
    # ASA-6-302013/302014: Built/Teardown connection for iface:src/sport to iface:dst/dport
    "302013": re.compile(
        r"(?P<action>Built|Teardown)\s+(?P<direction>\w+)?\s*(?P<protocol>\w+)\s+connection\s+(?P<conn_id>\d+)\s+"
        r"for\s+(?P<src_iface>\S+):(?P<src_ip>[\d.]+)/(?P<src_port>\d+)"
        r"(?:\s*\([^)]*\))?(?:\s*\([^)]*\))?"
        r"\s+to\s+(?P<dst_iface>\S+):(?P<dst_ip>[\d.]+)/(?P<dst_port>\d+)"
        r"(?:.*?(?P<bytes>\d+)\s+bytes)?",
        re.IGNORECASE | re.DOTALL,
    ),
    # ASA-7-710001/710002/710003: proto access action from src/sport to iface:dst/dport
    "710001": re.compile(
        r"(?P<protocol>\w+)\s+(?:request|access)\s+(?P<action>\w+)\s+from\s+"
        r"(?P<src_ip>[\d.]+)/(?P<src_port>\d+)\s+to\s+\S+:(?P<dst_ip>[\d.]+)/(?P<dst_port>\d+)",
        re.IGNORECASE | re.DOTALL,
    ),
}
# Aliases: same pattern for similar message IDs
_ASA_MSG_PATTERNS["106007"] = _ASA_MSG_PATTERNS["106006"]
_ASA_MSG_PATTERNS["106010"] = _ASA_MSG_PATTERNS["106006"]
_ASA_MSG_PATTERNS["302014"] = _ASA_MSG_PATTERNS["302013"]
_ASA_MSG_PATTERNS["302015"] = _ASA_MSG_PATTERNS["302013"]
_ASA_MSG_PATTERNS["302016"] = _ASA_MSG_PATTERNS["302013"]
_ASA_MSG_PATTERNS["710002"] = _ASA_MSG_PATTERNS["710001"]
_ASA_MSG_PATTERNS["710003"] = _ASA_MSG_PATTERNS["710001"]
_ASA_MSG_PATTERNS["710005"] = _ASA_MSG_PATTERNS["710001"]
_ASA_MSG_PATTERNS["710006"] = _ASA_MSG_PATTERNS["710001"]

# Fallback: catch any IPs from an unknown ASA message
_IP_PORT_RE = re.compile(r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})/(?P<port>\d+)")

# ASA severity number → log level name
_ASA_SEV = {
    "1": "critical", "2": "error", "3": "error",
    "4": "warning", "5": "notice", "6": "informational", "7": "debug",
}


def parse_cisco_asa(raw: str) -> Optional[FirewallEvent]:
    """Parse a Cisco ASA syslog message."""
    tag_m = _ASA_TAG_RE.search(raw)
    if not tag_m:
        return None

    ev = FirewallEvent(fmt="cisco_asa")

    # Optional syslog prefix (timestamp + hostname)
    pre_m = _ASA_SYSLOG_PREFIX_RE.match(raw)
    if pre_m:
        ev.month = pre_m.group("month")
        ev.day = pre_m.group("day")
        ev.time = pre_m.group("time")
        ev.hostname = pre_m.group("host")

    sev = tag_m.group("sev")
    msgid = tag_m.group("msgid")
    ev.level = _ASA_SEV.get(sev, "informational")
    ev.vendor_data["asa_severity"] = sev
    ev.vendor_data["asa_msgid"] = msgid
    ev.vendor_data["asa_tag"] = tag_m.group(0).rstrip(": ").lstrip("%")

    # Message body starts after the tag
    body = raw[tag_m.end():].strip()
    ev.vendor_data["message"] = body

    # Per-msgid structured parsing
    pattern = _ASA_MSG_PATTERNS.get(msgid)
    if pattern:
        mm = pattern.search(body)
        if mm:
            gd = {k: v for k, v in mm.groupdict().items() if v is not None and v.strip()}
            ev.src_ip = gd.get("src_ip")
            ev.src_port = gd.get("src_port")
            ev.dst_ip = gd.get("dst_ip")
            ev.dst_port = gd.get("dst_port")
            ev.protocol = gd.get("protocol")
            ev.action = gd.get("action")
            # Preserve extra parsed fields
            for k, v in gd.items():
                if k not in ("src_ip", "src_port", "dst_ip", "dst_port",
                             "protocol", "action"):
                    ev.put(k, v)

    # Fallback IP extraction for unrecognized message IDs
    if not ev.src_ip:
        ips = _IP_PORT_RE.findall(body)
        if len(ips) >= 1:
            ev.src_ip, ev.src_port = ips[0]
        if len(ips) >= 2:
            ev.dst_ip, ev.dst_port = ips[1]

    return ev


# ═════════════════════════════════════════════════════════════════════════════
# Juniper SRX parser
# ═════════════════════════════════════════════════════════════════════════════

# Optional syslog prefix + RT_FLOW event type
_SRX_PREFIX_RE = re.compile(
    r"^(?:<\d+>)?\s*"
    r"(?:(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+)?",
    re.IGNORECASE,
)
_SRX_EVENT_RE = re.compile(
    r"RT_FLOW(?:_SESSION)?_(?P<event>CREATE|CLOSE|DENY)\b", re.IGNORECASE
)
# Flow tuple: ip/port->ip/port
_SRX_FLOW_RE = re.compile(
    r"(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})/(?P<src_port>\d+)"
    r"\s*->\s*"
    r"(?P<dst_ip>\d{1,3}(?:\.\d{1,3}){3})/(?P<dst_port>\d+)"
)

_SRX_PROTO_NUM = _PROTO_NUM  # reuse same table

# Detailed RT_FLOW_SESSION_CLOSE / CREATE structured format
# Fields (space-separated after the flow tuple): 0x? service nat_src->nat_dst 0x? reason rule proto-id from-zone to-zone
_SRX_REASON_RE = re.compile(r"\bTCP\s+CLIENT\s+RST\b|\bAGED\s+OUT\b|\bCLOSE\b", re.IGNORECASE)


def parse_juniper_srx(raw: str) -> Optional[FirewallEvent]:
    """Parse a Juniper SRX RT_FLOW syslog event."""
    ev = FirewallEvent(fmt="juniper_srx")

    # Syslog prefix
    pm = _SRX_PREFIX_RE.match(raw)
    if pm:
        ev.month = pm.group("month")
        ev.day = pm.group("day")
        ev.time = pm.group("time")
        ev.hostname = pm.group("host")

    # Event type
    em = _SRX_EVENT_RE.search(raw)
    if not em:
        return None
    event_type = em.group("event").upper()  # CREATE | CLOSE | DENY
    ev.vendor_data["srx_event_type"] = event_type
    ev.action = "allow" if event_type in ("CREATE", "CLOSE") else "deny"

    # Primary flow tuple (first occurrence = original)
    fm = _SRX_FLOW_RE.search(raw)
    if fm:
        ev.src_ip = fm.group("src_ip")
        ev.src_port = fm.group("src_port")
        ev.dst_ip = fm.group("dst_ip")
        ev.dst_port = fm.group("dst_port")

    # Try to pull structured fields from the body after the event keyword
    body = raw[em.end():].strip().lstrip(": ")
    # Body structure (approximate): description: flow_tuple 0x? service nat_tuple 0x? reason? rule proto from-zone to-zone ...
    tokens = body.split()
    # Protocol ID is usually the standalone numeric token after from-zone reference
    # Look for an isolated protocol number (1, 6, 17, …)
    for tok in tokens:
        if tok.isdigit() and tok in _SRX_PROTO_NUM:
            ev.protocol = _SRX_PROTO_NUM[tok]
            ev.put("protocol_id", tok)
            break

    # Capture reason + policy name heuristically from known tokens
    reason_m = _SRX_REASON_RE.search(body)
    if reason_m:
        ev.put("reason", reason_m.group(0))

    # Preserve tokens > 3 chars that look like policy/zone names (heuristic)
    ev.vendor_data["srx_body"] = body[:256]  # truncated for safety

    return ev


# ═════════════════════════════════════════════════════════════════════════════
# NetScreen parser
# ═════════════════════════════════════════════════════════════════════════════

_NS_PREFIX_RE = re.compile(
    r"^(?:<\d+>)?\s*"
    r"(?:(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+)?",
    re.IGNORECASE,
)
# Key=value for NetScreen (unquoted or quoted)
_NS_KV_RE = re.compile(r'(\w[\w-]*)=(?:"([^"]*)"|([\S]*))')

# Zone fields use "src zone=X dst zone=Y" with a space in the key
_NS_SRC_ZONE_RE = re.compile(r"src\s+zone\s*=\s*(\S+)", re.IGNORECASE)
_NS_DST_ZONE_RE = re.compile(r"dst\s+zone\s*=\s*(\S+)", re.IGNORECASE)


def parse_netscreen(raw: str) -> Optional[FirewallEvent]:
    """Parse a Juniper NetScreen legacy firewall session log."""
    if "device_id=" not in raw and "NetScreen" not in raw:
        return None

    ev = FirewallEvent(fmt="netscreen")

    pm = _NS_PREFIX_RE.match(raw)
    if pm:
        ev.month = pm.group("month")
        ev.day = pm.group("day")
        ev.time = pm.group("time")
        ev.hostname = pm.group("host")

    kv: dict = {}
    for m in _NS_KV_RE.finditer(raw):
        key = m.group(1)
        value = m.group(2) if m.group(2) is not None else m.group(3)
        kv[key] = value

    # Core network fields (NetScreen uses src= dst= src_port= dst_port=)
    ev.src_ip = kv.get("src")
    ev.dst_ip = kv.get("dst")
    ev.src_port = kv.get("src_port")
    ev.dst_port = kv.get("dst_port")
    ev.protocol = kv.get("service") or (_PROTO_NUM.get(kv.get("proto", ""), kv.get("proto")))
    ev.action = kv.get("action")
    ev.level = kv.get("level")
    ev.hostname = ev.hostname or kv.get("hostname")

    # Zone fields with embedded spaces ("src zone=X") need special handling
    sz = _NS_SRC_ZONE_RE.search(raw)
    dz = _NS_DST_ZONE_RE.search(raw)
    if sz:
        ev.put("src_zone", sz.group(1))
    if dz:
        ev.put("dst_zone", dz.group(1))

    # Preserve all other kv fields
    for k, v in kv.items():
        ev.put(k, v)

    return ev
