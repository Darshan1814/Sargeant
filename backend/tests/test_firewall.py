"""
Firewall parser family test suite.

Tests:
  1. Detector — correct format identification for all 5 formats
  2. Envelope — field extraction per format
  3. Engine / full pipeline — OCSF output validation
  4. CEF regression — all 90 test cases from raw_logs/CEF_loga_json/
  5. Multi-sample — FortiGate, Cisco ASA various message IDs
  6. Negative — non-firewall logs must return None

Run via: pytest backend/tests/test_firewall.py -v
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

# ── Path bootstrap ────────────────────────────────────────────────────────────
_REPO = Path(__file__).parent.parent.parent
os.environ.setdefault("PARSERS_DIR", str(_REPO / "parsers" / "registry"))
os.environ.setdefault("DUCKDB_PATH", str(Path(tempfile.mkdtemp()) / "test_fw.db"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from firewall.detector import detect_format, is_firewall
from firewall.envelope import (
    parse_cef, parse_fortigate, parse_cisco_asa,
    parse_juniper_srx, parse_netscreen,
)
from firewall.engine import parse as fw_parse
from pipeline import process

FIXTURES = Path(__file__).parent / "fixtures"
CEF_FIXTURES = _REPO / "raw_logs" / "CEF_loga_json"


def _load(name: str) -> str:
    return (FIXTURES / name).read_text().strip()


# ═══════════════════════════════════════════════════════════════════════════════
# 1. DETECTOR
# ═══════════════════════════════════════════════════════════════════════════════

class TestDetector:
    def test_cef_detected(self):
        assert detect_format(_load("sample_cef.log")) == "cef"

    def test_fortigate_detected(self):
        assert detect_format(_load("sample_fortigate.log")) == "fortigate"

    def test_cisco_asa_detected(self):
        assert detect_format(_load("sample_cisco_asa.log")) == "cisco_asa"

    def test_juniper_srx_detected(self):
        assert detect_format(_load("sample_juniper_srx.log")) == "juniper_srx"

    def test_netscreen_detected(self):
        assert detect_format(_load("sample_netscreen.log")) == "netscreen"

    def test_windows_log_not_firewall(self):
        raw = (
            "Log Name:      Security\nSource:        Microsoft-Windows-Security-Auditing\n"
            "Event ID:      4624\nComputer:      DC01\n"
        )
        assert detect_format(raw) is None
        assert is_firewall(raw) is False

    def test_linux_syslog_not_firewall(self):
        raw = "May  4 10:00:00 myhost sshd[1234]: Accepted publickey for root from 10.0.0.1"
        assert detect_format(raw) is None

    def test_empty_not_firewall(self):
        assert detect_format("") is None
        assert detect_format("   ") is None

    def test_is_firewall_true(self):
        assert is_firewall(_load("sample_cef.log")) is True
        assert is_firewall(_load("sample_fortigate.log")) is True


# ═══════════════════════════════════════════════════════════════════════════════
# 2. ENVELOPE — field extraction
# ═══════════════════════════════════════════════════════════════════════════════

class TestCEFEnvelope:
    def test_basic_cef_parse(self):
        raw = "CEF:0|Security|threatmanager|1.0|100|worm successfully stopped|10|src=10.0.0.1 dst=2.1.2.2 spt=1232"
        ev = parse_cef(raw)
        assert ev is not None
        assert ev.fmt == "cef"
        assert ev.src_ip == "10.0.0.1"
        assert ev.dst_ip == "2.1.2.2"
        assert ev.src_port == "1232"
        assert ev.vendor_data["device_vendor"] == "Security"
        assert ev.vendor_data["device_product"] == "threatmanager"
        assert ev.vendor_data["name"] == "worm successfully stopped"
        assert ev.vendor_data["cef_severity"] == "10"

    def test_cef_multiword_extension_value(self):
        raw = "CEF:0|ArcSight|Logger|5.0.0.5355.2|sensor:115|Logger Internal Event|1|cat=/Monitor/Sensor/Fan5 cs2=Current Value cnt=1 dvc=10.0.0.1 cs3=Ok"
        ev = parse_cef(raw)
        assert ev is not None
        exts = ev.vendor_data.get("extensions", {})
        assert exts.get("cs2") == "Current Value", f"got: {exts.get('cs2')!r}"
        assert exts.get("cnt") == "1"
        assert exts.get("dvc") == "10.0.0.1"
        assert ev.hostname == "10.0.0.1"

    def test_cef_with_syslog_prefix(self):
        raw = "1493738863000 hostname.example.com CEF:0|Security|threatmanager|1.0|100|worm|10|src=10.0.0.1 dst=2.1.2.2 spt=1232"
        ev = parse_cef(raw)
        assert ev is not None
        assert ev.hostname == "hostname.example.com"

    def test_cef_no_extensions(self):
        raw = "CEF:0|Vendor|Product|1.0|eventId|Event Name|5|"
        ev = parse_cef(raw)
        assert ev is not None
        assert ev.vendor_data["name"] == "Event Name"

    def test_cef_pipe_in_header_field(self):
        # Escaped pipe in header field
        raw = "CEF:0|Vendor|Prod\\|uct|1.0|100|Name|5|src=1.2.3.4"
        ev = parse_cef(raw)
        assert ev is not None
        assert "Prod|uct" in ev.vendor_data.get("device_product", "")


class TestFortiGateEnvelope:
    def test_traffic_forward(self):
        raw = _load("sample_fortigate.log")
        ev = parse_fortigate(raw)
        assert ev is not None
        assert ev.fmt == "fortigate"
        assert ev.src_ip == "10.1.100.11"
        assert ev.dst_ip == "23.59.154.35"
        assert ev.src_port == "58012"
        assert ev.dst_port == "80"
        assert ev.protocol == "tcp"      # proto=6 → tcp
        assert ev.action == "close"
        assert ev.date == "2019-05-10"
        assert ev.time == "11:37:47"
        assert ev.level == "notice"

    def test_fortigate_quoted_values(self):
        raw = 'date=2019-05-13 time=11:45:03 logid="0211008192" type="utm" subtype="virus" level="warning" srcip=10.1.100.11 dstip=172.16.200.55 srcport=60446 dstport=80 proto=6 action="blocked" service="HTTP"'
        ev = parse_fortigate(raw)
        assert ev is not None
        assert ev.action == "blocked"
        assert ev.level == "warning"

    def test_fortigate_non_log_returns_none(self):
        assert parse_fortigate("some random line without logid") is None


class TestCiscoASAEnvelope:
    def test_106015_deny(self):
        raw = _load("sample_cisco_asa.log")
        ev = parse_cisco_asa(raw)
        assert ev is not None
        assert ev.fmt == "cisco_asa"
        assert ev.vendor_data.get("asa_msgid") == "106015"
        assert ev.src_ip == "10.0.0.5"
        assert ev.dst_ip == "192.168.1.1"
        assert ev.src_port == "12345"
        assert ev.dst_port == "80"
        assert ev.action is not None and "deny" in ev.action.lower()
        assert ev.protocol == "TCP"

    def test_302013_built(self):
        raw = "%ASA-6-302013: Built inbound TCP connection 12345 for outside:10.0.0.1/1234 to inside:192.168.1.1/80"
        ev = parse_cisco_asa(raw)
        assert ev is not None
        assert ev.vendor_data.get("asa_msgid") == "302013"
        assert ev.src_ip == "10.0.0.1"
        assert ev.dst_ip == "192.168.1.1"
        assert ev.action is not None and "built" in ev.action.lower()

    def test_710001_access_denied(self):
        raw = "%ASA-7-710001: TCP access requested from 10.0.0.5/12345 to outside:192.168.1.1/443"
        ev = parse_cisco_asa(raw)
        assert ev is not None
        assert ev.vendor_data.get("asa_msgid") == "710001"

    def test_no_asa_tag_returns_none(self):
        assert parse_cisco_asa("some random log line") is None

    def test_syslog_prefix_extraction(self):
        raw = "<166>May  4 09:00:01 asa-fw %ASA-6-106015: Deny TCP from 10.0.0.5/12345 to 192.168.1.1/80 on interface outside"
        ev = parse_cisco_asa(raw)
        assert ev is not None
        assert ev.hostname == "asa-fw"
        assert ev.month == "May"
        assert ev.day == "4"


class TestJuniperSRXEnvelope:
    def test_session_create(self):
        raw = _load("sample_juniper_srx.log")
        ev = parse_juniper_srx(raw)
        assert ev is not None
        assert ev.fmt == "juniper_srx"
        assert ev.src_ip == "10.0.0.1"
        assert ev.dst_ip == "192.168.1.1"
        assert ev.src_port == "1234"
        assert ev.dst_port == "80"
        assert ev.action == "allow"
        assert ev.vendor_data.get("srx_event_type") == "CREATE"

    def test_session_deny(self):
        raw = "May 14 10:00:00 srx1 RT_FLOW: RT_FLOW_SESSION_DENY: session denied 10.0.0.5/9999->10.0.0.1/22 0x0 ssh"
        ev = parse_juniper_srx(raw)
        assert ev is not None
        assert ev.action == "deny"
        assert ev.vendor_data.get("srx_event_type") == "DENY"
        assert ev.src_ip == "10.0.0.5"

    def test_no_rt_flow_returns_none(self):
        assert parse_juniper_srx("some other log line") is None


class TestNetScreenEnvelope:
    def test_permit_session(self):
        raw = _load("sample_netscreen.log")
        ev = parse_netscreen(raw)
        assert ev is not None
        assert ev.fmt == "netscreen"
        assert ev.src_ip == "10.1.1.1"
        assert ev.dst_ip == "10.2.2.2"
        assert ev.src_port == "1254"
        assert ev.dst_port == "21"
        assert ev.action == "Permit"

    def test_non_netscreen_returns_none(self):
        assert parse_netscreen("some random line") is None


# ═══════════════════════════════════════════════════════════════════════════════
# 3. ENGINE — OCSF output validation
# ═══════════════════════════════════════════════════════════════════════════════

class TestEngine:
    def _assert_base_ocsf(self, result):
        """Assert a FirewallParseResult produces valid OCSF output."""
        assert result is not None
        assert result.parser_id.startswith("FW-")
        assert result.confidence > 0.5
        pc = result.parser_config
        assert pc["ocsf_class_uid"] == 4001
        assert pc["os_family"] == "Network"
        assert "_confidence" in pc

    def test_cef_engine(self):
        raw = _load("sample_cef.log")
        result = fw_parse(raw)
        self._assert_base_ocsf(result)
        assert result.parser_id == "FW-CEF-GENERIC"
        assert result.fields.get("src_ip") == "10.0.0.1"
        assert result.fields.get("dst_ip") == "2.1.2.2"
        assert result.firewall_block.get("format") == "cef"

    def test_fortigate_engine(self):
        raw = _load("sample_fortigate.log")
        result = fw_parse(raw)
        self._assert_base_ocsf(result)
        assert result.parser_id == "FW-FORTIGATE-001"
        assert result.fields.get("src_ip") == "10.1.100.11"
        assert result.fields.get("dst_ip") == "23.59.154.35"
        assert result.fields.get("protocol") == "tcp"
        assert result.firewall_block.get("format") == "fortigate"

    def test_cisco_asa_engine(self):
        raw = _load("sample_cisco_asa.log")
        result = fw_parse(raw)
        self._assert_base_ocsf(result)
        assert "CISCO" in result.parser_id.upper()
        assert result.firewall_block.get("format") == "cisco_asa"

    def test_juniper_srx_engine(self):
        raw = _load("sample_juniper_srx.log")
        result = fw_parse(raw)
        self._assert_base_ocsf(result)
        assert result.parser_id == "FW-JUNIPER-SRX-001"
        assert result.fields.get("src_ip") == "10.0.0.1"
        assert result.fields.get("dst_ip") == "192.168.1.1"

    def test_netscreen_engine(self):
        raw = _load("sample_netscreen.log")
        result = fw_parse(raw)
        self._assert_base_ocsf(result)
        assert result.parser_id == "FW-NETSCREEN-001"
        assert result.fields.get("src_ip") == "10.1.1.1"

    def test_non_firewall_returns_none(self):
        raw = "Log Name: Security\nSource: Microsoft-Windows-Security-Auditing\nEvent ID: 4624"
        assert fw_parse(raw) is None

    def test_empty_returns_none(self):
        assert fw_parse("") is None
        assert fw_parse("   ") is None


# ═══════════════════════════════════════════════════════════════════════════════
# 4. FULL PIPELINE — OCSF structure
# ═══════════════════════════════════════════════════════════════════════════════

class TestPipeline:
    def _check_ocsf(self, result):
        assert result["normalized"]["class_uid"] == 4001
        assert result["normalized"]["class_name"] == "Network Activity"
        assert result["normalized"]["ocsf_mapping_status"] == "mapped"
        assert result["path"] == "ngre"

    def test_cef_full_pipeline(self):
        raw = _load("sample_cef.log")
        result = process(raw)
        assert result["parser_id"] == "FW-CEF-GENERIC"
        self._check_ocsf(result)
        norm = result["normalized"]
        assert norm["src_endpoint"]["ip"] == "10.0.0.1"
        assert norm["dst_endpoint"]["ip"] == "2.1.2.2"
        assert norm["src_endpoint"]["port"] == 1232
        # Firewall block preserved
        assert "firewall" in norm.get("unmapped", {})

    def test_fortigate_full_pipeline(self):
        raw = _load("sample_fortigate.log")
        result = process(raw)
        assert result["parser_id"] == "FW-FORTIGATE-001"
        self._check_ocsf(result)
        norm = result["normalized"]
        assert norm["src_endpoint"]["ip"] == "10.1.100.11"
        assert norm["dst_endpoint"]["ip"] == "23.59.154.35"
        assert norm["connection_info"]["protocol_name"] == "tcp"
        assert norm["time"] is not None  # timestamp reconstructed from date + time

    def test_cisco_asa_full_pipeline(self):
        raw = _load("sample_cisco_asa.log")
        result = process(raw)
        assert "CISCO" in result["parser_id"].upper()
        self._check_ocsf(result)
        norm = result["normalized"]
        assert norm["src_endpoint"]["ip"] == "10.0.0.5"
        assert norm["status"] == "Failure"   # Deny → Failure

    def test_juniper_srx_full_pipeline(self):
        raw = _load("sample_juniper_srx.log")
        result = process(raw)
        assert result["parser_id"] == "FW-JUNIPER-SRX-001"
        self._check_ocsf(result)
        norm = result["normalized"]
        assert norm["status"] == "Success"   # CREATE → allow → Success

    def test_netscreen_full_pipeline(self):
        raw = _load("sample_netscreen.log")
        result = process(raw)
        assert result["parser_id"] == "FW-NETSCREEN-001"
        self._check_ocsf(result)


# ═══════════════════════════════════════════════════════════════════════════════
# 5. CEF REGRESSION — all 90 test cases from raw_logs/CEF_loga_json/
# ═══════════════════════════════════════════════════════════════════════════════

def _load_cef_fixtures() -> list[dict]:
    """Load all JSON fixture files from the CEF test corpus."""
    if not CEF_FIXTURES.exists():
        return []
    items = []
    for f in sorted(CEF_FIXTURES.glob("*.json")):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            if "input" in data and "expected" in data:
                items.append({"file": f.name, **data})
        except Exception:
            pass
    return items


_CEF_CASES = _load_cef_fixtures()


@pytest.mark.parametrize("case", _CEF_CASES, ids=[c["file"] for c in _CEF_CASES])
def test_cef_regression(case):
    """Regression: every CEF fixture's input must parse and match expected fields."""
    raw = case["input"]
    expected = case["expected"]

    # Must detect as CEF
    assert detect_format(raw) == "cef", f"[{case['file']}] not detected as CEF"

    # Must parse via envelope
    ev = parse_cef(raw)
    assert ev is not None, f"[{case['file']}] parse_cef returned None"
    assert ev.fmt == "cef"

    # Verify header fields
    exp_version = expected.get("cefVersion")
    if exp_version is not None:
        assert ev.vendor_data.get("cef_version") == exp_version, \
            f"[{case['file']}] cef_version mismatch"

    for fld in ("deviceVendor", "deviceProduct", "deviceVersion",
                "deviceEventClassId", "name", "severity"):
        exp_val = expected.get(fld)
        if exp_val is None:
            continue
        our_key = {
            "deviceVendor": "device_vendor",
            "deviceProduct": "device_product",
            "deviceVersion": "device_version",
            "deviceEventClassId": "device_event_class_id",
            "name": "name",
            "severity": "cef_severity",
        }[fld]
        our_val = ev.vendor_data.get(our_key)
        # Allow type coercion (int vs str for version)
        assert str(our_val) == str(exp_val), \
            f"[{case['file']}] {fld}: expected {exp_val!r}, got {our_val!r}"

    # Verify extension fields
    exp_exts = expected.get("extensions", {})
    our_exts = ev.vendor_data.get("extensions", {})
    for k, exp_v in exp_exts.items():
        our_v = our_exts.get(k)
        assert our_v is not None, \
            f"[{case['file']}] extension key {k!r} missing (got keys: {list(our_exts)})"
        assert str(our_v).strip() == str(exp_v).strip(), \
            f"[{case['file']}] extension {k!r}: expected {exp_v!r}, got {our_v!r}"


# ═══════════════════════════════════════════════════════════════════════════════
# 6. STATUS NORMALIZATION
# ═══════════════════════════════════════════════════════════════════════════════

class TestStatusNormalization:
    def test_cisco_deny_yields_failure(self):
        raw = "%ASA-6-106015: Deny TCP from 10.0.0.5/12345 to 192.168.1.1/80 on interface outside"
        result = process(raw)
        assert result["normalized"]["status"] == "Failure"

    def test_cisco_built_yields_success(self):
        raw = "%ASA-6-302013: Built inbound TCP connection 999 for outside:10.0.0.1/1234 to inside:192.168.1.1/80"
        result = process(raw)
        assert result["normalized"]["status"] == "Success"

    def test_fortigate_accept_yields_success(self):
        raw = 'date=2019-05-10 time=11:37:47 logid="0000000013" type="traffic" subtype="forward" level="notice" srcip=10.1.100.11 srcport=58012 dstip=23.59.154.35 dstport=80 proto=6 action="accept" policyid=1'
        result = process(raw)
        assert result["normalized"]["status"] == "Success"

    def test_fortigate_block_yields_failure(self):
        raw = 'date=2019-05-13 time=11:45:03 logid="0211008192" type="utm" subtype="virus" level="warning" srcip=10.1.100.11 dstip=172.16.200.55 srcport=60446 dstport=80 proto=6 action="blocked"'
        result = process(raw)
        assert result["normalized"]["status"] == "Failure"

    def test_juniper_deny_yields_failure(self):
        raw = "May 14 10:00:00 srx1 RT_FLOW: RT_FLOW_SESSION_DENY: session denied 10.0.0.5/9999->10.0.0.1/22 0x0 ssh"
        result = process(raw)
        assert result["normalized"]["status"] == "Failure"


# ═══════════════════════════════════════════════════════════════════════════════
# 7. OCSF OBSERVABLES — IPs extracted from firewall logs
# ═══════════════════════════════════════════════════════════════════════════════

class TestObservables:
    def test_fortigate_ips_in_observables(self):
        raw = _load("sample_fortigate.log")
        result = process(raw)
        ip_obs = [o["value"] for o in result["normalized"]["observables"]
                  if o.get("type") == "IP Address"]
        assert "10.1.100.11" in ip_obs
        assert "23.59.154.35" in ip_obs

    def test_cisco_asa_ips_in_observables(self):
        raw = _load("sample_cisco_asa.log")
        result = process(raw)
        ip_obs = [o["value"] for o in result["normalized"]["observables"]
                  if o.get("type") == "IP Address"]
        assert "10.0.0.5" in ip_obs
        assert "192.168.1.1" in ip_obs


# ═══════════════════════════════════════════════════════════════════════════════
# 8. MULTIPLE CISCO ASA MESSAGE IDs
# ═══════════════════════════════════════════════════════════════════════════════

class TestCiscoASAMultiMsgID:
    @pytest.mark.parametrize("raw,expected_src,expected_dst", [
        (
            "%ASA-6-106001: Inbound TCP connection denied from 10.1.2.3/4321 to 192.168.0.1/80 flags SYN on interface outside",
            "10.1.2.3", "192.168.0.1",
        ),
        (
            "%ASA-4-106023: Deny tcp src outside:10.1.2.3/4321 dst inside:192.168.0.1/443 by access-group \"outside_in\"",
            "10.1.2.3", "192.168.0.1",
        ),
        (
            "%ASA-7-710002: TCP access permitted from 10.1.2.3/4321 to outside:192.168.0.1/443",
            "10.1.2.3", "192.168.0.1",
        ),
    ])
    def test_msgid_parsing(self, raw, expected_src, expected_dst):
        result = process(raw)
        norm = result["normalized"]
        assert norm["src_endpoint"]["ip"] == expected_src, f"src_ip mismatch: {norm['src_endpoint']}"
        assert norm["dst_endpoint"]["ip"] == expected_dst, f"dst_ip mismatch: {norm['dst_endpoint']}"


# ═══════════════════════════════════════════════════════════════════════════════
# 9. LOSSLESS PRESERVATION
# ═══════════════════════════════════════════════════════════════════════════════

class TestLosslessPreservation:
    def test_fortigate_vendor_block_preserved(self):
        raw = _load("sample_fortigate.log")
        result = process(raw)
        fw_block = result["normalized"].get("unmapped", {}).get("firewall", {})
        assert fw_block.get("format") == "fortigate"
        assert "vendor_data" in fw_block
        # logid should be in vendor data
        assert "logid" in fw_block.get("vendor_data", {})

    def test_cef_extensions_preserved(self):
        raw = "CEF:0|ArcSight|Logger|5.0.0.5355.2|sensor:115|Logger Internal Event|1|cat=/Monitor/Sensor/Fan5 cs2=Current Value cnt=1 dvc=10.0.0.1 cs3=Ok"
        result = process(raw)
        fw_block = result["normalized"].get("unmapped", {}).get("firewall", {})
        exts = fw_block.get("vendor_data", {}).get("extensions", {})
        assert exts.get("cs2") == "Current Value"
        assert exts.get("cat") == "/Monitor/Sensor/Fan5"

    def test_raw_data_preserved(self):
        raw = _load("sample_fortigate.log")
        result = process(raw)
        assert result["normalized"]["raw_data"] == raw

    def test_raw_sha256_present(self):
        raw = _load("sample_cef.log")
        result = process(raw)
        sha = result["normalized"]["metadata"]["raw_sha256"]
        assert sha is not None and len(sha) == 64


# ═══════════════════════════════════════════════════════════════════════════════
# 10. FORTIGATE REAL SAMPLE CORPUS (traffic, event, UTM, anomaly subtypes)
# ═══════════════════════════════════════════════════════════════════════════════

_FORTIGATE_REAL_SAMPLES = [
    # 1. Forward Traffic
    (
        'date=2019-05-10 time=11:37:47 logid="0000000013" type="traffic" subtype="forward" level="notice" vd="vdom1" eventtime=1557513467369913239 srcip=10.1.100.11 srcport=58012 srcintf="port12" dstip=23.59.154.35 dstport=80 dstintf="port11" proto=6 action="close" policyid=1 service="HTTP"',
        "10.1.100.11", "23.59.154.35", 58012, 80, "tcp",
    ),
    # 2. Local Traffic (session end server-rst)
    (
        'date=2019-05-10 time=11:50:48 logid="0001000014" type="traffic" subtype="local" level="notice" vd="vdom1" srcip=172.16.200.254 srcport=62024 dstip=172.16.200.2 dstport=443 sessionid=107478 proto=6 action="server-rst" service="HTTPS"',
        "172.16.200.254", "172.16.200.2", 62024, 443, "tcp",
    ),
    # 3. Event: System Admin Login
    (
        'date=2019-05-13 time=11:20:54 logid="0100032001" type="event" subtype="system" level="information" vd="vdom1" logdesc="Admin login successful" user="admin" srcip=172.16.200.254 dstip=172.16.200.2 action="login" status="success"',
        "172.16.200.254", "172.16.200.2", None, None, None,
    ),
    # 4. Event: Router OSPF (no IP fields)
    (
        'date=2019-05-13 time=14:12:26 logid="0103020301" type="event" subtype="router" level="warning" vd="root" logdesc="Routing log" msg="OSPF: RECV[Hello]: From 31.1.1.1: Invalid Area ID 0.0.0.0"',
        None, None, None, None, None,
    ),
    # 5. Event: VPN IPsec
    (
        'date=2019-05-13 time=14:21:42 logid="0101037127" type="event" subtype="vpn" level="notice" vd="root" logdesc="Progress IPsec phase 1" action="negotiate" remip=50.1.1.101 locip=50.1.1.100 remport=500 locport=500 vpntunnel="test"',
        None, None, None, None, None,
    ),
    # 6. UTM: Antivirus Blocked
    (
        'date=2019-05-13 time=11:45:03 logid="0211008192" type="utm" subtype="virus" eventtype="infected" level="warning" vd="vdom1" srcip=10.1.100.11 dstip=172.16.200.55 srcport=60446 dstport=80 proto=6 action="blocked" virus="EICAR_TEST_FILE"',
        "10.1.100.11", "172.16.200.55", 60446, 80, "tcp",
    ),
    # 7. UTM: Web Filter Blocked
    (
        'date=2019-05-13 time=16:29:45 logid="0316013056" type="utm" subtype="webfilter" level="warning" vd="vdom1" srcip=10.1.100.11 srcport=44258 dstip=185.244.31.158 dstport=80 proto=6 action="blocked" hostname="morrishittu.ddns.net" catdesc="Malicious Websites"',
        "10.1.100.11", "185.244.31.158", 44258, 80, "tcp",
    ),
    # 8. UTM: IPS Dropped
    (
        'date=2019-05-15 time=17:56:41 logid="0419016384" type="utm" subtype="ips" level="alert" vd="root" srcip=10.1.100.22 dstip=172.16.200.55 srcport=46810 dstport=80 action="dropped" proto=6 attack="Adobe.Flash.newfunction"',
        "10.1.100.22", "172.16.200.55", 46810, 80, "tcp",
    ),
    # 9. UTM: Anomaly icmp_flood
    (
        'date=2019-05-13 time=17:05:59 logid="0720018433" type="utm" subtype="anomaly" level="alert" vd="vdom1" srcip=10.1.100.11 dstip=172.16.200.55 proto=1 service="PING" action="clear_session" attack="icmp_flood"',
        "10.1.100.11", "172.16.200.55", None, None, "icmp",
    ),
    # 10. Event: HA Cluster state
    (
        'date=2019-05-10 time=09:53:21 logid="0108037892" type="event" subtype="ha" level="notice" vd="root" logdesc="Virtual cluster member state moved" ha_role="master" hostname="FW_QA4"',
        None, None, None, None, None,
    ),
]


class TestFortiGateRealCorpus:
    @pytest.mark.parametrize("raw,exp_src,exp_dst,exp_spt,exp_dpt,exp_proto", _FORTIGATE_REAL_SAMPLES)
    def test_fortigate_variants_parse_cleanly(self, raw, exp_src, exp_dst, exp_spt, exp_dpt, exp_proto):
        result = process(raw)
        assert result["parser_id"] == "FW-FORTIGATE-001"
        norm = result["normalized"]
        assert norm["class_uid"] == 4001
        assert norm["class_name"] == "Network Activity"
        assert norm["src_endpoint"]["ip"] == exp_src
        assert norm["dst_endpoint"]["ip"] == exp_dst
        assert norm["src_endpoint"]["port"] == exp_spt
        assert norm["dst_endpoint"]["port"] == exp_dpt
        if exp_proto:
            assert norm["connection_info"]["protocol_name"] == exp_proto


# ═══════════════════════════════════════════════════════════════════════════════
# 11. PIPELINE PRIORITY & ISOLATION
# ═══════════════════════════════════════════════════════════════════════════════

class TestPipelinePriorityAndIsolation:
    def test_syslog_wrapped_cef_routes_to_firewall(self):
        raw = "<134>May 14 09:00:00 border-gw CEF:0|Check Point|VPN-1|1.0|drop|Drop packet|6|src=10.0.0.1 dst=10.0.0.2 spt=1000 dpt=80 act=drop"
        result = process(raw)
        assert "FW-" in result["parser_id"]
        assert result["normalized"]["class_uid"] == 4001
        assert result["normalized"]["src_endpoint"]["ip"] == "10.0.0.1"

    def test_syslog_wrapped_cisco_routes_to_firewall(self):
        raw = "<166>May  4 09:00:01 asa-fw %ASA-6-106015: Deny TCP from 10.0.0.5/12345 to 192.168.1.1/80 flags RST on interface outside"
        result = process(raw)
        assert "CISCO" in result["parser_id"].upper()
        assert result["normalized"]["class_uid"] == 4001

    def test_syslog_wrapped_juniper_routes_to_firewall(self):
        raw = "May 14 09:33:21 srx1 RT_FLOW: RT_FLOW_SESSION_CREATE: session created 10.0.0.1/1234->192.168.1.1/80 0x0 junos-http"
        result = process(raw)
        assert result["parser_id"] == "FW-JUNIPER-SRX-001"
        assert result["normalized"]["class_uid"] == 4001

    def test_standard_linux_ssh_not_firewall(self):
        raw = "May  4 10:00:00 linux-srv sshd[1234]: Accepted publickey for root from 192.168.1.50 port 54321 ssh2"
        result = process(raw)
        assert result["parser_id"] != "FW-CEF-GENERIC"
        assert "FW-" not in result["parser_id"]
        assert "LINUX" in result["parser_id"]

    def test_standard_windows_evtx_not_firewall(self):
        raw = (
            "Log Name:      Security\n"
            "Source:        Microsoft-Windows-Security-Auditing\n"
            "Event ID:      4624\n"
            "Computer:      DC01.corp.local\n"
            "New Logon:\n"
            "  Account Name:  Administrator\n"
            "  Logon Type:    2\n"
        )
        result = process(raw)
        assert "WIN-" in result["parser_id"]
        assert "FW-" not in result["parser_id"]

    def test_android_logcat_not_firewall(self):
        raw = "08-10 09:20:19.692  1234  5678 I ActivityManager: Displayed com.android.settings/.Settings: +250ms"
        result = process(raw)
        assert "ANDROID-" in result["parser_id"]
        assert "FW-" not in result["parser_id"]

