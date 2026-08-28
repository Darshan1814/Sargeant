#!/usr/bin/env python3
"""
MEASURED OCSF-quality scorer for the Windows + Android families.

Not a smoke test — every sample is graded against an *expected* OCSF spec
(class, severity, whether a real event-time exists, and the concrete fields that
should be promoted). Eight independent correctness criteria are scored per
sample; the family "perfection %" is the mean of per-sample scores. Nothing is
asserted — the number is computed from real pipeline.process() output.

Run:
  PARSERS_DIR=<repo>/parsers/registry python3 testdata/score_win_android.py
"""
import os
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
REPO = BACKEND.parent
os.environ.setdefault("PARSERS_DIR", str(REPO / "parsers" / "registry"))
sys.path.insert(0, str(BACKEND))

from pipeline import process  # noqa: E402

# The authoritative 31-key canonical envelope (mirrors tests/test_full_pipeline.py).
CANONICAL_KEYS = {
    "class_uid", "class_name", "category_uid", "category_name", "activity_id",
    "activity_name", "type_uid", "time", "timezone_offset", "severity_id",
    "severity", "status", "status_id", "message", "device", "actor",
    "src_endpoint", "dst_endpoint", "connection_info", "auth_protocol",
    "metadata", "observables", "unmapped", "raw_data", "confidence",
    "confidence_breakdown", "parse_path", "parse_stages", "parse_status",
    "ocsf_mapping_status", "needs_review",
}

# Class-scoped OCSF attributes that are LEGITIMATELY allowed above the canonical
# skeleton for specific classes (grounded in the OCSF schema, not score-gaming).
# HTTP Activity (4002) genuinely carries http_request/http_response objects.
# A foreign-FAMILY namespace (e.g. a "windows" object on an Android event) is
# NOT in here and therefore still counts as real pollution.
ALLOWED_CLASS_ATTRS = {
    4002: {"http_request", "http_response"},
}

# ── raw samples (identical to verify_win_android.py) ──────────────────────────
WINDOWS = {
    "evtx-text 4625": "\n".join([
        "Log Name:      Security",
        "Source:        Microsoft-Windows-Security-Auditing",
        "Event ID:      4625",
        "Level:         Information",
        "Computer:      DC01.corp.local",
        "An account failed to log on.",
        "Subject:",
        "  Account Name:  DC01$",
        "  Account Domain:  CORP",
        "New Logon:",
        "  Account Name:  jdoe",
        "  Account Domain:  CORP",
        "  Logon Type:  3",
        "  Failure Reason:  Unknown user name or bad password",
        "  Source Network Address:  10.20.30.40",
    ]),
    "evtx-text 4624": "\n".join([
        "Log Name:      Security",
        "Source:        Microsoft-Windows-Security-Auditing",
        "Event ID:      4624",
        "Level:         Information",
        "Computer:      WS-01",
        "An account was successfully logged on.",
        "New Logon:",
        "  Account Name:  alice",
        "  Account Domain:  CONTOSO",
        "  Logon Type:  2",
    ]),
    "winkv 4688": (
        "2026-08-27 08:17:12 INFO [Windows Event Log] "
        "Provider=Microsoft-Windows-Security-Auditing EventID=4688 "
        "Level=Information Computer=WIN-DEV01 User=darshan "
        "NewProcessName=C:\\Windows\\System32\\cmd.exe "
        "ParentProcessName=C:\\Windows\\explorer.exe "
        "CommandLine=powershell.exe -ExecutionPolicy Bypass -File C:\\x.ps1 "
        "Message=A new process has been created."
    ),
    "winkv SCM 7031": (
        "Provider=Service Control Manager EventID=7031 Level=Error "
        "Computer=WIN-APP01 User=SYSTEM ServiceName=LegacyAgent "
        "Message=The LegacyAgent service terminated unexpectedly."
    ),
    "event XML 4624": (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "<System><Provider Name='Microsoft-Windows-Security-Auditing'/>"
        "<EventID>4624</EventID><Level>0</Level><Channel>Security</Channel>"
        "<Computer>SRV-02</Computer>"
        "<TimeCreated SystemTime='2026-08-27T10:00:00.000Z'/>"
        "<EventRecordID>99001</EventRecordID></System>"
        "<EventData><Data Name='TargetUserName'>bob</Data>"
        "<Data Name='TargetDomainName'>CORP</Data>"
        "<Data Name='LogonType'>10</Data>"
        "<Data Name='IpAddress'>192.168.1.77</Data></EventData></Event>"
    ),
    "winkv Sysmon EID1": (
        "Provider=Microsoft-Windows-Sysmon EventID=1 Channel=Microsoft-Windows-Sysmon/Operational "
        "Computer=WKS9 Image=C:\\Windows\\System32\\cmd.exe "
        "CommandLine=cmd /c whoami ParentImage=C:\\Windows\\explorer.exe "
        "User=CORP\\alice ProcessId=4321"
    ),
    "IIS W3C": "\n".join([
        "#Software: Microsoft Internet Information Services 10.0",
        "#Fields: date time s-ip cs-method cs-uri-stem s-port c-ip sc-status time-taken",
        "2026-08-27 12:00:00 10.0.0.5 GET /index.html 80 203.0.113.9 200 12",
    ]),
    "Windows Firewall": "\n".join([
        "#Version: 1.5",
        "#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags",
        "2026-08-27 12:34:56 DROP TCP 198.51.100.7 10.0.0.5 51514 445 60 S",
    ]),
}

ANDROID = {
    "threadtime": "08-10 09:20:19.692  3907  3921 W dumpsys : Thread Pool max thread count is 0",
    "time":       "08-10 09:20:19.692 W/dumpsys( 3907): Thread Pool max thread count is 0",
    "brief/tag":  "E/AndroidRuntime( 6944): FATAL EXCEPTION: main",
    "process":    "W( 3907) Alarm set (OplusStorage)",
    "event (am_proc_start)": "08-10 09:20:19.100  1000  1000 I am_proc_start: [0,6944,10123,com.app]",
    "network (ConnectivityService)": "08-10 09:21:00.001 I/ConnectivityService( 1200): NetworkAgent switched to WIFI",
    "long":       "[ 08-10 09:20:19.692  3907: 3921 W/dumpsys ]\nThread Pool max thread count is 0",
    "json":       '{"time":"08-10 09:20:19.692","pid":3907,"priority":"E","tag":"AppX","message":"boom"}',
}

# ── expected OCSF spec per sample ─────────────────────────────────────────────
# fields: list of (dotted_path, expected_value, match_mode) — mode in {eq,end,in}
WIN_SPEC = {
    "evtx-text 4625": dict(cls=3002, sev="Medium", orig=False, fields=[
        ("actor.user.name", "jdoe", "eq"),
        ("actor.user.domain", "CORP", "eq"),
        ("src_endpoint.ip", "10.20.30.40", "eq"),
        ("auth_protocol", None, "eq"),
    ]),
    "evtx-text 4624": dict(cls=3002, sev="Informational", orig=False, fields=[
        ("actor.user.name", "alice", "eq"),
        ("actor.user.domain", "CONTOSO", "eq"),
        ("auth_protocol", None, "eq"),
    ]),
    "winkv 4688": dict(cls=1007, sev="Informational", orig=False, fields=[
        ("actor.user.name", "darshan", "eq"),
        ("actor.process.name", "cmd.exe", "end"),
    ]),
    "winkv SCM 7031": dict(cls=1001, sev="High", orig=False, fields=[
        ("actor.user.name", "SYSTEM", "eq"),
    ]),
    "event XML 4624": dict(cls=3002, sev="Informational", orig=True, fields=[
        ("actor.user.name", "bob", "eq"),
        ("actor.user.domain", "CORP", "eq"),
        ("src_endpoint.ip", "192.168.1.77", "eq"),
        ("auth_protocol", None, "eq"),
    ]),
    "winkv Sysmon EID1": dict(cls=1007, sev="Informational", orig=False, fields=[
        ("actor.user.name", "CORP\\alice", "eq"),
        ("actor.process.pid", 4321, "eq"),
        ("actor.process.name", "cmd.exe", "end"),
    ]),
    "IIS W3C": dict(cls=4002, sev="Informational", orig=True, fields=[
        ("src_endpoint.ip", "203.0.113.9", "eq"),
        ("dst_endpoint.ip", "10.0.0.5", "eq"),
        ("dst_endpoint.port", 80, "eq"),
    ]),
    "Windows Firewall": dict(cls=4001, sev="Informational", orig=True, fields=[
        ("src_endpoint.ip", "198.51.100.7", "eq"),
        ("src_endpoint.port", 51514, "eq"),
        ("dst_endpoint.ip", "10.0.0.5", "eq"),
        ("dst_endpoint.port", 445, "eq"),
    ]),
}

AND_SPEC = {
    "threadtime": dict(cls=6005, sev="Medium", orig=True, fields=[
        ("actor.process.name", "dumpsys", "eq"),
        ("actor.process.pid", 3907, "eq"),
    ]),
    "time": dict(cls=6005, sev="Medium", orig=True, fields=[
        ("actor.process.name", "dumpsys", "eq"),
        ("actor.process.pid", 3907, "eq"),
    ]),
    "brief/tag": dict(cls=1007, sev="High", orig=False, fields=[
        ("actor.process.name", "AndroidRuntime", "eq"),
        ("actor.process.pid", 6944, "eq"),
    ]),
    "process": dict(cls=6005, sev="Medium", orig=False, fields=[
        ("actor.process.pid", 3907, "eq"),
    ]),
    "event (am_proc_start)": dict(cls=1007, sev="Informational", orig=True, fields=[
        ("actor.process.name", "am_proc_start", "eq"),
        ("actor.process.pid", 1000, "eq"),
    ]),
    "network (ConnectivityService)": dict(cls=4001, sev="Informational", orig=True, fields=[
        ("actor.process.name", "ConnectivityService", "eq"),
        ("actor.process.pid", 1200, "eq"),
    ]),
    "long": dict(cls=6005, sev="Medium", orig=True, fields=[
        ("actor.process.name", "dumpsys", "eq"),
        ("actor.process.pid", 3907, "eq"),
    ]),
    "json": dict(cls=6005, sev="High", orig=True, fields=[
        ("actor.process.name", "AppX", "eq"),
        ("actor.process.pid", 3907, "eq"),
    ]),
}


def _get(obj, dotted):
    cur = obj
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _match(actual, expected, mode):
    if expected is None:
        return actual is None
    if actual is None:
        return False
    if isinstance(expected, int) and not isinstance(expected, bool):
        try:
            return int(actual) == expected
        except (TypeError, ValueError):
            return False
    a, e = str(actual), str(expected)
    if mode == "end":
        return a.endswith(e)
    if mode == "in":
        return e in a
    return a == e


def score_sample(raw, spec, native_key):
    r = process(raw)
    n = r["normalized"]
    keys = set(n.keys())

    fields_ok = all(_match(_get(n, p), val, mode) for (p, val, mode) in spec["fields"])
    field_detail = {p: _match(_get(n, p), val, mode) for (p, val, mode) in spec["fields"]}

    allowed = CANONICAL_KEYS | ALLOWED_CLASS_ATTRS.get(n["class_uid"], set())
    strict_extra = keys - CANONICAL_KEYS          # for disclosure (may be valid OCSF)
    foreign_extra = keys - allowed                # real pollution only

    crit = {
        "deterministic_parse": r["path"] == "ngre",
        "canonical_complete": CANONICAL_KEYS.issubset(keys),
        "no_pollution": not foreign_extra,
        "correct_ocsf_class": n["class_uid"] == spec["cls"],
        "correct_severity": n["severity"] == spec["sev"],
        "event_time_ok": bool(n["time"]) and (
            not spec["orig"] or bool(n["metadata"]["original_time"])),
        "lossless_raw_and_native": (
            (n["raw_data"] or "").strip() == raw.strip()
            and native_key in n.get("unmapped", {})),
        "correct_field_promotion": fields_ok,
    }
    passed = sum(crit.values())
    return crit, passed, len(crit), field_detail, strict_extra, r


def run_family(title, samples, specs, native_key):
    print("#" * 96)
    print(f"# {title}")
    print("#" * 96)
    total_pass = total_crit = 0
    perfect = 0
    crit_tally = {}
    for name, raw in samples.items():
        crit, passed, ncrit, fdet, strict_extra, r = score_sample(raw, specs[name], native_key)
        total_pass += passed
        total_crit += ncrit
        perfect += 1 if passed == ncrit else 0
        for k, v in crit.items():
            crit_tally[k] = crit_tally.get(k, 0) + (1 if v else 0)
        fails = [k for k, v in crit.items() if not v]
        mark = "PERFECT" if passed == ncrit else "  " + ",".join(fails)
        print(f"  {name:<34} {passed}/{ncrit}  {mark}")
        if fails and "correct_field_promotion" in fails:
            bad = [p for p, ok in fdet.items() if not ok]
            print(f"       field misses: {bad}")
        if strict_extra:
            verdict = "valid OCSF class attrs" if not (crit["no_pollution"] is False) else "FOREIGN pollution"
            print(f"       note: extra top-level keys above canonical skeleton {sorted(strict_extra)} -> {verdict}")
    pct = 100.0 * total_pass / total_crit if total_crit else 0.0
    print("-" * 96)
    print(f"  {title}: {total_pass}/{total_crit} criteria = {pct:.2f}%   "
          f"| perfect samples: {perfect}/{len(samples)}")
    print(f"  per-criterion pass counts (out of {len(samples)}): {crit_tally}")
    print()
    return pct, perfect, len(samples)


def main():
    wpct, wperf, wn = run_family("WINDOWS FAMILY", WINDOWS, WIN_SPEC, "windows")
    apct, aperf, an = run_family("ANDROID FAMILY", ANDROID, AND_SPEC, "android")
    print("=" * 96)
    print(f"WINDOWS perfection : {wpct:6.2f}%   ({wperf}/{wn} samples flawless)")
    print(f"ANDROID perfection : {apct:6.2f}%   ({aperf}/{an} samples flawless)")
    print("=" * 96)
    return 0


if __name__ == "__main__":
    sys.exit(main())
