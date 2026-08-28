#!/usr/bin/env python3
"""
Ad-hoc verification harness (NOT a pytest): feed representative Windows and
Android logs through the REAL pipeline.process() and inspect the OCSF output.

Run:
  PARSERS_DIR=<repo>/parsers/registry python3 testdata/verify_win_android.py
"""
import json
import os
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
REPO = BACKEND.parent
os.environ.setdefault("PARSERS_DIR", str(REPO / "parsers" / "registry"))
sys.path.insert(0, str(BACKEND))

from pipeline import process  # noqa: E402

# ── representative samples ────────────────────────────────────────────────────
WINDOWS = {
    "evtx-text 4625 (failed logon, multiline)": "\n".join([
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
    "evtx-text 4624 (success logon)": "\n".join([
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
    "winkv 4688 (from sample_win.log)": (
        "2026-08-27 08:17:12 INFO [Windows Event Log] "
        "Provider=Microsoft-Windows-Security-Auditing EventID=4688 "
        "Level=Information Computer=WIN-DEV01 User=darshan "
        "NewProcessName=C:\\Windows\\System32\\cmd.exe "
        "ParentProcessName=C:\\Windows\\explorer.exe "
        "CommandLine=powershell.exe -ExecutionPolicy Bypass -File C:\\x.ps1 "
        "Message=A new process has been created."
    ),
    "winkv Service Control Manager 7031": (
        "Provider=Service Control Manager EventID=7031 Level=Error "
        "Computer=WIN-APP01 User=SYSTEM ServiceName=LegacyAgent "
        "Message=The LegacyAgent service terminated unexpectedly."
    ),
    "event XML (4624)": (
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
    "winkv Sysmon EventID=1 (process create)": (
        "Provider=Microsoft-Windows-Sysmon EventID=1 Channel=Microsoft-Windows-Sysmon/Operational "
        "Computer=WKS9 Image=C:\\Windows\\System32\\cmd.exe "
        "CommandLine=cmd /c whoami ParentImage=C:\\Windows\\explorer.exe "
        "User=CORP\\alice ProcessId=4321"
    ),
    "IIS W3C access log": "\n".join([
        "#Software: Microsoft Internet Information Services 10.0",
        "#Fields: date time s-ip cs-method cs-uri-stem s-port c-ip sc-status time-taken",
        "2026-08-27 12:00:00 10.0.0.5 GET /index.html 80 203.0.113.9 200 12",
    ]),
    "Windows Firewall pfirewall.log": "\n".join([
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

CANON = {  # canonical OCSF envelope keys that must ALWAYS be present
    "class_uid", "class_name", "category_uid", "time", "severity_id", "severity",
    "message", "device", "actor", "src_endpoint", "dst_endpoint", "metadata",
    "observables", "unmapped", "raw_data", "confidence", "parse_status",
}


def summarize(name, raw, native_key):
    r = process(raw)
    n = r["normalized"]
    missing = sorted(CANON - set(n.keys()))
    proc = n["actor"]["process"]
    user = n["actor"]["user"]
    src = n["src_endpoint"]
    checks = {
        "path==ngre": r["path"] == "ngre",
        "canonical-complete": not missing,
        f"native '{native_key}' block": native_key in n.get("unmapped", {}),
        "raw preserved": (n["raw_data"] or "").strip() == raw.strip(),
        "time set": bool(n["time"]),
    }
    ok = all(checks.values())
    print(f"\n{'='*88}\n{name}\n{'-'*88}")
    print(f"  parser_id      : {r['parser_id']}")
    print(f"  path/conf      : {r['path']}  conf={r['confidence']}")
    print(f"  OCSF class     : {n['class_uid']} {n['class_name']}  "
          f"(cat {n['category_uid']} {n['category_name']})")
    print(f"  activity       : {n['activity_id']} {n['activity_name']}")
    print(f"  severity/status: {n['severity_id']} {n['severity']} / {n['status']}")
    print(f"  time           : {n['time']}  (orig={n['metadata']['original_time']})")
    print(f"  message        : {str(n['message'])[:70]}")
    print(f"  actor.user     : name={user['name']} domain={user['domain']}")
    print(f"  actor.process  : name={proc['name']} pid={proc['pid']}")
    if src["ip"] or n["dst_endpoint"]["ip"]:
        print(f"  endpoints      : src={src['ip']}:{src['port']} -> "
              f"dst={n['dst_endpoint']['ip']}:{n['dst_endpoint']['port']}")
    print(f"  observables    : {n['observables']}")
    print(f"  parse_status   : {n['parse_status']}  ocsf_mapping={n['ocsf_mapping_status']}"
          f"  needs_review={n['needs_review']}")
    if missing:
        print(f"  !! MISSING     : {missing}")
    print(f"  CHECKS         : {'PASS' if ok else 'FAIL'}  {checks}")
    return ok, r


def main():
    print("#" * 88)
    print("# WINDOWS FAMILY")
    print("#" * 88)
    win_ok = True
    first_win = None
    for name, raw in WINDOWS.items():
        ok, r = summarize(name, raw, "windows")
        first_win = first_win or r
        win_ok = win_ok and ok

    print("\n\n" + "#" * 88)
    print("# ANDROID FAMILY")
    print("#" * 88)
    and_ok = True
    first_and = None
    for name, raw in ANDROID.items():
        ok, r = summarize(name, raw, "android")
        first_and = first_and or r
        and_ok = and_ok and ok

    # Full JSON dump of one representative from each family so the reviewer can
    # see the complete OCSF envelope shape end-to-end.
    print("\n\n" + "#" * 88)
    print("# FULL OCSF ENVELOPE — WINDOWS (evtx-text 4625)")
    print("#" * 88)
    print(json.dumps(first_win["normalized"], indent=2, default=str))

    print("\n" + "#" * 88)
    print("# FULL OCSF ENVELOPE — ANDROID (threadtime)")
    print("#" * 88)
    print(json.dumps(first_and["normalized"], indent=2, default=str))

    print("\n" + "=" * 88)
    print(f"WINDOWS: {'ALL PASS' if win_ok else 'FAILURES'}   "
          f"ANDROID: {'ALL PASS' if and_ok else 'FAILURES'}")
    print("=" * 88)
    return 0 if (win_ok and and_ok) else 1


if __name__ == "__main__":
    sys.exit(main())
