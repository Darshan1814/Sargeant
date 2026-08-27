#!/usr/bin/env python3
"""
Ingest the synthetic Windows/macOS fixtures into a running ULPF backend.

Each fixture line is a JSON object {"expected_parser_id", "raw"} where `raw`
may be a MULTI-LINE event (evtx-style block). We POST each as a single
`raw_log` form value so multi-line events are treated as ONE event (the file
upload path would wrongly split them per newline).

After ingesting, prints the measured parser_id it actually routed to vs. the
expected one, so a misroute is visible immediately.

Usage: python3 scripts/ingest_synthetic.py [base_url]
"""
import json
import sys
import urllib.parse
import urllib.request
from pathlib import Path

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
FIX = Path(__file__).parent.parent / "backend" / "tests" / "fixtures" / "synthetic"


def ingest(raw: str) -> dict:
    data = urllib.parse.urlencode({"raw_log": raw}).encode()
    req = urllib.request.Request(f"{BASE}/api/ingest", data=data, method="POST")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode())


def run(name: str):
    path = FIX / name
    rows = [json.loads(l) for l in path.read_text().splitlines() if l.strip()]
    ok = miss = 0
    for r in rows:
        expected = r.get("expected_parser_id", r.get("os", "?"))
        try:
            res = ingest(r["raw"])
            got = res.get("parser_id")
            if "expected_parser_id" in r:
                if got == expected:
                    ok += 1
                else:
                    miss += 1
                    print(f"  MISROUTE  {name}: expected {expected} got {got} "
                          f"(path={res.get('path')})")
            else:
                ok += 1  # malformed: any graceful path is fine
        except Exception as exc:
            miss += 1
            print(f"  ERROR     {name}: {expected}: {exc}")
    print(f"  {name}: {ok} ok, {miss} problem(s), {len(rows)} total")
    return ok, miss


if __name__ == "__main__":
    total_ok = total_miss = 0
    for f in ("windows.jsonl", "macos.jsonl", "malformed.jsonl"):
        if (FIX / f).exists():
            o, m = run(f)
            total_ok += o
            total_miss += m
    print(f"\nDONE: {total_ok} ingested cleanly, {total_miss} problems")
    sys.exit(1 if total_miss else 0)
