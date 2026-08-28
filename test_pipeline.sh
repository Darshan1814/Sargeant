#!/bin/bash
# test_pipeline.sh — Generate real system logs and test the ULPF pipeline
# Run from the ulpf/ directory with: bash test_pipeline.sh

API="http://localhost:8000"
PASS=0
FAIL=0

check_api() {
  if ! curl -sf "$API/health" > /dev/null 2>&1; then
    echo "[ERROR] Backend not reachable at $API — is docker compose up running?"
    exit 1
  fi
  echo "[OK] Backend is up"
}

send_and_check() {
  local label="$1"
  local log_text="$2"
  local expected_parser="$3"

  echo ""
  echo "=== TEST: $label ==="
  response=$(curl -sf -X POST "$API/api/ingest" \
    -F "raw_log=$log_text" 2>&1)

  if [ $? -ne 0 ]; then
    echo "[FAIL] Ingest request failed"
    FAIL=$((FAIL+1))
    return
  fi

  parser_id=$(echo "$response" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('parser_id','?'))")
  confidence=$(echo "$response" | python3 -c "import sys,json; d=json.load(sys.stdin); print(round(d.get('confidence',0)*100,1))")
  path=$(echo "$response" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('path','?'))")
  class_uid=$(echo "$response" | python3 -c "import sys,json; d=json.load(sys.stdin); n=d.get('normalized',{}); print(n.get('class_uid','?'))")
  time=$(echo "$response" | python3 -c "import sys,json; d=json.load(sys.stdin); n=d.get('normalized',{}); print(n.get('time','?'))")
  severity=$(echo "$response" | python3 -c "import sys,json; d=json.load(sys.stdin); n=d.get('normalized',{}); print(n.get('severity','?'))")

  echo "  Parser:     $parser_id (expected: $expected_parser)"
  echo "  Confidence: $confidence%"
  echo "  Path:       $path"
  echo "  OCSF class: $class_uid"
  echo "  Time:       $time"
  echo "  Severity:   $severity"

  if [ "$parser_id" = "$expected_parser" ] || [ "$expected_parser" = "DRAIN3" -a "$path" = "drain3" ]; then
    echo "  [PASS]"
    PASS=$((PASS+1))
  else
    echo "  [FAIL] Expected $expected_parser, got $parser_id"
    FAIL=$((FAIL+1))
  fi
}

# ── 1. Generate real macOS logs ───────────────────────────────────────────────
echo ""
echo "=== GENERATING REAL macOS SYSTEM LOGS ==="
MAC_LOG=$(log show --last 10m --style syslog 2>/dev/null | grep -E "\w{3}\s+[0-9]+\s[0-9]{2}:[0-9]{2}:[0-9]{2}\s\S+\s\S+\[[0-9]+\]" | head -1)

if [ -z "$MAC_LOG" ]; then
  echo "[NOTE] Could not capture live macOS log — using fixture sample"
  MAC_LOG="$(cat backend/tests/fixtures/sample_macos_syslog.log | head -1)"
else
  echo "[OK] Captured live macOS log: ${MAC_LOG:0:80}..."
fi

check_api

# ── Run tests ─────────────────────────────────────────────────────────────────
send_and_check "macOS syslog (LIVE or fixture)" "$MAC_LOG" "MAC-ULOG-001"

MACOS_FULL="$(cat backend/tests/fixtures/sample_macos_syslog.log)"
send_and_check "macOS syslog (full fixture)" "$MACOS_FULL" "MAC-ULOG-001"

WIN_SEC="$(cat backend/tests/fixtures/sample_windows_security.evtx.txt)"
send_and_check "Windows Security Event Log" "$WIN_SEC" "WIN-EVTLOG-001"

WIN_SYS="$(cat backend/tests/fixtures/sample_windows_system.evtx.txt)"
send_and_check "Windows System Event Log" "$WIN_SYS" "WIN-EVTLOG-001"

UNKNOWN="$(cat backend/tests/fixtures/sample_unknown_format.log)"
send_and_check "Unknown/garbled format (Drain3 fallback)" "$UNKNOWN" "DRAIN3"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "=============================="
echo "  Results: $PASS passed, $FAIL failed"
echo "=============================="
echo ""
echo "Stats: curl -s $API/api/stats | python3 -m json.tool"
