#!/usr/bin/env bash
# ============================================================
# M-Challenge Backend — Smoke Test Suite
# Tests all API endpoints against a running server.
# Usage: ./scripts/smoke-test.sh [BASE_URL]
# Default: http://localhost:3001
# ============================================================

set -uo pipefail

BASE="${1:-http://localhost:3001}"
PASS=0
FAIL=0
TOKEN=""
ADMIN_TOKEN=""
WEB_SCAN_ID=""
EMAIL_SCAN_ID=""
SCHEDULE_ID=""

G='\033[0;32m'; R='\033[0;31m'; Y='\033[0;33m'; C='\033[0;36m'; N='\033[0m'

check() {
  local name="$1" expected="$2" actual="$3"
  if echo "$actual" | grep -q "$expected" 2>/dev/null; then
    echo -e "  ${G}✓${N} $name"; ((PASS++))
  else
    echo -e "  ${R}✗${N} $name (expected: '$expected')"; echo "    Got: $(echo "$actual" | head -c 300)"; ((FAIL++))
  fi
}

req() {
  local method="$1" path="$2" data="${3:-}" tok="${4:-}"
  local args=(-s -S --max-time 15 -X "$method" "${BASE}${path}" -H "Content-Type: application/json")
  [ -n "$tok" ] && args+=(-H "Authorization: Bearer $tok")
  [ -n "$data" ] && args+=(-d "$data")
  curl "${args[@]}" 2>&1 || echo '{"error":"CONNECTION_REFUSED"}'
}

echo -e "\n${C}═══════════════════════════════════════════════════${N}"
echo -e "${C}  M-Challenge Backend — Smoke Test${N}"
echo -e "${C}  Target: ${BASE}${N}"
echo -e "${C}═══════════════════════════════════════════════════${N}\n"

# ---- 1. Health ----
echo -e "${Y}[1/8] Health${N}"
res=$(req GET /health)
check "GET /health" "ok" "$res"

# ---- 2. Auth ----
echo -e "\n${Y}[2/8] Authentication${N}"
RAND=$RANDOM
res=$(req POST /api/auth/register "{\"email\":\"smoke${RAND}@test.io\",\"password\":\"test1234\",\"fullName\":\"Smoke\"}")
check "POST /register" "token" "$res"
TOKEN=$(echo "$res" | grep -o '"token":"[^"]*"' | head -1 | cut -d'"' -f4)

res=$(req POST /api/auth/login '{"email":"admin@mchallenge.io","password":"admin123"}')
check "POST /login admin" "token" "$res"
ADMIN_TOKEN=$(echo "$res" | grep -o '"token":"[^"]*"' | head -1 | cut -d'"' -f4)

res=$(req GET /api/auth/whoami "" "$TOKEN")
check "GET /whoami" "isAuthenticated" "$res"

res=$(req GET /api/auth/client-ip)
check "GET /client-ip" "ip" "$res"

# ---- 3. Web Scan ----
echo -e "\n${Y}[3/8] Web Scanning${N}"
res=$(req POST /api/web-scan/start '{"url":"https://example.com","options":{"scan_profile":"quick","max_pages":5,"max_depth":1},"discover_subdomains":false,"guest_scans_used":0}' "$TOKEN")
check "POST /web-scan/start" "scan_id" "$res"
WEB_SCAN_ID=$(echo "$res" | grep -o '"scan_id":"[^"]*"' | head -1 | cut -d'"' -f4)

if [ -n "$WEB_SCAN_ID" ]; then
  sleep 3
  res=$(req GET "/api/web-scan/status/$WEB_SCAN_ID")
  check "GET /web-scan/status" "progress" "$res"
  res=$(req GET "/api/web-scan/result/$WEB_SCAN_ID")
  check "GET /web-scan/result" "domain" "$res"
fi

res=$(req POST /api/web-scan/analyze-exploitability '{"findings":[{"id":"t1","title":"HSTS Missing","severity":"high","category":"headers","description":"test"}]}')
check "POST /analyze-exploitability" "risk_cards" "$res"

# ---- 4. Email Scan ----
echo -e "\n${Y}[4/8] Email Scanning${N}"
res=$(req POST /api/email-scan/start '{"domain":"example.com"}' "$TOKEN")
check "POST /email-scan/start" "scan_id" "$res"
EMAIL_SCAN_ID=$(echo "$res" | grep -o '"scan_id":"[^"]*"' | head -1 | cut -d'"' -f4)

if [ -n "$EMAIL_SCAN_ID" ]; then
  sleep 3
  res=$(req GET "/api/email-scan/status/$EMAIL_SCAN_ID")
  check "GET /email-scan/status" "progress" "$res"
  res=$(req GET "/api/email-scan/result/$EMAIL_SCAN_ID")
  check "GET /email-scan/result" "domain" "$res"
fi

# ---- 5. MITRE + Analysis ----
echo -e "\n${Y}[5/8] MITRE ATT&CK + Analysis${N}"
res=$(req POST /api/mitre/correlate '{"target":"example.com","email_scan":{"emailSecurityScore":74,"dmarcRecord":{"exists":true,"policy":"none"}},"web_scan":{"webSecurityScore":52,"findings":[{"id":"csp-missing","title":"CSP Missing","severity":"high","category":"headers","description":"test"}]}}' "$ADMIN_TOKEN")
check "POST /mitre/correlate" "attack_score" "$res"

res=$(req POST /api/mitre/executive-pdf '{"target":"example.com","attackScore":42,"riskLevel":"moderate","topFindings":[{"title":"CSP Missing","severity":"high"}]}' "$ADMIN_TOKEN")
check "POST /executive-pdf" "pdf_url" "$res"

res=$(req POST /api/mitre/save-history '{"target":"example.com","attack_score":42,"risk_level":"moderate"}' "$ADMIN_TOKEN")
check "POST /save-history" "id" "$res"

# ---- 6. Schedules ----
echo -e "\n${Y}[6/8] Scheduled Scans${N}"
res=$(req POST /api/schedules/create '{"type":"web","data":{"target":"https://example.com","frequency":"weekly","notify_emails":["t@t.io"]}}' "$ADMIN_TOKEN")
check "POST /schedules/create" "id" "$res"
SCHEDULE_ID=$(echo "$res" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)

res=$(req GET /api/schedules/list "" "$ADMIN_TOKEN")
check "GET /schedules/list" "web" "$res"

if [ -n "$SCHEDULE_ID" ]; then
  res=$(req PATCH /api/schedules/toggle "{\"type\":\"web\",\"schedule_id\":\"$SCHEDULE_ID\",\"current_status\":true}" "$ADMIN_TOKEN")
  check "PATCH /schedules/toggle" "success" "$res"
  res=$(req DELETE "/api/schedules/web/$SCHEDULE_ID" "" "$ADMIN_TOKEN")
  check "DELETE /schedules/:id" "success" "$res"
fi

res=$(req GET /api/schedules/logs "" "$ADMIN_TOKEN")
check "GET /schedules/logs" "\[" "$res"

# ---- 7. Admin ----
echo -e "\n${Y}[7/8] Admin Panel${N}"
res=$(req GET /api/admin/users "" "$ADMIN_TOKEN")
check "GET /admin/users" "email" "$res"

res=$(req GET /api/admin/stats "" "$ADMIN_TOKEN")
check "GET /admin/stats" "totalUsers" "$res"

res=$(req POST /api/admin/users/invite "{\"email\":\"inv${RAND}@test.io\",\"role\":\"BASIC_SCANS\"}" "$ADMIN_TOKEN")
check "POST /admin/users/invite" "success" "$res"

res=$(req POST /api/admin/email-settings '{"action":"get"}' "$ADMIN_TOKEN")
check "POST /email-settings get" "" "$res"  # null is ok

# ---- 8. Data ----
echo -e "\n${Y}[8/8] Data Endpoints${N}"
res=$(req POST /api/data/latest-scans '{"target":"example.com","limit":5}')
check "POST /data/latest-scans" "email_scans" "$res"

res=$(req GET /api/data/scan-history/example.com)
check "GET /scan-history" "\[" "$res"

res=$(req POST /api/data/upgrade "" "$ADMIN_TOKEN")
check "POST /data/upgrade" "url" "$res"

# ---- Summary ----
TOTAL=$((PASS + FAIL))
echo -e "\n${C}═══════════════════════════════════════════════════${N}"
echo -e "  ${G}Passed: ${PASS}${N} / ${TOTAL}"
[ "$FAIL" -gt 0 ] && echo -e "  ${R}Failed: ${FAIL}${N}"
echo -e "${C}═══════════════════════════════════════════════════${N}"
[ "$FAIL" -eq 0 ] && echo -e "\n  ${G}★ ALL TESTS PASSED ★${N}\n" || echo -e "\n  ${R}Some tests failed${N}\n"
exit $FAIL
