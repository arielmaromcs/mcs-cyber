# M-Challenge Backend — Operational Runbook

## STATUS: Ready to Run

---

## 1. RUNBOOK — Exact Commands

### Option A: Docker Compose (recommended)
```bash
# 1. Clone/extract the project
cd m-challenge-backend

# 2. Create .env (copy example + edit as needed)
cp .env.example .env

# 3. Start everything (Postgres + Redis + Backend)
docker compose up --build -d

# 4. Wait ~30 seconds for DB migration + server start
docker compose logs -f backend

# 5. Seed demo data (run once)
docker compose exec backend npx tsx prisma/seed.ts
# If tsx not available in container, seed from host:
# DATABASE_URL="postgresql://mchallenge:mchallenge@localhost:5432/mchallenge" npx tsx prisma/seed.ts

# 6. Verify health
curl http://localhost:3001/health
# Expected: {"status":"ok","timestamp":"...","version":"1.0.0"}
```

### Option B: Local Development (without Docker)
```bash
# Prerequisites: Node 20+, PostgreSQL running, Redis running (optional)

# 1. Install
npm install

# 2. Configure
cp .env.example .env
# Edit DATABASE_URL to point to your Postgres instance

# 3. Push schema + generate client
npx prisma db push
npx prisma generate

# 4. Seed demo data
npx tsx prisma/seed.ts

# 5. Run dev server
npm run dev
```

### Useful Commands
```bash
# View logs
docker compose logs -f backend

# Stop everything
docker compose down

# Reset database (destructive!)
docker compose down -v
docker compose up --build -d

# Open Prisma Studio (GUI database viewer)
npx prisma studio

# Run smoke test
bash scripts/smoke-test.sh http://localhost:3001
```

---

## 2. URLs & PORTS

| Service    | URL                          | Purpose                     |
|------------|------------------------------|-----------------------------|
| Backend    | http://localhost:3001        | REST API                    |
| Health     | http://localhost:3001/health | Health check                |
| PostgreSQL | localhost:5432               | Database (mchallenge/mchallenge) |
| Redis      | localhost:6379               | Job queue (optional)        |

---

## 3. ENV VARS — Key Configuration

| Variable | Default | Required | Purpose |
|----------|---------|----------|---------|
| DATABASE_URL | postgresql://mchallenge:mchallenge@localhost:5432/mchallenge | Yes | PostgreSQL connection |
| JWT_SECRET | dev-secret-change-me | Yes (change in prod) | JWT signing key |
| PORT | 3001 | No | Server port |
| LLM_PROVIDER | local | No | MITRE engine: local/openai/anthropic |
| LLM_API_KEY | (empty) | No | API key for OpenAI/Anthropic |
| NMAP_API_KEY | (empty) | No | External NMAP service key |
| SHODAN_API_KEY | (empty) | No | Shodan port data |
| ABUSEIPDB_API_KEY | (empty) | No | IP reputation |
| EMAIL_PROVIDER | smtp | No | Email: smtp/microsoft_graph |
| SMTP_HOST | (empty) | No | SMTP server |

**All external APIs are optional.** Each service gracefully falls back:
- LLM → deterministic local analysis (no API call)
- NMAP → simulated port results
- Shodan/AbuseIPDB → `{ available: false }` stub
- Email → logs warning, returns false

---

## 4. VERIFICATION CHECKLIST

### Demo Accounts (after seeding)
| Email | Password | Role |
|-------|----------|------|
| admin@mchallenge.io | admin123 | ADMIN |
| analyst@mchallenge.io | analyst123 | FULL_SCANS |
| user@mchallenge.io | user123 | BASIC_SCANS |

### 4.1 Auth
```bash
# Register
curl -X POST http://localhost:3001/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.io","password":"test123456","fullName":"Test User"}'
# → { "token": "eyJ...", "user": { "id": "...", "email": "test@test.io", "role": "BASIC_SCANS" } }

# Login
curl -X POST http://localhost:3001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@mchallenge.io","password":"admin123"}'
# → { "token": "eyJ...", "user": { "role": "ADMIN" } }
# Save the token: TOKEN=eyJ...

# Whoami
curl http://localhost:3001/api/auth/whoami \
  -H "Authorization: Bearer $TOKEN"
# → { "user": {...}, "isAuthenticated": true }

# Client IP
curl http://localhost:3001/api/auth/client-ip
# → { "ip": "127.0.0.1" }
```

### 4.2 Web Scan (10-stage engine)
```bash
# Start scan
curl -X POST http://localhost:3001/api/web-scan/start \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"url":"https://example.com","options":{"scan_profile":"quick","max_pages":5,"max_depth":2},"discover_subdomains":false}'
# → { "scan_id": "uuid-here", "status": "started" }
# Save: SCAN_ID=uuid-here

# Poll status (every 1.5s until status=COMPLETED)
curl http://localhost:3001/api/web-scan/status/$SCAN_ID
# → { "status": "RUNNING", "progress": 45, "stage": "HEADERS", "pagesScanned": 2 }

# Fetch full result (after completion)
curl http://localhost:3001/api/web-scan/result/$SCAN_ID
# KEY FIELDS to verify:
#   webSecurityScore: number (0-100)
#   dnsSecurityScore: number (0-100)
#   riskScore: number (composite)
#   findings: array of { id, title, severity, category, description }
#   findingsCount: { critical, high, medium, low, info }
#   dnsAnalysis: { dns_score, records, dnssec }
#   exposureFindings: array of { path, status_code, severity }
#   technologies: { server, framework, cdn, waf, libraries }
#   scoreBreakdown: { main_domain_score, penalty_breakdown, score_cap }

# Exploitability analysis
curl -X POST http://localhost:3001/api/web-scan/analyze-exploitability \
  -H "Content-Type: application/json" \
  -d '{"findings":[{"id":"hsts-missing","title":"HSTS Missing","severity":"high","category":"headers","description":"HSTS not set"}]}'
# → { "risk_cards": [{ "title": "HSTS Missing", "exploitation_difficulty": "Medium", ... }] }
```

### 4.3 Email Scan (10-stage engine)
```bash
# Start scan
curl -X POST http://localhost:3001/api/email-scan/start \
  -H "Content-Type: application/json" \
  -d '{"domain":"example.com"}'
# → { "scan_id": "uuid-here" }

# Poll status (every 3s)
curl http://localhost:3001/api/email-scan/status/$EMAIL_ID
# → { "status": "RUNNING", "progress": 40, "currentStage": "DMARC" }

# Fetch result
curl http://localhost:3001/api/email-scan/result/$EMAIL_ID
# KEY FIELDS:
#   emailSecurityScore: number (0-100)
#   scoreBreakdown: { spf: 0-18, dkim: 0-18, dmarc: 0-22, relay: 0-18, misc: 0-12, ports: 0-12 }
#   spfRecord: { exists, record, policy, score, issues }
#   dkimRecord: { exists, selectors_found, key_length, score }
#   dmarcRecord: { exists, record, policy, score }
#   blacklistStatus: { ips_checked, reputation_score }
#   mxtoolboxLinks: { blacklist, email_health, mx_lookup, spf_lookup, dmarc_lookup }
#   recommendations: string[]
```

### 4.4 Threat Intel (NMAP)
```bash
# Discovery + scan start
curl -X POST http://localhost:3001/api/threat-intel/start-nmap \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"target":"example.com","nmap_config":{"scan_a_records":true,"scan_mx_records":true,"profile":"baseline_syn_1000"}}'
# → { "discovery": { "ips_discovered": N, "ips": [...] }, "jobs": [...], "stage": "scanning" }
# NOTE: Without NMAP_API_KEY, returns simulated results with { "simulated": true }

# Port scan
curl -X POST http://localhost:3001/api/threat-intel/nmap-port-scan \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"target":"93.184.216.34","step":1}'

# Exposure scan (requires client approval)
curl -X POST http://localhost:3001/api/threat-intel/run-nmap-exposure \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"nmap_config":{"scan_all_discovered_ports":true,"client_approved":true},"job_results":[{"ip":"93.184.216.34","open_ports":[{"port":80,"service":"http"}]}]}'
# → { "vulnerabilities": [...], "total_found": N }
```

### 4.5 MITRE ATT&CK (LLM engine)
```bash
# Correlate (uses local stub when LLM_PROVIDER=local)
curl -X POST http://localhost:3001/api/mitre/correlate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"target":"example.com","email_scan":{"emailSecurityScore":74,"dmarcRecord":{"exists":true,"policy":"none"}},"web_scan":{"webSecurityScore":52,"findings":[{"id":"csp-missing","title":"CSP Missing","severity":"high"}]}}'
# → FULL MITRE RESPONSE:
#   mitre_mapping: [{ tactic, technique, technique_id, why_relevant, confidence }]
#   attack_score: { score: 0-100, rating, reasoning }
#   potential_attack_paths: [{ entry_point, description, likelihood }]
#   remediation_roadmap: { immediate_30_days, short_term_60_days, long_term_90_days }
#   executive_summary: { overview, key_risks, immediate_actions }
#   disclaimer: "..."

# Executive PDF
curl -X POST http://localhost:3001/api/mitre/executive-pdf \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"target":"example.com","attackScore":42,"riskLevel":"moderate"}'
# → { "pdf_url": "/uploads/executive-report-uuid.txt", "file_size_kb": N }
```

### 4.6 Schedules
```bash
# Create schedule
curl -X POST http://localhost:3001/api/schedules/create \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"type":"web","data":{"target":"https://example.com","frequency":"weekly","notify_emails":["test@test.io"]}}'

# List all
curl http://localhost:3001/api/schedules/list \
  -H "Authorization: Bearer $TOKEN"

# Toggle
curl -X PATCH http://localhost:3001/api/schedules/toggle \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"type":"web","schedule_id":"uuid","current_status":true}'

# Test run
curl -X POST http://localhost:3001/api/schedules/test \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"scan_type":"web","target":"https://example.com"}'

# Execution logs
curl http://localhost:3001/api/schedules/logs \
  -H "Authorization: Bearer $TOKEN"

# Delete
curl -X DELETE http://localhost:3001/api/schedules/web/$SCHED_ID \
  -H "Authorization: Bearer $TOKEN"
```

### 4.7 Admin
```bash
# Stats
curl http://localhost:3001/api/admin/stats \
  -H "Authorization: Bearer $ADMIN_TOKEN"
# → { "totalUsers": N, "admins": N, "totalWebScans": N, "totalEmailScans": N }

# List users
curl http://localhost:3001/api/admin/users \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# Invite user
curl -X POST http://localhost:3001/api/admin/users/invite \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"email":"new@test.io","role":"BASIC_SCANS"}'
# → { "success": true, "user": {...}, "tempPassword": "..." }

# Email settings (get)
curl -X POST http://localhost:3001/api/admin/email-settings \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"action":"get"}'

# Email settings (save)
curl -X POST http://localhost:3001/api/admin/email-settings \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"action":"save","provider":"smtp","settings":{"smtp_host":"smtp.example.com","smtp_port":587,"from_email":"noreply@test.io"}}'
```

### 4.8 Data
```bash
# Latest scans for a target
curl -X POST http://localhost:3001/api/data/latest-scans \
  -H "Content-Type: application/json" \
  -d '{"target":"example.com","limit":5}'
# → { "email_scans": [...], "web_scans": [...], "threat_scans": [...] }

# Scan history (trending)
curl http://localhost:3001/api/data/scan-history/example.com

# Upgrade (Stripe stub)
curl -X POST http://localhost:3001/api/data/upgrade \
  -H "Authorization: Bearer $TOKEN"
# → { "url": "https://checkout.stripe.com/mock?...", "message": "Stripe stub..." }
```

---

## 5. ENGINE VERIFICATION

### Web Scanner — Confirm 10 stages
After starting a scan, poll `/api/web-scan/status/:id` and watch:
- `stage` cycles through: DISCOVERY → INIT → TLS → DNS → HEADERS → COOKIES → EXPOSURE → CRAWL → CONTENT → FINALIZE → COMPLETE
- `progress` increases 0→100
- Final result has: `webSecurityScore`, `dnsSecurityScore`, `riskScore`, `findings[]`, `dnsAnalysis`, `exposureFindings[]`, `technologies`, `scoreBreakdown`

### Email Scanner — Confirm all fields
Poll `/api/email-scan/status/:id` and watch:
- `currentStage` cycles: DNS → SPF → DKIM → DMARC → MX → WHOIS → SMTP → Blacklist → Ports → AbuseIPDB → Complete
- Final result has: `spfRecord`, `dkimRecord`, `dmarcRecord`, `blacklistStatus`, `mxtoolboxLinks`, `recommendations`

### NMAP — Stub mode
When `NMAP_API_KEY` is empty (default), returns: `{ "simulated": true, "open_ports": [...] }`. No external traffic.

### MITRE — Local stub
When `LLM_PROVIDER=local` (default), returns deterministic analysis based on actual scan data. No API calls.

### Email Gateway — Log-only mode  
When SMTP is not configured, `emailService.send()` logs a warning and returns `false`. No contract change.

### Scheduler — Manual trigger
The cron runs every 30 minutes. To trigger manually, use:
```bash
curl -X POST http://localhost:3001/api/schedules/test \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"scan_type":"web","target":"https://example.com"}'
```

---

## 6. KNOWN ISSUES / LIMITATIONS

1. **Seed in Docker**: The seed script requires `tsx` which may not be available in the production container. Run seed from host: `DATABASE_URL="postgresql://mchallenge:mchallenge@localhost:5432/mchallenge" npx tsx prisma/seed.ts`

2. **External DNS**: Web/Email scanners make real DNS queries to `dns.google`. This requires outbound HTTPS from the container. If blocked, scanners will still complete but with fewer findings.

3. **crt.sh rate limiting**: The subdomain discovery via crt.sh may timeout or be rate-limited. The scanner handles this gracefully.

4. **PDF format**: Executive reports are currently generated as `.txt` files (structured text). For actual PDF output, add `puppeteer` or switch to the jsPDF frontend generation.

5. **Stripe**: The upgrade endpoint returns a mock URL. Set `STRIPE_SECRET_KEY` for real Stripe integration.

6. **BullMQ**: Redis is included in docker-compose but BullMQ is not actively used — scheduling uses node-cron. Redis is available for future BullMQ migration.
