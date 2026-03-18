# M-Challenge Security Scanner — Backend

Self-hostable backend for the M-Challenge Security Scanner platform.  
Fastify + TypeScript + Prisma + PostgreSQL + node-cron scheduler.

## Quick Start

```bash
# 1. Install
npm install

# 2. Copy environment
cp .env.example .env
# Edit .env with your settings

# 3. Start PostgreSQL (via Docker or local)
docker compose up postgres redis -d

# 4. Push schema + seed
npx prisma db push
npx tsx prisma/seed.ts

# 5. Run
npm run dev
```

Or with Docker (everything at once):

```bash
docker compose up --build
```

## Default Accounts (after seeding)

| Email | Password | Role |
|-------|----------|------|
| admin@mchallenge.io | admin123 | ADMIN |
| analyst@mchallenge.io | analyst123 | FULL_SCANS |
| user@mchallenge.io | user123 | BASIC_SCANS |

## API Endpoints

### Auth
```
POST /api/auth/register     { email, password, fullName? }
POST /api/auth/login         { email, password } → { token, user }
GET  /api/auth/whoami         → { user, isAuthenticated }
GET  /api/auth/client-ip      → { ip }
```

### Web Scanning
```
POST /api/web-scan/start     { url, options?, discover_subdomains?, guest_scans_used? }
GET  /api/web-scan/status/:id   (poll every 1.5s)
GET  /api/web-scan/result/:id   (full results)
POST /api/web-scan/analyze-exploitability  { findings }
```

### Email Scanning
```
POST /api/email-scan/start   { domain }
GET  /api/email-scan/status/:id  (poll every 3s)
GET  /api/email-scan/result/:id
```

### Threat Intelligence (NMAP)
```
POST /api/threat-intel/start-nmap    { target, nmap_config }
POST /api/threat-intel/nmap-start    { target, profile, ports?, client_approved }
GET  /api/threat-intel/nmap-status/:jobId
POST /api/threat-intel/nmap-port-scan { target, step, ports?, domain, scanId }
POST /api/threat-intel/run-nmap-exposure { nmap_config, job_results }
```

### MITRE ATT&CK Analysis
```
POST /api/mitre/correlate        { target, email_scan?, web_scan?, threat_intel? }
POST /api/mitre/executive-pdf    { target, attackScore, riskLevel, ... }
POST /api/mitre/save-history     { target, attack_score, risk_level, ... }
```

### Scheduled Scans
```
POST   /api/schedules/create     { type, data: { target, frequency, ... } }
DELETE /api/schedules/:type/:id
PATCH  /api/schedules/toggle     { type, schedule_id, current_status }
POST   /api/schedules/test       { scan_type, target }
GET    /api/schedules/list
GET    /api/schedules/logs
```

### Admin
```
GET    /api/admin/users
POST   /api/admin/users/invite   { email, role, scans_remaining? }
PATCH  /api/admin/users/:id      { role?, scans_remaining?, plan? }
DELETE /api/admin/users/:id
POST   /api/admin/email-settings { action: get|save|verify|test, provider?, settings? }
GET    /api/admin/stats
```

### Data
```
POST /api/data/latest-scans     { target, limit? }
GET  /api/data/scan-history/:target
POST /api/data/upgrade
```

## Folder Structure

```
m-challenge-backend/
├── docker-compose.yml         # One-command deployment
├── Dockerfile                 # Multi-stage build
├── Makefile                   # Common commands
├── package.json
├── tsconfig.json
├── .env.example               # All configuration keys
├── prisma/
│   ├── schema.prisma          # 11 database models
│   └── seed.ts                # Demo data seeder
├── scripts/
│   └── start.sh               # Docker entrypoint
└── src/
    ├── server.ts              # Fastify app + route registration
    ├── config/
    │   ├── env.ts             # Environment config loader
    │   └── database.ts        # Prisma client singleton
    ├── api/routes/
    │   ├── auth.ts            # Login, register, whoami, client-ip
    │   ├── webScan.ts         # Web scan start/status/result
    │   ├── emailScan.ts       # Email scan start/status/result
    │   ├── threatIntel.ts     # NMAP orchestration endpoints
    │   ├── mitre.ts           # MITRE correlation + PDF
    │   ├── schedules.ts       # Schedule CRUD + toggle + test
    │   ├── admin.ts           # User management + email settings
    │   └── scanData.ts        # Latest scans + history + upgrade
    ├── services/
    │   ├── scanning/
    │   │   ├── webScanner.ts  # 10-stage web scanner (main engine)
    │   │   └── emailScanner.ts # 10-stage email scanner
    │   ├── nmap/
    │   │   └── nmapService.ts # NMAP proxy + discovery + exposure
    │   ├── analysis/
    │   │   ├── mitreCorrelation.ts # LLM-based MITRE mapping
    │   │   ├── exploitability.ts   # LLM exploitability assessment
    │   │   └── pdfService.ts       # Executive PDF generation
    │   ├── email/
    │   │   └── emailService.ts     # SMTP + Microsoft Graph
    │   └── scheduling/
    │       └── scheduleService.ts  # Schedule CRUD + execution
    ├── jobs/
    │   └── scheduler.ts       # Cron runner (every 30min)
    └── utils/
        └── scanUtils.ts       # DNS, HTTP, scoring, shared helpers
```

## Database Models (11)

| Model | Purpose |
|-------|---------|
| User | Auth, roles (ADMIN/FULL_SCANS/BASIC_SCANS), quota |
| WebScan | Web scan results, findings, scores, NMAP data |
| EmailScan | Email scan results, SPF/DKIM/DMARC analysis |
| WebScanSchedule | Recurring web scan configuration |
| EmailScanSchedule | Recurring email scan configuration |
| ThreatIntelSchedule | Recurring NMAP scan configuration |
| ScheduleExecutionLog | Execution history for all schedules |
| ScanHistory | Score trending data for MITRE analysis |
| ExecutiveReport | Generated PDF reports |
| AdminEmailSettings | SMTP/Graph configuration |
| Subscription | Stripe subscription state |

## Scanning Engine Details

### Web Scanner (10 Stages)
| Stage | Weight | What it does |
|-------|--------|-------------|
| DISCOVERY | 18% | crt.sh passive + 30 common subdomain probes |
| INIT | 4% | URL validation, connection test |
| TLS | 12% | HTTPS availability check |
| DNS | 14% | DNSSEC, CAA, NS, SPF, DMARC, DKIM, takeover risk |
| HEADERS | 10% | HSTS, CSP, XFO, XCTO, server disclosure, CORS |
| COOKIES | 8% | Secure, HttpOnly, SameSite flags |
| EXPOSURE | 10% | 40+ sensitive paths + JS mining |
| CRAWL | 14% | Spider up to max_pages/depth |
| CONTENT | 5% | SRI, mixed content, inline scripts |
| FINALIZE | 5% | Scoring calculation |

### Scoring System
```
Web Score = 100 - capped_penalties
  Critical: 15 pts each, max 45
  High:     8 pts each, max 25
  Medium:   4 pts each, max 20
  Low:      2 pts each, max 10

Score Caps:
  2+ critical → max 25
  1 critical  → max 45
  2+ high     → max 55

Composite Risk = (100-Web)×0.60 + (100-DNS)×0.25 + (100-Email)×0.15
```

### Email Score = SPF(18) + DKIM(18) + DMARC(22) + Relay(18) + Infra(12) + Ports(12) = 100

## External APIs (all optional)

| Service | Used for | Env var |
|---------|----------|---------|
| dns.google | DNS resolution | (no key needed) |
| crt.sh | Passive subdomain discovery | (no key needed) |
| NMAP API | Port scanning | NMAP_API_KEY |
| Shodan | Service banners | SHODAN_API_KEY |
| AbuseIPDB | IP reputation | ABUSEIPDB_API_KEY |
| OpenAI/Anthropic | MITRE analysis | LLM_API_KEY |
| Stripe | Subscriptions | STRIPE_SECRET_KEY |

All external APIs degrade gracefully — the system works without any keys.

## LLM Configuration

Set `LLM_PROVIDER` in .env:
- `local` — Returns structured stub response (no API needed)
- `openai` — Uses OpenAI API with JSON schema enforcement
- `anthropic` — Uses Anthropic API

The MITRE correlation engine uses strict JSON schema output to prevent hallucination drift.
