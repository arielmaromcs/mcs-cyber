# M-Challenge Frontend

React + TypeScript + Vite + Tailwind CSS frontend for M-Challenge Security Scanner.

## Setup

```bash
npm install
npm run dev    # http://localhost:3000
```

## Build

```bash
npm run build  # Output: dist/
```

## Pages

| Route | Page | Description |
|-------|------|-------------|
| `/` | Web Scanner | 10-stage web security scan with findings, DNS, exposures |
| `/email` | Email Scanner | SPF/DKIM/DMARC/Blacklist/AbuseIPDB analysis |
| `/threat` | Threat Intel | NMAP port scanning with CVE correlation |
| `/mitre` | MITRE ATT&CK | Multi-vector risk correlation and mapping |
| `/schedules` | Schedules | CRUD for automated recurring scans |
| `/admin` | Admin Panel | User management + email settings |
| `/about` | About | Bilingual (EN/HE) platform info |
| `/login` | Login | Auth with demo credentials |

## Backend

Connects to the Fastify backend at `http://localhost:3001/api` via Vite proxy.

Demo login: `admin@mchallenge.io` / `admin123`
