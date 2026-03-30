#!/bin/sh
set -e
echo "=== M-Challenge Backend Starting ==="
echo "1. Running database migrations..."
npx prisma db push 2>&1 || echo "Migration skipped - data preserved"

echo "2. Creating custom tables..."
node -e "
const { PrismaClient } = require('@prisma/client');
const p = new PrismaClient();
async function init() {
  await p.\$executeRawUnsafe('CREATE TABLE IF NOT EXISTS pentest_reports (id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text, user_id TEXT NOT NULL, customer_id TEXT, status TEXT NOT NULL DEFAULT \'PENDING\', target_domain TEXT, target_ip TEXT, target_url TEXT, client_name TEXT, client_company_id TEXT, client_phone TEXT, client_contact TEXT, client_email TEXT, results JSONB, score INTEGER, html_report TEXT, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)');
  await p.\$executeRawUnsafe('CREATE TABLE IF NOT EXISTS nuclei_scans (id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text, user_id TEXT NOT NULL, target TEXT NOT NULL, status TEXT NOT NULL DEFAULT \'PENDING\', severity TEXT, findings JSONB, summary JSONB, started_at TIMESTAMP, completed_at TIMESTAMP, error_message TEXT, customer_id TEXT, description TEXT, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)');
  await p.\$executeRawUnsafe('CREATE TABLE IF NOT EXISTS cve_feed (id VARCHAR(30) PRIMARY KEY, published_at TIMESTAMP, last_modified TIMESTAMP, description TEXT, severity VARCHAR(10), cvss_score FLOAT, cvss_vector TEXT, affected_products JSONB DEFAULT \'[]\', "references" TEXT, tags JSONB DEFAULT \'[]\', is_exploited BOOLEAN DEFAULT false, ai_summary_en TEXT, ai_summary_he TEXT, ai_relevance_score INTEGER, created_at TIMESTAMP DEFAULT NOW())');
  console.log('Tables ready');
  await p.\$disconnect();
}
init().catch(e => { console.error(e.message); process.exit(0); });
"

echo "3. Starting server..."
node dist/server.js
