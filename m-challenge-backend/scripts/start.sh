#!/bin/sh
set -e

echo "=== M-Challenge Backend Starting ==="

echo "1. Running database migrations..."
npx prisma db push --accept-data-loss 2>&1

echo "2. Creating missing tables..."
npx ts-node -e "
const { execSync } = require('child_process');
" 2>/dev/null || true

# Create tables that might not exist via Prisma
node -e "
const { Client } = require('pg');
const client = new Client({ connectionString: process.env.DATABASE_URL });
client.connect().then(() => {
  return client.query(\`
    CREATE TABLE IF NOT EXISTS pentest_reports (
      id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
      user_id TEXT NOT NULL,
      customer_id TEXT, status TEXT NOT NULL DEFAULT 'PENDING',
      target_domain TEXT, target_ip TEXT, target_url TEXT,
      client_name TEXT, client_company_id TEXT, client_phone TEXT,
      client_contact TEXT, client_email TEXT,
      results JSONB, score INTEGER, html_report TEXT,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS nuclei_scans (
      id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
      user_id TEXT NOT NULL, target TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'PENDING',
      severity TEXT, findings JSONB, summary JSONB,
      started_at TIMESTAMP, completed_at TIMESTAMP,
      error_message TEXT, customer_id TEXT, description TEXT,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
  \`);
}).then(() => { console.log('Tables ready'); client.end(); })
.catch(e => { console.error('Table init error:', e.message); client.end(); });
" 2>/dev/null || true

echo "3. Starting server..."
node dist/server.js
