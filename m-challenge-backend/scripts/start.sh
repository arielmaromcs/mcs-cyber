#!/bin/sh
set -e

echo "=== M-Challenge Backend Starting ==="

echo "1. Running database migrations..."
npx prisma db push --accept-data-loss 2>&1

echo "2. Starting server..."
node dist/server.js
