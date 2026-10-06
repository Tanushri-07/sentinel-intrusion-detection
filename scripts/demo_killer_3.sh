#!/bin/bash
set -e
PORT=${PORT:-8000}
URL="http://127.0.0.1:$PORT"
TARGET_IP="198.51.100.99"
ADMIN_KEY=${ADMIN_API_KEY:-"sentinel-admin-secret-key"}

echo "=== KILLER TEST 3: Exact Expiry (Zero Polling Lag) ==="
echo "Target: $URL"
echo "Test IP: $TARGET_IP"
echo ""

echo "1. Creating a short 3-second manual ban for $TARGET_IP via Admin API..."
BAN_RESP=$(curl -s -X POST "$URL/v1/decisions" \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $ADMIN_KEY" \
  -d "{\"value\": \"$TARGET_IP\", \"duration_seconds\": 3, \"scenario\": \"demo_exact_expiry\"}")
echo "Ban Response: $BAN_RESP"

echo ""
echo "2. Immediately sending request during ban window..."
BLOCKED_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$URL/login" \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: $TARGET_IP" \
  -d '{"username": "student", "password": "secret2024"}')
echo "HTTP Code during ban: $BLOCKED_CODE (403 expected)"

echo ""
echo "3. Waiting 3.2 seconds for ban to expire..."
sleep 3.2

echo "4. Sending request immediately AFTER expiry (request-time dynamic unblocking)..."
AFTER_RESP=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST "$URL/login" \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: $TARGET_IP" \
  -d '{"username": "student", "password": "secret2024"}')

AFTER_CODE=$(echo "$AFTER_RESP" | grep "HTTP_STATUS" | cut -d':' -f2)
AFTER_BODY=$(echo "$AFTER_RESP" | grep -v "HTTP_STATUS")

echo "Response Body: $AFTER_BODY"
echo "HTTP Status: $AFTER_CODE"

if [ "$BLOCKED_CODE" -eq 403 ] && [ "$AFTER_CODE" -eq 200 ]; then
  echo ""
  echo ">>> SUCCESS: Exact expiry verified! Blocked at t < until, unblocked at t >= until! <<<"
else
  echo ""
  echo ">>> FAILURE: Expected 403 then 200 <<<"
  exit 1
fi
