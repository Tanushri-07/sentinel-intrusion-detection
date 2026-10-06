#!/bin/bash
set -e
PORT=${PORT:-8000}
URL="http://127.0.0.1:$PORT"
ATTACKER_IP="198.51.100.10"

echo "=== KILLER TEST 1: Brute-Force Attack Detection & Blocking ==="
echo "Target: $URL/login"
echo "Attacker IP: $ATTACKER_IP"
echo ""

echo "1. Sending 10 failed login attempts..."
for i in {1..10}; do
  HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$URL/login" \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: $ATTACKER_IP" \
    -d "{\"username\": \"student\", \"password\": \"wrongpass$i\"}")
  echo "Attempt $i: HTTP $HTTP_CODE (401 Unauthorized expected)"
done

echo ""
echo "Waiting 0.5s for log watcher to process events and issue ban..."
sleep 0.5

echo ""
echo "2. Sending 11th request from Attacker ($ATTACKER_IP)..."
RESPONSE=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST "$URL/login" \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: $ATTACKER_IP" \
  -d '{"username": "student", "password": "anypassword"}')

HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_STATUS" | cut -d':' -f2)
BODY=$(echo "$RESPONSE" | grep -v "HTTP_STATUS")

echo "Response Body: $BODY"
echo "HTTP Status: $HTTP_CODE"

if [ "$HTTP_CODE" -eq 403 ]; then
  echo ""
  echo ">>> SUCCESS: Attacker IP is blocked with HTTP 403 Forbidden! <<<"
else
  echo ""
  echo ">>> FAILURE: Expected HTTP 403, got $HTTP_CODE <<<"
  exit 1
fi
