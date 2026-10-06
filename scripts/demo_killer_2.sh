#!/bin/bash
set -e
PORT=${PORT:-8000}
URL="http://127.0.0.1:$PORT"
ATTACKER_IP="198.51.100.10"
INNOCENT_IP="203.0.113.50"

echo "=== KILLER TEST 2: Innocent Bystander Isolation ==="
echo "Target: $URL/login"
echo "Attacker IP: $ATTACKER_IP"
echo "Innocent IP: $INNOCENT_IP"
echo ""

echo "1. Triggering ban on Attacker IP..."
for i in {1..10}; do
  curl -s -o /dev/null -X POST "$URL/login" \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: $ATTACKER_IP" \
    -d "{\"username\": \"student\", \"password\": \"wrongpass$i\"}"
done

sleep 0.5

echo "2. Verifying Attacker is blocked (HTTP 403)..."
ATTACKER_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$URL/login" \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: $ATTACKER_IP" \
  -d '{"username": "student", "password": "secret2024"}')
echo "Attacker HTTP Code: $ATTACKER_CODE"

echo ""
echo "3. Sending legitimate login from Innocent User ($INNOCENT_IP)..."
INNOCENT_RESP=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST "$URL/login" \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: $INNOCENT_IP" \
  -d '{"username": "student", "password": "secret2024"}')

INNOCENT_CODE=$(echo "$INNOCENT_RESP" | grep "HTTP_STATUS" | cut -d':' -f2)
INNOCENT_BODY=$(echo "$INNOCENT_RESP" | grep -v "HTTP_STATUS")

echo "Innocent User Response Body: $INNOCENT_BODY"
echo "Innocent User HTTP Status: $INNOCENT_CODE"

if [ "$ATTACKER_CODE" -eq 403 ] && [ "$INNOCENT_CODE" -eq 200 ]; then
  echo ""
  echo ">>> SUCCESS: Bystander isolated! Attacker blocked (403), Legitimate user allowed (200)! <<<"
else
  echo ""
  echo ">>> FAILURE: Expected Attacker 403 and Innocent 200 <<<"
  exit 1
fi
