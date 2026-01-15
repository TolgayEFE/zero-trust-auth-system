#!/usr/bin/env bash
set -euo pipefail

API_URL="${API_URL:-http://localhost:3000}"

echo "== Security Checks =="
echo "Target: ${API_URL}"
echo

echo "1) Invalid Login (expected 401)"
curl -i "${API_URL}/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"wrong-password"}'
echo

echo "2) Weak Password Registration (expected 400)"
curl -i "${API_URL}/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"weak@example.com","username":"weakuser","password":"123"}'
echo

echo "3) SQL Injection Attempt (expected 400)"
curl -i "${API_URL}/api/users?search=%27%20OR%201%3D1%20--"
echo

echo "4) XSS Attempt (expected 400)"
curl -i "${API_URL}/api/users?search=<script>alert(1)</script>"
echo

echo "5) Path Traversal Attempt (expected 400)"
curl -i "${API_URL}/../../etc/passwd"
echo

echo "6) Invalid Content-Type (expected 415)"
curl -i "${API_URL}/auth/login" \
  -H "Content-Type: text/plain" \
  -d "email=test@example.com&password=pass"
echo

echo "7) Missing Content-Type (expected 400)"
curl -i "${API_URL}/auth/login" \
  -d '{"email":"test@example.com","password":"password123"}'
echo

echo "8) Unauthorized Access to Devices (expected 401)"
curl -i "${API_URL}/api/devices"
echo

echo "== Brute Force / Rate Limit Test =="
echo "9) Login spam (check for 429 after a few attempts)"
for i in $(seq 1 30); do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    "${API_URL}/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"email":"test@example.com","password":"wrong-password"}')
  printf "Attempt %02d -> %s\n" "${i}" "${code}"
done
echo

echo "Done."
