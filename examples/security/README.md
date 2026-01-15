Security Testing with curl

These commands are intended to validate security controls in a controlled environment.
Replace tokens, host, and ports as needed.

Base URL:
  export API_URL="http://localhost:3000"

1) Invalid Login (basic auth failure)
  curl -i "$API_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"email":"test@example.com","password":"wrong-password"}'

2) Weak Password Registration (should fail validation)
  curl -i "$API_URL/auth/register" \
    -H "Content-Type: application/json" \
    -d '{"email":"weak@example.com","username":"weakuser","password":"123"}'

3) Brute Force / Rate Limit (login spam)
  for i in $(seq 1 30); do
    curl -s -o /dev/null -w "%{http_code}\n" \
      "$API_URL/auth/login" \
      -H "Content-Type: application/json" \
      -d '{"email":"test@example.com","password":"wrong-password"}'
  done

4) SQL Injection Attempt (query param)
  curl -i "$API_URL/api/users?search=' OR 1=1 --"

5) XSS Attempt (query param)
  curl -i "$API_URL/api/users?search=<script>alert(1)</script>"

6) Path Traversal Attempt
  curl -i "$API_URL/../../etc/passwd"

7) Invalid Content-Type (should fail validation)
  curl -i "$API_URL/auth/login" \
    -H "Content-Type: text/plain" \
    -d "email=test@example.com&password=pass"

8) Missing Content-Type (should fail validation)
  curl -i "$API_URL/auth/login" \
    -d '{"email":"test@example.com","password":"password123"}'

9) Unauthorized Access to Devices (no auth)
  curl -i "$API_URL/api/devices"

10) CSRF Check (cookie-based POST without CSRF)
  curl -i "$API_URL/api/users" \
    -H "Content-Type: application/json" \
    -H "Cookie: session_id=test" \
    -d '{"name":"test"}'
