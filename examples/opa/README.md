OPA Example Payloads

These JSON files are ready to POST to OPA.

Allow decision:
  curl -s http://localhost:8181/v1/data/gateway/authz/allow \
    -H "Content-Type: application/json" \
    -d @examples/opa/allow.json

Deny decision:
  curl -s http://localhost:8181/v1/data/gateway/authz/allow \
    -H "Content-Type: application/json" \
    -d @examples/opa/deny.json

Deny reasons:
  curl -s http://localhost:8181/v1/data/gateway/authz/deny \
    -H "Content-Type: application/json" \
    -d @examples/opa/deny-reasons.json
