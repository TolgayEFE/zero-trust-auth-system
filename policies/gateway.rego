package gateway.authz

import future.keywords.if
import future.keywords.in

# Default deny all requests (Zero Trust principle)
default allow := false

# Allow health check endpoints without authentication
allow if {
    input.request.path in ["/health", "/health/live", "/health/ready", "/health/detailed"]
}

# Allow metrics endpoint from internal IPs
allow if {
    input.request.path == "/metrics"
    is_internal_ip(input.subject.client.ip)
}

# Allow authenticated users with valid trust level
allow if {
    input.subject.user
    input.subject.user.id != ""
    valid_trust_level
    valid_risk_score
    has_required_permissions
}

# Validate trust level
valid_trust_level if {
    input.context.trustLevel in ["medium", "high", "verified"]
}

# Validate risk score (lower is better)
valid_risk_score if {
    to_number(input.context.riskScore) <= 50
}

# Check if user has required permissions for the action
has_required_permissions if {
    required := get_required_permissions(input.action, input.resource.type)
    every perm in required {
        perm in input.subject.user.permissions
    }
}

# Get required permissions based on action and resource
get_required_permissions(action, resource) := perms if {
    action == "read"
    perms := [sprintf("read:%s", [resource]), "read:all"]
}

get_required_permissions(action, resource) := perms if {
    action == "create"
    perms := [sprintf("write:%s", [resource]), "write:all"]
}

get_required_permissions(action, resource) := perms if {
    action == "update"
    perms := [sprintf("write:%s", [resource]), "write:all"]
}

get_required_permissions(action, resource) := perms if {
    action == "delete"
    perms := [sprintf("delete:%s", [resource]), "delete:all", "admin"]
}

get_required_permissions(_, _) := ["read:own"]

# Check if IP is internal
is_internal_ip(ip) if {
    startswith(ip, "10.")
}

is_internal_ip(ip) if {
    startswith(ip, "172.16.")
}

is_internal_ip(ip) if {
    startswith(ip, "192.168.")
}

is_internal_ip(ip) if {
    ip == "127.0.0.1"
}

is_internal_ip(ip) if {
    ip == "::1"
}

# Role-based access control
allow if {
    input.subject.user
    "admin" in input.subject.user.roles
    input.context.trustLevel in ["high", "verified"]
}

# Allow users to access their own resources
allow if {
    input.subject.user
    input.resource.id == input.subject.user.id
    input.action in ["read", "update"]
}

# Rate limit check - deny if too many requests
deny[msg] if {
    input.context.rateLimit.exceeded == true
    msg := "Rate limit exceeded"
}

# Block suspicious requests
deny[msg] if {
    to_number(input.context.riskScore) > 80
    msg := sprintf("High risk score detected: %v", [input.context.riskScore])
}

# Block requests from untrusted devices
deny[msg] if {
    input.subject.device
    input.subject.device.trusted == false
    not "admin" in input.subject.user.roles
    msg := "Untrusted device"
}

# Additional security checks
security_violations[violation] if {
    input.request.headers["x-forwarded-for"]
    count(split(input.request.headers["x-forwarded-for"], ",")) > 5
    violation := "Too many proxy hops"
}

security_violations[violation] if {
    not input.subject.user.mfaVerified
    sensitive_action
    violation := "MFA required for sensitive action"
}

sensitive_action if {
    input.action in ["delete", "create"]
    input.resource.type in ["users", "payments", "security"]
}

sensitive_action if {
    input.request.path in ["/api/admin", "/api/security"]
}
