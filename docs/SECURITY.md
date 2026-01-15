# Security Documentation

## Zero Trust Architecture Implementation

This document details the security mechanisms implemented in the Zero-Trust API Gateway.

## Security Layers

### 1. Network Security

#### TLS/mTLS Configuration
- TLS 1.3 with strong cipher suites
- Mutual TLS for service-to-service communication
- Certificate-based authentication
- Perfect forward secrecy

```typescript
const httpsOptions = {
  minVersion: 'TLSv1.3',
  ciphers: [
    'TLS_AES_256_GCM_SHA384',
    'TLS_CHACHA20_POLY1305_SHA256',
    'TLS_AES_128_GCM_SHA256',
  ].join(':'),
};
```

### 2. Application Security

#### Input Validation
All incoming requests are validated for:
- SQL Injection patterns
- XSS attack vectors
- Directory traversal attempts
- Prototype pollution
- Content-Type verification
- Request size limits

#### Request Validation Examples

```typescript
// SQL Injection Detection
const sqlPatterns = [
  /(\b(SELECT|INSERT|UPDATE|DELETE|DROP)\b)/i,
  /(--)|(\/\*)|(\*\/)/,
  /(\bOR\b\s*\d+\s*=\s*\d+)/i,
];

// XSS Detection
const xssPatterns = [
  /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
  /javascript:/gi,
  /on\w+\s*=/gi,
];
```

### 3. Authentication

#### JWT Token Security
- Short-lived access tokens (15 minutes default)
- Longer-lived refresh tokens (7 days)
- Token blacklisting support
- Algorithm verification (HS256 by default)
- Issuer and audience validation

```typescript
const payload = jwt.verify(token, secret, {
  issuer: 'zero-trust-gateway',
  audience: 'zero-trust-services',
  algorithms: ['HS256'],
});
```

#### OAuth 2.0 + PKCE
- Authorization Code flow with PKCE
- S256 code challenge method
- State parameter for CSRF protection
- Nonce for replay attack prevention

### 4. Authorization

#### Role-Based Access Control (RBAC)
```typescript
// Example role check
const requireRoles = (...roles: string[]) => {
  return (req, res, next) => {
    const hasRole = roles.some(role => user.roles.includes(role));
    if (!hasRole) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
};
```

#### Open Policy Agent (OPA)
Declarative policies written in Rego:

```rego
package gateway.authz

default allow := false

# Allow authenticated users with valid trust level
allow if {
    input.subject.user
    valid_trust_level
    valid_risk_score
}

valid_trust_level if {
    input.context.trustLevel in ["medium", "high", "verified"]
}

valid_risk_score if {
    to_number(input.context.riskScore) <= 50
}
```

### 5. Rate Limiting

Multiple layers of rate limiting:
- Global rate limit (100 requests/15 minutes)
- Authentication endpoint limit (5 attempts/15 minutes)
- Per-endpoint configurable limits
- Sliding window algorithm

### 6. CSRF Protection

Double-submit cookie pattern implementation:
- Cryptographically signed CSRF tokens
- Session-bound tokens
- Token expiration (1 hour)
- Automatic validation for state-changing requests

### 7. Security Headers (CSP)

Content Security Policy configuration:

```javascript
contentSecurityPolicy: {
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],
    styleSrc: ["'self'", "'unsafe-inline'"],
    imgSrc: ["'self'", 'data:', 'https:'],
    connectSrc: ["'self'"],
    fontSrc: ["'self'"],
    objectSrc: ["'none'"],
    mediaSrc: ["'self'"],
    frameSrc: ["'none'"],
    baseUri: ["'self'"],
    formAction: ["'self'"],
    frameAncestors: ["'none'"],
  },
}
```

Additional security headers:
- X-Frame-Options: DENY
- X-Content-Type-Options: nosniff
- X-XSS-Protection: 1; mode=block
- Strict-Transport-Security (HSTS)
- Referrer-Policy: strict-origin-when-cross-origin

## Trust Level Assessment

The gateway calculates a trust level for each request:

1. **NONE**: Unauthenticated request
2. **LOW**: Authenticated but high risk score (>50)
3. **MEDIUM**: Authenticated with moderate risk (25-50)
4. **HIGH**: Authenticated with low risk (<25)
5. **VERIFIED**: Authenticated, low risk, MFA verified, trusted device

### Risk Score Calculation

```typescript
const calculateRiskScore = (context: SecurityContext): number => {
  let score = 0;

  if (!context.authenticated) score += 30;
  if (!context.user?.mfaVerified) score += 20;
  if (context.device && !context.device.trusted) score += 25;
  if (context.device?.riskIndicators) {
    score += context.device.riskIndicators.length * 10;
  }

  return Math.min(score, 100);
};
```

## Audit Logging

All security events are logged with:
- Unique request ID
- Timestamp
- Actor information (user ID, IP, user agent)
- Action performed
- Resource accessed
- Outcome (success/failure/error)
- Security context

Example audit log entry:
```json
{
  "id": "audit_uuid",
  "timestamp": "2024-01-01T00:00:00Z",
  "requestId": "req_uuid",
  "action": "authentication:success",
  "actor": {
    "userId": "user_123",
    "ip": "192.168.1.1",
    "userAgent": "Mozilla/5.0..."
  },
  "resource": {
    "type": "auth",
    "id": null
  },
  "outcome": "success",
  "securityContext": {
    "authenticated": true,
    "trustLevel": "HIGH",
    "riskScore": 10
  }
}
```

## Cryptographic Operations

### Password Hashing
- scrypt algorithm with 64-byte output
- Random 16-byte salt per password
- Timing-safe comparison for verification

### Data Encryption
- AES-256-GCM for symmetric encryption
- Random 12-byte IV per encryption
- Authentication tag verification

### Request Signing
- HMAC-SHA256 for request signatures
- Timestamp validation (max 5 minute window)
- Prevents replay attacks

## Security Testing

### Attack Scenarios Tested

1. **SQL Injection**
   - UNION-based injection
   - Boolean-based injection
   - Time-based blind injection

2. **XSS (Cross-Site Scripting)**
   - Reflected XSS
   - Stored XSS
   - DOM-based XSS

3. **CSRF (Cross-Site Request Forgery)**
   - Token validation
   - Double-submit cookie

4. **Directory Traversal**
   - Path manipulation
   - Encoded path traversal

5. **Prototype Pollution**
   - __proto__ injection
   - Constructor pollution

6. **Authentication Bypass**
   - Token manipulation
   - Session hijacking

## Incident Response

### Security Event Categories

- **CRITICAL**: Authentication bypass, data breach
- **HIGH**: Multiple failed auth attempts, rate limit exceeded
- **MEDIUM**: Invalid tokens, policy violations
- **LOW**: General validation failures

### Response Actions

1. Automatic token blacklisting
2. IP-based rate limiting
3. Alert generation (via logging)
4. Request blocking
5. Audit trail maintenance

## Compliance Considerations

This implementation supports compliance with:
- OWASP Top 10
- NIST Zero Trust Architecture (SP 800-207)
- OAuth 2.0 Security Best Current Practice
- GDPR (data protection through encryption)
- SOC 2 (audit logging)

## Recommendations

1. **Regular Security Updates**
   - Keep dependencies updated
   - Monitor for CVEs
   - Apply patches promptly

2. **Secret Rotation**
   - Rotate JWT secrets periodically
   - Update certificates before expiration
   - Change encryption keys regularly

3. **Monitoring**
   - Set up alerts for security events
   - Monitor rate limit violations
   - Track authentication failures

4. **Testing**
   - Regular penetration testing
   - Automated security scanning
   - Code security reviews

5. **Documentation**
   - Keep security documentation updated
   - Document all security configurations
   - Maintain incident response procedures
