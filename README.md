# Zero-Trust API Gateway

A Multi-Layered Web Security Platform implementing Zero-Trust Architecture principles for microservices.

## Overview

Zero-Trust Auth is a Node.js/TypeScript API gateway that enforces identity, device trust, and policy decisions before routing traffic to GraphQL microservices. It combines JWT/OAuth authentication, optional mTLS, and OPA-based authorization with a Next.js dashboard for visibility and demos.

This project implements a comprehensive Zero-Trust security platform featuring:

- **Custom API Gateway** built with Node.js/Express.js
- **GraphQL Federation** using Apollo Gateway for unified API access
- **Multi-layered Authentication** with JWT, OAuth 2.0, and PKCE
- **Policy-based Authorization** using Open Policy Agent (OPA)
- **Security Hardening** with rate limiting, CSRF protection, and CSP
- **mTLS Support** for secure inter-service communication
- **Operational Visibility** with a built-in metrics endpoint and structured logging

## Architecture

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────────────────┐
│   Clients   │────▶│  API Gateway     │────▶│    Microservices        │
└─────────────┘     │  (Zero Trust)    │     │  - Users Service        │
                    │                  │     │  - Products Service     │
                    │                  │     │  - Orders Service       │
                    │                  │     │  - Inventory Service    │
                    │  ┌────────────┐  │     └─────────────────────────┘
                    │  │ Auth Layer │  │
                    │  │  JWT/OAuth │  │     ┌─────────────────┐
                    │  └────────────┘  │────▶│   OPA Policy    │
                    │                  │     │     Engine      │
                    │  ┌────────────┐  │     └─────────────────┘
                    │  │  Security  │  │
                    │  │   Layers   │  │     ┌─────────────────┐
                    │  │  Middleware│  │────▶│  Redis Cache    │
                    │  └────────────┘  │     │  (Optional)     │
                    │                  │     └─────────────────┘
                    │  ┌────────────┐  │
                    │  │  GraphQL   │  │
                    │  │ Federation │  │
                    │  │  Gateway   │  │
                    │  └────────────┘  │
                    └──────────────────┘
```

## Features

### Zero Trust Security
- **Never Trust, Always Verify**: Every request is authenticated and authorized
- **Continuous Verification**: Trust levels and risk scores calculated per request
- **Least Privilege Access**: Fine-grained permission and role-based access control
- **Device Trust Assessment**: Fingerprinting, trust score, and device history tracking

### Authentication & Authorization
- JWT-based authentication with configurable expiration
- OAuth 2.0 / OpenID Connect support
- PKCE (Proof Key for Code Exchange) for enhanced security
- Role-based access control (RBAC)
- Permission-based authorization
- MFA verification support
- Token blacklisting and revocation (in-memory implementation)

### API Gateway Features
- Request routing and load balancing via proxy middleware
- GraphQL Federation with Apollo Gateway
- Service discovery and health checking
- Request/response transformation
- Centralized logging and metrics

### Security Layers
- **Rate Limiting**: Configurable per-endpoint rate limits
- **CSRF Protection**: Double-submit cookie pattern
- **Content Security Policy**: Strict CSP headers via Helmet
- **Input Validation**: SQL injection, XSS, and prototype pollution protection
- **Security Headers**: HSTS, X-Frame-Options, X-Content-Type-Options
- **Audit Logging**: Comprehensive security event logging

### Stored Security Data
- **Users**: email, username, roles/permissions, password hash, MFA status/secret, backup codes, login metadata
- **Devices**: fingerprint, trust score, trusted flag, last seen, user agent, IP address
- **Sessions**: access/refresh tokens, device fingerprint, IP address, user agent, expiry
- **Token Blacklist**: revoked token hash, reason, expiry (TTL)
- **Audit Logs**: request ID, action, resource, outcome, security context metadata, timestamp

### Policy Engine (OPA)
- Declarative policy as code using Rego
- Fine-grained authorization decisions
- Cached policy evaluations
- Real-time policy updates

### mTLS Support
- Mutual TLS for service-to-service communication
- Certificate generation utilities
- TLS 1.3 with strong cipher suites
- Client certificate validation

### Monitoring & Observability
- Built-in metrics endpoint (Prometheus format)
- Structured JSON logging with Pino
- Request tracing and correlation IDs
- Health check endpoints (liveness/readiness)
- Performance metrics (latency, throughput)

## Current Limitations

This is an academic demonstration project. The following features use in-memory storage and are not production-ready without additional configuration:

- **User storage** - In-memory Map (resets on restart)
- **Session storage** - In-memory Map (no persistence across restarts)
- **Token blacklist** - In-memory Set (cleared on restart)
- **CSRF token storage** - In-memory Map (no distributed support)
- **Rate limiting counters** - In-memory store (use Redis backend for production)

**Note:** For production deployment, use a managed database and Redis for distributed session management and caching.

## Quick Start

### Prerequisites
- Node.js >= 18.0.0
- npm >= 9.0.0
- Docker & Docker Compose (optional)
- Redis (optional, for rate limiting)

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd zero-trust-auth

# Install dependencies
npm install

# Copy environment configuration
cp .env.example .env

# Edit .env with your configuration
# Important: Change JWT_SECRET to a secure value!

# Generate mTLS certificates (optional)
npm run generate:certs

# Build the project
npm run build

# Start in development mode
npm run dev
```

### Running with Docker

```bash
# Start all services
cd docker
docker-compose up -d

# View logs
docker-compose logs -f gateway

# Stop services
docker-compose down
```

### API Endpoints

#### Health Checks
```bash
# Basic health check
curl http://localhost:3000/health

# Detailed health status
curl http://localhost:3000/health/detailed

# Readiness probe
curl http://localhost:3000/health/ready

# Liveness probe
curl http://localhost:3000/health/live
```

#### Authentication
```bash
# Register a new user
curl -X POST http://localhost:3000/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "username": "newuser",
    "password": "SecurePass123!"
  }'

# Login
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "password123"
  }'

# Refresh token
curl -X POST http://localhost:3000/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refreshToken": "your-refresh-token"
  }'

# Logout
curl -X POST http://localhost:3000/auth/logout \
  -H "Authorization: Bearer your-access-token"
```

#### Protected API Routes
```bash
# Access protected resource
curl http://localhost:3000/api/users \
  -H "Authorization: Bearer your-jwt-token"

# Service discovery
curl http://localhost:3000/api/_services \
  -H "Authorization: Bearer your-jwt-token"
```

#### GraphQL (Federation)
```bash
curl -X POST http://localhost:3000/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-jwt-token" \
  -d '{
    "query": "{ users { id email username } }"
  }'
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `NODE_ENV` | Environment (development/production/test) | development |
| `PORT` | Server port | 3000 |
| `JWT_SECRET` | Secret for JWT signing (min 32 chars) | **Required** |
| `JWT_EXPIRATION` | Access token expiration | 15m |
| `ZERO_TRUST_MODE` | Security strictness (strict/moderate/permissive) | strict |
| `OPA_ENABLED` | Enable OPA policy engine | false |
| `OPA_URL` | OPA server URL | http://localhost:8181 |
| `MTLS_ENABLED` | Enable mutual TLS | false |
| `RATE_LIMIT_MAX_REQUESTS` | Max requests per window | 100 |
| `RATE_LIMIT_WINDOW_MS` | Rate limit window in ms | 900000 |
| `SERVICE_USERS_URL` | Users service GraphQL endpoint | http://localhost:4001/graphql |
| `SERVICE_PRODUCTS_URL` | Products service GraphQL endpoint | http://localhost:4002/graphql |
| `SERVICE_ORDERS_URL` | Orders service GraphQL endpoint | http://localhost:4003/graphql |
| `SERVICE_INVENTORY_URL` | Inventory service GraphQL endpoint | http://localhost:4004/graphql |

See `.env.example` for complete configuration options.

## Project Structure

```
zero-trust-auth/
├── certs/               # mTLS certificates (local/dev)
├── src/
│   ├── config/          # Configuration management
│   │   └── index.ts     # Environment config with Zod validation
│   ├── middleware/      # Security middleware
│   │   ├── jwt.ts       # JWT authentication & RBAC
│   │   ├── rateLimit.ts # Rate limiting
│   │   ├── csrf.ts      # CSRF protection
│   │   ├── opa.ts       # OPA policy authorization
│   │   ├── audit.ts     # Audit logging
│   │   └── validation.ts # Input validation (SQL/XSS/traversal)
│   ├── routes/          # API routes
│   │   ├── auth.ts      # Authentication endpoints (register/login/refresh/logout/OAuth)
│   │   ├── health.ts    # Health check endpoints
│   │   └── proxy.ts     # Service proxy with load balancing
│   ├── services/        # Core services
│   │   ├── health.ts    # Health checking
│   │   ├── metrics.ts   # Metrics collection (Prometheus format)
│   │   └── shutdown.ts  # Graceful shutdown handler
│   ├── graphql/         # GraphQL federation
│   │   └── gateway.ts   # Apollo Gateway configuration
│   ├── types/           # TypeScript type definitions
│   │   └── index.ts     # Security context, JWT, device types
│   ├── utils/           # Utility functions
│   │   ├── crypto.ts    # PKCE, hashing, encryption utilities
│   │   ├── logger.ts    # Pino + Winston logging
│   │   └── helpers.ts   # Risk scoring, trust level calculation
│   ├── __tests__/       # Test suites
│   │   ├── middleware/  # JWT, rate limit tests
│   │   ├── security/    # Attack scenario tests
│   │   └── utils/       # Crypto utility tests
│   ├── app.ts           # Express app with middleware stack
│   └── index.ts         # Server entry point
├── services/            # Sample microservices
│   ├── users-service/   # Users GraphQL subgraph (port 4001)
│   ├── products-service/ # Products GraphQL subgraph (port 4002)
│   ├── orders-service/  # Orders GraphQL subgraph (port 4003)
│   └── inventory-service/ # Inventory GraphQL subgraph (port 4004)
├── policies/            # OPA policies (Rego)
│   └── gateway.rego     # Authorization policy rules
├── docker/              # Docker configurations
│   ├── Dockerfile       # Gateway container
│   ├── Dockerfile.service # Microservice template
│   └── docker-compose.yml # Full stack orchestration
├── frontend/            # Next.js dashboard
├── examples/            # OPA sample inputs
│   └── opa/             # OPA allow/deny payloads
├── scripts/             # Utility scripts
│   ├── generate-certs.ts # mTLS certificate generation
│   ├── seed.ts          # Seed sample users/data
│   └── migrate.ts       # Database migration placeholder
└── logs/                # Application logs (gitignored)
```

## Testing

```bash
# Run all tests
npm test

# Run tests with coverage
npm test -- --coverage

# Run specific test suite
npm test -- --testPathPattern=jwt

# Run security tests
npm run test:security

# Watch mode
npm run test:watch
```

## Security Checks (curl)

Ready-to-run curl checks live under `examples/security/`:

- `examples/security/README.md` — manual commands and expected outcomes
- `examples/security/run_checks.sh` — automated checks with terminal output
- `examples/security/output.txt` — sample output for thesis screenshots

Run the checks:

```bash
chmod +x examples/security/run_checks.sh
API_URL=http://localhost:3000 examples/security/run_checks.sh | tee examples/security/output.txt
```

Sample results (expected):
- Invalid login → 401 (AUTHENTICATION_ERROR)
- Weak password → 400 (VALIDATION_ERROR)
- SQL injection → 400 (INVALID_QUERY_PARAMETER)
- XSS attempt → 400 (INVALID_QUERY_PARAMETER)
- Path traversal → 404 (NOT_FOUND)
- Invalid Content-Type → 415 (UNSUPPORTED_CONTENT_TYPE)
- Missing Content-Type → 400 (VALIDATION_ERROR)
- Unauthorized devices → 401 (Authorization header missing)
- Brute-force login → 429 after a few attempts (rate limit)

## Deployment

### Docker Deployment

```bash
# Build and start all services
cd docker
docker-compose up --build -d

# Scale gateway instances
docker-compose up -d --scale gateway=3

# View service health
docker-compose ps
```

### Kubernetes Deployment

This project ships with Docker Compose for local orchestration. Kubernetes manifests are not included.

## Security Considerations

### Production Checklist

- Change all default secrets (JWT_SECRET, CSRF_SECRET, etc.)
- Enable HTTPS/TLS in production
- Configure proper CORS origins
- Enable rate limiting with Redis backend
- Set up OPA with production policies
- Configure proper logging (no sensitive data)
- Enable audit logging
- Configure backup and disaster recovery
- Implement proper certificate management for mTLS
- Review and customize CSP headers
- Set up intrusion detection

### Security Best Practices

1. **Token Management**
   - Use short-lived access tokens (15 minutes recommended)
   - Implement token rotation
   - Store refresh tokens securely
   - Implement token blacklisting

2. **Input Validation**
   - Validate all inputs using Zod schemas
   - Sanitize user inputs
   - Implement request size limits
   - Check for injection attacks

3. **Monitoring**
   - Monitor failed authentication attempts
   - Track rate limit violations
   - Log security events
   - Set up alerts for suspicious activities

## Performance Optimization

- Enable response compression
- Implement caching strategies (OPA decisions, service health)
- Use connection pooling for databases
- Configure appropriate rate limits
- Monitor memory usage and implement cleanup routines
- Use horizontal pod autoscaling in Kubernetes

## Contributing

1. Follow the coding standards (ESLint + Prettier)
2. Write tests for new features
3. Update documentation
4. Run security linting: `npm run lint`
5. Ensure all tests pass: `npm test`

## License

MIT License - See LICENSE file for details.

## References

- [Zero Trust Architecture - NIST SP 800-207](https://csrc.nist.gov/publications/detail/sp/800-207/final)
- [Apollo GraphQL Federation](https://www.apollographql.com/docs/federation/)
- [Open Policy Agent](https://www.openpolicyagent.org/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OAuth 2.0 RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)
- [PKCE RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636)

## Acknowledgments

This project was developed as part of a thesis on "A Zero-Trust-Based Multi-Layered Web Security Platform: A Custom API Gateway Approach for Microservices."
