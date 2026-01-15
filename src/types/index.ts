import { Request } from 'express';
import { JwtPayload } from 'jsonwebtoken';

// Zero Trust Security Context
export interface SecurityContext {
  requestId: string;
  timestamp: number;
  clientIp: string;
  userAgent: string;
  authenticated: boolean;
  authorized: boolean;
  user?: AuthenticatedUser;
  device?: DeviceInfo;
  riskScore: number;
  trustLevel: TrustLevel;
  policies: PolicyDecision[];
}

export type TrustLevel = 'none' | 'low' | 'medium' | 'high' | 'verified';

export interface AuthenticatedUser {
  id: string;
  email: string;
  username: string;
  roles: string[];
  permissions: string[];
  attributes: Record<string, unknown>;
  sessionId: string;
  lastActivity: number;
  mfaVerified: boolean;
}

export interface DeviceInfo {
  id: string;
  fingerprint: string;
  trusted: boolean;
  lastSeen: number;
  riskIndicators: string[];
}

export interface PolicyDecision {
  policyId: string;
  policyName: string;
  decision: 'allow' | 'deny' | 'conditional';
  reason: string;
  conditions?: Record<string, unknown>;
  timestamp: number;
}

// JWT Token Types
export interface JWTTokenPayload extends JwtPayload {
  sub: string;
  email: string;
  username: string;
  roles: string[];
  permissions: string[];
  sessionId: string;
  deviceId?: string;
  mfaVerified?: boolean;
  iat: number;
  exp: number;
  iss: string;
  aud: string | string[];
}

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  tokenType: string;
}

// OAuth 2.0 / PKCE Types
export interface PKCEChallenge {
  codeVerifier: string;
  codeChallenge: string;
  codeChallengeMethod: 'S256' | 'plain';
}

export interface OAuthAuthorizationRequest {
  responseType: string;
  clientId: string;
  redirectUri: string;
  scope: string;
  state: string;
  codeChallenge: string;
  codeChallengeMethod: string;
  nonce?: string;
}

export interface OAuthTokenRequest {
  grantType: string;
  code: string;
  redirectUri: string;
  clientId: string;
  codeVerifier: string;
}

export interface OAuthTokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  id_token?: string;
  scope?: string;
}

// Rate Limiting Types
export interface RateLimitInfo {
  key: string;
  totalHits: number;
  resetTime: Date;
  remaining: number;
  retryAfter?: number;
}

export interface RateLimitConfig {
  windowMs: number;
  max: number;
  message: string;
  standardHeaders: boolean;
  legacyHeaders: boolean;
  skipSuccessfulRequests?: boolean;
  skipFailedRequests?: boolean;
  keyGenerator?: (req: Request) => string;
}

// Open Policy Agent Types
export interface OPAInput {
  request: {
    method: string;
    path: string;
    headers: Record<string, string>;
    query: Record<string, string>;
    body?: unknown;
  };
  subject: {
    user?: AuthenticatedUser;
    client: {
      ip: string;
      userAgent: string;
    };
  };
  resource: {
    type: string;
    id?: string;
    attributes?: Record<string, unknown>;
  };
  action: string;
  context: {
    time: string;
    environment: string;
    requestId: string;
  };
}

export interface OPAResponse {
  result: boolean | OPADecisionResult;
}

export interface OPADecisionResult {
  allow: boolean;
  reasons?: string[];
  obligations?: Record<string, unknown>;
}

// mTLS Types
export interface MTLSConfig {
  enabled: boolean;
  caCertPath: string;
  serverCertPath: string;
  serverKeyPath: string;
  clientCertRequired: boolean;
  verifyDepth: number;
  checkCRL: boolean;
  checkOCSP: boolean;
}

export interface CertificateInfo {
  subject: string;
  issuer: string;
  serialNumber: string;
  validFrom: Date;
  validTo: Date;
  fingerprint: string;
  publicKey: string;
}

// GraphQL Federation Types
export interface FederatedService {
  name: string;
  url: string;
  sdl?: string;
  healthCheckUrl?: string;
  timeout?: number;
  retryAttempts?: number;
}

export interface GraphQLContext {
  securityContext: SecurityContext;
  dataSources?: Record<string, unknown>;
  loaders?: Record<string, unknown>;
}

// Audit Log Types
export interface AuditLogEntry {
  id: string;
  timestamp: Date;
  requestId: string;
  action: string;
  actor: {
    userId?: string;
    ip: string;
    userAgent: string;
  };
  resource: {
    type: string;
    id?: string;
  };
  outcome: 'success' | 'failure' | 'error';
  details: Record<string, unknown>;
  securityContext: Partial<SecurityContext>;
}

// Health Check Types
export interface HealthCheckResult {
  status: 'healthy' | 'degraded' | 'unhealthy';
  timestamp: Date;
  uptime: number;
  version: string;
  checks: {
    [service: string]: {
      status: 'up' | 'down' | 'degraded';
      responseTime?: number;
      lastCheck: Date;
      details?: Record<string, unknown>;
    };
  };
}

// Error Types
export interface GatewayError {
  code: string;
  message: string;
  statusCode: number;
  details?: Record<string, unknown>;
  requestId?: string;
  timestamp: Date;
}

export class ZeroTrustError extends Error {
  public readonly code: string;
  public readonly statusCode: number;
  public readonly details?: Record<string, unknown>;

  constructor(
    message: string,
    code: string = 'ZERO_TRUST_ERROR',
    statusCode: number = 500,
    details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'ZeroTrustError';
    this.code = code;
    this.statusCode = statusCode;
    this.details = details;
    Error.captureStackTrace(this, this.constructor);
  }
}

export class AuthenticationError extends ZeroTrustError {
  constructor(message: string = 'Authentication failed', details?: Record<string, unknown>) {
    super(message, 'AUTHENTICATION_ERROR', 401, details);
    this.name = 'AuthenticationError';
  }
}

export class AuthorizationError extends ZeroTrustError {
  constructor(message: string = 'Authorization denied', details?: Record<string, unknown>) {
    super(message, 'AUTHORIZATION_ERROR', 403, details);
    this.name = 'AuthorizationError';
  }
}

export class RateLimitError extends ZeroTrustError {
  constructor(message: string = 'Rate limit exceeded', details?: Record<string, unknown>) {
    super(message, 'RATE_LIMIT_ERROR', 429, details);
    this.name = 'RateLimitError';
  }
}

export class PolicyViolationError extends ZeroTrustError {
  constructor(message: string = 'Policy violation', details?: Record<string, unknown>) {
    super(message, 'POLICY_VIOLATION_ERROR', 403, details);
    this.name = 'PolicyViolationError';
  }
}

// Express Request Extension
export interface ZeroTrustRequest extends Request {
  securityContext?: SecurityContext;
  requestId?: string;
  startTime?: number;
}

// Configuration Types
export interface GatewayConfig {
  server: ServerConfig;
  security: SecurityConfig;
  jwt: JWTConfig;
  oauth: OAuthConfig;
  rateLimit: RateLimitConfig;
  opa: OPAConfig;
  mtls: MTLSConfig;
  graphql: GraphQLConfig;
  services: ServiceRegistryConfig;
  logging: LoggingConfig;
  monitoring: MonitoringConfig;
  mongodb: MongoDBConfig;
}

export interface ServerConfig {
  port: number;
  host: string;
  env: string;
}

export interface SecurityConfig {
  zeroTrustMode: 'strict' | 'moderate' | 'permissive';
  verifyAllRequests: boolean;
  defaultDeny: boolean;
  csrfProtection: boolean;
  corsEnabled: boolean;
  corsOrigins: string[];
}

export interface JWTConfig {
  secret: string;
  expiration: string;
  refreshExpiration: string;
  issuer: string;
  audience: string;
  algorithm: string;
}

export interface OAuthConfig {
  authorizationUrl: string;
  tokenUrl: string;
  userInfoUrl: string;
  jwksUrl: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  scope: string;
}

export interface OPAConfig {
  enabled: boolean;
  url: string;
  policyPath: string;
  timeoutMs: number;
  cacheTtlMs: number;
}

export interface GraphQLConfig {
  path: string;
  playgroundEnabled: boolean;
  introspectionEnabled: boolean;
  debug: boolean;
  maxDepth: number;
  maxComplexity: number;
}

export interface ServiceRegistryConfig {
  [serviceName: string]: string;
}

export interface LoggingConfig {
  level: string;
  format: string;
  filePath: string;
  maxSize: string;
  maxFiles: number;
  compress: boolean;
}

export interface MonitoringConfig {
  metricsEnabled: boolean;
  metricsPath: string;
  metricsPort: number;
  healthCheckPath: string;
  healthCheckIntervalMs: number;
}

export interface MongoDBConfig {
  uri: string;
  dbName: string;
  user?: string;
  password?: string;
  maxPoolSize: number;
}
