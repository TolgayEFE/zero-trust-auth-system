import dotenv from 'dotenv';
import { z } from 'zod';
import { GatewayConfig } from '../types';

// Load environment variables
dotenv.config();

// Environment validation schema
const envSchema = z.object({
  // Server
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z.string().transform(Number).default('3000'),
  HOST: z.string().default('0.0.0.0'),

  // Zero Trust
  ZERO_TRUST_MODE: z.enum(['strict', 'moderate', 'permissive']).default('strict'),
  VERIFY_ALL_REQUESTS: z
    .string()
    .transform(v => v === 'true')
    .default('true'),
  DEFAULT_DENY: z
    .string()
    .transform(v => v === 'true')
    .default('true'),

  // JWT
  JWT_SECRET: z.string().min(32),
  JWT_EXPIRATION: z.string().default('15m'),
  JWT_REFRESH_EXPIRATION: z.string().default('7d'),
  JWT_ISSUER: z.string().default('zero-trust-gateway'),
  JWT_AUDIENCE: z.string().default('zero-trust-services'),

  // OAuth
  OAUTH_AUTHORIZATION_URL: z.string().url().optional(),
  OAUTH_TOKEN_URL: z.string().url().optional(),
  OAUTH_USERINFO_URL: z.string().url().optional(),
  OAUTH_JWKS_URL: z.string().url().optional(),
  OAUTH_CLIENT_ID: z.string().optional(),
  OAUTH_CLIENT_SECRET: z.string().optional(),
  OAUTH_REDIRECT_URI: z.string().url().optional(),
  OAUTH_SCOPE: z.string().default('openid profile email'),

  // Rate Limiting
  RATE_LIMIT_WINDOW_MS: z.string().transform(Number).default('900000'),
  RATE_LIMIT_MAX_REQUESTS: z.string().transform(Number).default('100'),

  // Redis
  REDIS_HOST: z.string().default('localhost'),
  REDIS_PORT: z.string().transform(Number).default('6379'),
  REDIS_PASSWORD: z.string().optional(),

  // MongoDB
  MONGODB_URI: z.string().default('mongodb://localhost:27017'),
  MONGODB_DB_NAME: z.string().default('zero-trust-auth'),
  MONGODB_USER: z.string().optional(),
  MONGODB_PASSWORD: z.string().optional(),
  MONGODB_MAX_POOL_SIZE: z.string().transform(Number).default('10'),

  // CSRF
  CSRF_SECRET: z.string().optional(),

  // mTLS
  MTLS_ENABLED: z
    .string()
    .transform(v => v === 'true')
    .default('false'),
  MTLS_CA_CERT_PATH: z.string().default('./certs/ca.crt'),
  MTLS_SERVER_CERT_PATH: z.string().default('./certs/server.crt'),
  MTLS_SERVER_KEY_PATH: z.string().default('./certs/server.key'),
  MTLS_CLIENT_CERT_REQUIRED: z
    .string()
    .transform(v => v === 'true')
    .default('true'),

  // OPA
  OPA_ENABLED: z
    .string()
    .transform(v => v === 'true')
    .default('false'),
  OPA_URL: z.string().default('http://localhost:8181'),
  OPA_POLICY_PATH: z.string().default('/v1/data/gateway/authz/allow'),
  OPA_TIMEOUT_MS: z.string().transform(Number).default('5000'),
  OPA_CACHE_TTL_MS: z.string().transform(Number).default('60000'),

  // GraphQL
  GRAPHQL_PATH: z.string().default('/graphql'),
  GRAPHQL_PLAYGROUND_ENABLED: z
    .string()
    .transform(v => v === 'true')
    .default('false'),
  GRAPHQL_INTROSPECTION_ENABLED: z
    .string()
    .transform(v => v === 'true')
    .default('false'),
  GRAPHQL_DEBUG: z
    .string()
    .transform(v => v === 'true')
    .default('false'),
  GRAPHQL_MAX_DEPTH: z.string().transform(Number).default('10'),
  GRAPHQL_MAX_COMPLEXITY: z.string().transform(Number).default('1000'),

  // Services
  SERVICE_USERS_URL: z.string().default(process.env.SERVICE_USERS_URL || 'http://localhost:4001/graphql'),
  SERVICE_PRODUCTS_URL: z.string().default(process.env.SERVICE_PRODUCTS_URL || 'http://localhost:4002/graphql'),
  SERVICE_ORDERS_URL: z.string().default(process.env.SERVICE_ORDERS_URL || 'http://localhost:4003/graphql'),
  SERVICE_INVENTORY_URL: z.string().default(process.env.SERVICE_INVENTORY_URL || 'http://localhost:4004/graphql'),

  // Logging
  LOG_LEVEL: z.string().default('info'),
  LOG_FORMAT: z.string().default('json'),
  LOG_FILE_PATH: z.string().default('./logs/gateway.log'),

  // Monitoring
  METRICS_ENABLED: z
    .string()
    .transform(v => v === 'true')
    .default('true'),
  METRICS_PATH: z.string().default('/metrics'),
  METRICS_PORT: z.string().transform(Number).default('9090'),
  HEALTH_CHECK_PATH: z.string().default('/health'),
  HEALTH_CHECK_INTERVAL_MS: z.string().transform(Number).default('30000'),

  // Audit
  AUDIT_LOG_ENABLED: z
    .string()
    .transform(v => v === 'true')
    .default('true'),
  AUDIT_LOG_PATH: z.string().default('./logs/audit.log'),

  // Feature Flags
  FEATURE_GRAPHQL_FEDERATION: z
    .string()
    .transform(v => v === 'true')
    .default('true'),
  FEATURE_MTLS: z
    .string()
    .transform(v => v === 'true')
    .default('false'),
  FEATURE_OPA_POLICIES: z
    .string()
    .transform(v => v === 'true')
    .default('false'),
  FEATURE_ADVANCED_RATE_LIMITING: z
    .string()
    .transform(v => v === 'true')
    .default('true'),
});

// Parse and validate environment
const parseEnv = (): z.infer<typeof envSchema> => {
  try {
    return envSchema.parse(process.env);
  } catch (error) {
    if (error instanceof z.ZodError) {
      const missingVars = error.errors.map(e => `${e.path.join('.')}: ${e.message}`).join('\n');
      throw new Error(`Environment validation failed:\n${missingVars}`);
    }
    throw error;
  }
};

const env = parseEnv();

// Build configuration object
export const config: GatewayConfig = {
  server: {
    port: env.PORT,
    host: env.HOST,
    env: env.NODE_ENV,
  },
  security: {
    zeroTrustMode: env.ZERO_TRUST_MODE,
    verifyAllRequests: env.VERIFY_ALL_REQUESTS,
    defaultDeny: env.DEFAULT_DENY,
    csrfProtection: true,
    corsEnabled: true,
    corsOrigins: process.env.CORS_ORIGINS?.split(',') || ['http://localhost:3000'],
  },
  jwt: {
    secret: env.JWT_SECRET,
    expiration: env.JWT_EXPIRATION,
    refreshExpiration: env.JWT_REFRESH_EXPIRATION,
    issuer: env.JWT_ISSUER,
    audience: env.JWT_AUDIENCE,
    algorithm: 'HS256',
  },
  oauth: {
    authorizationUrl: env.OAUTH_AUTHORIZATION_URL || '',
    tokenUrl: env.OAUTH_TOKEN_URL || '',
    userInfoUrl: env.OAUTH_USERINFO_URL || '',
    jwksUrl: env.OAUTH_JWKS_URL || '',
    clientId: env.OAUTH_CLIENT_ID || '',
    clientSecret: env.OAUTH_CLIENT_SECRET || '',
    redirectUri: env.OAUTH_REDIRECT_URI || '',
    scope: env.OAUTH_SCOPE,
  },
  rateLimit: {
    windowMs: env.RATE_LIMIT_WINDOW_MS,
    max: env.RATE_LIMIT_MAX_REQUESTS,
    message: 'Too many requests from this IP, please try again later',
    standardHeaders: true,
    legacyHeaders: false,
  },
  opa: {
    enabled: env.OPA_ENABLED,
    url: env.OPA_URL,
    policyPath: env.OPA_POLICY_PATH,
    timeoutMs: env.OPA_TIMEOUT_MS,
    cacheTtlMs: env.OPA_CACHE_TTL_MS,
  },
  mtls: {
    enabled: env.MTLS_ENABLED,
    caCertPath: env.MTLS_CA_CERT_PATH,
    serverCertPath: env.MTLS_SERVER_CERT_PATH,
    serverKeyPath: env.MTLS_SERVER_KEY_PATH,
    clientCertRequired: env.MTLS_CLIENT_CERT_REQUIRED,
    verifyDepth: 3,
    checkCRL: false,
    checkOCSP: false,
  },
  graphql: {
    path: env.GRAPHQL_PATH,
    playgroundEnabled: env.GRAPHQL_PLAYGROUND_ENABLED,
    introspectionEnabled: env.GRAPHQL_INTROSPECTION_ENABLED,
    debug: env.GRAPHQL_DEBUG,
    maxDepth: env.GRAPHQL_MAX_DEPTH,
    maxComplexity: env.GRAPHQL_MAX_COMPLEXITY,
  },
  services: {
    users: env.SERVICE_USERS_URL,
    products: env.SERVICE_PRODUCTS_URL,
    orders: env.SERVICE_ORDERS_URL,
    inventory: env.SERVICE_INVENTORY_URL,
  },
  logging: {
    level: env.LOG_LEVEL,
    format: env.LOG_FORMAT,
    filePath: env.LOG_FILE_PATH,
    maxSize: '10m',
    maxFiles: 5,
    compress: true,
  },
  monitoring: {
    metricsEnabled: env.METRICS_ENABLED,
    metricsPath: env.METRICS_PATH,
    metricsPort: env.METRICS_PORT,
    healthCheckPath: env.HEALTH_CHECK_PATH,
    healthCheckIntervalMs: env.HEALTH_CHECK_INTERVAL_MS,
  },
  mongodb: {
    uri: env.MONGODB_URI,
    dbName: env.MONGODB_DB_NAME,
    user: env.MONGODB_USER,
    password: env.MONGODB_PASSWORD,
    maxPoolSize: env.MONGODB_MAX_POOL_SIZE,
  },
};

// Feature flags
export const features = {
  graphqlFederation: env.FEATURE_GRAPHQL_FEDERATION,
  mtls: env.FEATURE_MTLS,
  opaPolicies: env.FEATURE_OPA_POLICIES,
  advancedRateLimiting: env.FEATURE_ADVANCED_RATE_LIMITING,
};

export default config;
