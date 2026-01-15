import { Request, Response } from 'express';
import { ZeroTrustRequest, SecurityContext, TrustLevel, GatewayError } from '../types';
import { generateUUID } from './crypto';

/**
 * Extract client IP from request (handles proxies)
 */
export const getClientIp = (req: Request): string => {
  const forwardedFor = req.headers['x-forwarded-for'];
  if (typeof forwardedFor === 'string') {
    return forwardedFor.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';
  }
  if (Array.isArray(forwardedFor)) {
    return forwardedFor[0] || req.socket.remoteAddress || 'unknown';
  }
  return req.socket.remoteAddress || 'unknown';
};

/**
 * Extract user agent from request
 */
export const getUserAgent = (req: Request): string => {
  return req.headers['user-agent'] || 'unknown';
};

/**
 * Initialize security context for a request
 */
export const initializeSecurityContext = (req: ZeroTrustRequest): SecurityContext => {
  const requestId = req.requestId || generateUUID();
  const clientIp = getClientIp(req);
  const userAgent = getUserAgent(req);

  return {
    requestId,
    timestamp: Date.now(),
    clientIp,
    userAgent,
    authenticated: false,
    authorized: false,
    riskScore: 0,
    trustLevel: 'none' as TrustLevel,
    policies: [],
  };
};

/**
 * Calculate risk score based on various factors
 */
export const calculateRiskScore = (context: SecurityContext): number => {
  let score = 0;

  // Check for suspicious patterns
  if (!context.authenticated) {
    score += 30;
  }

  if (!context.user?.mfaVerified) {
    score += 20;
  }

  // Check device trust
  if (context.device && !context.device.trusted) {
    score += 25;
  }

  // Check for risk indicators
  if (context.device?.riskIndicators) {
    score += context.device.riskIndicators.length * 10;
  }

  // Normalize score to 0-100
  return Math.min(score, 100);
};

/**
 * Determine trust level based on risk score and authentication state
 */
export const determineTrustLevel = (context: SecurityContext): TrustLevel => {
  if (!context.authenticated) {
    return 'none' as TrustLevel;
  }

  const riskScore = context.riskScore;

  if (riskScore <= 10 && context.user?.mfaVerified && context.device?.trusted) {
    return 'verified' as TrustLevel;
  }

  if (riskScore <= 25) {
    return 'high' as TrustLevel;
  }

  if (riskScore <= 50) {
    return 'medium' as TrustLevel;
  }

  return 'low' as TrustLevel;
};

/**
 * Format error response
 */
export const formatErrorResponse = (
  error: Error | GatewayError,
  requestId?: string
): GatewayError => {
  if ('code' in error && 'statusCode' in error) {
    return {
      code: error.code,
      message: error.message,
      statusCode: error.statusCode,
      details: 'details' in error ? (error.details as Record<string, unknown>) : undefined,
      requestId,
      timestamp: new Date(),
    };
  }

  return {
    code: 'INTERNAL_ERROR',
    message: error.message || 'An unexpected error occurred',
    statusCode: 500,
    requestId,
    timestamp: new Date(),
  };
};

/**
 * Send standardized JSON response
 */
export const sendJsonResponse = <T>(
  res: Response,
  statusCode: number,
  data: T,
  meta?: Record<string, unknown>
): void => {
  res.status(statusCode).json({
    success: statusCode >= 200 && statusCode < 300,
    data,
    meta: {
      timestamp: new Date().toISOString(),
      ...meta,
    },
  });
};

/**
 * Send error response
 */
export const sendErrorResponse = (
  res: Response,
  error: Error | GatewayError,
  requestId?: string
): void => {
  const formattedError = formatErrorResponse(error, requestId);

  res.status(formattedError.statusCode).json({
    success: false,
    error: {
      code: formattedError.code,
      message: formattedError.message,
      details: formattedError.details,
    },
    meta: {
      requestId: formattedError.requestId,
      timestamp: formattedError.timestamp.toISOString(),
    },
  });
};

/**
 * Parse authorization header
 */
export const parseAuthorizationHeader = (
  header: string | undefined
): { scheme: string; token: string } | null => {
  if (!header) {
    return null;
  }

  const parts = header.split(' ');
  if (parts.length !== 2) {
    return null;
  }

  return {
    scheme: parts[0]!.toLowerCase(),
    token: parts[1]!,
  };
};

/**
 * Mask sensitive data for logging
 */
export const maskSensitiveData = (data: Record<string, unknown>): Record<string, unknown> => {
  const sensitiveKeys = ['password', 'token', 'secret', 'key', 'authorization', 'cookie'];
  const masked: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(data)) {
    if (sensitiveKeys.some(sensitive => key.toLowerCase().includes(sensitive))) {
      masked[key] = '[REDACTED]';
    } else if (typeof value === 'object' && value !== null) {
      masked[key] = maskSensitiveData(value as Record<string, unknown>);
    } else {
      masked[key] = value;
    }
  }

  return masked;
};

/**
 * Validate URL safety
 */
export const isUrlSafe = (url: string): boolean => {
  try {
    const parsed = new URL(url);
    // Prevent SSRF attacks - block internal/private IPs
    const blockedHosts = [
      'localhost',
      '127.0.0.1',
      '::1',
      '0.0.0.0',
      '169.254.169.254', // AWS metadata
      '100.100.100.200', // Alibaba Cloud metadata
    ];

    if (blockedHosts.includes(parsed.hostname)) {
      return false;
    }

    // Block private IP ranges
    const privateIPPatterns = [
      /^10\./,
      /^172\.(1[6-9]|2[0-9]|3[01])\./,
      /^192\.168\./,
      /^fc00:/,
      /^fe80:/,
    ];

    for (const pattern of privateIPPatterns) {
      if (pattern.test(parsed.hostname)) {
        return false;
      }
    }

    // Only allow http and https
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return false;
    }

    return true;
  } catch {
    return false;
  }
};

/**
 * Rate limit key generator based on user and IP
 */
export const generateRateLimitKey = (req: Request): string => {
  const zeroTrustReq = req as ZeroTrustRequest;
  const userId = zeroTrustReq.securityContext?.user?.id;
  const ip = getClientIp(req);

  if (userId) {
    return `rate_limit:user:${userId}`;
  }

  return `rate_limit:ip:${ip}`;
};

/**
 * Sanitize string input
 */
export const sanitizeString = (input: string): string => {
  return input
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
};

/**
 * Deep freeze an object (make it immutable)
 */
export const deepFreeze = <T extends object>(obj: T): T => {
  Object.freeze(obj);

  Object.getOwnPropertyNames(obj).forEach(prop => {
    const value = (obj as Record<string, unknown>)[prop];
    if (
      value !== null &&
      typeof value === 'object' &&
      !Object.isFrozen(value)
    ) {
      deepFreeze(value as object);
    }
  });

  return obj;
};

/**
 * Sleep helper for async operations
 */
export const sleep = (ms: number): Promise<void> => {
  return new Promise(resolve => setTimeout(resolve, ms));
};

/**
 * Retry with exponential backoff
 */
export const retryWithBackoff = async <T>(
  fn: () => Promise<T>,
  maxRetries: number = 3,
  baseDelayMs: number = 1000,
  maxDelayMs: number = 10000
): Promise<T> => {
  let lastError: Error | undefined;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error as Error;

      if (attempt === maxRetries) {
        break;
      }

      const delay = Math.min(baseDelayMs * Math.pow(2, attempt), maxDelayMs);
      await sleep(delay);
    }
  }

  throw lastError;
};
