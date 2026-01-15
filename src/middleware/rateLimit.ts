import rateLimit from 'express-rate-limit';
import { Request, Response, NextFunction } from 'express';
import { config } from '../config';
import { ZeroTrustRequest, RateLimitError } from '../types';
import { securityLogger } from '../utils/logger';
import { generateRateLimitKey } from '../utils/helpers';

// Create rate limiter with custom key generator and handler
export const rateLimitMiddleware = rateLimit({
  windowMs: config.rateLimit.windowMs,
  max: config.rateLimit.max,
  message: config.rateLimit.message,
  standardHeaders: config.rateLimit.standardHeaders,
  legacyHeaders: config.rateLimit.legacyHeaders,
  skipSuccessfulRequests: config.rateLimit.skipSuccessfulRequests || false,
  skipFailedRequests: config.rateLimit.skipFailedRequests || false,

  // Custom key generator based on user ID or IP
  keyGenerator: (req: Request): string => {
    return generateRateLimitKey(req);
  },

  // Skip rate limiting for health checks
  skip: (req: Request): boolean => {
    const skipPaths = ['/health', '/ready', '/metrics'];
    return skipPaths.some(path => req.path.startsWith(path));
  },

  // Custom handler for when rate limit is exceeded
  handler: (req: Request, res: Response): void => {
    const zeroTrustReq = req as ZeroTrustRequest;

    securityLogger.warn(
      {
        requestId: zeroTrustReq.requestId,
        clientIp: zeroTrustReq.securityContext?.clientIp,
        path: req.path,
        method: req.method,
        userId: zeroTrustReq.securityContext?.user?.id,
      },
      'Rate limit exceeded'
    );

    const error = new RateLimitError('Too many requests, please try again later', {
      retryAfter: Math.ceil(config.rateLimit.windowMs / 1000),
    });

    res.status(error.statusCode).json({
      success: false,
      error: {
        code: error.code,
        message: error.message,
        retryAfter: Math.ceil(config.rateLimit.windowMs / 1000),
      },
      meta: {
        requestId: zeroTrustReq.requestId,
        timestamp: new Date().toISOString(),
      },
    });
  },
});

// Stricter rate limiter for authentication endpoints
export const authRateLimitMiddleware = rateLimit({
  windowMs: 30 * 1000, // 30 seconds TEST ONLY
  max: 5, // 5 attempts per window
  message: 'Too many authentication attempts',
  standardHeaders: true,
  legacyHeaders: false,

  keyGenerator: (req: Request): string => {
    const ip =
      (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
      req.socket.remoteAddress ||
      'unknown';
    return `auth_rate_limit:${ip}`;
  },

  handler: (req: Request, res: Response): void => {
    const zeroTrustReq = req as ZeroTrustRequest;

    securityLogger.warn(
      {
        requestId: zeroTrustReq.requestId,
        clientIp: zeroTrustReq.securityContext?.clientIp,
        path: req.path,
      },
      'Authentication rate limit exceeded - possible brute force attempt'
    );

    res.status(429).json({
      success: false,
      error: {
        code: 'AUTH_RATE_LIMIT_ERROR',
        message: 'Too many authentication attempts. Please try again later.',
        retryAfter: 30, // 30 seconds TEST ONLY
      },
      meta: {
        requestId: zeroTrustReq.requestId,
        timestamp: new Date().toISOString(),
      },
    });
  },
});

// API endpoint specific rate limiter
export const createEndpointRateLimiter = (max: number, windowMs: number = 60000) => {
  return rateLimit({
    windowMs,
    max,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req: Request): string => {
      return generateRateLimitKey(req);
    },
    handler: (req: Request, res: Response): void => {
      const zeroTrustReq = req as ZeroTrustRequest;
      res.status(429).json({
        success: false,
        error: {
          code: 'ENDPOINT_RATE_LIMIT_ERROR',
          message: 'Rate limit exceeded for this endpoint',
        },
        meta: {
          requestId: zeroTrustReq.requestId,
          timestamp: new Date().toISOString(),
        },
      });
    },
  });
};

// Sliding window rate limiter middleware (memory-based fallback)
const slidingWindowStore = new Map<string, { count: number; resetTime: number }>();

export const slidingWindowRateLimiter = (maxRequests: number, windowMs: number) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    const zeroTrustReq = req as ZeroTrustRequest;
    const key = generateRateLimitKey(req);
    const now = Date.now();

    let record = slidingWindowStore.get(key);

    if (!record || now > record.resetTime) {
      record = { count: 1, resetTime: now + windowMs };
      slidingWindowStore.set(key, record);
    } else {
      record.count++;
    }

    if (record.count > maxRequests) {
      securityLogger.warn(
        {
          requestId: zeroTrustReq.requestId,
          key,
          count: record.count,
          max: maxRequests,
        },
        'Sliding window rate limit exceeded'
      );

      res.status(429).json({
        success: false,
        error: {
          code: 'RATE_LIMIT_ERROR',
          message: 'Too many requests',
          retryAfter: Math.ceil((record.resetTime - now) / 1000),
        },
        meta: {
          requestId: zeroTrustReq.requestId,
          timestamp: new Date().toISOString(),
        },
      });
      return;
    }

    next();
  };
};

// Cleanup old entries periodically
setInterval(
  () => {
    const now = Date.now();
    for (const [key, record] of slidingWindowStore.entries()) {
      if (now > record.resetTime) {
        slidingWindowStore.delete(key);
      }
    }
  },
  60 * 1000
); // Clean every minute
