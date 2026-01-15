import { Request, Response, NextFunction } from 'express';
import { ZeroTrustRequest, ZeroTrustError } from '../types';
import { securityLogger } from '../utils/logger';
import { generateSecureRandom, signData, verifySignature } from '../utils/crypto';
import { config } from '../config';

// CSRF token store (in production, use Redis or similar)
const csrfTokenStore = new Map<string, { token: string; expiry: number }>();

// Token expiration time (1 hour)
const TOKEN_EXPIRY = 60 * 60 * 1000;

/**
 * Generate a CSRF token for a session
 */
const generateCsrfToken = (sessionId: string): string => {
  const randomPart = generateSecureRandom(32);
  const timestamp = Date.now().toString();
  const tokenData = `${sessionId}:${randomPart}:${timestamp}`;
  const signature = signData(tokenData, config.jwt.secret);
  return `${tokenData}:${signature}`;
};

/**
 * Validate a CSRF token
 */
const validateCsrfToken = (token: string, sessionId: string): boolean => {
  try {
    const parts = token.split(':');
    if (parts.length !== 4) {
      return false;
    }

    const [tokenSessionId, , timestamp, signature] = parts;

    // Check session ID matches
    if (tokenSessionId !== sessionId) {
      return false;
    }

    // Check token hasn't expired
    const tokenTime = parseInt(timestamp || '0', 10);
    if (Date.now() - tokenTime > TOKEN_EXPIRY) {
      return false;
    }

    // Verify signature
    const tokenData = parts.slice(0, 3).join(':');
    if (!signature) {
      return false;
    }
    return verifySignature(tokenData, signature, config.jwt.secret);
  } catch {
    return false;
  }
};

/**
 * Get session ID from request
 */
const getSessionId = (req: ZeroTrustRequest): string => {
  return (
    req.securityContext?.user?.sessionId ||
    req.cookies?.session_id ||
    req.requestId ||
    'anonymous'
  );
};

/**
 * CSRF protection middleware
 */
export const csrfProtection = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  const zeroTrustReq = req as ZeroTrustRequest;

  // Skip CSRF check for safe methods
  const safeMethods = ['GET', 'HEAD', 'OPTIONS'];
  if (safeMethods.includes(req.method)) {
    next();
    return;
  }

  // Skip CSRF for API calls with Bearer token (they have their own protection)
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    next();
    return;
  }

  const sessionId = getSessionId(zeroTrustReq);

  // Get CSRF token from request
  const csrfToken =
    (req.headers['x-csrf-token'] as string) ||
    (req.headers['x-xsrf-token'] as string) ||
    (req.body?._csrf as string) ||
    (req.query?._csrf as string);

  if (!csrfToken) {
    securityLogger.warn(
      {
        requestId: zeroTrustReq.requestId,
        path: req.path,
        method: req.method,
        clientIp: zeroTrustReq.securityContext?.clientIp,
      },
      'CSRF token missing'
    );

    res.status(403).json({
      success: false,
      error: {
        code: 'CSRF_TOKEN_MISSING',
        message: 'CSRF token is required for this request',
      },
      meta: {
        requestId: zeroTrustReq.requestId,
        timestamp: new Date().toISOString(),
      },
    });
    return;
  }

  // Validate token
  if (!validateCsrfToken(csrfToken, sessionId)) {
    securityLogger.warn(
      {
        requestId: zeroTrustReq.requestId,
        path: req.path,
        method: req.method,
        clientIp: zeroTrustReq.securityContext?.clientIp,
      },
      'CSRF token validation failed'
    );

    res.status(403).json({
      success: false,
      error: {
        code: 'CSRF_TOKEN_INVALID',
        message: 'Invalid CSRF token',
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

/**
 * Middleware to generate and attach CSRF token
 */
export const csrfTokenGenerator = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  const zeroTrustReq = req as ZeroTrustRequest;
  const sessionId = getSessionId(zeroTrustReq);

  // Generate new token
  const token = generateCsrfToken(sessionId);

  // Store token
  csrfTokenStore.set(sessionId, {
    token,
    expiry: Date.now() + TOKEN_EXPIRY,
  });

  // Set token in response
  res.cookie('XSRF-TOKEN', token, {
    httpOnly: false, // Must be readable by JavaScript
    secure: config.server.env === 'production',
    sameSite: 'strict',
    maxAge: TOKEN_EXPIRY,
  });

  // Also attach to locals for server-side rendering
  res.locals.csrfToken = token;

  next();
};

/**
 * Double Submit Cookie pattern validation
 */
export const doubleSubmitCookieValidation = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  const zeroTrustReq = req as ZeroTrustRequest;

  // Skip for safe methods
  const safeMethods = ['GET', 'HEAD', 'OPTIONS'];
  if (safeMethods.includes(req.method)) {
    next();
    return;
  }

  const cookieToken = req.cookies?.['XSRF-TOKEN'];
  const headerToken = req.headers['x-xsrf-token'] as string;

  if (!cookieToken || !headerToken) {
    securityLogger.warn(
      {
        requestId: zeroTrustReq.requestId,
        path: req.path,
        hasCookie: !!cookieToken,
        hasHeader: !!headerToken,
      },
      'Double submit cookie validation failed - missing token'
    );

    res.status(403).json({
      success: false,
      error: {
        code: 'CSRF_VALIDATION_FAILED',
        message: 'CSRF validation failed',
      },
      meta: {
        requestId: zeroTrustReq.requestId,
        timestamp: new Date().toISOString(),
      },
    });
    return;
  }

  // Tokens must match
  if (cookieToken !== headerToken) {
    securityLogger.warn(
      {
        requestId: zeroTrustReq.requestId,
        path: req.path,
      },
      'Double submit cookie validation failed - token mismatch'
    );

    res.status(403).json({
      success: false,
      error: {
        code: 'CSRF_TOKEN_MISMATCH',
        message: 'CSRF token mismatch',
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

// Cleanup expired tokens periodically
setInterval(
  () => {
    const now = Date.now();
    for (const [sessionId, record] of csrfTokenStore.entries()) {
      if (now > record.expiry) {
        csrfTokenStore.delete(sessionId);
      }
    }
  },
  5 * 60 * 1000
); // Clean every 5 minutes

export default csrfProtection;
