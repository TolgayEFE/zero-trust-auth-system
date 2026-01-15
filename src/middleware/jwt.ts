import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import {
  ZeroTrustRequest,
  JWTTokenPayload,
  AuthenticationError,
  AuthenticatedUser,
} from '../types';
import { config } from '../config';
import { securityLogger } from '../utils/logger';
import { parseAuthorizationHeader } from '../utils/helpers';
import { tokenRepository } from '../db/repositories/TokenRepository';
import { db } from '../db/connection';

// Token blacklist (fallback to memory if DB is down)
const tokenBlacklist = new Set<string>();

/**
 * Verify JWT token and extract payload
 */
const verifyToken = (token: string): JWTTokenPayload => {
  try {
    const payload = jwt.verify(token, config.jwt.secret, {
      issuer: config.jwt.issuer,
      audience: config.jwt.audience,
      algorithms: [config.jwt.algorithm as jwt.Algorithm],
    }) as JWTTokenPayload;

    return payload;
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      throw new AuthenticationError('Token expired', { expiredAt: error.expiredAt });
    }
    if (error instanceof jwt.JsonWebTokenError) {
      throw new AuthenticationError('Invalid token', { reason: error.message });
    }
    throw new AuthenticationError('Token verification failed');
  }
};

/**
 * Check if token is blacklisted
 */
const isTokenBlacklisted = async (token: string): Promise<boolean> => {
  // Check database if connected
  if (db.isHealthy()) {
    try {
      return await tokenRepository.isBlacklisted(token);
    } catch (error) {
      securityLogger.error('Error checking token blacklist in database:', error);
      // Fallback to memory check
    }
  }

  // Fallback to memory blacklist
  return tokenBlacklist.has(token);
};

/**
 * Add token to blacklist
 */
export const blacklistToken = async (token: string, reason: string = 'logout'): Promise<void> => {
  // Add to database if connected
  if (db.isHealthy()) {
    try {
      // Calculate expiration (use token's exp claim or default to 7 days)
      let expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

      try {
        const decoded = jwt.decode(token) as JWTTokenPayload;
        if (decoded && decoded.exp) {
          expiresAt = new Date(decoded.exp * 1000);
        }
      } catch {
        // Use default expiration
      }

      await tokenRepository.addToBlacklist(token, reason, expiresAt);
      securityLogger.info({ reason }, 'Token added to database blacklist');
    } catch (error) {
      securityLogger.error('Error adding token to database blacklist:', error);
      // Fallback to memory
      tokenBlacklist.add(token);
    }
  } else {
    // Fallback to memory blacklist
    tokenBlacklist.add(token);
  }
};

/**
 * Extract authenticated user from token payload
 */
const extractUserFromPayload = (payload: JWTTokenPayload): AuthenticatedUser => {
  return {
    id: payload.sub,
    email: payload.email,
    username: payload.username,
    roles: payload.roles || [],
    permissions: payload.permissions || [],
    attributes: {},
    sessionId: payload.sessionId,
    lastActivity: Date.now(),
    mfaVerified: payload.mfaVerified || false,
  };
};

/**
 * JWT Authentication middleware
 */
export const jwtAuthMiddleware = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  const zeroTrustReq = req as ZeroTrustRequest;

  try {
    const authHeader = req.headers.authorization;
    const cookieToken = req.cookies?.accessToken as string | undefined;

    let scheme = 'bearer';
    let token = '';

    if (authHeader) {
      const authResult = parseAuthorizationHeader(authHeader);
      if (!authResult) {
        throw new AuthenticationError('Authorization header missing');
      }
      scheme = authResult.scheme;
      token = authResult.token;
    } else if (cookieToken) {
      token = cookieToken;
    } else {
      securityLogger.debug(
        {
          requestId: zeroTrustReq.requestId,
          path: req.path,
        },
        'No authorization header or access token cookie present'
      );
      throw new AuthenticationError('Authorization header missing');
    }

    if (scheme !== 'bearer') {
      throw new AuthenticationError('Invalid authorization scheme', {
        expected: 'Bearer',
        received: scheme,
      });
    }

    // Check if token is blacklisted (async check)
    const isBlacklisted = await isTokenBlacklisted(token);
    if (isBlacklisted) {
      securityLogger.warn(
        {
          requestId: zeroTrustReq.requestId,
          clientIp: zeroTrustReq.securityContext?.clientIp,
        },
        'Blacklisted token used'
      );
      throw new AuthenticationError('Token has been revoked');
    }

    // Verify token
    const payload = verifyToken(token);

    // Extract user information
    const user = extractUserFromPayload(payload);

    // Update security context
    if (zeroTrustReq.securityContext) {
      zeroTrustReq.securityContext.authenticated = true;
      zeroTrustReq.securityContext.user = user;
    }

    securityLogger.info(
      {
        requestId: zeroTrustReq.requestId,
        userId: user.id,
        username: user.username,
        path: req.path,
      },
      'Request authenticated successfully'
    );

    next();
  } catch (error) {
    if (error instanceof AuthenticationError) {
      securityLogger.warn(
        {
          requestId: zeroTrustReq.requestId,
          clientIp: zeroTrustReq.securityContext?.clientIp,
          path: req.path,
          error: error.message,
        },
        'Authentication failed'
      );

      res.status(error.statusCode).json({
        success: false,
        error: {
          code: error.code,
          message: error.message,
          details: error.details,
        },
        meta: {
          requestId: zeroTrustReq.requestId,
          timestamp: new Date().toISOString(),
        },
      });
    } else {
      next(error);
    }
  }
};

/**
 * Optional JWT authentication (doesn't fail if no token)
 */
export const optionalJwtAuthMiddleware = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  const zeroTrustReq = req as ZeroTrustRequest;

  const authHeader = req.headers.authorization;
  const cookieToken = req.cookies?.accessToken as string | undefined;
  const authResult = authHeader ? parseAuthorizationHeader(authHeader) : null;

  if (!authResult && !cookieToken) {
    // No token provided, continue without authentication
    next();
    return;
  }

  // If token is provided, validate it
  jwtAuthMiddleware(req, res, next);
};

/**
 * Role-based authorization middleware
 */
export const requireRoles = (...roles: string[]) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    const zeroTrustReq = req as ZeroTrustRequest;
    const user = zeroTrustReq.securityContext?.user;

    if (!user) {
      res.status(401).json({
        success: false,
        error: {
          code: 'AUTHENTICATION_REQUIRED',
          message: 'Authentication required',
        },
        meta: {
          requestId: zeroTrustReq.requestId,
          timestamp: new Date().toISOString(),
        },
      });
      return;
    }

    const hasRequiredRole = roles.some(role => user.roles.includes(role));

    if (!hasRequiredRole) {
      securityLogger.warn(
        {
          requestId: zeroTrustReq.requestId,
          userId: user.id,
          userRoles: user.roles,
          requiredRoles: roles,
        },
        'Insufficient role permissions'
      );

      res.status(403).json({
        success: false,
        error: {
          code: 'INSUFFICIENT_PERMISSIONS',
          message: 'You do not have permission to access this resource',
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

/**
 * Permission-based authorization middleware
 */
export const requirePermissions = (...permissions: string[]) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    const zeroTrustReq = req as ZeroTrustRequest;
    const user = zeroTrustReq.securityContext?.user;

    if (!user) {
      res.status(401).json({
        success: false,
        error: {
          code: 'AUTHENTICATION_REQUIRED',
          message: 'Authentication required',
        },
        meta: {
          requestId: zeroTrustReq.requestId,
          timestamp: new Date().toISOString(),
        },
      });
      return;
    }

    const hasAllPermissions = permissions.every(perm => user.permissions.includes(perm));

    if (!hasAllPermissions) {
      securityLogger.warn(
        {
          requestId: zeroTrustReq.requestId,
          userId: user.id,
          userPermissions: user.permissions,
          requiredPermissions: permissions,
        },
        'Insufficient permissions'
      );

      res.status(403).json({
        success: false,
        error: {
          code: 'INSUFFICIENT_PERMISSIONS',
          message: 'You do not have the required permissions',
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

/**
 * MFA verification requirement middleware
 */
export const requireMFA = (req: Request, res: Response, next: NextFunction): void => {
  const zeroTrustReq = req as ZeroTrustRequest;
  const user = zeroTrustReq.securityContext?.user;

  if (!user) {
    res.status(401).json({
      success: false,
      error: {
        code: 'AUTHENTICATION_REQUIRED',
        message: 'Authentication required',
      },
      meta: {
        requestId: zeroTrustReq.requestId,
        timestamp: new Date().toISOString(),
      },
    });
    return;
  }

  if (!user.mfaVerified) {
    securityLogger.warn(
      {
        requestId: zeroTrustReq.requestId,
        userId: user.id,
      },
      'MFA verification required'
    );

    res.status(403).json({
      success: false,
      error: {
        code: 'MFA_REQUIRED',
        message: 'Multi-factor authentication verification required',
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

export default jwtAuthMiddleware;
