import { Router, Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { z } from 'zod';
import {
  ZeroTrustRequest,
  TokenPair,
  AuthenticationError,
} from '../types';
import { config } from '../config';
import { logger, securityLogger } from '../utils/logger';
import {
  generatePKCEChallenge,
  generateOAuthState,
  generateNonce,
  hashPassword,
  verifyPassword,
} from '../utils/crypto';
import { createValidationMiddleware } from '../middleware/validation';
import { authRateLimitMiddleware } from '../middleware/rateLimit';
import { blacklistToken, jwtAuthMiddleware } from '../middleware/jwt';
import { csrfTokenGenerator } from '../middleware/csrf';
import { logAuthenticationEvent } from '../middleware/audit';
import { userRepository } from '../db/repositories/UserRepository';
import { sessionRepository } from '../db/repositories/SessionRepository';
import { db } from '../db/connection';
import { generateTokenPair, parseExpiration } from '../services/tokenPair';
import {
  generateFingerprint,
  calculateDeviceTrustScore,
  updateDeviceTrust,
} from '../services/deviceFingerprint';

const router = Router();

// PKCE store
const pkceStore = new Map<
  string,
  {
    codeChallenge: string;
    codeChallengeMethod: string;
    expiry: number;
  }
>();

// Validation
const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
});

const registerSchema = z.object({
  email: z.string().email(),
  username: z.string().min(3).max(30),
  password: z.string().min(8).max(100),
});

const refreshTokenSchema = z
  .object({
    refreshToken: z.string().optional(),
  })
  .default({});

const getCookieOptions = () => {
  const isProduction = config.server.env === 'production';

  return {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'lax' as const,
    path: '/',
  };
};

const setAuthCookies = (res: Response, tokens: TokenPair): void => {
  const cookieOptions = getCookieOptions();
  const accessMaxAge = tokens.expiresIn * 1000;
  const refreshMaxAge = parseExpiration(config.jwt.refreshExpiration) * 1000;

  res.cookie('accessToken', tokens.accessToken, {
    ...cookieOptions,
    maxAge: accessMaxAge,
  });
  res.cookie('refreshToken', tokens.refreshToken, {
    ...cookieOptions,
    maxAge: refreshMaxAge,
  });
};

const clearAuthCookies = (res: Response): void => {
  const cookieOptions = getCookieOptions();
  res.clearCookie('accessToken', cookieOptions);
  res.clearCookie('refreshToken', cookieOptions);
};

// Register
router.post(
  '/register',
  authRateLimitMiddleware,
  createValidationMiddleware(registerSchema),
  async (req: Request, res: Response, next: NextFunction) => {
    const zeroTrustReq = req as ZeroTrustRequest;

    try {
      const { email, username, password } = req.body as z.infer<typeof registerSchema>;

      // Check if user exists
      if (db.isHealthy()) {
        const existingUserByEmail = await userRepository.findByEmail(email);
        const existingUserByUsername = await userRepository.findByUsername(username);

        if (existingUserByEmail) {
          throw new AuthenticationError('User already exists', { field: 'email' });
        }

        if (existingUserByUsername) {
          throw new AuthenticationError('User already exists', { field: 'username' });
        }
      }

      // Hash password
      const passwordHash = await hashPassword(password);

      // Create user
      let userId: string;
      if (db.isHealthy()) {
        const newUser = await userRepository.create({
          email,
          username,
          passwordHash,
          roles: ['user'],
          permissions: ['read:own', 'write:own'],
        });

        userId = newUser._id.toString();
        logger.info({ userId, email, username }, 'User registered successfully in database');
      } else {
        // Fallback if DB is down
        userId = `user_${Date.now()}`;
        logger.warn({ email, username }, 'User registered without database - data will be lost on restart');
      }

      res.status(201).json({
        success: true,
        data: {
          userId,
          email,
          username,
          message: 'User registered successfully',
        },
        meta: {
          requestId: zeroTrustReq.requestId,
          timestamp: new Date().toISOString(),
        },
      });
    } catch (error) {
      next(error);
    }
  }
);

/**
 * Login endpoint
 */
router.post(
  '/login',
  authRateLimitMiddleware,
  createValidationMiddleware(loginSchema),
  async (req: Request, res: Response, next: NextFunction) => {
    const zeroTrustReq = req as ZeroTrustRequest;

    try {
      const { email, password } = req.body as z.infer<typeof loginSchema>;

      // Load user
      let user;
      if (db.isHealthy()) {
        user = await userRepository.findByEmail(email);
      }

      if (!user) {
        logAuthenticationEvent(false, zeroTrustReq, undefined, { email });
        throw new AuthenticationError('Invalid credentials');
      }

      // Verify password
      const isValid = await verifyPassword(password, user.passwordHash);

      if (!isValid) {
        logAuthenticationEvent(false, zeroTrustReq, user._id.toString(), { email });
        throw new AuthenticationError('Invalid credentials');
      }

      // Issue tokens
      const userId = user._id.toString();
      const mfaRequired = user.mfaEnabled || false;

      const tokenPair = await generateTokenPair(
        {
          id: userId,
          email: user.email,
          username: user.username,
          roles: user.roles,
          permissions: user.permissions,
          mfaVerified: !mfaRequired,
        },
        zeroTrustReq
      );

      // If MFA is enabled, return a partial token
      if (mfaRequired) {
        logger.info({ userId, email }, 'Login successful, MFA verification required');

        clearAuthCookies(res);
        res.json({
          success: true,
          data: {
            requiresMfa: true,
            partialToken: tokenPair.accessToken,
            message: 'Please complete MFA verification',
            nextStep: 'POST /auth/mfa/verify',
          },
          meta: {
            requestId: zeroTrustReq.requestId,
            timestamp: new Date().toISOString(),
          },
        });
        return;
      }

      // Update last login after full auth
      if (db.isHealthy()) {
        await userRepository.updateLastLogin(userId);
      }

      // Update device after login (async)
      if (db.isHealthy()) {
        const deviceInfo = generateFingerprint(req);
        calculateDeviceTrustScore(deviceInfo.fingerprint, userId)
          .then(score => updateDeviceTrust(userId, deviceInfo, score.trustScore))
          .catch(error => {
            logger.error({ error, userId }, 'Failed to register device on login');
          });
      }

      setAuthCookies(res, tokenPair);
      logAuthenticationEvent(true, zeroTrustReq, userId, { email });

      securityLogger.info(
        {
          requestId: zeroTrustReq.requestId,
          userId,
          email: user.email,
        },
        'User logged in successfully'
      );

      res.json({
        success: true,
        data: {
          user: {
            id: userId,
            email: user.email,
            username: user.username,
            roles: user.roles,
          },
        },
        meta: {
          requestId: zeroTrustReq.requestId,
          timestamp: new Date().toISOString(),
        },
      });
    } catch (error) {
      next(error);
    }
  }
);

// Current user
router.get('/me', jwtAuthMiddleware, (req: Request, res: Response) => {
  const zeroTrustReq = req as ZeroTrustRequest;
  const user = zeroTrustReq.securityContext?.user;

  if (!user) {
    res.status(401).json({
      success: false,
      error: {
        code: 'UNAUTHORIZED',
        message: 'Authentication required',
      },
      meta: {
        requestId: zeroTrustReq.requestId,
        timestamp: new Date().toISOString(),
      },
    });
    return;
  }

  res.json({
    success: true,
    data: {
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        roles: user.roles,
        permissions: user.permissions,
      },
    },
    meta: {
      requestId: zeroTrustReq.requestId,
      timestamp: new Date().toISOString(),
    },
  });
});

// Refresh token
router.post(
  '/refresh',
  createValidationMiddleware(refreshTokenSchema),
  async (req: Request, res: Response, next: NextFunction) => {
    const zeroTrustReq = req as ZeroTrustRequest;

    try {
      const { refreshToken: refreshTokenBody } = req.body as z.infer<typeof refreshTokenSchema>;
      const refreshToken = refreshTokenBody || req.cookies?.refreshToken;

      if (!refreshToken) {
        throw new AuthenticationError('Refresh token missing');
      }

      // Verify refresh token
      const decoded = jwt.verify(refreshToken, config.jwt.secret) as {
        sub: string;
        sessionId: string;
      };

      // Check session
      let session;
      if (db.isHealthy()) {
        session = await sessionRepository.findByRefreshToken(refreshToken);

        if (!session) {
          throw new AuthenticationError('Invalid refresh token');
        }

        // Check expiry
        if (new Date() > session.expiresAt) {
          await sessionRepository.deleteByRefreshToken(refreshToken);
          throw new AuthenticationError('Refresh token expired');
        }
      }

      // Load user
      let user;
      if (db.isHealthy()) {
        user = await userRepository.findById(decoded.sub);
      }

      if (!user) {
        throw new AuthenticationError('User not found');
      }

      // Revoke old session
      if (db.isHealthy() && session) {
        await sessionRepository.deleteByRefreshToken(refreshToken);
      }

      // Issue new tokens
      const userId = user._id.toString();
      const newTokenPair = await generateTokenPair(
        {
          id: userId,
          email: user.email,
          username: user.username,
          roles: user.roles,
          permissions: user.permissions,
        },
        zeroTrustReq
      );

      logger.info({ userId }, 'Token refreshed successfully');

      setAuthCookies(res, newTokenPair);
      res.json({
        success: true,
        data: {
          message: 'Token refreshed successfully',
        },
        meta: {
          requestId: zeroTrustReq.requestId,
          timestamp: new Date().toISOString(),
        },
      });
    } catch (error) {
      next(error);
    }
  }
);

// Logout
router.post('/logout', async (req: Request, res: Response) => {
  const zeroTrustReq = req as ZeroTrustRequest;

  try {
    // Get token
    const authHeader = req.headers.authorization;
    const headerToken =
      authHeader && authHeader.startsWith('Bearer ') ? authHeader.substring(7) : undefined;
    const cookieToken = req.cookies?.accessToken as string | undefined;
    const token = headerToken || cookieToken;

    if (token) {

      // Blacklist access token
      await blacklistToken(token, 'logout');

      logger.info({ requestId: zeroTrustReq.requestId }, 'User logged out');
    }

    // Invalidate refresh token
    const refreshToken =
      (req.body?.refreshToken as string | undefined) || req.cookies?.refreshToken;
    if (refreshToken && db.isHealthy()) {
      await sessionRepository.deleteByRefreshToken(refreshToken);
    }

    clearAuthCookies(res);
    res.json({
      success: true,
      data: {
        message: 'Logged out successfully',
      },
      meta: {
        requestId: zeroTrustReq.requestId,
        timestamp: new Date().toISOString(),
      },
    });
  } catch (error) {
    logger.error({ error, requestId: zeroTrustReq.requestId }, 'Logout error');
    clearAuthCookies(res);
    res.json({
      success: true,
      data: {
        message: 'Logged out successfully',
      },
      meta: {
        requestId: zeroTrustReq.requestId,
        timestamp: new Date().toISOString(),
      },
    });
  }
});

// CSRF token
router.get('/csrf-token', csrfTokenGenerator, (req: Request, res: Response) => {
  const zeroTrustReq = req as ZeroTrustRequest;

  res.json({
    success: true,
    data: {
      csrfToken: res.locals.csrfToken,
    },
    meta: {
      requestId: zeroTrustReq.requestId,
      timestamp: new Date().toISOString(),
    },
  });
});

// OAuth start
router.get('/oauth/authorize', (req: Request, res: Response) => {
  const zeroTrustReq = req as ZeroTrustRequest;

  // Build PKCE challenge
  const pkceChallenge = generatePKCEChallenge();
  const state = generateOAuthState();
  const nonce = generateNonce();

  // Store PKCE
  pkceStore.set(state, {
    codeChallenge: pkceChallenge.codeChallenge,
    codeChallengeMethod: pkceChallenge.codeChallengeMethod,
    expiry: Date.now() + 10 * 60 * 1000, // 10 minutes
  });

  // Build auth URL
  const authUrl = new URL(config.oauth.authorizationUrl || 'http://localhost:3001/oauth/authorize');
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('client_id', config.oauth.clientId);
  authUrl.searchParams.set('redirect_uri', config.oauth.redirectUri);
  authUrl.searchParams.set('scope', config.oauth.scope);
  authUrl.searchParams.set('state', state);
  authUrl.searchParams.set('code_challenge', pkceChallenge.codeChallenge);
  authUrl.searchParams.set('code_challenge_method', pkceChallenge.codeChallengeMethod);
  authUrl.searchParams.set('nonce', nonce);

  res.json({
    success: true,
    data: {
      authorizationUrl: authUrl.toString(),
      state,
      codeVerifier: pkceChallenge.codeVerifier, // Client should store this securely
    },
    meta: {
      requestId: zeroTrustReq.requestId,
      timestamp: new Date().toISOString(),
    },
  });
});

// OAuth callback
router.get('/oauth/callback', (req: Request, res: Response) => {
  const zeroTrustReq = req as ZeroTrustRequest;
  const { code, state, error } = req.query as {
    code?: string;
    state?: string;
    error?: string;
  };

  if (error) {
    res.status(400).json({
      success: false,
      error: {
        code: 'OAUTH_ERROR',
        message: error,
      },
      meta: {
        requestId: zeroTrustReq.requestId,
        timestamp: new Date().toISOString(),
      },
    });
    return;
  }

  if (!code || !state) {
    res.status(400).json({
      success: false,
      error: {
        code: 'INVALID_CALLBACK',
        message: 'Missing authorization code or state',
      },
      meta: {
        requestId: zeroTrustReq.requestId,
        timestamp: new Date().toISOString(),
      },
    });
    return;
  }

  // Verify state
  const pkceData = pkceStore.get(state);
  if (!pkceData || Date.now() > pkceData.expiry) {
    pkceStore.delete(state);
    res.status(400).json({
      success: false,
      error: {
        code: 'INVALID_STATE',
        message: 'Invalid or expired state parameter',
      },
      meta: {
        requestId: zeroTrustReq.requestId,
        timestamp: new Date().toISOString(),
      },
    });
    return;
  }

  // Clean up
  pkceStore.delete(state);

  // Return code for token exchange
  res.json({
    success: true,
    data: {
      code,
      message: 'Authorization successful. Exchange code for tokens using /auth/oauth/token',
    },
    meta: {
      requestId: zeroTrustReq.requestId,
      timestamp: new Date().toISOString(),
    },
  });
});

// Clean expired PKCE data
setInterval(
  () => {
    const now = Date.now();

    // Cleanup
    for (const [state, data] of pkceStore.entries()) {
      if (now > data.expiry) {
        pkceStore.delete(state);
      }
    }
  },
  5 * 60 * 1000
);

export default router;
