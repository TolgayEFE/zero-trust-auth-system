import { Router, Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { ZeroTrustRequest, AuthenticationError, TokenPair } from '../types';
import { jwtAuthMiddleware } from '../middleware/jwt';
import { createValidationMiddleware } from '../middleware/validation';
import { userRepository } from '../db/repositories/UserRepository';
import { db } from '../db/connection';
import { logger } from '../utils/logger';
import { config } from '../config';
import { generateTokenPair, parseExpiration } from '../services/tokenPair';
import {
  generateMFASecret,
  generateQRCodeDataURL,
  verifyTOTP,
  generateBackupCodes,
  hashBackupCodes,
  validateBackupCode,
  removeUsedBackupCode,
  areBackupCodesLow,
} from '../services/mfa';
import { verifyPassword } from '../utils/crypto';

const router = Router();

// Temporary storage for MFA enrollment (in production, use Redis with TTL)
const enrollmentSessions = new Map<
  string,
  {
    secret: string;
    backupCodes: string[];
    expiresAt: number;
  }
>();

// Validation schemas
const verifyTOTPSchema = z.object({
  token: z.string().length(6).regex(/^\d{6}$/),
});

const confirmEnrollmentSchema = z.object({
  token: z.string().length(6).regex(/^\d{6}$/),
});

const disableMFASchema = z.object({
  password: z.string().min(8),
});

const verifyBackupCodeSchema = z.object({
  code: z.string(),
});

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

/**
 * Start MFA enrollment
 * POST /auth/mfa/enroll
 */
router.post(
  '/enroll',
  jwtAuthMiddleware,
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const zeroTrustReq = req as ZeroTrustRequest;

    try {
      const userId = zeroTrustReq.securityContext?.user?.id;
      const userEmail = zeroTrustReq.securityContext?.user?.email;

      if (!userId || !userEmail) {
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

      if (!db.isHealthy()) {
        res.status(503).json({
          success: false,
          error: {
            code: 'SERVICE_UNAVAILABLE',
            message: 'Database not available',
          },
          meta: {
            requestId: zeroTrustReq.requestId,
            timestamp: new Date().toISOString(),
          },
        });
        return;
      }

      // Check if MFA already enabled
      const user = await userRepository.findByIdWithMFA(userId);
      if (user?.mfaEnabled) {
        res.status(400).json({
          success: false,
          error: {
            code: 'MFA_ALREADY_ENABLED',
            message: 'MFA is already enabled for this account',
          },
          meta: {
            requestId: zeroTrustReq.requestId,
            timestamp: new Date().toISOString(),
          },
        });
        return;
      }

      // Generate secret and backup codes
      const secretObj = generateMFASecret(userEmail);
      const backupCodes = generateBackupCodes();
      const qrCodeDataUrl = await generateQRCodeDataURL(secretObj.base32!, userEmail);

      // Store in temporary session (expires in 10 minutes)
      enrollmentSessions.set(userId, {
        secret: secretObj.base32!,
        backupCodes,
        expiresAt: Date.now() + 10 * 60 * 1000,
      });

      logger.info({ userId }, 'MFA enrollment started');

      res.json({
        success: true,
        data: {
          qrCode: qrCodeDataUrl,
          secret: secretObj.base32,
          backupCodes, // Return codes now for user to save
          message: 'Scan the QR code with your authenticator app and verify with a code',
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
 * Confirm MFA enrollment with TOTP verification
 * POST /auth/mfa/confirm-enrollment
 */
router.post(
  '/confirm-enrollment',
  jwtAuthMiddleware,
  createValidationMiddleware(confirmEnrollmentSchema),
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const zeroTrustReq = req as ZeroTrustRequest;

    try {
      const userId = zeroTrustReq.securityContext?.user?.id;
      const { token } = req.body as z.infer<typeof confirmEnrollmentSchema>;

      if (!userId) {
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

      // Get enrollment session
      const session = enrollmentSessions.get(userId);
      if (!session || Date.now() > session.expiresAt) {
        enrollmentSessions.delete(userId);
        res.status(400).json({
          success: false,
          error: {
            code: 'ENROLLMENT_EXPIRED',
            message: 'Enrollment session expired. Please start over.',
          },
          meta: {
            requestId: zeroTrustReq.requestId,
            timestamp: new Date().toISOString(),
          },
        });
        return;
      }

      // Verify TOTP token
      const isValid = verifyTOTP(session.secret, token);
      if (!isValid) {
        res.status(400).json({
          success: false,
          error: {
            code: 'INVALID_TOKEN',
            message: 'Invalid verification code',
          },
          meta: {
            requestId: zeroTrustReq.requestId,
            timestamp: new Date().toISOString(),
          },
        });
        return;
      }

      if (!db.isHealthy()) {
        res.status(503).json({
          success: false,
          error: {
            code: 'SERVICE_UNAVAILABLE',
            message: 'Database not available',
          },
          meta: {
            requestId: zeroTrustReq.requestId,
            timestamp: new Date().toISOString(),
          },
        });
        return;
      }

      // Hash backup codes before storage
      const hashedBackupCodes = await hashBackupCodes(session.backupCodes);

      // Enable MFA in database
      await userRepository.update(userId, {
        mfaEnabled: true,
        mfaSecret: session.secret,
        mfaBackupCodes: hashedBackupCodes,
      });

      // Clean up enrollment session
      enrollmentSessions.delete(userId);

      logger.info({ userId }, 'MFA enrollment confirmed and enabled');

      res.json({
        success: true,
        data: {
          message: 'MFA enabled successfully',
          backupCodesRemaining: hashedBackupCodes.length,
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
 * Verify MFA during login
 * POST /auth/mfa/verify
 */
router.post(
  '/verify',
  jwtAuthMiddleware,
  createValidationMiddleware(verifyTOTPSchema),
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const zeroTrustReq = req as ZeroTrustRequest;

    try {
      const userId = zeroTrustReq.securityContext?.user?.id;
      const { token } = req.body as z.infer<typeof verifyTOTPSchema>;

      if (!userId) {
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

      if (!db.isHealthy()) {
        res.status(503).json({
          success: false,
          error: {
            code: 'SERVICE_UNAVAILABLE',
            message: 'Database not available',
          },
          meta: {
            requestId: zeroTrustReq.requestId,
            timestamp: new Date().toISOString(),
          },
        });
        return;
      }

      // Get user with MFA data
      const user = await userRepository.findByIdWithMFA(userId);
      if (!user || !user.mfaEnabled || !user.mfaSecret) {
        throw new AuthenticationError('MFA not configured');
      }

      // Verify TOTP token
      const isValid = verifyTOTP(user.mfaSecret, token);
      if (!isValid) {
        logger.warn({ userId }, 'MFA verification failed');
        res.status(401).json({
          success: false,
          error: {
            code: 'INVALID_MFA_TOKEN',
            message: 'Invalid verification code',
          },
          meta: {
            requestId: zeroTrustReq.requestId,
            timestamp: new Date().toISOString(),
          },
        });
        return;
      }

      const tokenPair = await generateTokenPair(
        {
          id: userId,
          email: user.email,
          username: user.username,
          roles: user.roles,
          permissions: user.permissions,
          mfaVerified: true,
        },
        zeroTrustReq
      );

      setAuthCookies(res, tokenPair);
      logger.info({ userId }, 'MFA verification successful, tokens issued');

      res.json({
        success: true,
        data: {
          message: 'MFA verification successful',
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

/**
 * Verify backup code during login
 * POST /auth/mfa/verify-backup
 */
router.post(
  '/verify-backup',
  jwtAuthMiddleware,
  createValidationMiddleware(verifyBackupCodeSchema),
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const zeroTrustReq = req as ZeroTrustRequest;

    try {
      const userId = zeroTrustReq.securityContext?.user?.id;
      const { code } = req.body as z.infer<typeof verifyBackupCodeSchema>;

      if (!userId) {
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

      if (!db.isHealthy()) {
        res.status(503).json({
          success: false,
          error: {
            code: 'SERVICE_UNAVAILABLE',
            message: 'Database not available',
          },
          meta: {
            requestId: zeroTrustReq.requestId,
            timestamp: new Date().toISOString(),
          },
        });
        return;
      }

      // Get user with MFA data
      const user = await userRepository.findByIdWithMFA(userId);
      if (!user || !user.mfaEnabled || !user.mfaBackupCodes) {
        throw new AuthenticationError('MFA not configured');
      }

      // Validate backup code
      const result = await validateBackupCode(user.mfaBackupCodes, code);
      if (!result.valid) {
        logger.warn({ userId }, 'Backup code verification failed');
        res.status(401).json({
          success: false,
          error: {
            code: 'INVALID_BACKUP_CODE',
            message: 'Invalid backup code',
          },
          meta: {
            requestId: zeroTrustReq.requestId,
            timestamp: new Date().toISOString(),
          },
        });
        return;
      }

      // Remove used backup code
      const updatedCodes = removeUsedBackupCode(user.mfaBackupCodes, result.usedIndex);
      await userRepository.update(userId, {
        mfaBackupCodes: updatedCodes,
      });

      const codesLow = areBackupCodesLow(updatedCodes);

      const tokenPair = await generateTokenPair(
        {
          id: userId,
          email: user.email,
          username: user.username,
          roles: user.roles,
          permissions: user.permissions,
          mfaVerified: true,
        },
        zeroTrustReq
      );

      setAuthCookies(res, tokenPair);
      logger.info(
        { userId, codesRemaining: updatedCodes.length },
        'Backup code verification successful, tokens issued'
      );

      res.json({
        success: true,
        data: {
          message: 'Backup code verification successful',
          user: {
            id: userId,
            email: user.email,
            username: user.username,
            roles: user.roles,
          },
          backupCodesRemaining: updatedCodes.length,
          warning: codesLow ? 'Backup codes running low. Please regenerate.' : undefined,
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
 * Disable MFA
 * POST /auth/mfa/disable
 */
router.post(
  '/disable',
  jwtAuthMiddleware,
  createValidationMiddleware(disableMFASchema),
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const zeroTrustReq = req as ZeroTrustRequest;

    try {
      const userId = zeroTrustReq.securityContext?.user?.id;
      const { password } = req.body as z.infer<typeof disableMFASchema>;

      if (!userId) {
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

      if (!db.isHealthy()) {
        res.status(503).json({
          success: false,
          error: {
            code: 'SERVICE_UNAVAILABLE',
            message: 'Database not available',
          },
          meta: {
            requestId: zeroTrustReq.requestId,
            timestamp: new Date().toISOString(),
          },
        });
        return;
      }

      // Get user and verify password
      const user = await userRepository.findById(userId);
      if (!user) {
        throw new AuthenticationError('User not found');
      }

      const isValidPassword = await verifyPassword(password, user.passwordHash);
      if (!isValidPassword) {
        res.status(401).json({
          success: false,
          error: {
            code: 'INVALID_PASSWORD',
            message: 'Invalid password',
          },
          meta: {
            requestId: zeroTrustReq.requestId,
            timestamp: new Date().toISOString(),
          },
        });
        return;
      }

      // Disable MFA
      await userRepository.update(userId, {
        mfaEnabled: false,
        mfaSecret: undefined,
        mfaBackupCodes: [],
      });

      logger.info({ userId }, 'MFA disabled');

      res.json({
        success: true,
        data: {
          message: 'MFA disabled successfully',
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
 * Regenerate backup codes
 * POST /auth/mfa/backup-codes/regenerate
 */
router.post(
  '/backup-codes/regenerate',
  jwtAuthMiddleware,
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const zeroTrustReq = req as ZeroTrustRequest;

    try {
      const userId = zeroTrustReq.securityContext?.user?.id;

      if (!userId) {
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

      if (!db.isHealthy()) {
        res.status(503).json({
          success: false,
          error: {
            code: 'SERVICE_UNAVAILABLE',
            message: 'Database not available',
          },
          meta: {
            requestId: zeroTrustReq.requestId,
            timestamp: new Date().toISOString(),
          },
        });
        return;
      }

      // Check MFA is enabled
      const user = await userRepository.findByIdWithMFA(userId);
      if (!user || !user.mfaEnabled) {
        res.status(400).json({
          success: false,
          error: {
            code: 'MFA_NOT_ENABLED',
            message: 'MFA is not enabled',
          },
          meta: {
            requestId: zeroTrustReq.requestId,
            timestamp: new Date().toISOString(),
          },
        });
        return;
      }

      // Generate new backup codes
      const newBackupCodes = generateBackupCodes();
      const hashedCodes = await hashBackupCodes(newBackupCodes);

      // Update database
      await userRepository.update(userId, {
        mfaBackupCodes: hashedCodes,
      });

      logger.info({ userId }, 'Backup codes regenerated');

      res.json({
        success: true,
        data: {
          backupCodes: newBackupCodes,
          message: 'New backup codes generated. Save them securely.',
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
 * Get MFA status
 * GET /auth/mfa/status
 */
router.get(
  '/status',
  jwtAuthMiddleware,
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const zeroTrustReq = req as ZeroTrustRequest;

    try {
      const userId = zeroTrustReq.securityContext?.user?.id;

      if (!userId) {
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

      if (!db.isHealthy()) {
        res.status(503).json({
          success: false,
          error: {
            code: 'SERVICE_UNAVAILABLE',
            message: 'Database not available',
          },
          meta: {
            requestId: zeroTrustReq.requestId,
            timestamp: new Date().toISOString(),
          },
        });
        return;
      }

      const user = await userRepository.findById(userId);
      if (!user) {
        throw new AuthenticationError('User not found');
      }

      res.json({
        success: true,
        data: {
          enabled: user.mfaEnabled || false,
          backupCodesRemaining: user.mfaBackupCodes?.length || 0,
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

// Cleanup expired enrollment sessions periodically
setInterval(
  () => {
    const now = Date.now();
    for (const [userId, session] of enrollmentSessions.entries()) {
      if (now > session.expiresAt) {
        enrollmentSessions.delete(userId);
        logger.debug({ userId }, 'MFA enrollment session expired and cleaned up');
      }
    }
  },
  5 * 60 * 1000
);

export default router;
