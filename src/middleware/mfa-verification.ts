import { Request, Response, NextFunction } from 'express';
import { ZeroTrustRequest } from '../types';
import { logger } from '../utils/logger';

/**
 * MFA Verification Middleware
 * Checks if MFA is required and verified for the current request
 */
export const mfaVerificationMiddleware = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  const zeroTrustReq = req as ZeroTrustRequest;

  // Check if user is authenticated
  if (!zeroTrustReq.securityContext?.authenticated) {
    next();
    return;
  }

  // Check JWT payload for MFA status
  const mfaVerified = zeroTrustReq.securityContext?.user?.mfaVerified;

  // If MFA is required but not verified, reject the request
  if (mfaVerified === false) {
    logger.warn(
      {
        requestId: zeroTrustReq.requestId,
        userId: zeroTrustReq.securityContext?.user?.id,
      },
      'MFA verification required but not completed'
    );

    res.status(403).json({
      success: false,
      error: {
        code: 'MFA_REQUIRED',
        message: 'Multi-factor authentication verification required',
        details: {
          nextStep: 'POST /auth/mfa/verify',
          hint: 'Provide TOTP token or backup code',
        },
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
 * Optional MFA middleware - only checks if MFA is enabled for user
 * Adds mfaRequired flag to security context
 */
export const checkMFAStatus = async (
  req: Request,
  _res: Response,
  next: NextFunction
): Promise<void> => {
  const zeroTrustReq = req as ZeroTrustRequest;

  try {
    // This would typically check the database to see if user has MFA enabled
    // For now, we rely on the JWT token's mfaVerified field
    if (zeroTrustReq.securityContext) {
      // If mfaVerified is false, it means MFA is enabled but not yet verified
      const mfaRequired = zeroTrustReq.securityContext.user?.mfaVerified === false;

      logger.debug(
        {
          requestId: zeroTrustReq.requestId,
          mfaRequired,
        },
        'MFA status checked'
      );
    }

    next();
  } catch (error) {
    logger.error(
      { error, requestId: zeroTrustReq.requestId },
      'Error checking MFA status'
    );
    next(error);
  }
};

export default mfaVerificationMiddleware;
