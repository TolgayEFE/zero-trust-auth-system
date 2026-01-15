import { Request, Response, NextFunction } from 'express';
import { ZeroTrustRequest } from '../types';
import {
  generateFingerprint,
  calculateDeviceTrustScore,
  updateDeviceTrust
} from '../services/deviceFingerprint';
import { logger } from '../utils/logger';
import { db } from '../db/connection';

/**
 * Device tracking middleware
 * Generates device fingerprint and calculates trust score
 */
export const deviceTrackingMiddleware = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  const zeroTrustReq = req as ZeroTrustRequest;

  try {
    // Generate device fingerprint
    const deviceInfo = generateFingerprint(req);

    // Get user ID if authenticated
    const userId = zeroTrustReq.securityContext?.user?.id;

    // Calculate trust score
    const trustScore = await calculateDeviceTrustScore(deviceInfo.fingerprint, userId);

    // Add device info to security context
    if (zeroTrustReq.securityContext) {
      zeroTrustReq.securityContext.device = {
        id: deviceInfo.fingerprint,
        fingerprint: deviceInfo.fingerprint,
        trusted: trustScore.trusted,
        lastSeen: Date.now(),
        riskIndicators: trustScore.riskFactors,
      };

      // Update risk score based on device trust
      if (trustScore.trustScore < 30) {
        zeroTrustReq.securityContext.riskScore += 30;
      } else if (trustScore.trustScore < 50) {
        zeroTrustReq.securityContext.riskScore += 15;
      } else if (trustScore.trustScore > 80) {
        zeroTrustReq.securityContext.riskScore = Math.max(
          0,
          zeroTrustReq.securityContext.riskScore - 10
        );
      }

      logger.debug(
        {
          requestId: zeroTrustReq.requestId,
          fingerprint: deviceInfo.fingerprint,
          trustScore: trustScore.trustScore,
          isNew: trustScore.isNew,
          riskFactors: trustScore.riskFactors,
        },
        'Device tracking completed'
      );
    }

    // Update device in database if user is authenticated and DB is available
    if (userId && db.isHealthy()) {
      // Don't wait for this to complete
      updateDeviceTrust(userId, deviceInfo, trustScore.trustScore).catch(err => {
        logger.error({ error: err, userId }, 'Failed to update device trust');
      });
    }

    next();
  } catch (error) {
    logger.error({ error, requestId: zeroTrustReq.requestId }, 'Device tracking error');
    // Don't fail the request if device tracking fails
    next();
  }
};

export default deviceTrackingMiddleware;
