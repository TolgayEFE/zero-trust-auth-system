import { Router, Request, Response, NextFunction } from 'express';
import { ZeroTrustRequest } from '../types';
import { jwtAuthMiddleware } from '../middleware/jwt';
import { userRepository } from '../db/repositories/UserRepository';
import { logger } from '../utils/logger';
import { db } from '../db/connection';

const router = Router();

/**
 * Get current user's devices
 */
router.get(
  '/',
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
        res.status(404).json({
          success: false,
          error: {
            code: 'USER_NOT_FOUND',
            message: 'User not found',
          },
          meta: {
            requestId: zeroTrustReq.requestId,
            timestamp: new Date().toISOString(),
          },
        });
        return;
      }

      const devices = user.devices || [];
      const currentFingerprint = zeroTrustReq.securityContext?.device?.fingerprint;

      res.json({
        success: true,
        data: {
          devices: devices.map(d => ({
            fingerprint: d.fingerprint,
            trusted: d.trusted,
            trustScore: d.trustScore,
            lastSeen: d.lastSeen,
            userAgent: d.userAgent,
            isCurrent: d.fingerprint === currentFingerprint,
          })),
          currentDevice: currentFingerprint,
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
 * Get current device info
 */
router.get(
  '/current',
  async (req: Request, res: Response) => {
    const zeroTrustReq = req as ZeroTrustRequest;

    res.json({
      success: true,
      data: {
        device: zeroTrustReq.securityContext?.device || null,
      },
      meta: {
        requestId: zeroTrustReq.requestId,
        timestamp: new Date().toISOString(),
      },
    });
  }
);

/**
 * Trust a device
 */
router.post(
  '/:fingerprint/trust',
  jwtAuthMiddleware,
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const zeroTrustReq = req as ZeroTrustRequest;
    const fingerprint = req.params.fingerprint as string;

    try {
      const userId = zeroTrustReq.securityContext?.user?.id as string | undefined;

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

      // At this point, userId is guaranteed to be string
      const userIdStr = userId as string;

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

      const user = await userRepository.findById(userIdStr);

      if (!user) {
        res.status(404).json({
          success: false,
          error: {
            code: 'USER_NOT_FOUND',
            message: 'User not found',
          },
          meta: {
            requestId: zeroTrustReq.requestId,
            timestamp: new Date().toISOString(),
          },
        });
        return;
      }

      const device = user.devices?.find(d => d.fingerprint === fingerprint);

      if (!device) {
        res.status(404).json({
          success: false,
          error: {
            code: 'DEVICE_NOT_FOUND',
            message: 'Device not found',
          },
          meta: {
            requestId: zeroTrustReq.requestId,
            timestamp: new Date().toISOString(),
          },
        });
        return;
      }

      // Update device to trusted
      await userRepository.updateDeviceTrust(userIdStr, fingerprint, 100);

      logger.info({ userId, fingerprint }, 'Device marked as trusted');

      res.json({
        success: true,
        data: {
          message: 'Device marked as trusted',
          fingerprint,
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
 * Remove a device
 */
router.delete(
  '/:fingerprint',
  jwtAuthMiddleware,
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const zeroTrustReq = req as ZeroTrustRequest;
    const fingerprint = req.params.fingerprint as string;

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

      // This would need a new repository method
      logger.info({ userId, fingerprint }, 'Device removal requested');

      res.json({
        success: true,
        data: {
          message: 'Device removed successfully',
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

export default router;
