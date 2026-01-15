import crypto from 'crypto';
import { Request } from 'express';
import UAParser from 'ua-parser-js';
import { logger } from '../utils/logger';
import { userRepository } from '../db/repositories/UserRepository';

export interface DeviceFingerprint {
  fingerprint: string;
  deviceType: string;
  os: string;
  osVersion: string;
  browser: string;
  browserVersion: string;
  ipAddress: string;
  userAgent: string;
}

export interface DeviceTrustScore {
  fingerprint: string;
  trusted: boolean;
  trustScore: number;
  isNew: boolean;
  riskFactors: string[];
}

/**
 * Generate device fingerprint from request
 */
export const generateFingerprint = (req: Request): DeviceFingerprint => {
  const userAgent = req.headers['user-agent'] || 'unknown';
  const ip = req.ip || req.socket.remoteAddress || 'unknown';
  const acceptLanguage = req.headers['accept-language'] || '';
  const acceptEncoding = req.headers['accept-encoding'] || '';

  // Create hash from device characteristics
  const hash = crypto
    .createHash('sha256')
    .update(userAgent)
    .update(ip)
    .update(acceptLanguage)
    .update(acceptEncoding)
    .digest('hex');

  // Parse user agent
  const parser = new UAParser(userAgent);
  const result = parser.getResult();

  return {
    fingerprint: hash.substring(0, 32),
    deviceType: result.device.type || 'desktop',
    os: result.os.name || 'unknown',
    osVersion: result.os.version || 'unknown',
    browser: result.browser.name || 'unknown',
    browserVersion: result.browser.version || 'unknown',
    ipAddress: ip,
    userAgent,
  };
};

/**
 * Calculate device trust score
 */
export const calculateDeviceTrustScore = async (
  fingerprint: string,
  userId?: string
): Promise<DeviceTrustScore> => {
  let baseScore = 50;
  const riskFactors: string[] = [];
  let trusted = false;
  let isNew = true;

  if (userId) {
    try {
      const user = await userRepository.findById(userId);

      if (user && user.devices && user.devices.length > 0) {
        const knownDevice = user.devices.find(d => d.fingerprint === fingerprint);

        if (knownDevice) {
          isNew = false;
          trusted = knownDevice.trusted;

          // Device seen before
          baseScore += 20;

          // Explicitly trusted by user
          if (knownDevice.trusted) {
            baseScore += 15;
          }

          // Recent activity (last 7 days)
          const daysSinceLastSeen = (Date.now() - knownDevice.lastSeen.getTime()) / (1000 * 60 * 60 * 24);
          if (daysSinceLastSeen < 7) {
            baseScore += 10;
          } else if (daysSinceLastSeen > 90) {
            baseScore -= 10;
            riskFactors.push('device_not_seen_recently');
          }

          // High trust score from previous assessments
          if (knownDevice.trustScore > 80) {
            baseScore += 5;
          }
        } else {
          // New device for this user
          riskFactors.push('new_device');
          baseScore -= 25;
        }
      } else {
        // No devices registered for this user yet
        riskFactors.push('no_device_history');
        baseScore -= 10;
      }
    } catch (error) {
      logger.error({ error, userId, fingerprint }, 'Error calculating device trust score');
      riskFactors.push('trust_calculation_error');
      baseScore -= 20;
    }
  } else {
    // Unauthenticated request
    riskFactors.push('unauthenticated');
    baseScore -= 30;
  }

  // Normalize score to 0-100
  const trustScore = Math.max(0, Math.min(100, baseScore));

  return {
    fingerprint,
    trusted,
    trustScore,
    isNew,
    riskFactors,
  };
};

/**
 * Check if device is trusted for user
 */
export const isDeviceTrusted = async (
  fingerprint: string,
  userId: string
): Promise<boolean> => {
  try {
    const user = await userRepository.findById(userId);

    if (!user || !user.devices) {
      return false;
    }

    const device = user.devices.find(d => d.fingerprint === fingerprint);
    return device ? device.trusted : false;
  } catch (error) {
    logger.error({ error, userId, fingerprint }, 'Error checking device trust');
    return false;
  }
};

/**
 * Update device trust score in database
 */
export const updateDeviceTrust = async (
  userId: string,
  deviceInfo: DeviceFingerprint,
  trustScore: number
): Promise<void> => {
  try {
    const user = await userRepository.findById(userId);

    if (!user) {
      return;
    }

    const existingDevice = user.devices?.find(d => d.fingerprint === deviceInfo.fingerprint);

    if (existingDevice) {
      // Update existing device
      await userRepository.updateDeviceTrust(userId, deviceInfo.fingerprint, trustScore);
      logger.debug({ userId, fingerprint: deviceInfo.fingerprint, trustScore }, 'Device trust updated');
    } else {
      // Add new device
      await userRepository.addDevice(userId, {
        fingerprint: deviceInfo.fingerprint,
        trusted: false,
        trustScore,
        lastSeen: new Date(),
        userAgent: deviceInfo.userAgent,
        ipAddress: deviceInfo.ipAddress,
      });
      logger.info({ userId, fingerprint: deviceInfo.fingerprint }, 'New device registered');
    }
  } catch (error) {
    logger.error({ error, userId }, 'Error updating device trust');
  }
};
