import jwt from 'jsonwebtoken';
import { config } from '../config';
import { logger } from '../utils/logger';
import { sessionRepository } from '../db/repositories/SessionRepository';
import { db } from '../db/connection';
import { ZeroTrustRequest, TokenPair } from '../types';
import { generateSessionId } from '../utils/crypto';

interface TokenUser {
  id: string;
  email: string;
  username: string;
  roles: string[];
  permissions: string[];
  mfaVerified?: boolean;
}

// Parse expiration string to seconds
export const parseExpiration = (exp: string): number => {
  const match = exp.match(/^(\d+)([smhd])$/);
  if (!match) return 900; // Default 15 minutes

  const value = parseInt(match[1] || '0', 10);
  const unit = match[2];

  switch (unit) {
    case 's':
      return value;
    case 'm':
      return value * 60;
    case 'h':
      return value * 3600;
    case 'd':
      return value * 86400;
    default:
      return 900;
  }
};

// Generate JWT tokens and store session if possible
export const generateTokenPair = async (
  user: TokenUser,
  req: ZeroTrustRequest
): Promise<TokenPair> => {
  const sessionId = generateSessionId();

  const accessToken = jwt.sign(
    {
      sub: user.id,
      email: user.email,
      username: user.username,
      roles: user.roles,
      permissions: user.permissions,
      sessionId,
      mfaVerified: user.mfaVerified || false,
    },
    config.jwt.secret,
    {
      expiresIn: config.jwt.expiration,
      issuer: config.jwt.issuer,
      audience: config.jwt.audience,
      algorithm: config.jwt.algorithm as jwt.Algorithm,
    } as jwt.SignOptions
  );

  const refreshToken = jwt.sign(
    {
      sub: user.id,
      sessionId,
      type: 'refresh',
    },
    config.jwt.secret,
    {
      expiresIn: config.jwt.refreshExpiration,
      issuer: config.jwt.issuer,
    } as jwt.SignOptions
  );

  // Store refresh token if DB is ready
  if (db.isHealthy()) {
    try {
      const decoded = jwt.decode(refreshToken) as { exp: number };
      const expiresAt = new Date(decoded.exp * 1000);

      await sessionRepository.create({
        userId: user.id,
        token: accessToken,
        refreshToken,
        ipAddress: req.securityContext?.clientIp || req.ip || 'unknown',
        userAgent: req.securityContext?.userAgent || req.headers['user-agent'] || 'unknown',
        expiresAt,
      });

      logger.debug({ userId: user.id, sessionId }, 'Session stored in database');
    } catch (error) {
      logger.error({ error, userId: user.id }, 'Failed to store session in database');
    }
  }

  return {
    accessToken,
    refreshToken,
    expiresIn: parseExpiration(config.jwt.expiration),
    tokenType: 'Bearer',
  };
};
