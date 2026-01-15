import { BlacklistedToken, IBlacklistedToken } from '../models/BlacklistedToken';
import { logger } from '../../utils/logger';

export class TokenRepository {
  async addToBlacklist(
    token: string,
    reason: string,
    expiresAt: Date
  ): Promise<IBlacklistedToken> {
    try {
      const blacklistedToken = new BlacklistedToken({
        token,
        reason,
        expiresAt,
      });
      return await blacklistedToken.save();
    } catch (error) {
      // If token already blacklisted, ignore duplicate key error
      if ((error as any).code === 11000) {
        logger.debug('Token already blacklisted');
        return await this.findByToken(token) as IBlacklistedToken;
      }
      logger.error('Error adding token to blacklist:', error);
      throw error;
    }
  }

  async isBlacklisted(token: string): Promise<boolean> {
    try {
      const result = await BlacklistedToken.findOne({ token }).exec();
      return result !== null;
    } catch (error) {
      logger.error('Error checking if token is blacklisted:', error);
      throw error;
    }
  }

  async findByToken(token: string): Promise<IBlacklistedToken | null> {
    try {
      return await BlacklistedToken.findOne({ token }).exec();
    } catch (error) {
      logger.error('Error finding blacklisted token:', error);
      throw error;
    }
  }

  async cleanupExpired(): Promise<number> {
    try {
      const result = await BlacklistedToken.deleteMany({
        expiresAt: { $lt: new Date() },
      }).exec();
      return result.deletedCount || 0;
    } catch (error) {
      logger.error('Error cleaning up expired tokens:', error);
      throw error;
    }
  }

  async removeFromBlacklist(token: string): Promise<boolean> {
    try {
      const result = await BlacklistedToken.deleteOne({ token }).exec();
      return result.deletedCount > 0;
    } catch (error) {
      logger.error('Error removing token from blacklist:', error);
      throw error;
    }
  }

  async countBlacklisted(): Promise<number> {
    try {
      return await BlacklistedToken.countDocuments().exec();
    } catch (error) {
      logger.error('Error counting blacklisted tokens:', error);
      throw error;
    }
  }
}

export const tokenRepository = new TokenRepository();
