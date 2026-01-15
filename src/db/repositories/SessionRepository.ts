import { Session, ISession } from '../models/Session';
import { logger } from '../../utils/logger';
import { Types } from 'mongoose';

export class SessionRepository {
  async create(sessionData: {
    userId: string | Types.ObjectId;
    token: string;
    refreshToken: string;
    deviceFingerprint?: string;
    ipAddress: string;
    userAgent: string;
    expiresAt: Date;
  }): Promise<ISession> {
    try {
      const session = new Session(sessionData);
      return await session.save();
    } catch (error) {
      logger.error('Error creating session:', error);
      throw error;
    }
  }

  async findByToken(token: string): Promise<ISession | null> {
    try {
      return await Session.findOne({ token }).exec();
    } catch (error) {
      logger.error('Error finding session by token:', error);
      throw error;
    }
  }

  async findByRefreshToken(refreshToken: string): Promise<ISession | null> {
    try {
      return await Session.findOne({ refreshToken }).exec();
    } catch (error) {
      logger.error('Error finding session by refresh token:', error);
      throw error;
    }
  }

  async deleteByToken(token: string): Promise<boolean> {
    try {
      const result = await Session.deleteOne({ token }).exec();
      return result.deletedCount > 0;
    } catch (error) {
      logger.error('Error deleting session by token:', error);
      throw error;
    }
  }

  async deleteByRefreshToken(refreshToken: string): Promise<boolean> {
    try {
      const result = await Session.deleteOne({ refreshToken }).exec();
      return result.deletedCount > 0;
    } catch (error) {
      logger.error('Error deleting session by refresh token:', error);
      throw error;
    }
  }

  async deleteByUserId(userId: string | Types.ObjectId): Promise<number> {
    try {
      const result = await Session.deleteMany({ userId }).exec();
      return result.deletedCount || 0;
    } catch (error) {
      logger.error('Error deleting sessions by user ID:', error);
      throw error;
    }
  }

  async deleteExpired(): Promise<number> {
    try {
      const result = await Session.deleteMany({
        expiresAt: { $lt: new Date() },
      }).exec();
      return result.deletedCount || 0;
    } catch (error) {
      logger.error('Error deleting expired sessions:', error);
      throw error;
    }
  }

  async countActiveSessionsForUser(
    userId: string | Types.ObjectId
  ): Promise<number> {
    try {
      return await Session.countDocuments({
        userId,
        expiresAt: { $gt: new Date() },
      }).exec();
    } catch (error) {
      logger.error('Error counting active sessions:', error);
      throw error;
    }
  }

  async findActiveSessionsByUserId(
    userId: string | Types.ObjectId
  ): Promise<ISession[]> {
    try {
      return await Session.find({
        userId,
        expiresAt: { $gt: new Date() },
      })
        .sort({ createdAt: -1 })
        .exec();
    } catch (error) {
      logger.error('Error finding active sessions:', error);
      throw error;
    }
  }

  async updateExpiration(
    token: string,
    newExpiresAt: Date
  ): Promise<ISession | null> {
    try {
      return await Session.findOneAndUpdate(
        { token },
        { expiresAt: newExpiresAt },
        { new: true }
      ).exec();
    } catch (error) {
      logger.error('Error updating session expiration:', error);
      throw error;
    }
  }
}

export const sessionRepository = new SessionRepository();
