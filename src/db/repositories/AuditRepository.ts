import { AuditLog, IAuditLog } from '../models/AuditLog';
import { logger } from '../../utils/logger';
import { Types } from 'mongoose';

export class AuditRepository {
  async create(auditData: {
    auditId: string;
    requestId: string;
    userId?: string | Types.ObjectId;
    action: string;
    resource: string;
    outcome: 'success' | 'failure' | 'error';
    metadata?: Record<string, any>;
  }): Promise<IAuditLog> {
    try {
      const auditLog = new AuditLog({
        ...auditData,
        timestamp: new Date(),
      });
      return await auditLog.save();
    } catch (error) {
      logger.error('Error creating audit log:', error);
      throw error;
    }
  }

  async findByUserId(
    userId: string | Types.ObjectId,
    options?: {
      limit?: number;
      skip?: number;
      startDate?: Date;
      endDate?: Date;
    }
  ): Promise<IAuditLog[]> {
    try {
      const query: any = { userId };

      if (options?.startDate || options?.endDate) {
        query.timestamp = {};
        if (options.startDate) {
          query.timestamp.$gte = options.startDate;
        }
        if (options.endDate) {
          query.timestamp.$lte = options.endDate;
        }
      }

      return await AuditLog.find(query)
        .sort({ timestamp: -1 })
        .limit(options?.limit || 100)
        .skip(options?.skip || 0)
        .exec();
    } catch (error) {
      logger.error('Error finding audit logs by user ID:', error);
      throw error;
    }
  }

  async findByDateRange(startDate: Date, endDate: Date): Promise<IAuditLog[]> {
    try {
      return await AuditLog.find({
        timestamp: {
          $gte: startDate,
          $lte: endDate,
        },
      })
        .sort({ timestamp: -1 })
        .exec();
    } catch (error) {
      logger.error('Error finding audit logs by date range:', error);
      throw error;
    }
  }

  async findFailedAuthentications(
    userId: string | Types.ObjectId,
    since: Date
  ): Promise<IAuditLog[]> {
    try {
      return await AuditLog.find({
        userId,
        action: 'authenticate',
        outcome: 'failure',
        timestamp: { $gte: since },
      })
        .sort({ timestamp: -1 })
        .exec();
    } catch (error) {
      logger.error('Error finding failed authentications:', error);
      throw error;
    }
  }

  async findByAction(
    action: string,
    options?: { limit?: number }
  ): Promise<IAuditLog[]> {
    try {
      return await AuditLog.find({ action })
        .sort({ timestamp: -1 })
        .limit(options?.limit || 100)
        .exec();
    } catch (error) {
      logger.error('Error finding audit logs by action:', error);
      throw error;
    }
  }

  async findByOutcome(
    outcome: 'success' | 'failure' | 'error',
    options?: { limit?: number; since?: Date }
  ): Promise<IAuditLog[]> {
    try {
      const query: any = { outcome };
      if (options?.since) {
        query.timestamp = { $gte: options.since };
      }

      return await AuditLog.find(query)
        .sort({ timestamp: -1 })
        .limit(options?.limit || 100)
        .exec();
    } catch (error) {
      logger.error('Error finding audit logs by outcome:', error);
      throw error;
    }
  }

  async countByAction(action: string, since?: Date): Promise<number> {
    try {
      const query: any = { action };
      if (since) {
        query.timestamp = { $gte: since };
      }
      return await AuditLog.countDocuments(query).exec();
    } catch (error) {
      logger.error('Error counting audit logs by action:', error);
      throw error;
    }
  }

  async deleteOlderThan(date: Date): Promise<number> {
    try {
      const result = await AuditLog.deleteMany({
        timestamp: { $lt: date },
      }).exec();
      return result.deletedCount || 0;
    } catch (error) {
      logger.error('Error deleting old audit logs:', error);
      throw error;
    }
  }
}

export const auditRepository = new AuditRepository();
