import { User, IUser, IDevice } from '../models/User';
import { logger } from '../../utils/logger';
import { Types } from 'mongoose';

export class UserRepository {
  async findById(id: string | Types.ObjectId): Promise<IUser | null> {
    try {
      return await User.findById(id).exec();
    } catch (error) {
      logger.error('Error finding user by ID:', error);
      throw error;
    }
  }

  async findByEmail(email: string): Promise<IUser | null> {
    try {
      return await User.findOne({ email: email.toLowerCase() }).exec();
    } catch (error) {
      logger.error('Error finding user by email:', error);
      throw error;
    }
  }

  async findByUsername(username: string): Promise<IUser | null> {
    try {
      return await User.findOne({ username }).exec();
    } catch (error) {
      logger.error('Error finding user by username:', error);
      throw error;
    }
  }

  async create(userData: {
    email: string;
    username: string;
    passwordHash: string;
    roles?: string[];
    permissions?: string[];
  }): Promise<IUser> {
    try {
      const user = new User({
        email: userData.email.toLowerCase(),
        username: userData.username,
        passwordHash: userData.passwordHash,
        roles: userData.roles || ['user'],
        permissions: userData.permissions || ['read:own'],
        mfaEnabled: false,
        devices: [],
        failedLoginAttempts: 0,
      });

      return await user.save();
    } catch (error) {
      logger.error('Error creating user:', error);
      throw error;
    }
  }

  async update(
    id: string | Types.ObjectId,
    updates: Partial<IUser>
  ): Promise<IUser | null> {
    try {
      return await User.findByIdAndUpdate(id, updates, {
        new: true,
        runValidators: true,
      }).exec();
    } catch (error) {
      logger.error('Error updating user:', error);
      throw error;
    }
  }

  async delete(id: string | Types.ObjectId): Promise<boolean> {
    try {
      const result = await User.findByIdAndDelete(id).exec();
      return result !== null;
    } catch (error) {
      logger.error('Error deleting user:', error);
      throw error;
    }
  }

  async updateLastLogin(id: string | Types.ObjectId): Promise<void> {
    try {
      await User.findByIdAndUpdate(id, {
        lastLoginAt: new Date(),
        failedLoginAttempts: 0,
      }).exec();
    } catch (error) {
      logger.error('Error updating last login:', error);
      throw error;
    }
  }

  async incrementFailedAttempts(id: string | Types.ObjectId): Promise<void> {
    try {
      await User.findByIdAndUpdate(id, {
        $inc: { failedLoginAttempts: 1 },
      }).exec();
    } catch (error) {
      logger.error('Error incrementing failed attempts:', error);
      throw error;
    }
  }

  async resetFailedAttempts(id: string | Types.ObjectId): Promise<void> {
    try {
      await User.findByIdAndUpdate(id, {
        failedLoginAttempts: 0,
      }).exec();
    } catch (error) {
      logger.error('Error resetting failed attempts:', error);
      throw error;
    }
  }

  async addDevice(
    userId: string | Types.ObjectId,
    deviceInfo: IDevice
  ): Promise<void> {
    try {
      await User.findByIdAndUpdate(userId, {
        $push: { devices: deviceInfo },
      }).exec();
    } catch (error) {
      logger.error('Error adding device:', error);
      throw error;
    }
  }

  async updateDeviceTrust(
    userId: string | Types.ObjectId,
    fingerprint: string,
    trustScore: number,
    trusted?: boolean
  ): Promise<void> {
    try {
      const updateData: any = {
        'devices.$.trustScore': trustScore,
        'devices.$.lastSeen': new Date(),
      };

      if (trusted !== undefined) {
        updateData['devices.$.trusted'] = trusted;
      }

      await User.findOneAndUpdate(
        { _id: userId, 'devices.fingerprint': fingerprint },
        { $set: updateData }
      ).exec();
    } catch (error) {
      logger.error('Error updating device trust:', error);
      throw error;
    }
  }

  async findByDevice(fingerprint: string): Promise<IUser | null> {
    try {
      return await User.findOne({
        'devices.fingerprint': fingerprint,
      }).exec();
    } catch (error) {
      logger.error('Error finding user by device:', error);
      throw error;
    }
  }

  async findByIdWithMFA(id: string | Types.ObjectId): Promise<IUser | null> {
    try {
      // Include mfaSecret and mfaBackupCodes in the query
      return await User.findById(id)
        .select('+mfaSecret +mfaBackupCodes')
        .exec();
    } catch (error) {
      logger.error('Error finding user with MFA:', error);
      throw error;
    }
  }
}

export const userRepository = new UserRepository();
