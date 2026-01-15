import mongoose, { Schema, Document } from 'mongoose';

export interface IDevice {
  fingerprint: string;
  trusted: boolean;
  trustScore: number;
  lastSeen: Date;
  userAgent: string;
  ipAddress: string;
}

export interface IUser extends Document {
  email: string;
  username: string;
  passwordHash: string;
  roles: string[];
  permissions: string[];
  mfaEnabled: boolean;
  mfaSecret?: string;
  mfaBackupCodes: string[];
  devices: IDevice[];
  failedLoginAttempts: number;
  lastLoginAt?: Date;
  createdAt: Date;
  updatedAt: Date;
}

const DeviceSchema = new Schema<IDevice>({
  fingerprint: { type: String, required: true },
  trusted: { type: Boolean, default: false },
  trustScore: { type: Number, default: 50, min: 0, max: 100 },
  lastSeen: { type: Date, default: Date.now },
  userAgent: { type: String, required: true },
  ipAddress: { type: String, required: true },
});

const UserSchema = new Schema<IUser>(
  {
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },
    username: {
      type: String,
      required: true,
      unique: true,
      trim: true,
    },
    passwordHash: {
      type: String,
      required: true,
    },
    roles: {
      type: [String],
      default: ['user'],
    },
    permissions: {
      type: [String],
      default: ['read:own'],
    },
    mfaEnabled: {
      type: Boolean,
      default: false,
    },
    mfaSecret: {
      type: String,
      select: false, // Don't return by default
    },
    mfaBackupCodes: {
      type: [String],
      default: [],
      select: false, // Don't return by default
    },
    devices: {
      type: [DeviceSchema],
      default: [],
    },
    failedLoginAttempts: {
      type: Number,
      default: 0,
    },
    lastLoginAt: {
      type: Date,
    },
  },
  {
    timestamps: true, // Adds createdAt and updatedAt
  }
);

// Additional index for device queries (unique indexes already defined in schema)
UserSchema.index({ 'devices.fingerprint': 1 });

export const User = mongoose.model<IUser>('User', UserSchema);
