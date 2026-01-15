import mongoose, { Schema, Document } from 'mongoose';

export interface IBlacklistedToken extends Document {
  token: string;
  reason: string;
  expiresAt: Date;
  createdAt: Date;
}

const BlacklistedTokenSchema = new Schema<IBlacklistedToken>(
  {
    token: {
      type: String,
      required: true,
      unique: true,
    },
    reason: {
      type: String,
      default: 'logout',
    },
    expiresAt: {
      type: Date,
      required: true,
    },
  },
  {
    timestamps: { createdAt: true, updatedAt: false },
  }
);

// TTL index - automatically delete expired blacklisted tokens
BlacklistedTokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export const BlacklistedToken = mongoose.model<IBlacklistedToken>(
  'BlacklistedToken',
  BlacklistedTokenSchema
);
