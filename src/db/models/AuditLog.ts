import mongoose, { Schema, Document, Types } from 'mongoose';

export interface IAuditLog extends Document {
  auditId: string;
  requestId: string;
  userId?: Types.ObjectId;
  action: string;
  resource: string;
  outcome: 'success' | 'failure' | 'error';
  metadata: Record<string, any>;
  timestamp: Date;
}

const AuditLogSchema = new Schema<IAuditLog>(
  {
    auditId: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    requestId: {
      type: String,
      required: true,
      index: true,
    },
    userId: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      index: true,
    },
    action: {
      type: String,
      required: true,
      index: true,
    },
    resource: {
      type: String,
      required: true,
    },
    outcome: {
      type: String,
      enum: ['success', 'failure', 'error'],
      required: true,
      index: true,
    },
    metadata: {
      type: Schema.Types.Mixed,
      default: {},
    },
    timestamp: {
      type: Date,
      default: Date.now,
      index: true,
    },
  },
  {
    timestamps: false, // We use our own timestamp field
  }
);

// Compound indexes for common queries
AuditLogSchema.index({ userId: 1, timestamp: -1 });
AuditLogSchema.index({ action: 1, outcome: 1, timestamp: -1 });
AuditLogSchema.index({ timestamp: -1 }); // For time-range queries

export const AuditLog = mongoose.model<IAuditLog>('AuditLog', AuditLogSchema);
