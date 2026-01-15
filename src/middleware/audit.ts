import { Request, Response, NextFunction } from 'express';
import { ZeroTrustRequest, AuditLogEntry } from '../types';
import { auditLogger } from '../utils/logger';
import { generateUUID } from '../utils/crypto';
import { auditRepository } from '../db/repositories/AuditRepository';
import { db } from '../db/connection';

// Pending audit entries for response capture
const pendingAuditEntries = new Map<string, AuditLogEntry>();

/**
 * Persist audit entry to database
 */
const persistAuditEntry = async (entry: AuditLogEntry): Promise<void> => {
  if (!db.isHealthy()) {
    // Database not available, only log to file
    return;
  }

  try {
    await auditRepository.create({
      auditId: entry.id,
      requestId: entry.requestId,
      userId: entry.actor.userId,
      action: entry.action,
      resource: entry.resource.type,
      outcome: entry.outcome,
      metadata: {
        resourceId: entry.resource.id,
        actorIp: entry.actor.ip,
        actorUserAgent: entry.actor.userAgent,
        details: entry.details,
        securityContext: entry.securityContext,
      },
    });
  } catch (error) {
    auditLogger.error({ error, auditId: entry.id }, 'Failed to persist audit entry to database');
  }
};

/**
 * Determine action from HTTP method and path
 */
const determineAction = (method: string, path: string): string => {
  const baseAction = (() => {
    switch (method) {
      case 'GET':
        return 'read';
      case 'POST':
        return 'create';
      case 'PUT':
      case 'PATCH':
        return 'update';
      case 'DELETE':
        return 'delete';
      default:
        return 'unknown';
    }
  })();

  // Extract resource type from path
  const pathParts = path.split('/').filter(Boolean);
  const resourceType = pathParts[1] || 'resource';

  return `${baseAction}:${resourceType}`;
};

/**
 * Extract resource information from path
 */
const extractResource = (path: string): { type: string; id?: string } => {
  const pathParts = path.split('/').filter(Boolean);
  return {
    type: pathParts[1] || 'unknown',
    id: pathParts[2],
  };
};

/**
 * Audit logging middleware
 */
export const auditLogMiddleware = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  const zeroTrustReq = req as ZeroTrustRequest;

  // Skip audit for certain paths
  const skipPaths = ['/health', '/ready', '/metrics', '/csp-report'];
  if (skipPaths.some(p => req.path.startsWith(p))) {
    next();
    return;
  }

  const auditId = generateUUID();
  const auditEntry: AuditLogEntry = {
    id: auditId,
    timestamp: new Date(),
    requestId: zeroTrustReq.requestId || generateUUID(),
    action: determineAction(req.method, req.path),
    actor: {
      userId: zeroTrustReq.securityContext?.user?.id,
      ip: zeroTrustReq.securityContext?.clientIp || req.socket.remoteAddress || 'unknown',
      userAgent: zeroTrustReq.securityContext?.userAgent || req.headers['user-agent'] || 'unknown',
    },
    resource: extractResource(req.path),
    outcome: 'success', // Will be updated on response
    details: {
      method: req.method,
      path: req.path,
      query: req.query,
      // Don't log sensitive body data
      hasBody: !!req.body && Object.keys(req.body as object).length > 0,
    },
    securityContext: {
      authenticated: zeroTrustReq.securityContext?.authenticated,
      trustLevel: zeroTrustReq.securityContext?.trustLevel,
      riskScore: zeroTrustReq.securityContext?.riskScore,
    },
  };

  // Store entry for completion on response
  pendingAuditEntries.set(auditId, auditEntry);

  // Capture response for audit
  const originalEnd = res.end;
  const originalJson = res.json;

  // Override res.json to capture response data
  res.json = function (this: Response, body?: unknown): Response {
    const entry = pendingAuditEntries.get(auditId);
    if (entry) {
      entry.outcome = res.statusCode >= 400 ? 'failure' : 'success';
      entry.details = {
        ...entry.details,
        statusCode: res.statusCode,
        responseSize: JSON.stringify(body).length,
      };

      // Update with final security context
      entry.securityContext = {
        ...entry.securityContext,
        authenticated: zeroTrustReq.securityContext?.authenticated,
        authorized: zeroTrustReq.securityContext?.authorized,
        trustLevel: zeroTrustReq.securityContext?.trustLevel,
        riskScore: zeroTrustReq.securityContext?.riskScore,
      };

      // Log the audit entry
      auditLogger.info(entry, 'Audit log entry');

      // Persist to database (async, don't wait)
      persistAuditEntry(entry).catch(err => {
        auditLogger.error({ error: err }, 'Failed to persist audit entry');
      });

      // Clean up
      pendingAuditEntries.delete(auditId);
    }

    return originalJson.call(this, body) as Response;
  };

  // Override res.end for non-JSON responses
  res.end = function (this: Response, chunk?: any, encoding?: any, callback?: any): Response {
    const entry = pendingAuditEntries.get(auditId);
    if (entry) {
      entry.outcome = res.statusCode >= 400 ? 'failure' : 'success';
      if (res.statusCode >= 500) {
        entry.outcome = 'error';
      }
      entry.details = {
        ...entry.details,
        statusCode: res.statusCode,
      };

      auditLogger.info(entry, 'Audit log entry');

      // Persist to database (async, don't wait)
      persistAuditEntry(entry).catch(err => {
        auditLogger.error({ error: err }, 'Failed to persist audit entry');
      });

      pendingAuditEntries.delete(auditId);
    }

    // Call original end with all arguments
    return originalEnd.call(this, chunk, encoding, callback);
  } as typeof res.end;

  next();
};

/**
 * Log security-specific events
 */
export const logSecurityEvent = (
  eventType: string,
  req: ZeroTrustRequest,
  details: Record<string, unknown> = {}
): void => {
  const securityEvent: AuditLogEntry = {
    id: generateUUID(),
    timestamp: new Date(),
    requestId: req.requestId || 'unknown',
    action: eventType,
    actor: {
      userId: req.securityContext?.user?.id,
      ip: req.securityContext?.clientIp || 'unknown',
      userAgent: req.securityContext?.userAgent || 'unknown',
    },
    resource: {
      type: 'security',
    },
    outcome: 'success',
    details,
    securityContext: {
      authenticated: req.securityContext?.authenticated,
      trustLevel: req.securityContext?.trustLevel,
    },
  };

  auditLogger.info(securityEvent, `Security event: ${eventType}`);

  // Persist to database (async, don't wait)
  persistAuditEntry(securityEvent).catch(err => {
    auditLogger.error({ error: err }, 'Failed to persist security event');
  });
};

/**
 * Log authentication events
 */
export const logAuthenticationEvent = (
  success: boolean,
  req: ZeroTrustRequest,
  userId?: string,
  details: Record<string, unknown> = {}
): void => {
  logSecurityEvent(success ? 'authentication:success' : 'authentication:failure', req, {
    userId,
    ...details,
  });
};

/**
 * Log authorization events
 */
export const logAuthorizationEvent = (
  allowed: boolean,
  req: ZeroTrustRequest,
  resource: string,
  action: string,
  details: Record<string, unknown> = {}
): void => {
  logSecurityEvent(allowed ? 'authorization:granted' : 'authorization:denied', req, {
    resource,
    action,
    ...details,
  });
};

// Cleanup stale pending entries
setInterval(
  () => {
    const fiveMinutesAgo = Date.now() - 5 * 60 * 1000;
    for (const [id, entry] of pendingAuditEntries.entries()) {
      if (entry.timestamp.getTime() < fiveMinutesAgo) {
        auditLogger.warn(
          { auditId: id },
          'Cleaning up stale audit entry'
        );
        pendingAuditEntries.delete(id);
      }
    }
  },
  60 * 1000
);

export default auditLogMiddleware;
