import { Request, Response, NextFunction } from 'express';
import axios from 'axios';
import { ZeroTrustRequest, OPAInput, OPAResponse, PolicyViolationError } from '../types';
import { config, features } from '../config';
import { securityLogger } from '../utils/logger';
import { retryWithBackoff } from '../utils/helpers';

// OPA decision cache
const opaCache = new Map<string, { result: boolean; expiry: number }>();

// Build OPA input
const buildOPAInput = (req: ZeroTrustRequest): OPAInput => {
  return {
    request: {
      method: req.method,
      path: req.path,
      headers: Object.fromEntries(
        Object.entries(req.headers).map(([key, value]) => [
          key,
          Array.isArray(value) ? value.join(', ') : value || '',
        ])
      ),
      query: req.query as Record<string, string>,
      body: req.body as unknown,
    },
    subject: {
      user: req.securityContext?.user,
      client: {
        ip: req.securityContext?.clientIp || 'unknown',
        userAgent: req.securityContext?.userAgent || 'unknown',
      },
    },
    resource: {
      type: extractResourceType(req.path),
      id: extractResourceId(req.path),
      attributes: {},
    },
    action: mapHttpMethodToAction(req.method),
    context: {
      time: new Date().toISOString(),
      environment: config.server.env,
      requestId: req.requestId || 'unknown',
    },
  };
};

// Resource type from path
const extractResourceType = (path: string): string => {
  const parts = path.split('/').filter(Boolean);
  return parts[1] || 'unknown'; // e.g., /api/users -> users
};

// Resource ID from path
const extractResourceId = (path: string): string | undefined => {
  const parts = path.split('/').filter(Boolean);
  return parts[2]; // e.g., /api/users/123 -> 123
};

// Map HTTP method to action
const mapHttpMethodToAction = (method: string): string => {
  const actionMap: Record<string, string> = {
    GET: 'read',
    POST: 'create',
    PUT: 'update',
    PATCH: 'update',
    DELETE: 'delete',
    HEAD: 'read',
    OPTIONS: 'options',
  };
  return actionMap[method] || 'unknown';
};

// Cache key for OPA decision
const generateCacheKey = (input: OPAInput): string => {
  const userId = input.subject.user?.id || 'anonymous';
  const { method, path } = input.request;
  return `${userId}:${method}:${path}`;
};

// Query OPA for decision
const queryOPA = async (input: OPAInput): Promise<boolean> => {
  const cacheKey = generateCacheKey(input);

  // Check cache
  const cached = opaCache.get(cacheKey);
  if (cached && Date.now() < cached.expiry) {
    securityLogger.debug({ cacheKey }, 'OPA decision served from cache');
    return cached.result;
  }

  // Query OPA with retry
  const response = await retryWithBackoff(
    async () => {
      const res = await axios.post<OPAResponse>(
        `${config.opa.url}${config.opa.policyPath}`,
        { input },
        {
          timeout: config.opa.timeoutMs,
          headers: {
            'Content-Type': 'application/json',
          },
        }
      );
      return res;
    },
    2,
    500,
    2000
  );

  let result: boolean;

  if (typeof response.data.result === 'boolean') {
    result = response.data.result;
  } else if (typeof response.data.result === 'object' && response.data.result !== null) {
    result = response.data.result.allow;

    // Log reasons if present
    if (response.data.result.reasons) {
      securityLogger.info(
        {
          reasons: response.data.result.reasons,
          obligations: response.data.result.obligations,
        },
        'OPA decision with additional context'
      );
    }
  } else {
    // Default deny on bad response
    result = false;
  }

  // Cache result
  opaCache.set(cacheKey, {
    result,
    expiry: Date.now() + config.opa.cacheTtlMs,
  });

  return result;
};

// OPA authorization
export const opaAuthorizationMiddleware = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  const zeroTrustReq = req as ZeroTrustRequest;

  // Skip if OPA is off
  if (!features.opaPolicies || !config.opa.enabled) {
    next();
    return;
  }

  try {
    const input = buildOPAInput(zeroTrustReq);

    securityLogger.debug(
      {
        requestId: zeroTrustReq.requestId,
        input: {
          method: input.request.method,
          path: input.request.path,
          userId: input.subject.user?.id,
          action: input.action,
        },
      },
      'Querying OPA for authorization'
    );

    const allowed = await queryOPA(input);

    if (!allowed) {
      securityLogger.warn(
        {
          requestId: zeroTrustReq.requestId,
          userId: input.subject.user?.id,
          method: input.request.method,
          path: input.request.path,
          action: input.action,
        },
        'OPA authorization denied'
      );

      // Update security context
      if (zeroTrustReq.securityContext) {
        zeroTrustReq.securityContext.authorized = false;
        zeroTrustReq.securityContext.policies.push({
          policyId: 'opa-gateway',
          policyName: 'OPA Gateway Policy',
          decision: 'deny',
          reason: 'Policy evaluation denied access',
          timestamp: Date.now(),
        });
      }

      const error = new PolicyViolationError('Access denied by policy', {
        path: input.request.path,
        action: input.action,
      });

      res.status(error.statusCode).json({
        success: false,
        error: {
          code: error.code,
          message: error.message,
        },
        meta: {
          requestId: zeroTrustReq.requestId,
          timestamp: new Date().toISOString(),
        },
      });
      return;
    }

    // Update security context
    if (zeroTrustReq.securityContext) {
      zeroTrustReq.securityContext.authorized = true;
      zeroTrustReq.securityContext.policies.push({
        policyId: 'opa-gateway',
        policyName: 'OPA Gateway Policy',
        decision: 'allow',
        reason: 'Policy evaluation granted access',
        timestamp: Date.now(),
      });
    }

    securityLogger.info(
      {
        requestId: zeroTrustReq.requestId,
        userId: input.subject.user?.id,
        path: input.request.path,
      },
      'OPA authorization granted'
    );

    next();
  } catch (error) {
    securityLogger.error(
      {
        requestId: zeroTrustReq.requestId,
        error,
      },
      'OPA authorization check failed'
    );

    // Strict mode: deny on error
    if (config.security.zeroTrustMode === 'strict' || config.security.defaultDeny) {
      res.status(503).json({
        success: false,
        error: {
          code: 'POLICY_CHECK_FAILED',
          message: 'Policy authorization service unavailable',
        },
        meta: {
          requestId: zeroTrustReq.requestId,
          timestamp: new Date().toISOString(),
        },
      });
    } else {
      // Log warning, allow request
      securityLogger.warn(
        {
          requestId: zeroTrustReq.requestId,
        },
        'OPA check failed, allowing request in non-strict mode'
      );
      next();
    }
  }
};

// Cleanup expired cache entries
setInterval(
  () => {
    const now = Date.now();
    for (const [key, entry] of opaCache.entries()) {
      if (now > entry.expiry) {
        opaCache.delete(key);
      }
    }
  },
  60 * 1000
);

export default opaAuthorizationMiddleware;
