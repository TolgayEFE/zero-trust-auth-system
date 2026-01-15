import { Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { ZeroTrustRequest, ZeroTrustError } from '../types';
import { securityLogger } from '../utils/logger';
import { sanitizeString } from '../utils/helpers';

// Validate and sanitize requests
export const requestValidationMiddleware = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  const zeroTrustReq = req as ZeroTrustRequest;

  try {
    // Check Content-Type for requests with body
    if (['POST', 'PUT', 'PATCH'].includes(req.method) && req.body) {
      const contentType = req.headers['content-type'];
      if (!contentType) {
        throw new ZeroTrustError(
          'Content-Type header is required',
          'MISSING_CONTENT_TYPE',
          400
        );
      }

      // Allow only safe content types
      const allowedContentTypes = [
        'application/json',
        'application/x-www-form-urlencoded',
        'multipart/form-data',
      ];

      const isAllowed = allowedContentTypes.some(type => contentType.includes(type));

      if (!isAllowed) {
        throw new ZeroTrustError(
          'Unsupported Content-Type',
          'UNSUPPORTED_CONTENT_TYPE',
          415
        );
      }
    }

    // Block path traversal
    if (req.path.includes('..') || req.path.includes('%2e%2e')) {
      securityLogger.warn(
        {
          requestId: zeroTrustReq.requestId,
          path: req.path,
          clientIp: zeroTrustReq.securityContext?.clientIp,
        },
        'Directory traversal attempt detected'
      );

      throw new ZeroTrustError(
        'Invalid path',
        'INVALID_PATH',
        400
      );
    }

    // Check for risky headers
    const suspiciousHeaders = ['x-forwarded-host', 'x-original-url', 'x-rewrite-url'];
    for (const header of suspiciousHeaders) {
      const value = req.headers[header];
      if (value && typeof value === 'string') {
        if (value.includes('..') || value.includes('%00') || value.includes('\x00')) {
          securityLogger.warn(
            {
              requestId: zeroTrustReq.requestId,
              header,
              value,
            },
            'Suspicious header value detected'
          );

          throw new ZeroTrustError(
            'Invalid header value',
            'INVALID_HEADER',
            400
          );
        }
      }
    }

    // Validate query params
    if (req.query) {
      for (const [key, value] of Object.entries(req.query)) {
        if (typeof value === 'string') {
          // Check SQLi patterns
          const sqlPatterns = [
            /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|FETCH|DECLARE|TRUNCATE)\b)/i,
            /(--)|(\/\*)|(\*\/)/,
            /(\bOR\b\s*\d+\s*=\s*\d+)/i,
            /(\bAND\b\s*\d+\s*=\s*\d+)/i,
          ];

          for (const pattern of sqlPatterns) {
            if (pattern.test(value)) {
              securityLogger.warn(
                {
                  requestId: zeroTrustReq.requestId,
                  key,
                  value,
                },
                'Potential SQL injection detected in query parameter'
              );

              throw new ZeroTrustError(
                'Invalid query parameter',
                'INVALID_QUERY_PARAMETER',
                400
              );
            }
          }

          // Check XSS patterns
          const xssPatterns = [
            /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
            /javascript:/gi,
            /on\w+\s*=/gi,
            /<iframe/gi,
            /<object/gi,
            /<embed/gi,
            /<svg.*on/gi,
          ];

          for (const pattern of xssPatterns) {
            if (pattern.test(value)) {
              securityLogger.warn(
                {
                  requestId: zeroTrustReq.requestId,
                  key,
                  value,
                },
                'Potential XSS detected in query parameter'
              );

              throw new ZeroTrustError(
                'Invalid query parameter',
                'INVALID_QUERY_PARAMETER',
                400
              );
            }
          }
        }
      }
    }

    // Check body size
    const contentLength = parseInt(req.headers['content-length'] || '0', 10);
    const maxBodySize = 10 * 1024 * 1024; // 10MB

    if (contentLength > maxBodySize) {
      throw new ZeroTrustError(
        'Request body too large',
        'PAYLOAD_TOO_LARGE',
        413
      );
    }

    // Validate JSON body
    if (req.body && typeof req.body === 'object' && req.headers['content-type']?.includes('application/json')) {
      // Check prototype pollution
      const dangerousKeys = ['__proto__', 'constructor', 'prototype'];
      const checkForDangerousKeys = (obj: unknown, path: string = ''): void => {
        if (obj === null || typeof obj !== 'object') return;

        for (const key of Object.keys(obj as object)) {
          if (dangerousKeys.includes(key)) {
            securityLogger.warn(
              {
                requestId: zeroTrustReq.requestId,
                key,
                path: path ? `${path}.${key}` : key,
              },
              'Prototype pollution attempt detected'
            );

            throw new ZeroTrustError(
              'Invalid request body',
              'INVALID_REQUEST_BODY',
              400
            );
          }

          const value = (obj as Record<string, unknown>)[key];
          if (typeof value === 'object' && value !== null) {
            checkForDangerousKeys(value, path ? `${path}.${key}` : key);
          }
        }
      };

      checkForDangerousKeys(req.body);
    }

    next();
  } catch (error) {
    if (error instanceof ZeroTrustError) {
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
    } else {
      next(error);
    }
  }
};

/**
 * Create a validation middleware from a Zod schema
 */
export const createValidationMiddleware = (
  schema: z.ZodType,
  source: 'body' | 'query' | 'params' = 'body'
) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    const zeroTrustReq = req as ZeroTrustRequest;

    try {
      const dataToValidate = req[source];
      const result = schema.safeParse(dataToValidate);

      if (!result.success) {
        const errors = result.error.errors.map(err => ({
          field: err.path.join('.'),
          message: err.message,
        }));

        res.status(400).json({
          success: false,
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Request validation failed',
            details: { errors },
          },
          meta: {
            requestId: zeroTrustReq.requestId,
            timestamp: new Date().toISOString(),
          },
        });
        return;
      }

      // Use validated data
      (req as unknown as Record<string, unknown>)[source] = result.data;

      next();
    } catch (error) {
      next(error);
    }
  };
};

// Sanitize request body
export const sanitizeBodyMiddleware = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  if (req.body && typeof req.body === 'object') {
    const sanitizeObject = (obj: unknown): unknown => {
      if (obj === null || typeof obj !== 'object') {
        if (typeof obj === 'string') {
          return sanitizeString(obj);
        }
        return obj;
      }

      if (Array.isArray(obj)) {
        return obj.map(sanitizeObject);
      }

      const sanitized: Record<string, unknown> = {};
      for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
        sanitized[sanitizeString(key)] = sanitizeObject(value);
      }
      return sanitized;
    };

    req.body = sanitizeObject(req.body);
  }

  next();
};

export default requestValidationMiddleware;
