import express, { Application, Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import cookieParser from 'cookie-parser';
import morgan from 'morgan';

import { config, features } from './config';
import { ZeroTrustRequest, ZeroTrustError } from './types';
import { logger, requestLogger } from './utils/logger';
import { generateUUID } from './utils/crypto';
import {
  initializeSecurityContext,
  sendErrorResponse,
  calculateRiskScore,
  determineTrustLevel,
} from './utils/helpers';

// Import middleware (will be created)
import { rateLimitMiddleware } from './middleware/rateLimit';
import { csrfProtection } from './middleware/csrf';
import { jwtAuthMiddleware } from './middleware/jwt';
import { opaAuthorizationMiddleware } from './middleware/opa';
import { auditLogMiddleware } from './middleware/audit';
import { requestValidationMiddleware } from './middleware/validation';
import { deviceTrackingMiddleware } from './middleware/device-tracking';

// Import routes
import authRoutes from './routes/auth';
import healthRoutes from './routes/health';
import proxyRoutes from './routes/proxy';
import deviceRoutes from './routes/devices';
import mfaRoutes from './routes/mfa';

export const createApp = (): Application => {
  const app = express();

  // Trust proxy headers
  app.set('trust proxy', 1);

  // Request ID
  app.use((req: ZeroTrustRequest, res: Response, next: NextFunction) => {
    req.requestId = (req.headers['x-request-id'] as string) || generateUUID();
    req.startTime = Date.now();
    res.setHeader('X-Request-ID', req.requestId);
    next();
  });

  // Security context
  app.use((req: ZeroTrustRequest, res: Response, next: NextFunction) => {
    req.securityContext = initializeSecurityContext(req);
    next();
  });

  // Device tracking
  app.use(deviceTrackingMiddleware);

  // Security headers
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          imgSrc: ["'self'", 'data:', 'https:'],
          connectSrc: ["'self'"],
          fontSrc: ["'self'"],
          objectSrc: ["'none'"],
          mediaSrc: ["'self'"],
          frameSrc: ["'none'"],
          baseUri: ["'self'"],
          formAction: ["'self'"],
          frameAncestors: ["'none'"],
          upgradeInsecureRequests: [],
        },
        reportOnly: false,
      },
      crossOriginEmbedderPolicy: true,
      crossOriginOpenerPolicy: { policy: 'same-origin' },
      crossOriginResourcePolicy: { policy: 'same-origin' },
      dnsPrefetchControl: { allow: false },
      frameguard: { action: 'deny' },
      hidePoweredBy: true,
      hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true,
      },
      ieNoOpen: true,
      noSniff: true,
      originAgentCluster: true,
      permittedCrossDomainPolicies: { permittedPolicies: 'none' },
      referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
      xssFilter: true,
    })
  );

  // CORS
  app.use(
    cors({
      origin: (origin, callback) => {
      // Allow requests with no origin (mobile apps, curl)
        if (!origin) return callback(null, true);

        const allowedOrigins = config.security.corsOrigins;
        console.log('origin', origin);
        console.log('allowedOrigins', allowedOrigins);
        console.log('config.server.env', config.server.env);
        if (allowedOrigins.includes(origin) || config.server.env === 'development') {
          callback(null, true);
        } else {
          callback(new Error('Not allowed by CORS'));
        }
      },
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
      allowedHeaders: [
        'Content-Type',
        'Authorization',
        'X-Requested-With',
        'X-CSRF-Token',
        'X-Request-ID',
      ],
      exposedHeaders: ['X-Request-ID', 'X-RateLimit-Limit', 'X-RateLimit-Remaining'],
      maxAge: 86400,
    })
  );

  // Compression
  app.use(compression());

  // Body parsing
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true, limit: '10mb' }));
  app.use(cookieParser());

  // Request logging
  if (config.server.env !== 'test') {
    app.use(
      morgan('combined', {
        stream: {
          write: (message: string) => {
            requestLogger.info(message.trim());
          },
        },
      })
    );
  }

  // Rate limiting
  app.use(rateLimitMiddleware);

  // Request validation
  app.use(requestValidationMiddleware);

  // Audit logging
  app.use(auditLogMiddleware);

  // Health routes
  app.use('/health', healthRoutes);
  app.use('/ready', healthRoutes);

  // Auth routes
  app.use('/auth', authRoutes);

  // MFA routes
  app.use('/auth/mfa', mfaRoutes);

  // Device routes
  app.use('/api/devices', deviceRoutes);

  // CSRF for state-changing routes
  app.use('/api', csrfProtection);

  // JWT auth for protected routes
  app.use('/api', jwtAuthMiddleware);

  // Risk score and trust level
  app.use('/api', (req: ZeroTrustRequest, res: Response, next: NextFunction) => {
    if (req.securityContext) {
      req.securityContext.riskScore = calculateRiskScore(req.securityContext);
      req.securityContext.trustLevel = determineTrustLevel(req.securityContext);
    }
    next();
  });

  // OPA policy
  app.use('/api', opaAuthorizationMiddleware);

  // Proxy routes
  app.use('/api', proxyRoutes);

  // CSP report endpoint
  app.post('/csp-report', express.json({ type: 'application/csp-report' }), (req, res) => {
    logger.warn({ report: req.body }, 'CSP Violation Report');
    res.status(204).end();
  });

  // 404 handler
  app.use((req: ZeroTrustRequest, res: Response, next: NextFunction) => {
    if (features.graphqlFederation && req.path === config.graphql.path) {
      next();
      return;
    }

    sendErrorResponse(
      res,
      new ZeroTrustError('Resource not found', 'NOT_FOUND', 404),
      req.requestId
    );
  });

  // Error handler
  app.use((err: Error, req: ZeroTrustRequest, res: Response, _next: NextFunction) => {
    logger.error(
      {
        error: err,
        requestId: req.requestId,
        path: req.path,
        method: req.method,
      },
      'Unhandled error'
    );

    if (err instanceof ZeroTrustError) {
      sendErrorResponse(res, err, req.requestId);
    } else if (err.name === 'UnauthorizedError') {
      sendErrorResponse(
        res,
        new ZeroTrustError('Invalid token', 'INVALID_TOKEN', 401),
        req.requestId
      );
    } else if (err.message === 'Not allowed by CORS') {
      sendErrorResponse(
        res,
        new ZeroTrustError('CORS policy violation', 'CORS_ERROR', 403),
        req.requestId
      );
    } else {
      sendErrorResponse(
        res,
        new ZeroTrustError(
          config.server.env === 'production'
            ? 'Internal server error'
            : err.message || 'Internal server error',
          'INTERNAL_ERROR',
          500
        ),
        req.requestId
      );
    }
  });

  return app;
};

export default createApp;
