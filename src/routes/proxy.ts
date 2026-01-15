import { Router, Request, Response } from 'express';
import { createProxyMiddleware, Options } from 'http-proxy-middleware';
import { ZeroTrustRequest } from '../types';
import { config } from '../config';
import { logger, securityLogger } from '../utils/logger';
import { generateRequestSignature } from '../utils/crypto';

const router = Router();

/**
 * Create proxy options for a service
 */
const createProxyOptions = (
  serviceName: string,
  targetUrl: string
): Options => {
  return {
    target: targetUrl,
    changeOrigin: true,
    pathRewrite: {
      [`^/api/${serviceName}`]: '',
    },
    timeout: 30000,
    proxyTimeout: 30000,

    onProxyReq: (proxyReq, req) => {
      const zeroTrustReq = req as ZeroTrustRequest;

      // Add security headers for inter-service communication
      if (zeroTrustReq.requestId) {
        proxyReq.setHeader('X-Request-ID', zeroTrustReq.requestId);
      }

      // Add user context if authenticated
      if (zeroTrustReq.securityContext?.user) {
        proxyReq.setHeader('X-User-ID', zeroTrustReq.securityContext.user.id);
        proxyReq.setHeader('X-User-Roles', zeroTrustReq.securityContext.user.roles.join(','));
        proxyReq.setHeader(
          'X-User-Permissions',
          zeroTrustReq.securityContext.user.permissions.join(',')
        );
      }

      // Add trust level
      if (zeroTrustReq.securityContext?.trustLevel) {
        proxyReq.setHeader('X-Trust-Level', zeroTrustReq.securityContext.trustLevel);
      }

      // Add risk score
      if (zeroTrustReq.securityContext?.riskScore !== undefined) {
        proxyReq.setHeader('X-Risk-Score', zeroTrustReq.securityContext.riskScore.toString());
      }

      // Add request signature for verification
      const timestamp = Date.now();
      const body = JSON.stringify(req.body || {});
      const signature = generateRequestSignature(
        req.method,
        req.path,
        timestamp,
        body,
        config.jwt.secret
      );

      proxyReq.setHeader('X-Gateway-Signature', signature);
      proxyReq.setHeader('X-Gateway-Timestamp', timestamp.toString());

      logger.debug(
        {
          service: serviceName,
          method: req.method,
          path: req.path,
          target: targetUrl,
        },
        'Proxying request to service'
      );
    },

    onProxyRes: (proxyRes, req) => {
      const zeroTrustReq = req as ZeroTrustRequest;

      logger.debug(
        {
          service: serviceName,
          requestId: zeroTrustReq.requestId,
          statusCode: proxyRes.statusCode,
        },
        'Received response from service'
      );

      // Add gateway headers to response
      proxyRes.headers['X-Gateway-Service'] = serviceName;
      proxyRes.headers['X-Gateway-Version'] = process.env.npm_package_version || '1.0.0';
    },

    onError: (err, req, res) => {
      const zeroTrustReq = req as ZeroTrustRequest;

      logger.error(
        {
          service: serviceName,
          requestId: zeroTrustReq.requestId,
          error: err.message,
        },
        'Proxy error'
      );

      securityLogger.warn(
        {
          service: serviceName,
          requestId: zeroTrustReq.requestId,
          error: err.message,
        },
        'Service communication failed'
      );

      // Type guard for response
      if ('status' in res && typeof res.status === 'function') {
        (res as Response).status(503).json({
          success: false,
          error: {
            code: 'SERVICE_UNAVAILABLE',
            message: `Service ${serviceName} is currently unavailable`,
          },
          meta: {
            requestId: zeroTrustReq.requestId,
            timestamp: new Date().toISOString(),
          },
        });
      }
    },
  };
};

// Register proxy routes for each service
Object.entries(config.services).forEach(([serviceName, serviceUrl]) => {
  if (typeof serviceUrl === 'string' && serviceUrl) {
    // Extract base URL for REST endpoints (remove /graphql)
    const baseUrl = serviceUrl.replace(/\/graphql$/, '');

    router.use(
      `/${serviceName}`,
      createProxyMiddleware(createProxyOptions(serviceName, baseUrl))
    );

    logger.info({ service: serviceName, target: baseUrl }, 'Registered proxy route');
  }
});

/**
 * Service discovery endpoint
 */
router.get('/_services', (req: Request, res: Response) => {
  const zeroTrustReq = req as ZeroTrustRequest;

  const services = Object.entries(config.services).map(([name, url]) => ({
    name,
    url,
    status: 'registered',
  }));

  res.json({
    success: true,
    data: {
      services,
      count: services.length,
    },
    meta: {
      requestId: zeroTrustReq.requestId,
      timestamp: new Date().toISOString(),
    },
  });
});

/**
 * Catch-all for undefined service routes
 */
router.use('*', (req: Request, res: Response) => {
  const zeroTrustReq = req as ZeroTrustRequest;

  res.status(404).json({
    success: false,
    error: {
      code: 'SERVICE_NOT_FOUND',
      message: 'The requested service or endpoint does not exist',
    },
    meta: {
      requestId: zeroTrustReq.requestId,
      timestamp: new Date().toISOString(),
    },
  });
});

export default router;
