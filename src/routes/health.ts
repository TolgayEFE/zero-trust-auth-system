import { Router, Request, Response } from 'express';
import { HealthCheckResult } from '../types';
import { config } from '../config';
import { checkDatabaseHealth } from '../services/health';

const router = Router();

// Server start time for uptime calculation
const serverStartTime = Date.now();

// Service health statuses
const serviceHealthCache = new Map<
  string,
  { status: 'up' | 'down' | 'degraded'; responseTime?: number; lastCheck: Date }
>();

/**
 * Basic health check
 */
router.get('/', (_req: Request, res: Response) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
  });
});

/**
 * Detailed health check
 */
router.get('/detailed', async (_req: Request, res: Response) => {
  const uptime = Date.now() - serverStartTime;
  const memoryUsage = process.memoryUsage();
  const cpuUsage = process.cpuUsage();

  const healthResult: HealthCheckResult = {
    status: 'healthy',
    timestamp: new Date(),
    uptime: Math.floor(uptime / 1000), // in seconds
    version: process.env.npm_package_version || '1.0.0',
    checks: {
      gateway: {
        status: 'up',
        lastCheck: new Date(),
        details: {
          uptime: Math.floor(uptime / 1000),
          environment: config.server.env,
          nodeVersion: process.version,
          platform: process.platform,
          memory: {
            heapUsed: Math.round(memoryUsage.heapUsed / 1024 / 1024),
            heapTotal: Math.round(memoryUsage.heapTotal / 1024 / 1024),
            rss: Math.round(memoryUsage.rss / 1024 / 1024),
            external: Math.round(memoryUsage.external / 1024 / 1024),
          },
          cpu: {
            user: cpuUsage.user,
            system: cpuUsage.system,
          },
        },
      },
    },
  };

  // Check MongoDB health
  try {
    const dbHealth = await checkDatabaseHealth();
    healthResult.checks.mongodb = {
      status: dbHealth.status,
      responseTime: dbHealth.responseTime,
      lastCheck: new Date(),
      details: {
        message: dbHealth.details,
      },
    };
  } catch (error) {
    healthResult.checks.mongodb = {
      status: 'down',
      lastCheck: new Date(),
      details: {
        error: error instanceof Error ? error.message : 'Unknown error',
      },
    };
  }

  // Add service health checks
  for (const [serviceName, serviceStatus] of serviceHealthCache.entries()) {
    healthResult.checks[serviceName] = serviceStatus;
  }

  // Determine overall status
  const hasUnhealthyService = Object.values(healthResult.checks).some(
    check => check.status === 'down'
  );
  const hasDegradedService = Object.values(healthResult.checks).some(
    check => check.status === 'degraded'
  );

  if (hasUnhealthyService) {
    healthResult.status = 'unhealthy';
  } else if (hasDegradedService) {
    healthResult.status = 'degraded';
  }

  const statusCode =
    healthResult.status === 'healthy' ? 200 : healthResult.status === 'degraded' ? 200 : 503;

  res.status(statusCode).json(healthResult);
});

/**
 * Liveness probe (Kubernetes)
 */
router.get('/live', (_req: Request, res: Response) => {
  // Simple check - if we can respond, we're alive
  res.status(200).json({
    status: 'alive',
    timestamp: new Date().toISOString(),
  });
});

/**
 * Readiness probe (Kubernetes)
 */
router.get('/ready', (_req: Request, res: Response) => {
  // Check if the application is ready to serve traffic
  // In production, check database connections, external services, etc.

  const checks = {
    configLoaded: true,
    memoryWithinLimits: process.memoryUsage().heapUsed < 500 * 1024 * 1024, // 500MB
  };

  const isReady = Object.values(checks).every(check => check === true);

  if (isReady) {
    res.status(200).json({
      status: 'ready',
      checks,
      timestamp: new Date().toISOString(),
    });
  } else {
    res.status(503).json({
      status: 'not_ready',
      checks,
      timestamp: new Date().toISOString(),
    });
  }
});

/**
 * Version information
 */
router.get('/version', (_req: Request, res: Response) => {
  res.json({
    version: process.env.npm_package_version || '1.0.0',
    name: 'zero-trust-api-gateway',
    environment: config.server.env,
    buildTime: process.env.BUILD_TIME || 'unknown',
    gitCommit: process.env.GIT_COMMIT || 'unknown',
    nodeVersion: process.version,
    platform: process.platform,
    arch: process.arch,
  });
});

/**
 * Update service health (called by health check service)
 */
export const updateServiceHealth = (
  serviceName: string,
  status: 'up' | 'down' | 'degraded',
  responseTime?: number
): void => {
  serviceHealthCache.set(serviceName, {
    status,
    responseTime,
    lastCheck: new Date(),
  });
};

export default router;
