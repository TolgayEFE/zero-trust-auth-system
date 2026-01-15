import axios from 'axios';
import { config } from '../config';
import { logger } from '../utils/logger';
import { updateServiceHealth } from '../routes/health';
import { retryWithBackoff } from '../utils/helpers';
import { db } from '../db/connection';

// Store for health check intervals
const healthCheckIntervals: NodeJS.Timeout[] = [];

/**
 * Check MongoDB database health
 */
export const checkDatabaseHealth = async (): Promise<{
  status: 'up' | 'down' | 'degraded';
  responseTime: number;
  details?: string;
}> => {
  const startTime = Date.now();

  try {
    if (!db.isHealthy()) {
      return {
        status: 'down',
        responseTime: Date.now() - startTime,
        details: 'Database not connected',
      };
    }

    // Ping database
    const pingTime = await db.ping();

    return {
      status: pingTime < 100 ? 'up' : 'degraded',
      responseTime: pingTime,
      details: `Ping: ${pingTime}ms`,
    };
  } catch (error) {
    return {
      status: 'down',
      responseTime: Date.now() - startTime,
      details: error instanceof Error ? error.message : 'Unknown error',
    };
  }
};

/**
 * Check health of a single service
 */
const checkServiceHealth = async (
  serviceName: string,
  serviceUrl: string
): Promise<void> => {
  const startTime = Date.now();

  try {
    // Try to reach the service health endpoint
    const healthUrl = serviceUrl.replace(/\/graphql$/, '/health');

    const response = await retryWithBackoff(
      () =>
        axios.get(healthUrl, {
          timeout: 5000,
          validateStatus: status => status < 500,
        }),
      2,
      500,
      2000
    );

    const responseTime = Date.now() - startTime;

    if (response.status === 200) {
      updateServiceHealth(serviceName, 'up', responseTime);
      logger.debug(
        {
          service: serviceName,
          responseTime,
        },
        'Service health check passed'
      );
    } else {
      updateServiceHealth(serviceName, 'degraded', responseTime);
      logger.warn(
        {
          service: serviceName,
          status: response.status,
          responseTime,
        },
        'Service health check returned non-200 status'
      );
    }
  } catch (error) {
    const responseTime = Date.now() - startTime;
    updateServiceHealth(serviceName, 'down', responseTime);

    logger.error(
      {
        service: serviceName,
        error: error instanceof Error ? error.message : 'Unknown error',
        responseTime,
      },
      'Service health check failed'
    );
  }
};

/**
 * Initialize health checks for all registered services
 */
export const initializeHealthChecks = (): void => {
  logger.info('Initializing service health checks');

  // Check each service periodically
  for (const [serviceName, serviceUrl] of Object.entries(config.services)) {
    if (typeof serviceUrl === 'string' && serviceUrl) {
      // Initial check
      checkServiceHealth(serviceName, serviceUrl).catch(() => {
        // Error already logged in checkServiceHealth
      });

      // Schedule periodic checks
      const interval = setInterval(() => {
        checkServiceHealth(serviceName, serviceUrl).catch(() => {
          // Error already logged in checkServiceHealth
        });
      }, config.monitoring.healthCheckIntervalMs);

      healthCheckIntervals.push(interval);

      logger.info(
        {
          service: serviceName,
          url: serviceUrl,
          intervalMs: config.monitoring.healthCheckIntervalMs,
        },
        'Health check scheduled for service'
      );
    }
  }
};

/**
 * Stop all health checks
 */
export const stopHealthChecks = (): void => {
  for (const interval of healthCheckIntervals) {
    clearInterval(interval);
  }
  healthCheckIntervals.length = 0;
  logger.info('Health checks stopped');
};

/**
 * Perform a manual health check for all services
 */
export const checkAllServices = async (): Promise<
  Map<string, { status: string; responseTime: number }>
> => {
  const results = new Map<string, { status: string; responseTime: number }>();

  const checks = Object.entries(config.services).map(async ([serviceName, serviceUrl]) => {
    if (typeof serviceUrl === 'string' && serviceUrl) {
      const startTime = Date.now();

      try {
        const healthUrl = serviceUrl.replace(/\/graphql$/, '/health');
        const response = await axios.get(healthUrl, {
          timeout: 5000,
        });

        const responseTime = Date.now() - startTime;

        results.set(serviceName, {
          status: response.status === 200 ? 'up' : 'degraded',
          responseTime,
        });
      } catch {
        const responseTime = Date.now() - startTime;
        results.set(serviceName, {
          status: 'down',
          responseTime,
        });
      }
    }
  });

  await Promise.all(checks);

  return results;
};
