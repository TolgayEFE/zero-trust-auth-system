import { Server } from 'http';
import { logger } from '../utils/logger';
import { db } from '../db/connection';

const SHUTDOWN_TIMEOUT = 30000; // 30 seconds

let isShuttingDown = false;

/**
 * Setup graceful shutdown handlers
 */
export const setupGracefulShutdown = (server: Server): void => {
  const shutdown = (signal: string) => {
    if (isShuttingDown) {
      logger.info('Shutdown already in progress');
      return;
    }

    isShuttingDown = true;
    logger.info({ signal }, 'Received shutdown signal, starting graceful shutdown');

    // Stop accepting new connections
    server.close(err => {
      if (err) {
        logger.error({ error: err }, 'Error during server close');
        process.exit(1);
      }

      logger.info('HTTP server closed');

      // Cleanup resources
      performCleanup()
        .then(() => {
          logger.info('Graceful shutdown completed');
          process.exit(0);
        })
        .catch(cleanupErr => {
          logger.error({ error: cleanupErr }, 'Error during cleanup');
          process.exit(1);
        });
    });

    // Force shutdown after timeout
    setTimeout(() => {
      logger.error('Forced shutdown due to timeout');
      process.exit(1);
    }, SHUTDOWN_TIMEOUT);
  };

  // Register signal handlers
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGHUP', () => shutdown('SIGHUP'));

  logger.info('Graceful shutdown handlers registered');
};

/**
 * Perform cleanup tasks before shutdown
 */
const performCleanup = async (): Promise<void> => {
  logger.info('Performing cleanup tasks');

  try {
    // Close MongoDB connection
    if (db.isHealthy()) {
      logger.info('Closing MongoDB connection...');
      await db.disconnect();
      logger.info('MongoDB connection closed');
    }

    // Add more cleanup tasks here:
    // - Close Redis connections
    // - Flush logs
    // - Clean up temporary files
    // - Deregister from service discovery

    await new Promise(resolve => setTimeout(resolve, 100));

    logger.info('Cleanup tasks completed');
  } catch (error) {
    logger.error({ error }, 'Error during cleanup');
    throw error;
  }
};

/**
 * Check if shutdown is in progress
 */
export const isShuttingDownNow = (): boolean => {
  return isShuttingDown;
};
