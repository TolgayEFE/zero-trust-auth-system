import https from 'https';
import http from 'http';
import fs from 'fs';
import path from 'path';

import { createApp } from './app';
import { config, features } from './config';
import { logger } from './utils/logger';
import { setupGracefulShutdown } from './services/shutdown';
import { initializeGraphQLGateway } from './graphql/gateway';
import { startMetricsServer } from './services/metrics';
import { initializeHealthChecks } from './services/health';
import { db } from './db/connection';

const startServer = async (): Promise<void> => {
  try {
    logger.info('Starting Zero-Trust API Gateway...');

    // Initialize MongoDB connection
    try {
      logger.info('Connecting to MongoDB...');
      await db.connect(config.mongodb.uri, config.mongodb.dbName);
      logger.info('MongoDB connected successfully');
    } catch (error) {
      logger.error('Failed to connect to MongoDB:', error);
      logger.warn('DB not ready. Using memory storage.');
    }

    // Create Express app
    const app = createApp();

    // Initialize GraphQL Gateway if enabled
    if (features.graphqlFederation) {
      logger.info('Initializing GraphQL Federation Gateway...');
      await initializeGraphQLGateway(app);
      logger.info('GraphQL Federation Gateway initialized');
    }

    let server: https.Server | http.Server;

    // Create HTTPS server with mTLS if enabled
    if (features.mtls && config.mtls.enabled) {
      logger.info('Initializing mTLS configuration...');

      const caCertPath = path.resolve(config.mtls.caCertPath);
      const serverCertPath = path.resolve(config.mtls.serverCertPath);
      const serverKeyPath = path.resolve(config.mtls.serverKeyPath);

      // Check if certificates exist
      if (
        !fs.existsSync(caCertPath) ||
        !fs.existsSync(serverCertPath) ||
        !fs.existsSync(serverKeyPath)
      ) {
        logger.warn('mTLS certificates not found. Falling back to HTTP server.');
        logger.warn('Run `npm run generate:certs` to generate certificates.');
        server = http.createServer(app);
      } else {
        const httpsOptions: https.ServerOptions = {
          ca: fs.readFileSync(caCertPath),
          cert: fs.readFileSync(serverCertPath),
          key: fs.readFileSync(serverKeyPath),
          requestCert: config.mtls.clientCertRequired,
          rejectUnauthorized: config.mtls.clientCertRequired,
          minVersion: 'TLSv1.3',
          ciphers: [
            'TLS_AES_256_GCM_SHA384',
            'TLS_CHACHA20_POLY1305_SHA256',
            'TLS_AES_128_GCM_SHA256',
          ].join(':'),
        };

        server = https.createServer(httpsOptions, app);
        logger.info('mTLS enabled with TLS 1.3');
      }
    } else {
      server = http.createServer(app);
      logger.info('Running in HTTP mode (mTLS disabled)');
    }

    // Start main server
    server.listen(config.server.port, config.server.host, () => {
      logger.info(
        {
          port: config.server.port,
          host: config.server.host,
          environment: config.server.env,
          zeroTrustMode: config.security.zeroTrustMode,
          features: {
            graphqlFederation: features.graphqlFederation,
            mtls: features.mtls && config.mtls.enabled,
            opaPolicies: features.opaPolicies,
            advancedRateLimiting: features.advancedRateLimiting,
          },
        },
        `Zero-Trust API Gateway started on ${config.server.host}:${config.server.port}`
      );
    });

    // Start metrics server if enabled
    if (config.monitoring.metricsEnabled) {
      startMetricsServer();
    }

    // Initialize health checks
    initializeHealthChecks();

    // Setup graceful shutdown
    setupGracefulShutdown(server);

    // Handle uncaught exceptions
    process.on('uncaughtException', error => {
      logger.fatal({ error }, 'Uncaught Exception');
      process.exit(1);
    });

    // Handle unhandled rejections
    process.on('unhandledRejection', (reason, promise) => {
      logger.fatal({ reason, promise }, 'Unhandled Rejection');
      process.exit(1);
    });
  } catch (error) {
    logger.fatal({ error }, 'Failed to start server');
    process.exit(1);
  }
};

// Start the server
startServer().catch(error => {
  logger.fatal({ error }, 'Server startup failed');
  process.exit(1);
});
