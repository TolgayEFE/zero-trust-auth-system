import pino from 'pino';
import { config } from '../config';

// Create the main logger instance
export const logger = pino({
  level: config.logging.level,
  formatters: {
    level: label => ({ level: label }),
    bindings: () => ({}),
  },
  timestamp: pino.stdTimeFunctions.isoTime,
  base: {
    service: 'zero-trust-gateway',
    version: process.env.npm_package_version || '1.0.0',
    environment: config.server.env,
  },
  redact: {
    paths: [
      'req.headers.authorization',
      'req.headers.cookie',
      'password',
      'token',
      'accessToken',
      'refreshToken',
      'secret',
      'privateKey',
    ],
    censor: '[REDACTED]',
  },
  serializers: {
    req: req => ({
      id: req.id,
      method: req.method,
      url: req.url,
      query: req.query,
      params: req.params,
      headers: {
        host: req.headers.host,
        'user-agent': req.headers['user-agent'],
        'content-type': req.headers['content-type'],
        'x-request-id': req.headers['x-request-id'],
      },
      remoteAddress: req.socket?.remoteAddress,
      remotePort: req.socket?.remotePort,
    }),
    res: res => ({
      statusCode: res.statusCode,
      headers: res.getHeaders ? res.getHeaders() : {},
    }),
    err: pino.stdSerializers.err,
  },
});

// Create child loggers for different modules
export const createModuleLogger = (moduleName: string): pino.Logger => {
  return logger.child({ module: moduleName });
};

// Audit logger for security events
export const auditLogger = logger.child({
  type: 'audit',
  module: 'security',
});

// Performance logger
export const performanceLogger = logger.child({
  type: 'performance',
  module: 'metrics',
});

// Security event logger
export const securityLogger = logger.child({
  type: 'security',
  module: 'zero-trust',
});

// Request lifecycle logger
export const requestLogger = logger.child({
  type: 'request',
  module: 'gateway',
});

export default logger;
