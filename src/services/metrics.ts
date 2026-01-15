import http from 'http';
import { config } from '../config';
import { logger, performanceLogger } from '../utils/logger';

// Metrics storage
const metrics = {
  requests: {
    total: 0,
    success: 0,
    error: 0,
    byMethod: new Map<string, number>(),
    byPath: new Map<string, number>(),
    byStatus: new Map<number, number>(),
  },
  latency: {
    total: 0,
    count: 0,
    min: Infinity,
    max: 0,
    buckets: new Map<number, number>(),
  },
  security: {
    authSuccess: 0,
    authFailure: 0,
    rateLimitHits: 0,
    policyDenials: 0,
    suspiciousRequests: 0,
  },
  system: {
    startTime: Date.now(),
    memoryUsage: process.memoryUsage(),
    cpuUsage: process.cpuUsage(),
  },
};

// Histogram buckets for latency (in ms)
const latencyBuckets = [5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000];

/**
 * Record a request metric
 */
export const recordRequest = (
  method: string,
  path: string,
  statusCode: number,
  latencyMs: number
): void => {
  metrics.requests.total++;

  if (statusCode >= 200 && statusCode < 400) {
    metrics.requests.success++;
  } else {
    metrics.requests.error++;
  }

  // Track by method
  const methodCount = metrics.requests.byMethod.get(method) || 0;
  metrics.requests.byMethod.set(method, methodCount + 1);

  // Track by path (normalize path)
  const normalizedPath = normalizePath(path);
  const pathCount = metrics.requests.byPath.get(normalizedPath) || 0;
  metrics.requests.byPath.set(normalizedPath, pathCount + 1);

  // Track by status
  const statusCount = metrics.requests.byStatus.get(statusCode) || 0;
  metrics.requests.byStatus.set(statusCode, statusCount + 1);

  // Track latency
  metrics.latency.total += latencyMs;
  metrics.latency.count++;
  metrics.latency.min = Math.min(metrics.latency.min, latencyMs);
  metrics.latency.max = Math.max(metrics.latency.max, latencyMs);

  // Update histogram buckets
  for (const bucket of latencyBuckets) {
    if (latencyMs <= bucket) {
      const bucketCount = metrics.latency.buckets.get(bucket) || 0;
      metrics.latency.buckets.set(bucket, bucketCount + 1);
    }
  }

  performanceLogger.debug(
    {
      method,
      path: normalizedPath,
      statusCode,
      latencyMs,
    },
    'Request metric recorded'
  );
};

/**
 * Normalize path by removing IDs
 */
const normalizePath = (path: string): string => {
  return path
    .replace(/\/\d+/g, '/:id')
    .replace(/\/[a-f0-9-]{36}/gi, '/:uuid')
    .replace(/\/user_\w+/g, '/:userId');
};

/**
 * Record security event metrics
 */
export const recordSecurityEvent = (
  eventType: 'authSuccess' | 'authFailure' | 'rateLimitHits' | 'policyDenials' | 'suspiciousRequests'
): void => {
  metrics.security[eventType]++;
};

/**
 * Get all metrics in Prometheus format
 */
const getPrometheusMetrics = (): string => {
  const lines: string[] = [];
  const prefix = 'zero_trust_gateway';

  // Request metrics
  lines.push(`# HELP ${prefix}_requests_total Total number of requests`);
  lines.push(`# TYPE ${prefix}_requests_total counter`);
  lines.push(`${prefix}_requests_total ${metrics.requests.total}`);

  lines.push(`# HELP ${prefix}_requests_success_total Total successful requests`);
  lines.push(`# TYPE ${prefix}_requests_success_total counter`);
  lines.push(`${prefix}_requests_success_total ${metrics.requests.success}`);

  lines.push(`# HELP ${prefix}_requests_error_total Total error requests`);
  lines.push(`# TYPE ${prefix}_requests_error_total counter`);
  lines.push(`${prefix}_requests_error_total ${metrics.requests.error}`);

  // Requests by method
  lines.push(`# HELP ${prefix}_requests_by_method_total Requests by HTTP method`);
  lines.push(`# TYPE ${prefix}_requests_by_method_total counter`);
  for (const [method, count] of metrics.requests.byMethod.entries()) {
    lines.push(`${prefix}_requests_by_method_total{method="${method}"} ${count}`);
  }

  // Requests by status
  lines.push(`# HELP ${prefix}_requests_by_status_total Requests by status code`);
  lines.push(`# TYPE ${prefix}_requests_by_status_total counter`);
  for (const [status, count] of metrics.requests.byStatus.entries()) {
    lines.push(`${prefix}_requests_by_status_total{status="${status}"} ${count}`);
  }

  // Latency metrics
  const avgLatency = metrics.latency.count > 0 ? metrics.latency.total / metrics.latency.count : 0;
  lines.push(`# HELP ${prefix}_request_duration_ms Request duration in milliseconds`);
  lines.push(`# TYPE ${prefix}_request_duration_ms summary`);
  lines.push(`${prefix}_request_duration_ms_sum ${metrics.latency.total}`);
  lines.push(`${prefix}_request_duration_ms_count ${metrics.latency.count}`);

  lines.push(`# HELP ${prefix}_request_duration_ms_avg Average request duration`);
  lines.push(`# TYPE ${prefix}_request_duration_ms_avg gauge`);
  lines.push(`${prefix}_request_duration_ms_avg ${avgLatency.toFixed(2)}`);

  lines.push(`# HELP ${prefix}_request_duration_ms_min Minimum request duration`);
  lines.push(`# TYPE ${prefix}_request_duration_ms_min gauge`);
  lines.push(
    `${prefix}_request_duration_ms_min ${metrics.latency.min === Infinity ? 0 : metrics.latency.min}`
  );

  lines.push(`# HELP ${prefix}_request_duration_ms_max Maximum request duration`);
  lines.push(`# TYPE ${prefix}_request_duration_ms_max gauge`);
  lines.push(`${prefix}_request_duration_ms_max ${metrics.latency.max}`);

  // Histogram
  lines.push(`# HELP ${prefix}_request_duration_bucket Request duration histogram`);
  lines.push(`# TYPE ${prefix}_request_duration_bucket histogram`);
  for (const bucket of latencyBuckets) {
    const count = metrics.latency.buckets.get(bucket) || 0;
    lines.push(`${prefix}_request_duration_bucket{le="${bucket}"} ${count}`);
  }
  lines.push(`${prefix}_request_duration_bucket{le="+Inf"} ${metrics.latency.count}`);

  // Security metrics
  lines.push(`# HELP ${prefix}_auth_success_total Authentication successes`);
  lines.push(`# TYPE ${prefix}_auth_success_total counter`);
  lines.push(`${prefix}_auth_success_total ${metrics.security.authSuccess}`);

  lines.push(`# HELP ${prefix}_auth_failure_total Authentication failures`);
  lines.push(`# TYPE ${prefix}_auth_failure_total counter`);
  lines.push(`${prefix}_auth_failure_total ${metrics.security.authFailure}`);

  lines.push(`# HELP ${prefix}_rate_limit_hits_total Rate limit hits`);
  lines.push(`# TYPE ${prefix}_rate_limit_hits_total counter`);
  lines.push(`${prefix}_rate_limit_hits_total ${metrics.security.rateLimitHits}`);

  lines.push(`# HELP ${prefix}_policy_denials_total Policy denials`);
  lines.push(`# TYPE ${prefix}_policy_denials_total counter`);
  lines.push(`${prefix}_policy_denials_total ${metrics.security.policyDenials}`);

  // System metrics
  const mem = process.memoryUsage();
  lines.push(`# HELP ${prefix}_memory_heap_used_bytes Heap memory used`);
  lines.push(`# TYPE ${prefix}_memory_heap_used_bytes gauge`);
  lines.push(`${prefix}_memory_heap_used_bytes ${mem.heapUsed}`);

  lines.push(`# HELP ${prefix}_memory_heap_total_bytes Total heap memory`);
  lines.push(`# TYPE ${prefix}_memory_heap_total_bytes gauge`);
  lines.push(`${prefix}_memory_heap_total_bytes ${mem.heapTotal}`);

  lines.push(`# HELP ${prefix}_memory_rss_bytes RSS memory`);
  lines.push(`# TYPE ${prefix}_memory_rss_bytes gauge`);
  lines.push(`${prefix}_memory_rss_bytes ${mem.rss}`);

  const uptime = (Date.now() - metrics.system.startTime) / 1000;
  lines.push(`# HELP ${prefix}_uptime_seconds Server uptime in seconds`);
  lines.push(`# TYPE ${prefix}_uptime_seconds gauge`);
  lines.push(`${prefix}_uptime_seconds ${uptime.toFixed(0)}`);

  return lines.join('\n') + '\n';
};

/**
 * Start metrics server
 */
export const startMetricsServer = (): void => {
  const metricsServer = http.createServer((req, res) => {
    if (req.url === config.monitoring.metricsPath) {
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end(getPrometheusMetrics());
    } else if (req.url === '/') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(`
        <html>
          <head><title>Metrics Server</title></head>
          <body>
            <h1>Zero-Trust Gateway Metrics</h1>
            <p><a href="${config.monitoring.metricsPath}">Prometheus Metrics</a></p>
          </body>
        </html>
      `);
    } else {
      res.writeHead(404);
      res.end('Not found');
    }
  });

  metricsServer.listen(config.monitoring.metricsPort, () => {
    logger.info(
      { port: config.monitoring.metricsPort, path: config.monitoring.metricsPath },
      'Metrics server started'
    );
  });
};

/**
 * Get current metrics (for internal use)
 */
export const getCurrentMetrics = (): typeof metrics => {
  return { ...metrics };
};
