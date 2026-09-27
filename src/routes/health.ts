import { Router, Request, Response } from 'express';
import { metadataStore } from '../services/metadata-store';
import { PgPoolManager } from '../services/pg-pool';

const router = Router();

router.get('/health', async (req: Request, res: Response) => {
  const pgStatus = await PgPoolManager.testConnection();

  const isHealthy = pgStatus.connected;
  const statusCode = isHealthy ? 200 : 503;

  return res.status(statusCode).json({
    status: isHealthy ? 'healthy' : 'degraded',
    timestamp: new Date().toISOString(),
    uptimeSeconds: Math.floor(process.uptime()),
    database: {
      connected: pgStatus.connected,
      error: pgStatus.error || null,
    },
  });
});

router.get('/metrics', (req: Request, res: Response) => {
  const stats = metadataStore.getStats();

  // Prometheus format
  const metrics = [
    '# HELP dbapi_total_requests_total Total number of API requests handled',
    '# TYPE dbapi_total_requests_total counter',
    `dbapi_total_requests_total ${stats.totalRequests}`,
    '',
    '# HELP dbapi_threats_blocked_total Total number of security threats blocked',
    '# TYPE dbapi_threats_blocked_total counter',
    `dbapi_threats_blocked_total ${stats.threatsBlocked}`,
    '',
    '# HELP dbapi_active_keys_total Total active API keys',
    '# TYPE dbapi_active_keys_total gauge',
    `dbapi_active_keys_total ${stats.activeKeys}`,
    '',
    '# HELP dbapi_active_apps_total Total active registered applications',
    '# TYPE dbapi_active_apps_total gauge',
    `dbapi_active_apps_total ${stats.activeApps}`,
    '',
    '# HELP dbapi_process_uptime_seconds Process uptime in seconds',
    '# TYPE dbapi_process_uptime_seconds gauge',
    `dbapi_process_uptime_seconds ${Math.floor(process.uptime())}`,
  ].join('\n');

  res.setHeader('Content-Type', 'text/plain; version=0.0.4');
  return res.send(metrics);
});

export default router;
