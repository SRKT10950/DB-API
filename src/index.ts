import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import path from 'path';
import { config } from './config';
import { apiRateLimiter } from './middleware/rate-limiter';
import apiV1Router from './routes/api-v1';
import adminApiRouter from './routes/admin-api';
import healthRouter from './routes/health';
import { PgPoolManager } from './services/pg-pool';
import { DbStorageService } from './services/db-storage';

const app = express();

// Security and utility middleware
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'", 'https://cdn.tailwindcss.com', 'https://unpkg.com'],
        styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com', 'https://cdn.tailwindcss.com'],
        fontSrc: ["'self'", 'https://fonts.gstatic.com'],
        connectSrc: ["'self'"],
        imgSrc: ["'self'", 'data:'],
      },
    },
    crossOriginEmbedderPolicy: false,
  })
);

app.use(cors());
app.use(compression());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Static Admin Dashboard assets
const publicDir = path.join(__dirname, 'public');
app.get('/admin/login', (req, res) => {
  res.sendFile(path.join(publicDir, 'login.html'));
});
app.use('/admin', express.static(publicDir));

// System Health & Metrics
app.use(healthRouter);

// Admin API
app.use('/admin/api', adminApiRouter);

// Main Database API Endpoints: /API/1/:dbName
// Case-insensitive routing for /API/1/:dbName or /api/1/:dbName
app.use(['/API/1/:dbName', '/api/1/:dbName'], apiRateLimiter, apiV1Router);

// Root path redirect
app.get('/', (req, res) => {
  res.redirect('/admin');
});

// 404 Handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'Endpoint not found',
    documentation: 'See /admin for interactive documentation and control dashboard',
  });
});

// Global Error Handler
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error('[GlobalError]', err);
  res.status(err.status || 500).json({
    success: false,
    error: err.message || 'Internal Server Error',
  });
});

// Start Server if executed directly
let server: any = null;
if (require.main === module) {
  server = app.listen(config.port, () => {
    console.log(`=======================================================`);
    console.log(`  DB API Gateway active on port ${config.port}`);
    console.log(`  Environment: ${config.nodeEnv}`);
    console.log(`  Base API URL: ${config.apiBaseUrl}`);
    console.log(`  Target PostgreSQL Host: ${config.pg.host}:${config.pg.port}`);
    console.log(`  Admin Dashboard: http://localhost:${config.port}/admin`);
    console.log(`=======================================================`);

    // Initialize persistent db_admin and db_device tables in PostgreSQL
    DbStorageService.initSystemTables().catch((err) => {
      console.warn('[DbStorageService] Startup initialization deferred:', err.message);
    });
  });
}

// Graceful Shutdown
async function shutdown(signal: string) {
  console.log(`\nReceived ${signal}. Shutting down DB API Gateway gracefully...`);
  server.close(async () => {
    try {
      await PgPoolManager.closeAll();
      console.log('PostgreSQL pools closed.');
      process.exit(0);
    } catch (err) {
      console.error('Error during shutdown:', err);
      process.exit(1);
    }
  });
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

export default app;
