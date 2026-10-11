import dotenv from 'dotenv';
import path from 'path';

// Load environment variables
dotenv.config();

const isProduction = (process.env.NODE_ENV || 'development') === 'production';

export const config = {
  port: parseInt(process.env.PORT || '3000', 10),
  nodeEnv: process.env.NODE_ENV || 'development',
  apiBaseUrl: process.env.API_BASE_URL || 'https://db.mhservice.co.in',

  // PostgreSQL settings - Points to Common Database (shared_postgres in production or localhost in dev)
  pg: {
    host: process.env.PG_HOST || (isProduction ? 'shared_postgres' : 'localhost'),
    port: parseInt(process.env.PG_PORT || '5432', 10),
    user: process.env.PG_USER || 'postgres',
    password: process.env.PG_PASSWORD || (isProduction ? 'postgres_master_pass_2026' : 'postgres'),
    defaultDatabase: process.env.PG_DEFAULT_DATABASE || process.env.PG_COMMON_DATABASE || 'postgres',
    ssl: process.env.PG_SSL === 'true',
    maxPoolSize: parseInt(process.env.PG_MAX_POOL_SIZE || '20', 10),
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 5000,
  },

  // Admin access
  adminSecret: process.env.ADMIN_SECRET || 'mh_admin_super_secret_key_2026',

  // Rate Limiting
  rateLimit: {
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000', 10),
    maxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '120', 10),
  },

  // Storage
  dataDir: process.env.DATA_DIR || path.join(process.cwd(), 'data'),
  maxQueryExecutionTimeMs: parseInt(process.env.MAX_QUERY_EXECUTION_TIME_MS || '15000', 10),
};
