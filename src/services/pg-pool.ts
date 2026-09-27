import { Pool, PoolConfig, QueryResult } from 'pg';
import { config } from '../config';

export interface QueryExecutionResult {
  rows: any[];
  rowCount: number;
  durationMs: number;
  command: string;
}

export class PgPoolManager {
  private static pools: Map<string, Pool> = new Map();

  /**
   * Retrieves or creates a PostgreSQL connection pool for the given database name.
   */
  public static getPool(dbName: string): Pool {
    const key = dbName.toLowerCase().trim();

    if (!this.pools.has(key)) {
      const poolConfig: PoolConfig = {
        host: config.pg.host,
        port: config.pg.port,
        user: config.pg.user,
        password: config.pg.password,
        database: key,
        ssl: config.pg.ssl ? { rejectUnauthorized: false } : false,
        max: config.pg.maxPoolSize,
        idleTimeoutMillis: config.pg.idleTimeoutMillis,
        connectionTimeoutMillis: config.pg.connectionTimeoutMillis,
      };

      const pool = new Pool(poolConfig);

      pool.on('error', (err) => {
        console.error(`[PgPoolManager] Unexpected error on idle client for database '${key}':`, err);
      });

      this.pools.set(key, pool);
    }

    return this.pools.get(key)!;
  }

  /**
   * Executes a parameterized SQL query on a specific database with timeout handling.
   */
  public static async executeQuery(
    dbName: string,
    sql: string,
    params: any[] = []
  ): Promise<QueryExecutionResult> {
    const pool = this.getPool(dbName);
    const start = performance.now();

    const client = await pool.connect();
    try {
      // Set statement timeout for safety
      await client.query(`SET statement_timeout = ${config.maxQueryExecutionTimeMs}`);
      
      const result: QueryResult = await client.query(sql, params);
      const durationMs = Math.round((performance.now() - start) * 100) / 100;

      return {
        rows: result.rows || [],
        rowCount: result.rowCount || (result.rows ? result.rows.length : 0),
        durationMs,
        command: result.command || 'UNKNOWN',
      };
    } finally {
      client.release();
    }
  }

  /**
   * Tests general connection to PostgreSQL default database.
   */
  public static async testConnection(): Promise<{ connected: boolean; version?: string; error?: string }> {
    try {
      const pool = this.getPool(config.pg.defaultDatabase);
      const res = await pool.query('SELECT version()');
      return {
        connected: true,
        version: res.rows[0]?.version,
      };
    } catch (err: any) {
      return {
        connected: false,
        error: err.message || 'Failed to connect to PostgreSQL',
      };
    }
  }

  /**
   * Lists available databases in PostgreSQL instance.
   */
  public static async listDatabases(): Promise<string[]> {
    const pool = this.getPool(config.pg.defaultDatabase);
    const res = await pool.query(
      `SELECT datname FROM pg_database WHERE datistemplate = false ORDER BY datname ASC;`
    );
    return res.rows.map((r) => r.datname);
  }

  /**
   * Provisions a new database on the local PostgreSQL instance.
   */
  public static async createDatabase(newDbName: string): Promise<boolean> {
    // Validate database name identifier strictly
    if (!/^[a-zA-Z0-9_]{1,63}$/.test(newDbName)) {
      throw new Error('Invalid database name. Only alphanumeric characters and underscores allowed (max 63 chars).');
    }

    const pool = this.getPool(config.pg.defaultDatabase);
    // CREATE DATABASE cannot run in a multi-command block or parameter
    await pool.query(`CREATE DATABASE "${newDbName}"`);
    return true;
  }

  /**
   * Lists tables within a specific database.
   */
  public static async listTables(dbName: string): Promise<string[]> {
    const pool = this.getPool(dbName);
    const res = await pool.query(
      `SELECT table_name 
       FROM information_schema.tables 
       WHERE table_schema = 'public' 
       AND table_type = 'BASE TABLE'
       ORDER BY table_name ASC;`
    );
    return res.rows.map((r) => r.table_name);
  }

  /**
   * Closes all connection pools gracefully.
   */
  public static async closeAll(): Promise<void> {
    for (const [name, pool] of this.pools.entries()) {
      try {
        await pool.end();
      } catch (err) {
        console.error(`Error closing pool for ${name}:`, err);
      }
    }
    this.pools.clear();
  }
}
