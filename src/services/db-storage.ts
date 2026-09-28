import crypto from 'crypto';
import { config } from '../config';
import { PgPoolManager } from './pg-pool';
import { metadataStore, ApiKeyRecord, DeviceRecord } from './metadata-store';
import { KeyService } from './key-service';

export class DbStorageService {
  private static initialized = false;

  /**
   * Initializes persistent system tables: db_admin and db_device in PostgreSQL
   */
  public static async initSystemTables(): Promise<void> {
    try {
      const pool = PgPoolManager.getPool(config.pg.defaultDatabase);

      // 1. Create db_admin table to store API Keys
      await pool.query(`
        CREATE TABLE IF NOT EXISTS db_admin (
          id SERIAL PRIMARY KEY,
          api_key VARCHAR(255) NOT NULL,
          key_hash VARCHAR(64) UNIQUE NOT NULL,
          key_prefix VARCHAR(50) NOT NULL,
          app_name VARCHAR(100) NOT NULL,
          db_name VARCHAR(100) NOT NULL,
          can_create BOOLEAN DEFAULT TRUE,
          can_read BOOLEAN DEFAULT TRUE,
          can_update BOOLEAN DEFAULT TRUE,
          can_delete BOOLEAN DEFAULT FALSE,
          can_ddl BOOLEAN DEFAULT FALSE,
          allowed_ips JSONB DEFAULT '[]'::jsonb,
          status VARCHAR(20) DEFAULT 'active',
          created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
          last_used_at TIMESTAMP WITH TIME ZONE
        );
        CREATE INDEX IF NOT EXISTS idx_db_admin_hash ON db_admin(key_hash);
        CREATE INDEX IF NOT EXISTS idx_db_admin_app_db ON db_admin(app_name, db_name);
      `);

      // 2. Create db_device table to store Device Keys
      await pool.query(`
        CREATE TABLE IF NOT EXISTS db_device (
          id SERIAL PRIMARY KEY,
          app_name VARCHAR(100) NOT NULL,
          device_name VARCHAR(100) NOT NULL,
          device_type VARCHAR(50) NOT NULL,
          device_key VARCHAR(255) NOT NULL,
          device_key_hash VARCHAR(64) NOT NULL,
          device_key_prefix VARCHAR(50) NOT NULL,
          location VARCHAR(100),
          ip_address VARCHAR(50),
          status VARCHAR(20) DEFAULT 'active',
          created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
          last_seen_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_db_device_lookup ON db_device(app_name, device_name, device_type);
        CREATE INDEX IF NOT EXISTS idx_db_device_key ON db_device(device_key_hash);
      `);

      // 3. Sync existing keys from PostgreSQL db_admin to metadataStore
      const adminRows = await pool.query('SELECT * FROM db_admin WHERE status = $1', ['active']);
      for (const row of adminRows.rows) {
        const record: ApiKeyRecord = {
          id: `key_${row.id}`,
          keyHash: row.key_hash,
          keyPrefix: row.key_prefix,
          appName: row.app_name,
          dbName: row.db_name,
          permissions: {
            can_create: row.can_create,
            can_read: row.can_read,
            can_update: row.can_update,
            can_delete: row.can_delete,
            can_ddl: row.can_ddl,
          },
          allowedIps: Array.isArray(row.allowed_ips) ? row.allowed_ips : [],
          expiresAt: null,
          createdAt: row.created_at ? new Date(row.created_at).toISOString() : new Date().toISOString(),
          lastUsedAt: row.last_used_at ? new Date(row.last_used_at).toISOString() : null,
          status: row.status,
        };
        metadataStore.saveKey(record);
      }

      // 4. Sync existing devices from PostgreSQL db_device to metadataStore
      const deviceRows = await pool.query('SELECT * FROM db_device WHERE status = $1', ['active']);
      for (const row of deviceRows.rows) {
        const record: DeviceRecord = {
          id: `dev_${row.id}`,
          appName: row.app_name,
          deviceName: row.device_name,
          deviceType: row.device_type,
          securityKeyHash: row.device_key_hash,
          securityKeyPrefix: row.device_key_prefix,
          allowedLocations: row.location ? [row.location] : [],
          status: row.status,
          createdAt: row.created_at ? new Date(row.created_at).toISOString() : new Date().toISOString(),
          lastSeenAt: row.last_seen_at ? new Date(row.last_seen_at).toISOString() : null,
        };
        metadataStore.saveDevice(record);
      }

      // 5. Back-fill initial metadataStore defaults into PostgreSQL if db_admin is empty
      if (adminRows.rows.length === 0) {
        for (const k of metadataStore.getKeys()) {
          await this.persistApiKey(k, k.keyPrefix);
        }
      }

      if (deviceRows.rows.length === 0) {
        for (const d of metadataStore.getDevices()) {
          await this.persistDeviceKey(d, d.securityKeyPrefix);
        }
      }

      this.initialized = true;
      console.log('[DbStorageService] Persistent db_admin and db_device tables verified in PostgreSQL.');
    } catch (err: any) {
      console.warn('[DbStorageService] Could not initialize PostgreSQL system tables on boot (PostgreSQL might be initializing):', err.message);
    }
  }

  /**
   * Ensures that system tables have been initialized
   */
  public static async ensureInitialized(): Promise<void> {
    if (!this.initialized) {
      await this.initSystemTables();
    }
  }

  /**
   * Ensures that db_device table exists in the target database
   */
  public static async ensureTargetDbDeviceTable(dbName: string): Promise<void> {
    try {
      const pool = PgPoolManager.getPool(dbName);
      await pool.query(`
        CREATE TABLE IF NOT EXISTS db_device (
          id SERIAL PRIMARY KEY,
          app_name VARCHAR(100) NOT NULL,
          device_name VARCHAR(100) NOT NULL,
          device_type VARCHAR(50) NOT NULL,
          device_key VARCHAR(255) NOT NULL,
          device_key_hash VARCHAR(64) NOT NULL,
          device_key_prefix VARCHAR(50) NOT NULL,
          location VARCHAR(100),
          ip_address VARCHAR(50),
          status VARCHAR(20) DEFAULT 'active',
          created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
          last_seen_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
      `);
    } catch (err: any) {
      console.warn(`[DbStorageService] Could not create db_device table in database '${dbName}':`, err.message);
    }
  }

  /**
   * Persists an API Key to db_admin
   */
  public static async persistApiKey(record: ApiKeyRecord, rawKey: string): Promise<void> {
    try {
      const pool = PgPoolManager.getPool(config.pg.defaultDatabase);
      await pool.query(
        `INSERT INTO db_admin (api_key, key_hash, key_prefix, app_name, db_name, can_create, can_read, can_update, can_delete, can_ddl, allowed_ips, status, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
         ON CONFLICT (key_hash) DO UPDATE SET
           can_create = EXCLUDED.can_create,
           can_read = EXCLUDED.can_read,
           can_update = EXCLUDED.can_update,
           can_delete = EXCLUDED.can_delete,
           can_ddl = EXCLUDED.can_ddl,
           status = EXCLUDED.status;`,
        [
          rawKey,
          record.keyHash,
          record.keyPrefix,
          record.appName,
          record.dbName,
          record.permissions.can_create,
          record.permissions.can_read,
          record.permissions.can_update,
          record.permissions.can_delete,
          record.permissions.can_ddl,
          JSON.stringify(record.allowedIps),
          record.status,
          record.createdAt,
        ]
      );
    } catch (err: any) {
      console.warn('[DbStorageService] Could not persist API key to db_admin:', err.message);
    }
  }

  /**
   * Persists a Device Key to db_device (both master and optional target DB)
   */
  public static async persistDeviceKey(
    record: DeviceRecord,
    rawDeviceKey: string,
    targetDbName?: string
  ): Promise<void> {
    const dbsToPersist = [config.pg.defaultDatabase];
    if (targetDbName && targetDbName.toLowerCase() !== config.pg.defaultDatabase.toLowerCase()) {
      dbsToPersist.push(targetDbName);
    }

    for (const db of dbsToPersist) {
      try {
        await this.ensureTargetDbDeviceTable(db);
        const pool = PgPoolManager.getPool(db);
        await pool.query(
          `INSERT INTO db_device (app_name, device_name, device_type, device_key, device_key_hash, device_key_prefix, location, ip_address, status, created_at, last_seen_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11);`,
          [
            record.appName,
            record.deviceName,
            record.deviceType,
            rawDeviceKey,
            record.securityKeyHash,
            record.securityKeyPrefix,
            record.allowedLocations[0] || null,
            null,
            record.status,
            record.createdAt,
            record.lastSeenAt || record.createdAt,
          ]
        );
      } catch (err: any) {
        console.warn(`[DbStorageService] Could not persist device to db_device in database '${db}':`, err.message);
      }
    }
  }

  /**
   * Checks whether a table name matches user/account conventions
   */
  public static isUserAccountTable(tableName: string): boolean {
    if (!tableName) return false;
    const clean = tableName.toLowerCase().replace(/[^a-z0-9_]/g, '');
    return (
      clean === 'user' ||
      clean === 'users' ||
      clean === 'account' ||
      clean === 'accounts' ||
      clean === 'user_account' ||
      clean === 'user_accounts' ||
      clean === 'app_user' ||
      clean === 'app_users' ||
      clean.endsWith('_user') ||
      clean.endsWith('_users') ||
      clean.endsWith('_account') ||
      clean.endsWith('_accounts')
    );
  }

  /**
   * Extracts user/account table name from raw SQL INSERT/UPDATE query if present
   */
  public static extractUserAccountTableFromQuery(query: string): string | null {
    if (!query) return null;
    const match = query.match(/(?:INSERT\s+INTO|UPDATE)\s+["']?(?:[a-zA-Z0-9_]+\.)?([a-zA-Z0-9_]+)["']?/i);
    if (match && this.isUserAccountTable(match[1])) {
      return match[1];
    }
    return null;
  }

  /**
   * Generates a new Device Key, records it in db_device (both master and target database),
   * and registers it in memory.
   */
  public static async autoProvisionDevice(options: {
    appName: string;
    deviceName: string;
    deviceType: string;
    location?: string;
    ipAddress?: string;
    targetDbName?: string;
  }): Promise<{ rawDeviceKey: string; record: DeviceRecord }> {
    const rawDeviceKey = `dsk_${crypto.randomBytes(20).toString('hex')}`;
    const securityKeyHash = KeyService.hashKey(rawDeviceKey);

    const record: DeviceRecord = {
      id: `dev_${crypto.randomBytes(6).toString('hex')}`,
      appName: options.appName.trim(),
      deviceName: (options.deviceName || 'Device-Auto').trim(),
      deviceType: (options.deviceType || 'Client').trim(),
      securityKeyHash,
      securityKeyPrefix: rawDeviceKey.substring(0, 10) + '...',
      allowedLocations: options.location ? [options.location] : [],
      status: 'active',
      createdAt: new Date().toISOString(),
      lastSeenAt: new Date().toISOString(),
    };

    // Save to metadataStore cache
    metadataStore.saveDevice(record);

    // Save to PostgreSQL db_device (master + target database)
    await this.persistDeviceKey(record, rawDeviceKey, options.targetDbName);

    return { rawDeviceKey, record };
  }

  /**
   * Ensures that the target table has a device_key column, and injects the device key into the payload.
   */
  public static async injectDeviceKeyIntoPayload(
    dbName: string,
    tableName: string,
    payload: any,
    deviceKey: string
  ): Promise<any> {
    // 1. Ensure device_key column exists in the user/account table
    try {
      const pool = PgPoolManager.getPool(dbName);
      await pool.query(`ALTER TABLE "${tableName}" ADD COLUMN IF NOT EXISTS device_key VARCHAR(255);`);
    } catch (err: any) {
      console.warn(`[DbStorageService] Note: Could not auto-add device_key column to '${tableName}':`, err.message);
    }

    // 2. Inject device_key into payload object(s)
    if (Array.isArray(payload)) {
      return payload.map((item) => {
        if (typeof item === 'object' && item !== null) {
          return { ...item, device_key: deviceKey };
        }
        return item;
      });
    } else if (typeof payload === 'object' && payload !== null) {
      return { ...payload, device_key: deviceKey };
    }

    return payload;
  }

  /**
   * Injects device_key into a raw SQL query (INSERT or UPDATE) targeting a user/account table
   */
  public static injectDeviceKeyIntoSql(
    query: string,
    params: any[],
    deviceKey: string
  ): { modifiedQuery: string; modifiedParams: any[] } {
    if (!query) return { modifiedQuery: query, modifiedParams: params };

    // If query already references device_key, leave SQL unchanged
    if (/\bdevice_key\b/i.test(query)) {
      return { modifiedQuery: query, modifiedParams: params };
    }

    const currentParams = Array.isArray(params) ? [...params] : [];

    // Case A: INSERT INTO table (col1, col2) VALUES ($1, $2) or VALUES ('v1', 'v2')
    const insertMatch = query.match(
      /INSERT\s+INTO\s+((?:[a-zA-Z0-9_]+\.)?[a-zA-Z0-9_]+)\s*\(([^)]+)\)\s*VALUES\s*\(([^)]+)\)(.*)/is
    );
    if (insertMatch) {
      const fullTable = insertMatch[1];
      const cols = insertMatch[2].trim();
      const vals = insertMatch[3].trim();
      const trailing = insertMatch[4] || '';

      const isParameterized = /\$\d+/.test(vals);
      if (isParameterized) {
        currentParams.push(deviceKey);
        const nextParamIndex = currentParams.length;
        const newCols = `${cols}, device_key`;
        const newVals = `${vals}, $${nextParamIndex}`;
        const modifiedQuery = query.replace(
          insertMatch[0],
          `INSERT INTO ${fullTable} (${newCols}) VALUES (${newVals})${trailing}`
        );
        return { modifiedQuery, modifiedParams: currentParams };
      } else {
        const escapedKey = deviceKey.replace(/'/g, "''");
        const newCols = `${cols}, device_key`;
        const newVals = `${vals}, '${escapedKey}'`;
        const modifiedQuery = query.replace(
          insertMatch[0],
          `INSERT INTO ${fullTable} (${newCols}) VALUES (${newVals})${trailing}`
        );
        return { modifiedQuery, modifiedParams: currentParams };
      }
    }

    // Case B: UPDATE table SET col1 = $1, col2 = $2 WHERE ...
    const updateMatch = query.match(
      /UPDATE\s+((?:[a-zA-Z0-9_]+\.)?[a-zA-Z0-9_]+)\s+SET\s+(.+?)\s+(WHERE\s+.+)/is
    );
    if (updateMatch) {
      const fullTable = updateMatch[1];
      const setClause = updateMatch[2].trim();
      const whereClause = updateMatch[3].trim();

      const isParameterized = /\$\d+/.test(query);
      if (isParameterized) {
        currentParams.push(deviceKey);
        const nextParamIndex = currentParams.length;
        const newSetClause = `${setClause}, device_key = $${nextParamIndex}`;
        const modifiedQuery = query.replace(
          updateMatch[0],
          `UPDATE ${fullTable} SET ${newSetClause} ${whereClause}`
        );
        return { modifiedQuery, modifiedParams: currentParams };
      } else {
        const escapedKey = deviceKey.replace(/'/g, "''");
        const newSetClause = `${setClause}, device_key = '${escapedKey}'`;
        const modifiedQuery = query.replace(
          updateMatch[0],
          `UPDATE ${fullTable} SET ${newSetClause} ${whereClause}`
        );
        return { modifiedQuery, modifiedParams: currentParams };
      }
    }

    return { modifiedQuery: query, modifiedParams: currentParams };
  }

  /**
   * Revokes an API Key in db_admin
   */
  public static async revokeApiKey(keyId: string): Promise<void> {
    try {
      const pool = PgPoolManager.getPool(config.pg.defaultDatabase);
      const numericId = keyId.startsWith('key_') ? parseInt(keyId.substring(4), 10) : NaN;
      if (!isNaN(numericId)) {
        await pool.query("UPDATE db_admin SET status = 'revoked' WHERE id = $1", [numericId]);
      } else {
        const rec = metadataStore.getKeyById(keyId);
        if (rec) {
          await pool.query("UPDATE db_admin SET status = 'revoked' WHERE key_hash = $1", [rec.keyHash]);
        }
      }
    } catch (err: any) {
      console.warn('[DbStorageService] Could not update db_admin status to revoked:', err.message);
    }
  }

  /**
   * Revokes a Device Key in db_device
   */
  public static async revokeDeviceKey(deviceId: string): Promise<void> {
    try {
      const pool = PgPoolManager.getPool(config.pg.defaultDatabase);
      const numericId = deviceId.startsWith('dev_') ? parseInt(deviceId.substring(4), 10) : NaN;
      if (!isNaN(numericId)) {
        await pool.query("UPDATE db_device SET status = 'revoked' WHERE id = $1", [numericId]);
      } else {
        const dev = metadataStore.getDevices().find((d) => d.id === deviceId);
        if (dev) {
          await pool.query("UPDATE db_device SET status = 'revoked' WHERE device_key_hash = $1", [
            dev.securityKeyHash,
          ]);
        }
      }
    } catch (err: any) {
      console.warn('[DbStorageService] Could not update db_device status to revoked:', err.message);
    }
  }

  /**
   * Updates an API Key's access permissions (CRUD & DDL) in db_admin
   */
  public static async updateApiKeyPermissions(
    keyId: string,
    permissions: {
      can_create?: boolean;
      can_read?: boolean;
      can_update?: boolean;
      can_delete?: boolean;
      can_ddl?: boolean;
    }
  ): Promise<boolean> {
    try {
      const pool = PgPoolManager.getPool(config.pg.defaultDatabase);
      const numericId = keyId.startsWith('key_') ? parseInt(keyId.substring(4), 10) : NaN;
      let query = `
        UPDATE db_admin
        SET
          can_create = COALESCE($1, can_create),
          can_read   = COALESCE($2, can_read),
          can_update = COALESCE($3, can_update),
          can_delete = COALESCE($4, can_delete),
          can_ddl    = COALESCE($5, can_ddl)
      `;
      const params: any[] = [
        permissions.can_create !== undefined ? permissions.can_create : null,
        permissions.can_read !== undefined ? permissions.can_read : null,
        permissions.can_update !== undefined ? permissions.can_update : null,
        permissions.can_delete !== undefined ? permissions.can_delete : null,
        permissions.can_ddl !== undefined ? permissions.can_ddl : null,
      ];

      if (!isNaN(numericId)) {
        query += ' WHERE id = $6;';
        params.push(numericId);
      } else {
        const rec = metadataStore.getKeyById(keyId);
        query += ' WHERE key_hash = $6;';
        params.push(rec ? rec.keyHash : keyId);
      }

      const res = await pool.query(query, params);
      return (res.rowCount ?? 0) > 0;
    } catch (err: any) {
      console.warn('[DbStorageService] Could not update permissions in db_admin:', err.message);
      return false;
    }
  }
}
