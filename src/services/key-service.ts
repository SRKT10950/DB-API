import crypto from 'crypto';
import { metadataStore, ApiKeyRecord, DeviceRecord } from './metadata-store';
import { OperationType } from './threat-detector';

export interface GenerateKeyOptions {
  appName: string;
  dbName: string;
  permissions?: {
    can_create?: boolean;
    can_read?: boolean;
    can_update?: boolean;
    can_delete?: boolean;
    can_ddl?: boolean;
  };
  allowedIps?: string[];
  expiresInDays?: number;
}

export interface GenerateDeviceKeyOptions {
  appName: string;
  deviceName: string;
  deviceType: string;
  allowedLocations?: string[];
}

export class KeyService {
  /**
   * Hashes a secret key using SHA-256.
   */
  public static hashKey(key: string): string {
    return crypto.createHash('sha256').update(key.trim()).digest('hex');
  }

  /**
   * Generates a new API Key for a specific app and database with granular permissions.
   */
  public static generateApiKey(options: GenerateKeyOptions): {
    rawKey: string;
    record: ApiKeyRecord;
  } {
    // Generate 32 bytes of secure random hex
    const randomBytes = crypto.randomBytes(24).toString('hex');
    const rawKey = `dbapi_live_${randomBytes}`;
    const keyHash = this.hashKey(rawKey);

    const now = new Date();
    let expiresAt: string | null = null;
    if (options.expiresInDays && options.expiresInDays > 0) {
      const expDate = new Date(now.getTime() + options.expiresInDays * 24 * 60 * 60 * 1000);
      expiresAt = expDate.toISOString();
    }

    const record: ApiKeyRecord = {
      id: `key_${crypto.randomBytes(8).toString('hex')}`,
      keyHash,
      keyPrefix: rawKey.substring(0, 16) + '...',
      appName: options.appName.trim(),
      dbName: options.dbName.trim(),
      permissions: {
        can_create: options.permissions?.can_create ?? true,
        can_read: options.permissions?.can_read ?? true,
        can_update: options.permissions?.can_update ?? true,
        can_delete: options.permissions?.can_delete ?? false,
        can_ddl: options.permissions?.can_ddl ?? false,
      },
      allowedIps: options.allowedIps || [],
      expiresAt,
      createdAt: now.toISOString(),
      lastUsedAt: null,
      status: 'active',
    };

    metadataStore.saveKey(record);
    // Persist to PostgreSQL db_admin table
    import('./db-storage').then(({ DbStorageService }) => {
      DbStorageService.persistApiKey(record, rawKey).catch((e) => console.warn(e.message));
    });

    return { rawKey, record };
  }

  /**
   * Registers a Device and generates a Device Security Key.
   */
  public static registerDevice(options: GenerateDeviceKeyOptions): {
    rawDeviceSecurityKey: string;
    deviceRecord: DeviceRecord;
  } {
    const rawDeviceSecurityKey = `dsk_${crypto.randomBytes(20).toString('hex')}`;
    const securityKeyHash = this.hashKey(rawDeviceSecurityKey);

    const deviceRecord: DeviceRecord = {
      id: `dev_${crypto.randomBytes(6).toString('hex')}`,
      appName: options.appName.trim(),
      deviceName: options.deviceName.trim(),
      deviceType: options.deviceType.trim(),
      securityKeyHash,
      securityKeyPrefix: rawDeviceSecurityKey.substring(0, 10) + '...',
      allowedLocations: options.allowedLocations || [],
      status: 'active',
      createdAt: new Date().toISOString(),
      lastSeenAt: null,
    };

    metadataStore.saveDevice(deviceRecord);
    // Persist to PostgreSQL db_device table
    import('./db-storage').then(({ DbStorageService }) => {
      DbStorageService.persistDeviceKey(deviceRecord, rawDeviceSecurityKey).catch((e) => console.warn(e.message));
    });

    return { rawDeviceSecurityKey, deviceRecord };
  }

  /**
   * Validates if a key is authorized for a specific operation.
   */
  public static checkPermission(
    keyRecord: ApiKeyRecord,
    operation: OperationType
  ): { allowed: boolean; reason?: string } {
    switch (operation) {
      case 'SELECT':
        if (!keyRecord.permissions.can_read) {
          return { allowed: false, reason: 'Read (SELECT) permission is disabled for this API Key' };
        }
        return { allowed: true };

      case 'INSERT':
        if (!keyRecord.permissions.can_create) {
          return { allowed: false, reason: 'Create (INSERT) permission is disabled for this API Key' };
        }
        return { allowed: true };

      case 'UPDATE':
        if (!keyRecord.permissions.can_update) {
          return { allowed: false, reason: 'Update (UPDATE) permission is disabled for this API Key' };
        }
        return { allowed: true };

      case 'DELETE':
        if (!keyRecord.permissions.can_delete) {
          return { allowed: false, reason: 'Delete (DELETE) permission is disabled for this API Key' };
        }
        return { allowed: true };

      case 'DDL':
        if (!keyRecord.permissions.can_ddl) {
          return { allowed: false, reason: 'DDL (Data Definition Language) permission is disabled for this API Key' };
        }
        return { allowed: true };

      default:
        return { allowed: true };
    }
  }
}
