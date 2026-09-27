import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { config } from '../config';

export interface AppRecord {
  id: string;
  name: string;
  description: string;
  status: 'active' | 'disabled';
  createdAt: string;
}

export interface ApiKeyRecord {
  id: string;
  keyHash: string;
  keyPrefix: string;
  appName: string;
  dbName: string;
  permissions: {
    can_create: boolean; // INSERT
    can_read: boolean;   // SELECT
    can_update: boolean; // UPDATE
    can_delete: boolean; // DELETE
    can_ddl: boolean;    // CREATE, ALTER, DROP, TRUNCATE, etc.
  };
  allowedIps: string[];
  expiresAt: string | null;
  createdAt: string;
  lastUsedAt: string | null;
  status: 'active' | 'revoked';
}

export interface DeviceRecord {
  id: string;
  appName: string;
  deviceName: string;
  deviceType: string;
  securityKeyHash: string;
  securityKeyPrefix: string;
  allowedLocations: string[];
  status: 'active' | 'revoked';
  createdAt: string;
  lastSeenAt: string | null;
}

export interface AuditLogRecord {
  id: string;
  timestamp: string;
  keyId: string | null;
  appName: string;
  dbName: string;
  endpoint: string;
  method: string;
  deviceName: string;
  deviceType: string;
  location: string;
  reportedIp: string;
  actualIp: string;
  operationType: 'SELECT' | 'INSERT' | 'UPDATE' | 'DELETE' | 'DDL' | 'BLOCKED' | 'AUTH_FAILED' | 'SCHEMA' | 'UNKNOWN';
  querySummary: string;
  durationMs: number;
  statusCode: number;
  threatLevel: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  threatReason: string | null;
  rowCount: number | null;
}

interface MetadataState {
  version: number;
  apps: AppRecord[];
  apiKeys: ApiKeyRecord[];
  devices: DeviceRecord[];
  auditLogs: AuditLogRecord[];
}

export class MetadataStore {
  private filePath: string;
  private state: MetadataState = {
    version: 1,
    apps: [],
    apiKeys: [],
    devices: [],
    auditLogs: [],
  };
  private maxLogsInMemory = 5000;
  private saveTimeout: NodeJS.Timeout | null = null;

  constructor() {
    this.filePath = path.join(config.dataDir, 'metadata.json');
    this.init();
  }

  private init() {
    try {
      if (!fs.existsSync(config.dataDir)) {
        fs.mkdirSync(config.dataDir, { recursive: true });
      }

      if (fs.existsSync(this.filePath)) {
        const raw = fs.readFileSync(this.filePath, 'utf-8');
        this.state = JSON.parse(raw);
      } else {
        this.seedInitialDefaults();
        this.saveImmediately();
      }
    } catch (err) {
      console.error('[MetadataStore] Failed to initialize metadata store:', err);
      this.seedInitialDefaults();
    }
  }

  private seedInitialDefaults() {
    const defaultApp: AppRecord = {
      id: 'app_default_demo',
      name: 'MainSystem',
      description: 'Default master demo application',
      status: 'active',
      createdAt: new Date().toISOString(),
    };

    // Default API Key: dbapi_live_master_key_default_demo
    // SHA256 of plain key
    const rawDemoKey = 'dbapi_live_demo_key_7f8a9b0c';
    const keyHash = crypto.createHash('sha256').update(rawDemoKey).digest('hex');

    const defaultKey: ApiKeyRecord = {
      id: 'key_master_demo',
      keyHash: keyHash,
      keyPrefix: rawDemoKey.substring(0, 15) + '...',
      appName: 'MainSystem',
      dbName: 'postgres',
      permissions: {
        can_create: true,
        can_read: true,
        can_update: true,
        can_delete: true,
        can_ddl: true,
      },
      allowedIps: [],
      expiresAt: null,
      createdAt: new Date().toISOString(),
      lastUsedAt: null,
      status: 'active',
    };

    // Default Device: Terminal-1
    const rawDeviceKey = 'dsk_demo_sec_998877';
    const deviceKeyHash = crypto.createHash('sha256').update(rawDeviceKey).digest('hex');

    const defaultDevice: DeviceRecord = {
      id: 'dev_terminal_1',
      appName: 'MainSystem',
      deviceName: 'Terminal-1',
      deviceType: 'Server',
      securityKeyHash: deviceKeyHash,
      securityKeyPrefix: rawDeviceKey.substring(0, 10) + '...',
      allowedLocations: [],
      status: 'active',
      createdAt: new Date().toISOString(),
      lastSeenAt: null,
    };

    this.state = {
      version: 1,
      apps: [defaultApp],
      apiKeys: [defaultKey],
      devices: [defaultDevice],
      auditLogs: [],
    };
  }

  private saveImmediately() {
    try {
      if (!fs.existsSync(config.dataDir)) {
        fs.mkdirSync(config.dataDir, { recursive: true });
      }
      const tmpPath = `${this.filePath}.tmp.${Date.now()}`;
      fs.writeFileSync(tmpPath, JSON.stringify(this.state, null, 2), 'utf-8');
      fs.renameSync(tmpPath, this.filePath);
    } catch (err) {
      console.error('[MetadataStore] Failed to save metadata file:', err);
    }
  }

  public scheduleSave() {
    if (this.saveTimeout) return;
    this.saveTimeout = setTimeout(() => {
      this.saveTimeout = null;
      this.saveImmediately();
    }, 1000);
  }

  // --- App Management ---
  public getApps(): AppRecord[] {
    return [...this.state.apps];
  }

  public getAppByName(name: string): AppRecord | undefined {
    return this.state.apps.find((a) => a.name.toLowerCase() === name.toLowerCase());
  }

  public createApp(name: string, description: string): AppRecord {
    const existing = this.getAppByName(name);
    if (existing) {
      throw new Error(`App with name '${name}' already exists.`);
    }

    const newApp: AppRecord = {
      id: `app_${crypto.randomBytes(6).toString('hex')}`,
      name: name.trim(),
      description: description.trim(),
      status: 'active',
      createdAt: new Date().toISOString(),
    };

    this.state.apps.push(newApp);
    this.scheduleSave();
    return newApp;
  }

  // --- API Key Management ---
  public getKeys(): ApiKeyRecord[] {
    return [...this.state.apiKeys];
  }

  public getKeyById(id: string): ApiKeyRecord | undefined {
    return this.state.apiKeys.find((k) => k.id === id);
  }

  public findKeyByHash(hash: string): ApiKeyRecord | undefined {
    return this.state.apiKeys.find((k) => k.keyHash === hash && k.status === 'active');
  }

  public saveKey(record: ApiKeyRecord) {
    const idx = this.state.apiKeys.findIndex((k) => k.id === record.id);
    if (idx >= 0) {
      this.state.apiKeys[idx] = record;
    } else {
      this.state.apiKeys.push(record);
    }
    this.scheduleSave();
  }

  public revokeKey(id: string): boolean {
    const key = this.getKeyById(id);
    if (!key) return false;
    key.status = 'revoked';
    this.scheduleSave();
    return true;
  }

  // --- Device Management ---
  public getDevices(): DeviceRecord[] {
    return [...this.state.devices];
  }

  public findDevice(appName: string, deviceName: string, deviceType: string): DeviceRecord | undefined {
    return this.state.devices.find(
      (d) =>
        d.appName.toLowerCase() === appName.toLowerCase() &&
        d.deviceName.toLowerCase() === deviceName.toLowerCase() &&
        d.deviceType.toLowerCase() === deviceType.toLowerCase() &&
        d.status === 'active'
    );
  }

  public saveDevice(record: DeviceRecord) {
    const idx = this.state.devices.findIndex((d) => d.id === record.id);
    if (idx >= 0) {
      this.state.devices[idx] = record;
    } else {
      this.state.devices.push(record);
    }
    this.scheduleSave();
  }

  public revokeDevice(id: string): boolean {
    const dev = this.state.devices.find((d) => d.id === id);
    if (!dev) return false;
    dev.status = 'revoked';
    this.scheduleSave();
    return true;
  }

  // --- Audit Logging ---
  public addAuditLog(entry: AuditLogRecord) {
    this.state.auditLogs.unshift(entry);
    if (this.state.auditLogs.length > this.maxLogsInMemory) {
      this.state.auditLogs = this.state.auditLogs.slice(0, this.maxLogsInMemory);
    }
    this.scheduleSave();
  }

  public getAuditLogs(options?: {
    limit?: number;
    dbName?: string;
    appName?: string;
    threatLevel?: string;
  }): AuditLogRecord[] {
    let filtered = this.state.auditLogs;

    if (options?.dbName) {
      filtered = filtered.filter((l) => l.dbName.toLowerCase() === options.dbName!.toLowerCase());
    }
    if (options?.appName) {
      filtered = filtered.filter((l) => l.appName.toLowerCase() === options.appName!.toLowerCase());
    }
    if (options?.threatLevel && options.threatLevel !== 'ALL') {
      filtered = filtered.filter((l) => l.threatLevel === options.threatLevel);
    }

    const limit = options?.limit || 100;
    return filtered.slice(0, limit);
  }

  public getStats() {
    const totalRequests = this.state.auditLogs.length;
    const threatsBlocked = this.state.auditLogs.filter(
      (l) => l.threatLevel === 'HIGH' || l.threatLevel === 'CRITICAL' || l.operationType === 'BLOCKED'
    ).length;
    const activeKeys = this.state.apiKeys.filter((k) => k.status === 'active').length;
    const activeApps = this.state.apps.filter((a) => a.status === 'active').length;
    const activeDevices = this.state.devices.filter((d) => d.status === 'active').length;

    return {
      totalRequests,
      threatsBlocked,
      activeKeys,
      activeApps,
      activeDevices,
    };
  }
}

export const metadataStore = new MetadataStore();
