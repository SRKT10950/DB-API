import { Router, Request, Response, NextFunction } from 'express';
import { config } from '../config';
import { metadataStore } from '../services/metadata-store';
import { KeyService } from '../services/key-service';
import { PgPoolManager } from '../services/pg-pool';

const router = Router();

/**
 * Admin authentication middleware
 */
function adminAuthMiddleware(req: Request, res: Response, next: NextFunction) {
  const secretHeader =
    req.headers['x-admin-secret'] ||
    req.headers['authorization']?.replace(/^Bearer\s+/i, '');

  if (!secretHeader || secretHeader !== config.adminSecret) {
    return res.status(401).json({
      success: false,
      error: 'Unauthorized: Invalid or missing X-Admin-Secret header',
    });
  }

  next();
}

router.use(adminAuthMiddleware);

/**
 * 1. Overview & Health stats
 */
router.get('/overview', async (req: Request, res: Response) => {
  const stats = metadataStore.getStats();
  const pgStatus = await PgPoolManager.testConnection();

  return res.json({
    success: true,
    stats,
    database: {
      connected: pgStatus.connected,
      version: pgStatus.version,
      error: pgStatus.error,
      host: config.pg.host,
      port: config.pg.port,
    },
    system: {
      uptimeSeconds: Math.floor(process.uptime()),
      memoryUsageMb: Math.round(process.memoryUsage().rss / 1024 / 1024),
      nodeVersion: process.version,
    },
  });
});

/**
 * 2. Apps
 */
router.get('/apps', (req: Request, res: Response) => {
  return res.json({ success: true, apps: metadataStore.getApps() });
});

router.post('/apps', (req: Request, res: Response) => {
  const { name, description } = req.body;
  if (!name || typeof name !== 'string') {
    return res.status(400).json({ success: false, error: 'App "name" is required' });
  }

  try {
    const app = metadataStore.createApp(name, description || '');
    return res.status(201).json({ success: true, app });
  } catch (err: any) {
    return res.status(400).json({ success: false, error: err.message });
  }
});

/**
 * 3. Keys
 */
router.get('/keys', (req: Request, res: Response) => {
  return res.json({ success: true, keys: metadataStore.getKeys() });
});

router.post('/keys', (req: Request, res: Response) => {
  const { appName, dbName, permissions, allowedIps, expiresInDays } = req.body;

  if (!appName || !dbName) {
    return res.status(400).json({ success: false, error: '"appName" and "dbName" are required' });
  }

  const result = KeyService.generateApiKey({
    appName,
    dbName,
    permissions,
    allowedIps,
    expiresInDays,
  });

  return res.status(201).json({
    success: true,
    message: 'API Key generated successfully. Save the raw key securely; it will not be displayed again.',
    rawKey: result.rawKey,
    keyRecord: result.record,
  });
});

router.delete('/keys/:keyId', (req: Request, res: Response) => {
  const revoked = metadataStore.revokeKey(req.params.keyId);
  if (!revoked) {
    return res.status(404).json({ success: false, error: 'Key not found' });
  }
  return res.json({ success: true, message: 'Key revoked successfully' });
});

/**
 * 4. Devices
 */
router.get('/devices', (req: Request, res: Response) => {
  return res.json({ success: true, devices: metadataStore.getDevices() });
});

router.post('/devices', (req: Request, res: Response) => {
  const { appName, deviceName, deviceType, allowedLocations } = req.body;

  if (!appName || !deviceName || !deviceType) {
    return res.status(400).json({
      success: false,
      error: '"appName", "deviceName", and "deviceType" are required',
    });
  }

  const result = KeyService.registerDevice({
    appName,
    deviceName,
    deviceType,
    allowedLocations,
  });

  return res.status(201).json({
    success: true,
    message: 'Device registered successfully. Save the Device Security Key securely.',
    rawDeviceSecurityKey: result.rawDeviceSecurityKey,
    deviceRecord: result.deviceRecord,
  });
});

router.delete('/devices/:deviceId', (req: Request, res: Response) => {
  const revoked = metadataStore.revokeDevice(req.params.deviceId);
  if (!revoked) {
    return res.status(404).json({ success: false, error: 'Device not found' });
  }
  return res.json({ success: true, message: 'Device revoked successfully' });
});

/**
 * 5. Audit & Threat Logs
 */
router.get('/logs', (req: Request, res: Response) => {
  const limit = parseInt((req.query.limit as string) || '100', 10);
  const dbName = req.query.dbName as string;
  const appName = req.query.appName as string;
  const threatLevel = req.query.threatLevel as string;

  const logs = metadataStore.getAuditLogs({ limit, dbName, appName, threatLevel });
  return res.json({ success: true, count: logs.length, logs });
});

/**
 * 6. Databases Management
 */
router.get('/databases', async (req: Request, res: Response) => {
  try {
    const databases = await PgPoolManager.listDatabases();
    return res.json({ success: true, databases });
  } catch (err: any) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

router.post('/databases', async (req: Request, res: Response) => {
  const { dbName } = req.body;
  if (!dbName || typeof dbName !== 'string') {
    return res.status(400).json({ success: false, error: '"dbName" is required' });
  }

  try {
    await PgPoolManager.createDatabase(dbName);
    return res.status(201).json({ success: true, message: `Database '${dbName}' created successfully.` });
  } catch (err: any) {
    return res.status(400).json({ success: false, error: err.message });
  }
});

/**
 * 7. Setup & Demo Seeding Helper
 */
router.post('/setup-demo-db', async (req: Request, res: Response) => {
  const demoDbName = 'mh_demo_db';

  try {
    // 1. Check/create database
    const dbs = await PgPoolManager.listDatabases();
    if (!dbs.includes(demoDbName)) {
      await PgPoolManager.createDatabase(demoDbName);
    }

    // 2. Create sample tables and insert demo records
    const pool = PgPoolManager.getPool(demoDbName);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS products (
        id SERIAL PRIMARY KEY,
        sku VARCHAR(50) UNIQUE NOT NULL,
        name VARCHAR(100) NOT NULL,
        price NUMERIC(10, 2) NOT NULL,
        stock_quantity INT DEFAULT 0,
        status VARCHAR(20) DEFAULT 'in_stock',
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS orders (
        id SERIAL PRIMARY KEY,
        customer_email VARCHAR(100) NOT NULL,
        total_amount NUMERIC(10, 2) NOT NULL,
        order_status VARCHAR(20) DEFAULT 'pending',
        shipping_city VARCHAR(50),
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Insert rows if table is empty
    const countCheck = await pool.query('SELECT COUNT(*) FROM products');
    if (parseInt(countCheck.rows[0].count, 10) === 0) {
      await pool.query(`
        INSERT INTO products (sku, name, price, stock_quantity, status) VALUES
        ('SKU-1001', 'Wireless Noise Canceling Headphones', 199.99, 45, 'in_stock'),
        ('SKU-1002', 'Ultra-Slim Mechanical Keyboard', 129.50, 80, 'in_stock'),
        ('SKU-1003', '4K USB-C Gaming Monitor 27"', 349.00, 15, 'in_stock'),
        ('SKU-1004', 'Ergonomic Vertical Mouse', 59.99, 120, 'in_stock');

        INSERT INTO orders (customer_email, total_amount, order_status, shipping_city) VALUES
        ('alice@example.com', 259.98, 'completed', 'Mumbai'),
        ('bob@example.com', 129.50, 'processing', 'Delhi'),
        ('charlie@example.com', 349.00, 'shipped', 'Bengaluru');
      `);
    }

    // Register Demo App and Keys if not present
    let app = metadataStore.getAppByName('StoreFrontApp');
    if (!app) {
      app = metadataStore.createApp('StoreFrontApp', 'E-Commerce Storefront Application');
    }

    // Generate dedicated API Key for StoreFrontApp on mh_demo_db with CRUD enabled but DDL disabled
    const existingKey = metadataStore
      .getKeys()
      .find((k) => k.appName === 'StoreFrontApp' && k.dbName === demoDbName && k.status === 'active');

    let keyInfo: any = null;
    if (!existingKey) {
      keyInfo = KeyService.generateApiKey({
        appName: 'StoreFrontApp',
        dbName: demoDbName,
        permissions: {
          can_create: true,
          can_read: true,
          can_update: true,
          can_delete: true,
          can_ddl: false, // DDL disabled for security!
        },
      });
    }

    // Register default device
    let dev = metadataStore.findDevice('StoreFrontApp', 'POS-Terminal-01', 'Desktop');
    let devKey = 'dsk_storefront_pos_key_5566';
    if (!dev) {
      const devRes = KeyService.registerDevice({
        appName: 'StoreFrontApp',
        deviceName: 'POS-Terminal-01',
        deviceType: 'Desktop',
      });
      devRes.deviceRecord.securityKeyHash = KeyService.hashKey(devKey);
      devRes.deviceRecord.securityKeyPrefix = devKey.substring(0, 10) + '...';
      metadataStore.saveDevice(devRes.deviceRecord);
    }

    return res.json({
      success: true,
      message: 'Demo database "mh_demo_db" initialized with sample tables (products, orders) and test credentials.',
      demoDatabase: demoDbName,
      app: 'StoreFrontApp',
      apiKey: keyInfo ? keyInfo.rawKey : existingKey?.keyPrefix,
      device: {
        deviceName: 'POS-Terminal-01',
        deviceType: 'Desktop',
        deviceSecurityKey: devKey,
      },
    });
  } catch (err: any) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

export default router;
