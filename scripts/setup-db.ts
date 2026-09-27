import { config } from '../src/config';
import { PgPoolManager } from '../src/services/pg-pool';
import { metadataStore } from '../src/services/metadata-store';
import { KeyService } from '../src/services/key-service';

async function main() {
  console.log('====================================================');
  console.log('  DB API - PostgreSQL Database Setup & Seeder');
  console.log('====================================================');
  console.log(`Connecting to PostgreSQL at ${config.pg.host}:${config.pg.port} as '${config.pg.user}'...`);

  // 1. Test Connection
  const status = await PgPoolManager.testConnection();
  if (!status.connected) {
    console.error(`\n[ERROR] Could not connect to PostgreSQL: ${status.error}`);
    console.error('Please ensure PostgreSQL is running or run:');
    console.error('  docker compose up -d');
    process.exit(1);
  }

  console.log(`[SUCCESS] Connected to PostgreSQL! Version: ${status.version?.split(' on ')[0]}`);

  // 2. Setup Target Database: mh_demo_db
  const targetDb = 'mh_demo_db';
  const existingDbs = await PgPoolManager.listDatabases();
  if (!existingDbs.includes(targetDb)) {
    console.log(`Creating database '${targetDb}'...`);
    await PgPoolManager.createDatabase(targetDb);
    console.log(`[SUCCESS] Database '${targetDb}' created.`);
  } else {
    console.log(`Database '${targetDb}' already exists.`);
  }

  // 3. Create Sample Tables
  console.log(`Creating sample tables (products, orders) in '${targetDb}'...`);
  const pool = PgPoolManager.getPool(targetDb);

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

  // Insert seed data if empty
  const countRes = await pool.query('SELECT COUNT(*) FROM products');
  if (parseInt(countRes.rows[0].count, 10) === 0) {
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
    console.log('[SUCCESS] Sample products and orders seeded.');
  }

  // 4. Register App & Generate API Key
  const appName = 'StoreFrontApp';
  let app = metadataStore.getAppByName(appName);
  if (!app) {
    app = metadataStore.createApp(appName, 'Production E-Commerce Client');
  }

  const { rawKey, record: keyRecord } = KeyService.generateApiKey({
    appName,
    dbName: targetDb,
    permissions: {
      can_create: true,
      can_read: true,
      can_update: true,
      can_delete: true,
      can_ddl: false, // Protected: DDL disabled
    },
  });

  // 5. Register Device & Device Security Key
  const deviceName = 'POS-Terminal-01';
  const deviceType = 'Desktop';
  const { rawDeviceSecurityKey } = KeyService.registerDevice({
    appName,
    deviceName,
    deviceType,
  });

  console.log('\n====================================================');
  console.log('  SETUP COMPLETE! SAVE YOUR CREDENTIALS:');
  console.log('====================================================');
  console.log(`API Endpoint: ${config.apiBaseUrl}/API/1/${targetDb}/query`);
  console.log(`Target Database: ${targetDb}`);
  console.log(`App Name: ${appName}`);
  console.log(`API Key: ${rawKey}`);
  console.log(`Device Name: ${deviceName}`);
  console.log(`Device Type: ${deviceType}`);
  console.log(`Device Security Key: ${rawDeviceSecurityKey}`);
  console.log('\nExample cURL Command:');
  console.log(`curl -X POST "http://localhost:${config.port}/API/1/${targetDb}/query" \\
  -H "Content-Type: application/json" \\
  -H "Key: ${rawKey}" \\
  -H "IP: 127.0.0.1" \\
  -H "DeviceName: ${deviceName}" \\
  -H "Location: Store-Branch-1" \\
  -H "DeviceType: ${deviceType}" \\
  -H "AppName: ${appName}" \\
  -H "Device Security Key: ${rawDeviceSecurityKey}" \\
  -d '{"query": "SELECT * FROM products LIMIT 5;"}'`);
  console.log('====================================================\n');

  await PgPoolManager.closeAll();
  process.exit(0);
}

main().catch((err) => {
  console.error('[Fatal Error]', err);
  process.exit(1);
});
