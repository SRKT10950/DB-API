import http from 'http';
import app from '../src/index';
import { ThreatDetector } from '../src/services/threat-detector';
import { KeyService } from '../src/services/key-service';
import { metadataStore } from '../src/services/metadata-store';

interface TestCase {
  name: string;
  fn: () => Promise<void>;
}

const tests: TestCase[] = [];

function test(name: string, fn: () => Promise<void>) {
  tests.push({ name, fn });
}

function assert(condition: boolean, message: string) {
  if (!condition) {
    throw new Error(`Assertion failed: ${message}`);
  }
}

// 1. Unit Tests for ThreatDetector
test('ThreatDetector: Detects boolean tautology SQL Injection (OR 1=1)', async () => {
  const result = ThreatDetector.analyzeQuery("SELECT * FROM users WHERE username = 'admin' OR 1=1--");
  assert(!result.isValid, 'Should mark query as invalid');
  assert(result.threatLevel === 'CRITICAL' || result.threatLevel === 'HIGH', 'Should flag high/critical threat');
});

test('ThreatDetector: Detects pg_sleep denial of service injection', async () => {
  const result = ThreatDetector.analyzeQuery("SELECT * FROM items WHERE id = 1; SELECT pg_sleep(10);");
  assert(!result.isValid, 'Should mark pg_sleep as invalid');
  assert(result.threatReason?.includes('pg_sleep') ?? false, 'Should flag pg_sleep in reason');
});

test('ThreatDetector: Detects DDL statements correctly (DROP TABLE)', async () => {
  const result = ThreatDetector.analyzeQuery("DROP TABLE orders;");
  assert(result.operationType === 'DDL', 'Should classify operation as DDL');
  assert(result.detectedOperations.includes('DDL'), 'detectedOperations should include DDL');
});

test('ThreatDetector: Detects clean SELECT statements as safe', async () => {
  const result = ThreatDetector.analyzeQuery("SELECT id, name, price FROM products WHERE status = $1 LIMIT 10;");
  assert(result.isValid, 'Valid query must be marked valid');
  assert(result.operationType === 'SELECT', 'Operation must be SELECT');
  assert(result.threatLevel === 'NONE', 'Threat level must be NONE');
});

// 2. Unit Tests for KeyService & Permissions
test('KeyService: Enforces permission denial for DDL when can_ddl is false', async () => {
  const { record } = KeyService.generateApiKey({
    appName: 'TestApp',
    dbName: 'testdb',
    permissions: {
      can_create: true,
      can_read: true,
      can_update: false,
      can_delete: false,
      can_ddl: false,
    },
  });

  const ddlCheck = KeyService.checkPermission(record, 'DDL');
  assert(!ddlCheck.allowed, 'DDL should be blocked');

  const readCheck = KeyService.checkPermission(record, 'SELECT');
  assert(readCheck.allowed, 'Read should be permitted');

  const deleteCheck = KeyService.checkPermission(record, 'DELETE');
  assert(!deleteCheck.allowed, 'Delete should be blocked');
});

// 3. Unit Tests for DbStorageService (Table matching, SQL injection, Auto-Provisioning)
test('DbStorageService: isUserAccountTable correctly identifies user and account tables', async () => {
  const { DbStorageService } = await import('../src/services/db-storage');
  assert(DbStorageService.isUserAccountTable('user'), 'user should match');
  assert(DbStorageService.isUserAccountTable('users'), 'users should match');
  assert(DbStorageService.isUserAccountTable('account'), 'account should match');
  assert(DbStorageService.isUserAccountTable('accounts'), 'accounts should match');
  assert(DbStorageService.isUserAccountTable('app_users'), 'app_users should match');
  assert(DbStorageService.isUserAccountTable('client_account'), 'client_account should match');

  assert(!DbStorageService.isUserAccountTable('products'), 'products should not match');
  assert(!DbStorageService.isUserAccountTable('orders'), 'orders should not match');
  assert(!DbStorageService.isUserAccountTable('audit_logs'), 'audit_logs should not match');
});

test('DbStorageService: extractUserAccountTableFromQuery extracts table from raw SQL', async () => {
  const { DbStorageService } = await import('../src/services/db-storage');
  const t1 = DbStorageService.extractUserAccountTableFromQuery('INSERT INTO users (name) VALUES ($1)');
  assert(t1 === 'users', `Expected 'users', got ${t1}`);

  const t2 = DbStorageService.extractUserAccountTableFromQuery('UPDATE accounts SET balance = $1 WHERE id = $2');
  assert(t2 === 'accounts', `Expected 'accounts', got ${t2}`);

  const t3 = DbStorageService.extractUserAccountTableFromQuery('SELECT * FROM users WHERE id = $1');
  assert(t3 === null, 'SELECT should not trigger auto-provisioning extraction');

  const t4 = DbStorageService.extractUserAccountTableFromQuery('INSERT INTO orders (total) VALUES ($1)');
  assert(t4 === null, 'Non-user table orders should not trigger auto-provisioning');
});

test('DbStorageService: injectDeviceKeyIntoSql correctly injects into INSERT and UPDATE', async () => {
  const { DbStorageService } = await import('../src/services/db-storage');
  const dummyKey = 'dsk_test_1234567890';

  // INSERT parameterized
  const ins = DbStorageService.injectDeviceKeyIntoSql(
    'INSERT INTO users (name, email) VALUES ($1, $2)',
    ['Alice', 'alice@test.com'],
    dummyKey
  );
  assert(ins.modifiedQuery.includes('device_key'), 'Should include device_key column');
  assert(ins.modifiedQuery.includes('$3'), 'Should include $3 placeholder');
  assert(ins.modifiedParams.length === 3 && ins.modifiedParams[2] === dummyKey, 'Should push deviceKey to params');

  // UPDATE parameterized
  const upd = DbStorageService.injectDeviceKeyIntoSql(
    'UPDATE accounts SET balance = $1 WHERE id = $2',
    [500, 1],
    dummyKey
  );
  assert(upd.modifiedQuery.includes('device_key = $3'), 'Should include device_key = $3 in SET clause');
  assert(upd.modifiedParams.length === 3 && upd.modifiedParams[2] === dummyKey, 'Should push deviceKey to params');
});

test('KeyService & MetadataStore: Updating key access permissions updates enforcement immediately', async () => {
  const { record } = KeyService.generateApiKey({
    appName: 'PermApp',
    dbName: 'permdb',
    permissions: {
      can_create: true,
      can_read: true,
      can_update: false,
      can_delete: false,
      can_ddl: false,
    },
  });

  // Initially DDL and DELETE are false
  assert(!KeyService.checkPermission(record, 'DDL').allowed, 'DDL should initially be blocked');
  assert(!KeyService.checkPermission(record, 'DELETE').allowed, 'DELETE should initially be blocked');

  // Update permissions
  const updated = metadataStore.updateKeyPermissions(record.id, {
    can_ddl: true,
    can_delete: true,
  });
  assert(Boolean(updated), 'Key should be found and updated');
  assert(updated!.permissions.can_ddl === true, 'can_ddl should now be true');
  assert(updated!.permissions.can_delete === true, 'can_delete should now be true');

  // Verify permission check enforcement uses updated permissions
  assert(KeyService.checkPermission(record, 'DDL').allowed, 'DDL should now be permitted');
  assert(KeyService.checkPermission(record, 'DELETE').allowed, 'DELETE should now be permitted');
});

// Helper for HTTP requests
function makeRequest(
  serverPort: number,
  options: {
    path: string;
    method: string;
    headers?: Record<string, string>;
    body?: any;
  }
): Promise<{ status: number; body: any }> {
  return new Promise((resolve, reject) => {
    const payload = options.body ? JSON.stringify(options.body) : undefined;
    const req = http.request(
      {
        hostname: '127.0.0.1',
        port: serverPort,
        path: options.path,
        method: options.method,
        headers: {
          'Content-Type': 'application/json',
          ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {}),
          ...(options.headers || {}),
        },
      },
      (res) => {
        let raw = '';
        res.on('data', (chunk) => (raw += chunk));
        res.on('end', () => {
          let parsed = {};
          try {
            parsed = JSON.parse(raw);
          } catch {
            parsed = raw;
          }
          resolve({ status: res.statusCode || 500, body: parsed });
        });
      }
    );

    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

// 3. HTTP Integration Tests
async function runHttpTests() {
  const testPort = 3999;
  const server = app.listen(testPort);

  // Setup test App and Key
  const testAppName = 'SecurityAuditApp';
  let appRecord = metadataStore.getAppByName(testAppName);
  if (!appRecord) {
    appRecord = metadataStore.createApp(testAppName, 'Audit client');
  }

  const { rawKey } = KeyService.generateApiKey({
    appName: testAppName,
    dbName: 'postgres',
    permissions: {
      can_create: true,
      can_read: true,
      can_update: false,
      can_delete: false,
      can_ddl: false, // DDL disabled
    },
  });

  const testDeviceName = 'Audit-Device-01';
  const testDeviceType = 'Server';
  const { rawDeviceSecurityKey } = KeyService.registerDevice({
    appName: testAppName,
    deviceName: testDeviceName,
    deviceType: testDeviceType,
  });

  try {
    // Test 1: Missing Required Headers
    console.log('Testing: Missing Required Headers returns HTTP 400...');
    const res1 = await makeRequest(testPort, {
      path: '/API/1/postgres/query',
      method: 'POST',
      headers: {
        Key: rawKey,
        // Missing IP, DeviceName, Location, DeviceType, AppName, Device Security Key
      },
      body: { query: 'SELECT 1;' },
    });
    assert(res1.status === 400, `Expected 400 Bad Request, got ${res1.status}`);
    assert(res1.body.missingHeaders.length === 6, 'Should identify all missing headers');
    console.log('  [PASS] Missing headers rejected with HTTP 400.');

    // Test 2: AppName Mismatch
    console.log('Testing: AppName mismatch returns HTTP 403...');
    const res2 = await makeRequest(testPort, {
      path: '/API/1/postgres/query',
      method: 'POST',
      headers: {
        'Key': rawKey,
        'IP': '127.0.0.1',
        'DeviceName': testDeviceName,
        'Location': 'Office',
        'DeviceType': testDeviceType,
        'AppName': 'WrongAppName',
        'Device-Security-Key': rawDeviceSecurityKey,
      },
      body: { query: 'SELECT 1;' },
    });
    assert(res2.status === 403, `Expected 403 Forbidden, got ${res2.status}`);
    console.log('  [PASS] AppName mismatch rejected with HTTP 403.');

    // Test 3: Invalid Device Security Key
    console.log('Testing: Invalid Device Security Key returns HTTP 401...');
    const res3 = await makeRequest(testPort, {
      path: '/API/1/postgres/query',
      method: 'POST',
      headers: {
        'Key': rawKey,
        'IP': '127.0.0.1',
        'DeviceName': testDeviceName,
        'Location': 'Office',
        'DeviceType': testDeviceType,
        'AppName': testAppName,
        'Device-Security-Key': 'dsk_fake_invalid_key',
      },
      body: { query: 'SELECT 1;' },
    });
    assert(res3.status === 401, `Expected 401 Unauthorized, got ${res3.status}`);
    console.log('  [PASS] Invalid Device Security Key rejected with HTTP 401.');

    // Test 4: SQL Injection Blocked by Firewall
    console.log('Testing: SQL Injection pattern blocked with HTTP 403...');
    const res4 = await makeRequest(testPort, {
      path: '/API/1/postgres/query',
      method: 'POST',
      headers: {
        'Key': rawKey,
        'IP': '127.0.0.1',
        'DeviceName': testDeviceName,
        'Location': 'Office',
        'DeviceType': testDeviceType,
        'AppName': testAppName,
        'Device-Security-Key': rawDeviceSecurityKey,
      },
      body: { query: "SELECT * FROM users WHERE username = 'admin' OR 1=1;" },
    });
    assert(res4.status === 403, `Expected 403 Forbidden for SQLi, got ${res4.status}`);
    assert(res4.body.threatLevel === 'CRITICAL', 'Should be CRITICAL threat level');
    console.log('  [PASS] SQL Injection blocked with HTTP 403.');

    // Test 5: DDL Command Blocked (Permission Denied)
    console.log('Testing: DDL command rejected when can_ddl is false...');
    const res5 = await makeRequest(testPort, {
      path: '/API/1/postgres/query',
      method: 'POST',
      headers: {
        'Key': rawKey,
        'IP': '127.0.0.1',
        'DeviceName': testDeviceName,
        'Location': 'Office',
        'DeviceType': testDeviceType,
        'AppName': testAppName,
        'Device-Security-Key': rawDeviceSecurityKey,
      },
      body: { query: 'DROP TABLE accounts;' },
    });
    assert(res5.status === 403, `Expected 403 Forbidden for DDL, got ${res5.status}`);
    assert(res5.body.error === 'Permission Denied', 'Should state Permission Denied');
    console.log('  [PASS] DDL blocked when permission disabled.');

    // Test 6: Health Endpoint
    console.log('Testing: /health endpoint...');
    const res6 = await makeRequest(testPort, {
      path: '/health',
      method: 'GET',
    });
    assert(res6.status === 200 || res6.status === 503, 'Health endpoint responds');
    console.log('  [PASS] /health endpoint responds.');

    // Test 7: Admin Login with Invalid Secret (401)
    console.log('Testing: /admin/api/auth/login with invalid secret...');
    const res7 = await makeRequest(testPort, {
      path: '/admin/api/auth/login',
      method: 'POST',
      body: { username: 'admin', secret: 'wrong_secret_123' },
    });
    assert(res7.status === 401, `Expected 401 Unauthorized, got ${res7.status}`);
    console.log('  [PASS] Admin login rejects invalid credentials.');

    // Test 8: Admin Login with Valid Secret (200 + Token)
    console.log('Testing: /admin/api/auth/login with valid secret...');
    const res8 = await makeRequest(testPort, {
      path: '/admin/api/auth/login',
      method: 'POST',
      body: { username: 'admin', secret: 'mh_admin_super_secret_key_2026' },
    });
    assert(res8.status === 200, `Expected 200 OK, got ${res8.status}`);
    assert(typeof res8.body.token === 'string' && res8.body.token.includes(':'), 'Should return signed token');
    console.log('  [PASS] Admin login succeeds and returns signed session token.');

    // Test 9: Verify Session Token (200)
    console.log('Testing: /admin/api/auth/verify with session token...');
    const res9 = await makeRequest(testPort, {
      path: '/admin/api/auth/verify',
      method: 'GET',
      headers: {
        Authorization: `Bearer ${res8.body.token}`,
      },
    });
    assert(res9.status === 200, `Expected 200 OK, got ${res9.status}`);
    assert(res9.body.valid === true, 'Session token should be valid');
    console.log('  [PASS] Session token verified successfully.');

    // Test 10: Admin Login Page Route (200)
    console.log('Testing: GET /admin/login serves login page...');
    const res10 = await makeRequest(testPort, {
      path: '/admin/login',
      method: 'GET',
    });
    assert(res10.status === 200, `Expected 200 OK, got ${res10.status}`);
    console.log('  [PASS] /admin/login serves login page.');

    // Test 11: Non-user table (products) rejects missing Device Security Key
    console.log('Testing: Non-user table (products) rejects missing Device Security Key with HTTP 400...');
    const res11 = await makeRequest(testPort, {
      path: '/API/1/postgres/tables/products',
      method: 'POST',
      headers: {
        'Key': rawKey,
        'IP': '127.0.0.1',
        'DeviceName': 'Device-NoKey',
        'Location': 'Office',
        'DeviceType': 'Desktop',
        'AppName': testAppName,
        // Missing Device Security Key
      },
      body: { name: 'Widget A', price: 99 },
    });
    assert(res11.status === 400, `Expected 400 Bad Request for non-user table, got ${res11.status}`);
    assert(res11.body.missingHeaders?.includes('Device Security Key'), 'Should list Device Security Key as missing');
    console.log('  [PASS] Non-user table strictly enforces Device Security Key header.');

    // Test 12: User table (users) allows missing Device Security Key and auto-provisions device
    console.log('Testing: User table (users) allows missing Device Security Key and triggers auto-provisioning...');
    const autoDeviceName = 'Phone-Auto-1';
    const res12 = await makeRequest(testPort, {
      path: '/API/1/postgres/tables/users',
      method: 'POST',
      headers: {
        'Key': rawKey,
        'IP': '127.0.0.1',
        'DeviceName': autoDeviceName,
        'Location': 'Remote',
        'DeviceType': 'Mobile',
        'AppName': testAppName,
        // No Device Security Key header!
      },
      body: { username: 'john_doe', email: 'john@example.com' },
    });
    // It must NOT fail with missing header 400!
    assert(res12.status !== 400 || !res12.body.missingHeaders, 'Must not be rejected for missing Device Security Key');
    // Verify device record was created in metadataStore
    const provisionedDev = metadataStore.findDevice(testAppName, autoDeviceName, 'Mobile');
    assert(Boolean(provisionedDev), 'Device must be auto-provisioned in device registry');
    console.log('  [PASS] User table triggers auto-provisioning when device key is not found.');

    // Test 13: Option to update Access Permissions (CRUD & DDL) via Admin API
    console.log('Testing: PATCH /admin/api/keys/:keyId/permissions updates access permissions...');
    const allKeys = metadataStore.getKeys();
    const targetKey = allKeys.find((k) => k.appName === testAppName)!;
    assert(Boolean(targetKey), 'Target key should exist');
    assert(targetKey.permissions.can_ddl === false, 'Initially can_ddl should be false');

    const res13 = await makeRequest(testPort, {
      path: `/admin/api/keys/${targetKey.id}/permissions`,
      method: 'PATCH',
      headers: {
        Authorization: `Bearer ${res8.body.token}`,
      },
      body: {
        permissions: {
          can_ddl: true,
          can_delete: true,
        },
      },
    });
    assert(res13.status === 200, `Expected 200 OK, got ${res13.status}`);
    assert(res13.body.success === true, 'Should indicate success');
    assert(res13.body.key.permissions.can_ddl === true, 'Updated can_ddl should be true');
    assert(res13.body.key.permissions.can_delete === true, 'Updated can_delete should be true');
    console.log('  [PASS] Admin API successfully updates CRUD & DDL access permissions.');
  } finally {
    server.close();
  }
}

async function run() {
  console.log('====================================================');
  console.log('  RUNNING DB API TEST SUITE');
  console.log('====================================================\n');

  let passed = 0;
  let failed = 0;

  for (const t of tests) {
    try {
      await t.fn();
      console.log(`[PASS] ${t.name}`);
      passed++;
    } catch (err: any) {
      console.error(`[FAIL] ${t.name}: ${err.message}`);
      failed++;
    }
  }

  console.log('\nRunning Integration HTTP Tests...\n');
  try {
    await runHttpTests();
    passed += 13;
  } catch (err: any) {
    console.error(`[FAIL] HTTP Integration tests: ${err.message}`);
    failed++;
  }

  console.log('\n====================================================');
  console.log(`  TEST RESULTS: ${passed} PASSED, ${failed} FAILED`);
  console.log('====================================================');

  process.exit(failed > 0 ? 1 : 0);
}

run();
