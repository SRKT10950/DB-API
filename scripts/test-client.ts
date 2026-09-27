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
    passed += 6;
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
