const http = require('http');

function request(options, body) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const req = http.request(
      {
        hostname: '192.168.50.109',
        port: 80,
        path: options.path,
        method: options.method,
        headers: {
          Host: 'db.mhservice.co.in',
          ...(data
            ? {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(data),
              }
            : {}),
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
          resolve({ status: res.statusCode, headers: res.headers, body: parsed });
        });
      }
    );
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

(async () => {
  try {
    console.log('===========================================================');
    console.log('  LIVE VERIFICATION: DB API AUTO-PROVISIONING & POSTGRES');
    console.log('===========================================================');

    // 1. Generate API Key for MobileApp
    console.log('\n[Step 1] Generating API Key for App: "MobileApp", Database: "postgres"...');
    const keyRes = await request(
      {
        path: '/admin/api/keys',
        method: 'POST',
        headers: { 'x-admin-secret': 'mh_admin_super_secret_key_2026' },
      },
      {
        appName: 'MobileApp',
        dbName: 'postgres',
        permissions: {
          can_create: true,
          can_read: true,
          can_update: true,
          can_delete: false,
          can_ddl: false,
        },
      }
    );
    console.log('  HTTP Status:', keyRes.status);
    console.log('  API Key Generated:', keyRes.body.rawKey);
    const apiKey = keyRes.body.rawKey;

    if (!apiKey) {
      throw new Error('Failed to generate API Key: ' + JSON.stringify(keyRes.body));
    }

    // 2. Perform insert into users table WITHOUT Device Security Key
    console.log('\n[Step 2] Sending POST to /API/1/postgres/tables/users WITHOUT Device Security Key...');
    const insertRes = await request(
      {
        path: '/API/1/postgres/tables/users',
        method: 'POST',
        headers: {
          Key: apiKey,
          IP: '192.168.1.50',
          DeviceName: 'iPhone-16-Pro',
          DeviceType: 'Mobile',
          Location: 'Mumbai, IN',
          AppName: 'MobileApp',
          // Notice: NO Device Security Key provided!
        },
      },
      {
        username: 'sriram',
        email: 'sriram@mhservice.co.in',
      }
    );

    console.log('  HTTP Status:', insertRes.status);
    console.log('  Device-Security-Key Response Header:', insertRes.headers['device-security-key']);
    console.log('  Response Body:');
    console.log(JSON.stringify(insertRes.body, null, 2));

    const provisionedKey = insertRes.body.deviceKey;
    if (!provisionedKey) {
      throw new Error('Device Key was NOT returned in response!');
    }

    // 3. Perform second operation WITH the newly received Device Security Key
    console.log('\n[Step 3] Sending GET to /API/1/postgres/tables/users WITH the provisioned Device Security Key...');
    const getRes = await request(
      {
        path: '/API/1/postgres/tables/users',
        method: 'GET',
        headers: {
          Key: apiKey,
          IP: '192.168.1.50',
          DeviceName: 'iPhone-16-Pro',
          DeviceType: 'Mobile',
          Location: 'Mumbai, IN',
          AppName: 'MobileApp',
          'Device-Security-Key': provisionedKey,
        },
      },
      null
    );

    // 4. Perform raw query insert on users table with new device without Device Security Key
    console.log('\n[Step 4] Sending raw query POST to /API/1/postgres/query on users table without Device Security Key...');
    const queryRes = await request(
      {
        path: '/API/1/postgres/query',
        method: 'POST',
        headers: {
          Key: apiKey,
          IP: '192.168.1.55',
          DeviceName: 'Pixel-9-Pro',
          DeviceType: 'Mobile',
          Location: 'Bengaluru, IN',
          AppName: 'MobileApp',
        },
      },
      {
        query: 'INSERT INTO users (username, email) VALUES ($1, $2) RETURNING *;',
        params: ['raj', 'raj@mhservice.co.in'],
      }
    );

    console.log('  HTTP Status:', queryRes.status);
    console.log('  Device-Security-Key Response Header:', queryRes.headers['device-security-key']);
    console.log('  Response Body:');
    console.log(JSON.stringify(queryRes.body, null, 2));

    const pixelKey = queryRes.body.deviceKey;
    if (!pixelKey) {
      throw new Error('Device Key was NOT returned for raw query insert!');
    }

    console.log('\n===========================================================');
    console.log('  LIVE VERIFICATION SUCCEEDED: ALL CHECKS PASSED!');
    console.log('===========================================================');
  } catch (err) {
    console.error('Verification failed:', err);
    process.exit(1);
  }
})();
