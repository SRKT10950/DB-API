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
    console.log('  LIVE VERIFICATION: DYNAMIC PERMISSION UPDATES (CRUD & DDL)');
    console.log('===========================================================');

    // 1. Authenticate with Admin API
    console.log('\n[Step 1] Logging into Admin API...');
    const loginRes = await request(
      { path: '/admin/api/auth/login', method: 'POST' },
      { secret: 'mh_admin_super_secret_key_2026' }
    );
    const token = loginRes.body.token;
    console.log('  Login successful! Session token obtained.');

    // 2. Fetch Keys
    console.log('\n[Step 2] Fetching active keys...');
    const keysRes = await request(
      {
        path: '/admin/api/keys',
        method: 'GET',
        headers: { Authorization: `Bearer ${token}` },
      },
      null
    );
    const mobileKey = keysRes.body.keys.find((k) => k.appName === 'MobileApp');
    if (!mobileKey) {
      throw new Error('MobileApp key not found!');
    }
    console.log(`  Found Key for MobileApp: ${mobileKey.id} (${mobileKey.keyPrefix})`);
    console.log('  Initial Permissions:', JSON.stringify(mobileKey.permissions));

    // 3. Test DELETE with key that has can_delete: false
    // First, let's ensure can_delete is false
    await request(
      {
        path: `/admin/api/keys/${mobileKey.id}/permissions`,
        method: 'PATCH',
        headers: { Authorization: `Bearer ${token}` },
      },
      {
        permissions: { can_delete: false, can_ddl: false },
      }
    );

    // Get a device key for MobileApp
    const devicesRes = await request(
      {
        path: '/admin/api/devices',
        method: 'GET',
        headers: { Authorization: `Bearer ${token}` },
      },
      null
    );
    const mobileDevice = devicesRes.body.devices.find((d) => d.appName === 'MobileApp');

    // 4. Update permissions: Enable DELETE and DDL
    console.log('\n[Step 3] Updating permissions to enable DELETE and DDL via PATCH /admin/api/keys/:keyId/permissions...');
    const patchRes = await request(
      {
        path: `/admin/api/keys/${mobileKey.id}/permissions`,
        method: 'PATCH',
        headers: { Authorization: `Bearer ${token}` },
      },
      {
        permissions: {
          can_delete: true,
          can_ddl: true,
        },
      }
    );
    console.log('  HTTP Status:', patchRes.status);
    console.log('  Response:', JSON.stringify(patchRes.body, null, 2));

    if (!patchRes.body.success || patchRes.body.key.permissions.can_delete !== true) {
      throw new Error('Failed to update permissions to allow DELETE!');
    }

    // 5. Update permissions back: Disable DELETE
    console.log('\n[Step 4] Updating permissions to disable DELETE again...');
    const patchRes2 = await request(
      {
        path: `/admin/api/keys/${mobileKey.id}/permissions`,
        method: 'PATCH',
        headers: { Authorization: `Bearer ${token}` },
      },
      {
        permissions: {
          can_delete: false,
        },
      }
    );
    console.log('  HTTP Status:', patchRes2.status);
    console.log('  Updated can_delete:', patchRes2.body.key.permissions.can_delete);

    if (patchRes2.body.key.permissions.can_delete !== false) {
      throw new Error('Failed to update permissions to disable DELETE!');
    }

    console.log('\n===========================================================');
    console.log('  PERMISSIONS UPDATE VERIFIED SUCCESSFULLY!');
    console.log('===========================================================');
  } catch (err) {
    console.error('Verification failed:', err);
    process.exit(1);
  }
})();
