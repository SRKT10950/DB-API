// DB API Dashboard Client Script

const state = {
  authToken: localStorage.getItem('dbapi_auth_token') || localStorage.getItem('dbapi_admin_secret'),
  user: null,
  stats: {},
  keys: [],
  devices: [],
  logs: [],
  databases: [],
};

// Check if user is cached
try {
  const cachedUser = localStorage.getItem('dbapi_admin_user');
  if (cachedUser) state.user = JSON.parse(cachedUser);
} catch (e) {}

// DOM Elements
const pgStatusPill = document.getElementById('pgStatusPill');
const logoutBtn = document.getElementById('logoutBtn');
const adminUsernameBadge = document.getElementById('adminUsernameBadge');

// Authentication Check on Load
document.addEventListener('DOMContentLoaded', async () => {
  if (!state.authToken) {
    window.location.replace('/admin/login');
    return;
  }

  // Verify session validity
  try {
    const verifyRes = await fetch('/admin/api/auth/verify', {
      headers: {
        'Authorization': 'Bearer ' + state.authToken,
        'X-Admin-Secret': state.authToken,
      },
    });
    if (!verifyRes.ok) {
      localStorage.removeItem('dbapi_auth_token');
      localStorage.removeItem('dbapi_admin_secret');
      localStorage.removeItem('dbapi_admin_user');
      window.location.replace('/admin/login');
      return;
    }
  } catch (err) {
    console.warn('Could not verify session with server:', err);
  }

  // Display user badge
  if (adminUsernameBadge && state.user && state.user.username) {
    adminUsernameBadge.textContent = state.user.username;
  }

  // Bind Logout button
  if (logoutBtn) {
    logoutBtn.addEventListener('click', () => {
      localStorage.removeItem('dbapi_auth_token');
      localStorage.removeItem('dbapi_admin_secret');
      localStorage.removeItem('dbapi_admin_user');
      window.location.replace('/admin/login');
    });
  }

  setupTabs();
  loadAll();
  setInterval(loadOverview, 4000);
});

// Fetch wrapper with authentication headers
async function fetchAdmin(endpoint, options = {}) {
  const headers = {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer ' + state.authToken,
    'X-Admin-Secret': state.authToken,
    ...(options.headers || {}),
  };

  try {
    const res = await fetch(`/admin/api${endpoint}`, { ...options, headers });
    if (res.status === 401) {
      localStorage.removeItem('dbapi_auth_token');
      localStorage.removeItem('dbapi_admin_secret');
      localStorage.removeItem('dbapi_admin_user');
      window.location.replace('/admin/login');
      return { success: false, error: 'Session expired' };
    }
    return await res.json();
  } catch (err) {
    console.error('Fetch error:', err);
    return { success: false, error: err.message };
  }
}

// Tab navigation
function setupTabs() {
  const tabs = document.querySelectorAll('.nav-tab');
  tabs.forEach((tab) => {
    tab.addEventListener('click', () => {
      tabs.forEach((t) => t.classList.remove('active-tab'));
      tab.classList.add('active-tab');

      const targetTab = tab.getAttribute('data-tab');
      document.querySelectorAll('.tab-pane').forEach((pane) => {
        pane.classList.add('hidden');
        pane.classList.remove('active');
      });

      const pane = document.getElementById(targetTab);
      if (pane) {
        pane.classList.remove('hidden');
        pane.classList.add('active');
      }

      if (targetTab === 'keysTab') loadKeys();
      if (targetTab === 'devicesTab') loadDevices();
      if (targetTab === 'logsTab') loadLogs();
      if (targetTab === 'dbTab') loadDatabases();
    });
  });
}

// Load All Data
async function loadAll() {
  await loadOverview();
  await loadKeys();
  await loadDevices();
  await loadLogs();
  await loadDatabases();
}

// 1. Overview
async function loadOverview() {
  const data = await fetchAdmin('/overview');
  if (!data.success) {
    pgStatusPill.innerHTML = `
      <span class="w-2 h-2 rounded-full bg-rose-500"></span>
      <span class="text-rose-400">Auth Error</span>
    `;
    return;
  }

  // Update DB Status Pill
  if (data.database.connected) {
    pgStatusPill.innerHTML = `
      <span class="w-2 h-2 rounded-full bg-emerald-400"></span>
      <span class="text-emerald-400 font-mono">Postgres Connected</span>
    `;
  } else {
    pgStatusPill.innerHTML = `
      <span class="w-2 h-2 rounded-full bg-rose-500"></span>
      <span class="text-rose-400 font-mono">DB Disconnected</span>
    `;
  }

  // Update Stat Cards
  document.getElementById('statTotalRequests').textContent = data.stats.totalRequests.toLocaleString();
  document.getElementById('statThreatsBlocked').textContent = data.stats.threatsBlocked.toLocaleString();
  document.getElementById('statActiveKeys').textContent = data.stats.activeKeys.toLocaleString();
  document.getElementById('statActiveDevices').textContent = data.stats.activeDevices.toLocaleString();
}

// 2. Keys
async function loadKeys() {
  const data = await fetchAdmin('/keys');
  if (!data.success) return;

  const tbody = document.getElementById('keysTableBody');
  tbody.innerHTML = '';

  data.keys.forEach((key) => {
    const tr = document.createElement('tr');
    tr.className = 'hover:bg-slate-800/40 transition font-mono text-xs';

    const p = key.permissions;
    const badge = (name, enabled, color = 'emerald') => {
      const cls = enabled
        ? `bg-${color}-500/10 text-${color}-400 border border-${color}-500/20`
        : 'bg-slate-800 text-slate-500 border border-slate-700/50 line-through';
      return `<span class="px-1.5 py-0.5 rounded text-[10px] font-semibold ${cls}">${name}</span>`;
    };

    const statusBadge =
      key.status === 'active'
        ? '<span class="px-2 py-0.5 rounded-full text-[11px] bg-emerald-500/10 text-emerald-400 font-semibold border border-emerald-500/20">active</span>'
        : '<span class="px-2 py-0.5 rounded-full text-[11px] bg-rose-500/10 text-rose-400 font-semibold border border-rose-500/20">revoked</span>';

    tr.innerHTML = `
      <td class="py-3 px-3 text-white font-bold font-sans">${escapeHtml(key.appName)}</td>
      <td class="py-3 px-3 text-sky-400 font-semibold">${escapeHtml(key.dbName)}</td>
      <td class="py-3 px-3 text-slate-400">${escapeHtml(key.keyPrefix)}</td>
      <td class="py-3 px-3">
        <div class="flex flex-wrap gap-1">
          ${badge('C:Insert', p.can_create, 'emerald')}
          ${badge('R:Select', p.can_read, 'emerald')}
          ${badge('U:Update', p.can_update, 'emerald')}
          ${badge('D:Delete', p.can_delete, 'amber')}
          ${badge('DDL', p.can_ddl, 'rose')}
        </div>
      </td>
      <td class="py-3 px-3">${statusBadge}</td>
      <td class="py-3 px-3 text-slate-400">${key.lastUsedAt ? new Date(key.lastUsedAt).toLocaleTimeString() : 'Never'}</td>
      <td class="py-3 px-3 text-right">
        ${
          key.status === 'active'
            ? `<button onclick="revokeKey('${key.id}')" class="text-xs text-rose-400 hover:text-rose-300 font-sans">Revoke</button>`
            : '<span class="text-slate-600">-</span>'
        }
      </td>
    `;
    tbody.appendChild(tr);
  });
}

// Revoke Key
window.revokeKey = async function (id) {
  if (!confirm('Are you sure you want to revoke this API Key?')) return;
  const res = await fetchAdmin(`/keys/${id}`, { method: 'DELETE' });
  if (res.success) {
    loadKeys();
    loadOverview();
  } else {
    alert(res.error || 'Failed to revoke key');
  }
};

// 3. Devices
async function loadDevices() {
  const data = await fetchAdmin('/devices');
  if (!data.success) return;

  const tbody = document.getElementById('devicesTableBody');
  tbody.innerHTML = '';

  data.devices.forEach((dev) => {
    const tr = document.createElement('tr');
    tr.className = 'hover:bg-slate-800/40 transition font-mono text-xs';

    const statusBadge =
      dev.status === 'active'
        ? '<span class="px-2 py-0.5 rounded-full text-[11px] bg-emerald-500/10 text-emerald-400 font-semibold border border-emerald-500/20">active</span>'
        : '<span class="px-2 py-0.5 rounded-full text-[11px] bg-rose-500/10 text-rose-400 font-semibold border border-rose-500/20">revoked</span>';

    tr.innerHTML = `
      <td class="py-3 px-3 text-white font-bold font-sans">${escapeHtml(dev.appName)}</td>
      <td class="py-3 px-3 text-indigo-400 font-semibold">${escapeHtml(dev.deviceName)}</td>
      <td class="py-3 px-3 text-slate-300">${escapeHtml(dev.deviceType)}</td>
      <td class="py-3 px-3 text-slate-400">${escapeHtml(dev.securityKeyPrefix)}</td>
      <td class="py-3 px-3">${statusBadge}</td>
      <td class="py-3 px-3 text-slate-400">${dev.lastSeenAt ? new Date(dev.lastSeenAt).toLocaleTimeString() : 'Never'}</td>
      <td class="py-3 px-3 text-right">
        ${
          dev.status === 'active'
            ? `<button onclick="revokeDevice('${dev.id}')" class="text-xs text-rose-400 hover:text-rose-300 font-sans">Revoke</button>`
            : '<span class="text-slate-600">-</span>'
        }
      </td>
    `;
    tbody.appendChild(tr);
  });
}

window.revokeDevice = async function (id) {
  if (!confirm('Revoke this device?')) return;
  const res = await fetchAdmin(`/devices/${id}`, { method: 'DELETE' });
  if (res.success) {
    loadDevices();
    loadOverview();
  }
};

// 4. Logs
async function loadLogs() {
  const threatFilter = document.getElementById('logThreatFilter').value;
  const data = await fetchAdmin(`/logs?limit=100&threatLevel=${threatFilter}`);
  if (!data.success) return;

  const tbody = document.getElementById('logsTableBody');
  tbody.innerHTML = '';

  data.logs.forEach((log) => {
    const tr = document.createElement('tr');
    tr.className = 'hover:bg-slate-800/40 transition text-xs border-b border-slate-800/40';

    let threatBadgeCls = 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20';
    if (log.threatLevel === 'CRITICAL') threatBadgeCls = 'text-rose-400 bg-rose-500/10 border-rose-500/20 animate-pulse';
    else if (log.threatLevel === 'HIGH') threatBadgeCls = 'text-amber-400 bg-amber-500/10 border-amber-500/20';
    else if (log.threatLevel === 'MEDIUM') threatBadgeCls = 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20';

    const statusColor = log.statusCode < 400 ? 'text-emerald-400' : 'text-rose-400';

    tr.innerHTML = `
      <td class="py-2.5 px-3 text-slate-400">${new Date(log.timestamp).toLocaleTimeString()}</td>
      <td class="py-2.5 px-3 font-bold ${statusColor}">${log.statusCode}</td>
      <td class="py-2.5 px-3">
        <span class="px-2 py-0.5 rounded text-[10px] font-semibold border ${threatBadgeCls}">${log.operationType}</span>
      </td>
      <td class="py-2.5 px-3 text-slate-300">${escapeHtml(log.appName)} / <span class="text-sky-400">${escapeHtml(log.dbName)}</span></td>
      <td class="py-2.5 px-3 text-slate-400">${escapeHtml(log.deviceName)} <span class="text-[10px] text-slate-500">(${escapeHtml(log.actualIp)})</span></td>
      <td class="py-2.5 px-3 text-slate-400">${log.durationMs}ms</td>
      <td class="py-2.5 px-3 text-slate-300 truncate max-w-xs" title="${escapeHtml(log.querySummary)}">
        ${escapeHtml(log.threatReason || log.querySummary)}
      </td>
    `;
    tbody.appendChild(tr);
  });
}

document.getElementById('refreshLogsBtn').addEventListener('click', loadLogs);
document.getElementById('logThreatFilter').addEventListener('change', loadLogs);

// 5. Databases
async function loadDatabases() {
  const data = await fetchAdmin('/databases');
  if (!data.success) return;

  const list = document.getElementById('databasesList');
  list.innerHTML = '';

  data.databases.forEach((db) => {
    const li = document.createElement('li');
    li.className = 'p-3 bg-dark-800 rounded-lg border border-slate-700/60 flex items-center justify-between';
    li.innerHTML = `
      <div class="flex items-center space-x-2">
        <span class="w-2.5 h-2.5 rounded-full bg-sky-400"></span>
        <span class="text-xs font-mono font-bold text-white">${escapeHtml(db)}</span>
      </div>
      <button onclick="selectPlaygroundDb('${db}')" class="text-xs text-sky-400 hover:text-sky-300 font-sans">Use in Playground</button>
    `;
    list.appendChild(li);
  });
}

window.selectPlaygroundDb = function (db) {
  document.getElementById('playDbName').value = db;
  document.getElementById('playEndpoint').value = `/API/1/${db}/query`;
  document.querySelector('[data-tab="playgroundTab"]').click();
};

// Create Database
document.getElementById('createDbForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const dbName = document.getElementById('newDbNameInput').value.trim();
  const res = await fetchAdmin('/databases', {
    method: 'POST',
    body: JSON.stringify({ dbName }),
  });
  if (res.success) {
    showToast(`Database '${dbName}' created!`);
    document.getElementById('newDbNameInput').value = '';
    loadDatabases();
  } else {
    alert(res.error || 'Failed to create database');
  }
});

// Setup Demo DB Banner Button
document.getElementById('setupDemoBtn').addEventListener('click', async () => {
  const btn = document.getElementById('setupDemoBtn');
  btn.disabled = true;
  btn.textContent = 'Provisioning...';

  const res = await fetchAdmin('/setup-demo-db', { method: 'POST' });
  btn.disabled = false;
  btn.innerHTML = `<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6"/></svg> Provision Demo DB & Test Keys`;

  if (res.success) {
    showToast('Demo Database and Test Keys Initialized!');
    loadAll();
    // Fill playground automatically
    document.getElementById('playDbName').value = res.demoDatabase;
    document.getElementById('playEndpoint').value = `/API/1/${res.demoDatabase}/query`;
    document.getElementById('playAppName').value = res.app;
    if (res.apiKey) document.getElementById('playKey').value = res.apiKey;
    if (res.device) {
      document.getElementById('playDeviceName').value = res.device.deviceName;
      document.getElementById('playDeviceType').value = res.device.deviceType;
      document.getElementById('playDeviceSecKey').value = res.device.deviceSecurityKey;
    }
  } else {
    alert(res.error || 'Setup failed');
  }
});

// 6. Modals Setup
const newKeyModal = document.getElementById('newKeyModal');
const openNewKeyModalBtn = document.getElementById('openNewKeyModalBtn');
const closeKeyModalBtn = document.getElementById('closeKeyModalBtn');

openNewKeyModalBtn.addEventListener('click', () => newKeyModal.classList.remove('hidden'));
closeKeyModalBtn.addEventListener('click', () => newKeyModal.classList.add('hidden'));

document.getElementById('createKeyForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const appName = document.getElementById('keyAppName').value.trim();
  const dbName = document.getElementById('keyDbName').value.trim();
  const can_create = document.getElementById('permCreate').checked;
  const can_read = document.getElementById('permRead').checked;
  const can_update = document.getElementById('permUpdate').checked;
  const can_delete = document.getElementById('permDelete').checked;
  const can_ddl = document.getElementById('permDDL').checked;
  const rawIps = document.getElementById('keyAllowedIps').value.trim();
  const allowedIps = rawIps ? rawIps.split(',').map((s) => s.trim()) : [];

  const res = await fetchAdmin('/keys', {
    method: 'POST',
    body: JSON.stringify({
      appName,
      dbName,
      permissions: { can_create, can_read, can_update, can_delete, can_ddl },
      allowedIps,
    }),
  });

  if (res.success) {
    newKeyModal.classList.add('hidden');
    document.getElementById('newPlainKeyDisplay').textContent = res.rawKey;
    document.getElementById('keyCreatedModal').classList.remove('hidden');
    loadKeys();
    loadOverview();
  } else {
    alert(res.error || 'Failed to create key');
  }
});

document.getElementById('copyKeyBtn').addEventListener('click', () => {
  const text = document.getElementById('newPlainKeyDisplay').textContent;
  navigator.clipboard.writeText(text);
  showToast('API Key copied to clipboard!');
});

document.getElementById('dismissKeyCreatedModalBtn').addEventListener('click', () => {
  document.getElementById('keyCreatedModal').classList.add('hidden');
});

// Device Modal
const newDeviceModal = document.getElementById('newDeviceModal');
document.getElementById('openNewDeviceModalBtn').addEventListener('click', () => newDeviceModal.classList.remove('hidden'));
document.getElementById('closeDeviceModalBtn').addEventListener('click', () => newDeviceModal.classList.add('hidden'));

document.getElementById('createDeviceForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const appName = document.getElementById('devAppName').value.trim();
  const deviceName = document.getElementById('devDeviceName').value.trim();
  const deviceType = document.getElementById('devDeviceType').value;

  const res = await fetchAdmin('/devices', {
    method: 'POST',
    body: JSON.stringify({ appName, deviceName, deviceType }),
  });

  if (res.success) {
    newDeviceModal.classList.add('hidden');
    alert(`Device registered!\nDevice Security Key: ${res.rawDeviceSecurityKey}\nSave it securely!`);
    loadDevices();
    loadOverview();
  } else {
    alert(res.error || 'Failed to register device');
  }
});

// 7. Interactive Playground
const playDbName = document.getElementById('playDbName');
const playEndpoint = document.getElementById('playEndpoint');

playDbName.addEventListener('input', () => {
  playEndpoint.value = `/API/1/${playDbName.value.trim()}/query`;
});

// Presets
document.getElementById('presetSelect').addEventListener('click', () => {
  document.getElementById('playRequestBody').value = JSON.stringify(
    { query: 'SELECT * FROM products LIMIT 5;', params: [] },
    null,
    2
  );
});

document.getElementById('presetDDL').addEventListener('click', () => {
  document.getElementById('playRequestBody').value = JSON.stringify(
    { query: 'DROP TABLE products;', params: [] },
    null,
    2
  );
});

document.getElementById('presetSQLi').addEventListener('click', () => {
  document.getElementById('playRequestBody').value = JSON.stringify(
    { query: "SELECT * FROM products WHERE name = '' OR 1=1;", params: [] },
    null,
    2
  );
});

document.getElementById('sendPlaygroundBtn').addEventListener('click', async () => {
  const endpoint = playEndpoint.value.trim();
  const key = document.getElementById('playKey').value.trim();
  const ip = document.getElementById('playIP').value.trim();
  const deviceName = document.getElementById('playDeviceName').value.trim();
  const location = document.getElementById('playLocation').value.trim();
  const deviceType = document.getElementById('playDeviceType').value.trim();
  const appName = document.getElementById('playAppName').value.trim();
  const deviceSecurityKey = document.getElementById('playDeviceSecKey').value.trim();
  const bodyText = document.getElementById('playRequestBody').value;

  let bodyJson = {};
  try {
    bodyJson = JSON.parse(bodyText);
  } catch (err) {
    alert('Invalid JSON in Request Body');
    return;
  }

  const metaEl = document.getElementById('playResponseMeta');
  const outputEl = document.getElementById('playResponseOutput');

  metaEl.innerHTML = '<span class="text-sky-400">Sending request...</span>';
  const start = performance.now();

  try {
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Key': key,
        'IP': ip,
        'DeviceName': deviceName,
        'Location': location,
        'DeviceType': deviceType,
        'AppName': appName,
        'Device-Security-Key': deviceSecurityKey,
      },
      body: JSON.stringify(bodyJson),
    });

    const elapsed = Math.round(performance.now() - start);
    const data = await res.json();

    const statusColor = res.ok ? 'text-emerald-400' : 'text-rose-400';
    metaEl.innerHTML = `<span class="${statusColor} font-bold">HTTP ${res.status}</span> • <span>${elapsed}ms</span>`;
    outputEl.textContent = JSON.stringify(data, null, 2);

    loadOverview();
    loadLogs();
  } catch (err) {
    metaEl.innerHTML = '<span class="text-rose-400">Network / Connection Error</span>';
    outputEl.textContent = err.message;
  }
});

// Toast notification helper
function showToast(message) {
  const toast = document.createElement('div');
  toast.className = 'fixed bottom-5 right-5 bg-sky-600 text-white text-xs px-4 py-2.5 rounded-lg shadow-xl z-50 transition transform';
  toast.textContent = message;
  document.body.appendChild(toast);
  setTimeout(() => {
    toast.remove();
  }, 3000);
}

function escapeHtml(text) {
  if (!text) return '';
  return String(text).replace(/[&<>"']/g, (m) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m]));
}
