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
let currentKeysMap = new Map();

async function loadKeys() {
  const data = await fetchAdmin('/keys');
  if (!data || !data.success) return;

  const tbody = document.getElementById('keysTableBody');
  if (!tbody) return;
  tbody.innerHTML = '';
  currentKeysMap.clear();
  state.keys = data.keys || [];

  data.keys.forEach((key) => {
    currentKeysMap.set(key.id, key);
    const tr = document.createElement('tr');
    tr.className = 'hover:bg-slate-800/40 transition font-mono text-xs';

    const p = key.permissions || {};
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
        <div data-edit-key="${key.id}" onclick="openEditPermissionsModal('${key.id}')" class="edit-perm-btn flex flex-wrap items-center gap-1 cursor-pointer hover:opacity-85 transition group" title="Click to edit permissions">
          ${badge('C:Insert', p.can_create, 'emerald')}
          ${badge('R:Select', p.can_read, 'emerald')}
          ${badge('U:Update', p.can_update, 'emerald')}
          ${badge('D:Delete', p.can_delete, 'amber')}
          ${badge('DDL', p.can_ddl, 'rose')}
          <span class="text-[10px] text-sky-400/80 group-hover:text-sky-300 group-hover:underline ml-1 font-sans">Edit</span>
        </div>
      </td>
      <td class="py-3 px-3">${statusBadge}</td>
      <td class="py-3 px-3 text-slate-400">${key.lastUsedAt ? new Date(key.lastUsedAt).toLocaleTimeString() : 'Never'}</td>
      <td class="py-3 px-3 text-right">
        <div class="flex items-center justify-end gap-1.5 font-sans">
          <button type="button" data-edit-key="${key.id}" onclick="openEditPermissionsModal('${key.id}')" class="edit-perm-btn px-2 py-1 rounded bg-slate-800 hover:bg-sky-950/60 hover:text-sky-300 text-sky-400 text-xs transition border border-slate-700 hover:border-sky-500/30 font-medium flex items-center gap-1">
            <svg class="w-3 h-3 pointer-events-none" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"/></svg>
            <span class="pointer-events-none">Edit</span>
          </button>
          ${
            key.status === 'active'
              ? `<button type="button" onclick="revokeKey('${key.id}')" class="px-2 py-1 rounded bg-rose-950/30 hover:bg-rose-950/60 text-rose-400 hover:text-rose-300 text-xs transition border border-rose-500/20 font-medium">Revoke</button>`
              : '<span class="text-slate-600 px-2 py-1">-</span>'
          }
        </div>
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

if (openNewKeyModalBtn && newKeyModal) {
  openNewKeyModalBtn.addEventListener('click', () => newKeyModal.classList.remove('hidden'));
}
if (closeKeyModalBtn && newKeyModal) {
  closeKeyModalBtn.addEventListener('click', () => newKeyModal.classList.add('hidden'));
}

const createKeyForm = document.getElementById('createKeyForm');
if (createKeyForm) {
  createKeyForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const appName = document.getElementById('keyAppName')?.value.trim();
    const dbName = document.getElementById('keyDbName')?.value.trim();
    const can_create = document.getElementById('permCreate')?.checked ?? false;
    const can_read = document.getElementById('permRead')?.checked ?? false;
    const can_update = document.getElementById('permUpdate')?.checked ?? false;
    const can_delete = document.getElementById('permDelete')?.checked ?? false;
    const can_ddl = document.getElementById('permDDL')?.checked ?? false;
    const rawIps = document.getElementById('keyAllowedIps')?.value.trim();
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
      if (newKeyModal) newKeyModal.classList.add('hidden');
      const plainDisplay = document.getElementById('newPlainKeyDisplay');
      if (plainDisplay) plainDisplay.textContent = res.rawKey;
      const createdModal = document.getElementById('keyCreatedModal');
      if (createdModal) createdModal.classList.remove('hidden');
      loadKeys();
      loadOverview();
    } else {
      alert(res.error || 'Failed to create key');
    }
  });
}

const copyKeyBtn = document.getElementById('copyKeyBtn');
if (copyKeyBtn) {
  copyKeyBtn.addEventListener('click', () => {
    const text = document.getElementById('newPlainKeyDisplay')?.textContent || '';
    navigator.clipboard.writeText(text);
    showToast('API Key copied to clipboard!');
  });
}

const dismissKeyCreatedModalBtn = document.getElementById('dismissKeyCreatedModalBtn');
if (dismissKeyCreatedModalBtn) {
  dismissKeyCreatedModalBtn.addEventListener('click', () => {
    const createdModal = document.getElementById('keyCreatedModal');
    if (createdModal) createdModal.classList.add('hidden');
  });
}

// -------------------------------------------------------------
// Edit Permissions Modal (with Dynamic DOM fallback & delegation)
// -------------------------------------------------------------
function ensureEditPermissionsModal() {
  let modal = document.getElementById('editPermissionsModal');
  if (!modal) {
    console.log('[DB API] editPermissionsModal not in DOM, creating dynamically...');
    modal = document.createElement('div');
    modal.id = 'editPermissionsModal';
    modal.className = 'fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4';
    modal.style.display = 'none';
    modal.innerHTML = `
      <div class="bg-dark-900 border border-slate-800 rounded-2xl max-w-lg w-full p-6 shadow-2xl">
        <div class="flex items-center justify-between mb-2">
          <h3 class="text-base font-bold text-white flex items-center gap-2">
            <svg class="w-5 h-5 text-sky-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"/></svg>
            <span>Update Access Permissions (CRUD & DDL)</span>
          </h3>
          <span id="editKeyStatusBadge" class="px-2 py-0.5 rounded-full text-[10px] font-mono font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">active</span>
        </div>
        <p class="text-xs text-slate-400 mb-4">Modify CRUD and DDL operation privileges for this API key. Updates apply immediately in memory and in PostgreSQL <code class="text-sky-400 font-mono">db_admin</code>.</p>

        <div class="bg-dark-950 p-3 rounded-xl border border-slate-800/80 mb-4 space-y-1.5 text-xs font-mono">
          <div class="flex justify-between">
            <span class="text-slate-400">Application:</span>
            <span id="editKeyAppName" class="text-white font-sans font-bold"></span>
          </div>
          <div class="flex justify-between">
            <span class="text-slate-400">Database:</span>
            <span id="editKeyDbName" class="text-sky-400 font-semibold"></span>
          </div>
          <div class="flex justify-between">
            <span class="text-slate-400">Key Prefix:</span>
            <span id="editKeyPrefix" class="text-slate-300"></span>
          </div>
        </div>

        <form id="editPermissionsForm" class="space-y-4">
          <input type="hidden" id="editKeyId" value="">

          <div>
            <label class="block text-xs font-semibold text-slate-200 mb-2">CRUD & DDL Operation Privileges:</label>
            <div class="grid grid-cols-2 gap-2.5 bg-dark-800 p-3 rounded-xl border border-slate-700/60 text-xs">
              <label class="flex items-center space-x-2.5 text-slate-300 cursor-pointer p-1.5 rounded-lg hover:bg-slate-700/30 transition">
                <input type="checkbox" id="editPermCreate" class="w-4 h-4 rounded border-slate-600 bg-dark-900 text-sky-500 focus:ring-0">
                <div>
                  <div class="font-semibold text-white">Create (INSERT)</div>
                  <div class="text-[10px] text-slate-400">Insert new table records</div>
                </div>
              </label>
              <label class="flex items-center space-x-2.5 text-slate-300 cursor-pointer p-1.5 rounded-lg hover:bg-slate-700/30 transition">
                <input type="checkbox" id="editPermRead" class="w-4 h-4 rounded border-slate-600 bg-dark-900 text-sky-500 focus:ring-0">
                <div>
                  <div class="font-semibold text-white">Read (SELECT)</div>
                  <div class="text-[10px] text-slate-400">Query and list tables</div>
                </div>
              </label>
              <label class="flex items-center space-x-2.5 text-slate-300 cursor-pointer p-1.5 rounded-lg hover:bg-slate-700/30 transition">
                <input type="checkbox" id="editPermUpdate" class="w-4 h-4 rounded border-slate-600 bg-dark-900 text-sky-500 focus:ring-0">
                <div>
                  <div class="font-semibold text-white">Update (UPDATE)</div>
                  <div class="text-[10px] text-slate-400">Modify existing records</div>
                </div>
              </label>
              <label class="flex items-center space-x-2.5 text-slate-300 cursor-pointer p-1.5 rounded-lg hover:bg-slate-700/30 transition">
                <input type="checkbox" id="editPermDelete" class="w-4 h-4 rounded border-slate-600 bg-dark-900 text-amber-500 focus:ring-0">
                <div>
                  <div class="font-semibold text-amber-300">Delete (DELETE)</div>
                  <div class="text-[10px] text-slate-400">Remove table records</div>
                </div>
              </label>
              <label class="flex items-center space-x-2.5 text-rose-300 col-span-2 pt-2 border-t border-slate-700/60 cursor-pointer p-1.5 rounded-lg hover:bg-rose-950/20 transition">
                <input type="checkbox" id="editPermDDL" class="w-4 h-4 rounded border-slate-600 bg-dark-900 text-rose-500 focus:ring-0">
                <div>
                  <div class="font-semibold text-rose-400 flex items-center gap-1.5">
                    <span>DDL (Data Definition Language)</span>
                    <span class="text-[9px] px-1.5 py-0.2 rounded bg-rose-500/20 text-rose-300 font-mono">HIGH RISK</span>
                  </div>
                  <div class="text-[10px] text-slate-400">CREATE TABLE, ALTER TABLE, DROP TABLE, TRUNCATE</div>
                </div>
              </label>
            </div>
          </div>

          <div id="editPermissionsError" class="text-xs text-rose-400 hidden bg-rose-950/30 border border-rose-500/30 p-2.5 rounded-lg"></div>

          <div class="flex items-center justify-end space-x-2 pt-2">
            <button type="button" id="closeEditPermissionsModalBtn" class="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 font-medium transition">Cancel</button>
            <button type="submit" id="savePermissionsBtn" class="px-4 py-2 rounded-lg bg-sky-600 hover:bg-sky-500 text-xs text-white font-semibold shadow transition flex items-center gap-1.5">
              <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>
              Save Permissions
            </button>
          </div>
        </form>
      </div>
    `;
    document.body.appendChild(modal);
  }

  const closeBtn = document.getElementById('closeEditPermissionsModalBtn');
  if (closeBtn && !closeBtn._bound) {
    closeBtn._bound = true;
    closeBtn.addEventListener('click', closeEditPermissionsModal);
  }

  const form = document.getElementById('editPermissionsForm');
  if (form && !form._bound) {
    form._bound = true;
    form.addEventListener('submit', handleSavePermissions);
  }

  if (!modal._backdropBound) {
    modal._backdropBound = true;
    modal.addEventListener('click', (e) => {
      if (e.target === modal) {
        closeEditPermissionsModal();
      }
    });
  }

  return modal;
}

function closeEditPermissionsModal() {
  const modal = document.getElementById('editPermissionsModal');
  if (modal) {
    modal.style.display = 'none';
    modal.classList.add('hidden');
  }
}
window.closeEditPermissionsModal = closeEditPermissionsModal;

window.openEditPermissionsModal = async function (id) {
  console.log('[DB API] openEditPermissionsModal called with id:', id);
  try {
    const modal = ensureEditPermissionsModal();
    let key = currentKeysMap.get(id);

    if (!key && state && Array.isArray(state.keys)) {
      key = state.keys.find((k) => String(k.id) === String(id));
    }

    if (!key) {
      console.warn('[DB API] Key not in map, fetching latest /keys...');
      const data = await fetchAdmin('/keys');
      if (data && data.success && Array.isArray(data.keys)) {
        state.keys = data.keys;
        data.keys.forEach((k) => currentKeysMap.set(k.id, k));
        key = currentKeysMap.get(id) || data.keys.find((k) => String(k.id) === String(id));
      }
    }

    if (!key) {
      console.error('[DB API] Unable to find key for id:', id);
      alert('Could not load details for this API key. Please refresh.');
      return;
    }

    const editKeyId = document.getElementById('editKeyId');
    const editKeyAppName = document.getElementById('editKeyAppName');
    const editKeyDbName = document.getElementById('editKeyDbName');
    const editKeyPrefix = document.getElementById('editKeyPrefix');
    const editKeyStatusBadge = document.getElementById('editKeyStatusBadge');

    if (editKeyId) editKeyId.value = key.id;
    if (editKeyAppName) editKeyAppName.textContent = key.appName || '';
    if (editKeyDbName) editKeyDbName.textContent = key.dbName || '';
    if (editKeyPrefix) editKeyPrefix.textContent = key.keyPrefix || '';
    if (editKeyStatusBadge) {
      editKeyStatusBadge.textContent = key.status || 'active';
      editKeyStatusBadge.className =
        key.status === 'active'
          ? 'px-2 py-0.5 rounded-full text-[10px] font-mono font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
          : 'px-2 py-0.5 rounded-full text-[10px] font-mono font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/20';
    }

    const p = key.permissions || {};
    const setChecked = (elemId, val) => {
      const el = document.getElementById(elemId);
      if (el) el.checked = Boolean(val);
    };
    setChecked('editPermCreate', p.can_create);
    setChecked('editPermRead', p.can_read);
    setChecked('editPermUpdate', p.can_update);
    setChecked('editPermDelete', p.can_delete);
    setChecked('editPermDDL', p.can_ddl);

    const errEl = document.getElementById('editPermissionsError');
    if (errEl) {
      errEl.classList.add('hidden');
      errEl.style.display = 'none';
      errEl.textContent = '';
    }

    modal.classList.remove('hidden');
    modal.style.display = 'flex';
  } catch (err) {
    console.error('[DB API] Error in openEditPermissionsModal:', err);
    alert('Error opening edit permissions modal: ' + err.message);
  }
};

async function handleSavePermissions(e) {
  if (e) e.preventDefault();
  const keyId = document.getElementById('editKeyId')?.value;
  if (!keyId) return;

  const can_create = document.getElementById('editPermCreate')?.checked ?? false;
  const can_read = document.getElementById('editPermRead')?.checked ?? false;
  const can_update = document.getElementById('editPermUpdate')?.checked ?? false;
  const can_delete = document.getElementById('editPermDelete')?.checked ?? false;
  const can_ddl = document.getElementById('editPermDDL')?.checked ?? false;

  const saveBtn = document.getElementById('savePermissionsBtn');
  const originalHtml = saveBtn ? saveBtn.innerHTML : 'Save Permissions';
  if (saveBtn) {
    saveBtn.innerHTML = '<span>Saving...</span>';
    saveBtn.disabled = true;
  }

  try {
    const res = await fetchAdmin(`/keys/${keyId}/permissions`, {
      method: 'PATCH',
      body: JSON.stringify({
        permissions: {
          can_create,
          can_read,
          can_update,
          can_delete,
          can_ddl,
        },
      }),
    });

    if (res.success) {
      closeEditPermissionsModal();
      showToast('Access permissions updated successfully!');
      await loadKeys();
    } else {
      const errEl = document.getElementById('editPermissionsError');
      if (errEl) {
        errEl.textContent = res.error || 'Failed to update permissions';
        errEl.classList.remove('hidden');
        errEl.style.display = 'block';
      } else {
        alert(res.error || 'Failed to update permissions');
      }
    }
  } catch (err) {
    console.error('[DB API] Error in handleSavePermissions:', err);
    alert('Failed to save permissions: ' + err.message);
  } finally {
    if (saveBtn) {
      saveBtn.innerHTML = originalHtml;
      saveBtn.disabled = false;
    }
  }
}

// Delegated click handler for edit permissions triggers
document.addEventListener('click', (e) => {
  const trigger = e.target.closest('[data-edit-key]');
  if (trigger) {
    const keyId = trigger.getAttribute('data-edit-key');
    if (keyId) {
      window.openEditPermissionsModal(keyId);
    }
  }
});

// Device Modal
const newDeviceModal = document.getElementById('newDeviceModal');
const openNewDeviceModalBtn = document.getElementById('openNewDeviceModalBtn');
if (openNewDeviceModalBtn && newDeviceModal) {
  openNewDeviceModalBtn.addEventListener('click', () => newDeviceModal.classList.remove('hidden'));
}
const closeDeviceModalBtn = document.getElementById('closeDeviceModalBtn');
if (closeDeviceModalBtn && newDeviceModal) {
  closeDeviceModalBtn.addEventListener('click', () => newDeviceModal.classList.add('hidden'));
}

const createDeviceForm = document.getElementById('createDeviceForm');
if (createDeviceForm) {
  createDeviceForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const appName = document.getElementById('devAppName')?.value.trim();
    const deviceName = document.getElementById('devDeviceName')?.value.trim();
    const deviceType = document.getElementById('devDeviceType')?.value;

    const res = await fetchAdmin('/devices', {
      method: 'POST',
      body: JSON.stringify({ appName, deviceName, deviceType }),
    });

    if (res.success) {
      if (newDeviceModal) newDeviceModal.classList.add('hidden');
      alert(`Device registered!\nDevice Security Key: ${res.rawDeviceSecurityKey}\nSave it securely!`);
      loadDevices();
      loadOverview();
    } else {
      alert(res.error || 'Failed to register device');
    }
  });
}

// 7. Interactive Playground
const playDbName = document.getElementById('playDbName');
const playEndpoint = document.getElementById('playEndpoint');

if (playDbName && playEndpoint) {
  playDbName.addEventListener('input', () => {
    playEndpoint.value = `/API/1/${playDbName.value.trim()}/query`;
  });
}

// Presets
const presetSelect = document.getElementById('presetSelect');
if (presetSelect) {
  presetSelect.addEventListener('click', () => {
    const bodyEl = document.getElementById('playRequestBody');
    if (bodyEl) {
      bodyEl.value = JSON.stringify(
        { query: 'SELECT * FROM products LIMIT 5;', params: [] },
        null,
        2
      );
    }
  });
}

const presetDDL = document.getElementById('presetDDL');
if (presetDDL) {
  presetDDL.addEventListener('click', () => {
    const bodyEl = document.getElementById('playRequestBody');
    if (bodyEl) {
      bodyEl.value = JSON.stringify(
        { query: 'DROP TABLE products;', params: [] },
        null,
        2
      );
    }
  });
}

const presetSQLi = document.getElementById('presetSQLi');
if (presetSQLi) {
  presetSQLi.addEventListener('click', () => {
    const bodyEl = document.getElementById('playRequestBody');
    if (bodyEl) {
      bodyEl.value = JSON.stringify(
        { query: "SELECT * FROM products WHERE name = '' OR 1=1;", params: [] },
        null,
        2
      );
    }
  });
}

const sendPlaygroundBtn = document.getElementById('sendPlaygroundBtn');
if (sendPlaygroundBtn) {
  sendPlaygroundBtn.addEventListener('click', async () => {
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
}

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
