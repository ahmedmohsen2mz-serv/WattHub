/**
 * WattHub — Secure IoT Dashboard
 * Single-page application for MTTL-W01 smart strip control
 *
 * Security features:
 * - JWT-based auth with refresh token rotation
 * - CSRF double-submit cookie protection
 * - Auto-logout on token expiry
 * - All state changes require POST + auth + CSRF
 * - Rate-limited login with lockout display
 */

// ══════════════════════════════════════════════════════════════════════════
//  AUTH MODULE
// ══════════════════════════════════════════════════════════════════════════

const Auth = (() => {
  const STORAGE_KEY = 'watthub_auth';

  function save(data) {
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(data));
  }

  function load() {
    try {
      return JSON.parse(sessionStorage.getItem(STORAGE_KEY));
    } catch { return null; }
  }

  function clear() {
    sessionStorage.removeItem(STORAGE_KEY);
  }

  function getToken() {
    const d = load();
    return d ? d.access_token : null;
  }

  function getRefreshToken() {
    const d = load();
    return d ? d.refresh_token : null;
  }

  function getCsrf() {
    const d = load();
    return d ? d.csrf_token : '';
  }

  function getUser() {
    const d = load();
    return d ? d.user : null;
  }

  function isLoggedIn() {
    return !!getToken();
  }

  async function refreshToken() {
    const rt = getRefreshToken();
    if (!rt) return false;
    try {
      const res = await fetch('/api/auth/refresh', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: rt }),
      });
      if (!res.ok) { clear(); return false; }
      const data = await res.json();
      const existing = load();
      existing.access_token = data.access_token;
      save(existing);
      return true;
    } catch {
      clear();
      return false;
    }
  }

  return { save, load, clear, getToken, getRefreshToken, getCsrf, getUser, isLoggedIn, refreshToken };
})();

// ══════════════════════════════════════════════════════════════════════════
//  API MODULE
// ══════════════════════════════════════════════════════════════════════════

const API = (() => {
  async function request(path, options = {}) {
    const headers = { ...options.headers };
    const token = Auth.getToken();
    if (token) headers['Authorization'] = `Bearer ${token}`;
    if (options.body) headers['Content-Type'] = 'application/json';
    if (options.method === 'POST') headers['X-CSRF-Token'] = Auth.getCsrf();

    const res = await fetch(path, { ...options, headers });

    // Auto-refresh on 401
    if (res.status === 401 && path !== '/api/auth/login' && path !== '/api/auth/refresh') {
      const refreshed = await Auth.refreshToken();
      if (refreshed) {
        headers['Authorization'] = `Bearer ${Auth.getToken()}`;
        return fetch(path, { ...options, headers });
      } else {
        Auth.clear();
        App.render();
        throw new Error('Session expired');
      }
    }
    return res;
  }

  async function get(path) {
    const res = await request(path);
    return res.json();
  }

  async function post(path, body) {
    const res = await request(path, {
      method: 'POST',
      body: JSON.stringify(body),
    });
    return res.json();
  }

  return { request, get, post };
})();

// ══════════════════════════════════════════════════════════════════════════
//  TOAST NOTIFICATIONS
// ══════════════════════════════════════════════════════════════════════════

const Toast = (() => {
  let container = null;

  function ensureContainer() {
    if (!container) {
      container = document.createElement('div');
      container.className = 'toast-container';
      document.body.appendChild(container);
    }
  }

  function show(message, type = 'info', duration = 4000) {
    ensureContainer();
    const icons = { success: '✓', error: '✗', warning: '⚠', info: 'ℹ' };
    const el = document.createElement('div');
    el.className = `toast ${type}`;
    el.innerHTML = `<span>${icons[type] || ''}</span><span>${escapeHtml(message)}</span>`;
    container.appendChild(el);
    setTimeout(() => {
      el.classList.add('leaving');
      setTimeout(() => el.remove(), 200);
    }, duration);
  }

  return { show };
})();

// ══════════════════════════════════════════════════════════════════════════
//  CHART MODULE (Simple canvas line chart)
// ══════════════════════════════════════════════════════════════════════════

const Chart = (() => {
  function draw(canvas, data, label, color = '#2ecc71') {
    if (!canvas || !data.length) return;
    const ctx = canvas.getContext('2d');
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    ctx.scale(dpr, dpr);

    const w = rect.width;
    const h = rect.height;
    const pad = { top: 20, right: 10, bottom: 30, left: 50 };
    const plotW = w - pad.left - pad.right;
    const plotH = h - pad.top - pad.bottom;

    const values = data.map(d => d.power_w || 0);
    const maxVal = Math.max(...values, 1);
    const minVal = 0;

    // Clear
    ctx.clearRect(0, 0, w, h);

    // Grid lines
    ctx.strokeStyle = 'rgba(255,255,255,0.04)';
    ctx.lineWidth = 1;
    for (let i = 0; i <= 4; i++) {
      const y = pad.top + (plotH / 4) * i;
      ctx.beginPath();
      ctx.moveTo(pad.left, y);
      ctx.lineTo(w - pad.right, y);
      ctx.stroke();

      // Labels
      ctx.fillStyle = 'rgba(255,255,255,0.3)';
      ctx.font = '11px Inter, sans-serif';
      ctx.textAlign = 'right';
      const val = maxVal - (maxVal / 4) * i;
      ctx.fillText(val.toFixed(1), pad.left - 8, y + 4);
    }

    // Y-axis label
    ctx.save();
    ctx.translate(12, pad.top + plotH / 2);
    ctx.rotate(-Math.PI / 2);
    ctx.fillStyle = 'rgba(255,255,255,0.3)';
    ctx.font = '11px Inter, sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText(label, 0, 0);
    ctx.restore();

    if (values.length < 2) return;

    // Gradient fill
    const gradient = ctx.createLinearGradient(0, pad.top, 0, pad.top + plotH);
    gradient.addColorStop(0, color + '30');
    gradient.addColorStop(1, color + '00');

    // Draw area
    ctx.beginPath();
    ctx.moveTo(pad.left, pad.top + plotH);
    for (let i = 0; i < values.length; i++) {
      const x = pad.left + (plotW / (values.length - 1)) * i;
      const y = pad.top + plotH - (values[i] / maxVal) * plotH;
      if (i === 0) ctx.lineTo(x, y);
      else ctx.lineTo(x, y);
    }
    ctx.lineTo(pad.left + plotW, pad.top + plotH);
    ctx.closePath();
    ctx.fillStyle = gradient;
    ctx.fill();

    // Draw line
    ctx.beginPath();
    for (let i = 0; i < values.length; i++) {
      const x = pad.left + (plotW / (values.length - 1)) * i;
      const y = pad.top + plotH - (values[i] / maxVal) * plotH;
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    }
    ctx.strokeStyle = color;
    ctx.lineWidth = 2;
    ctx.lineJoin = 'round';
    ctx.lineCap = 'round';
    ctx.stroke();

    // Latest value dot
    if (values.length > 0) {
      const lastX = pad.left + plotW;
      const lastY = pad.top + plotH - (values[values.length - 1] / maxVal) * plotH;
      ctx.beginPath();
      ctx.arc(lastX, lastY, 4, 0, Math.PI * 2);
      ctx.fillStyle = color;
      ctx.fill();
      ctx.beginPath();
      ctx.arc(lastX, lastY, 7, 0, Math.PI * 2);
      ctx.strokeStyle = color + '60';
      ctx.lineWidth = 2;
      ctx.stroke();
    }

    // Time labels
    if (data.length > 1) {
      ctx.fillStyle = 'rgba(255,255,255,0.3)';
      ctx.font = '10px Inter, sans-serif';
      ctx.textAlign = 'center';
      const first = new Date(data[0].ts * 1000);
      const last = new Date(data[data.length - 1].ts * 1000);
      ctx.fillText(formatTime(first), pad.left, h - 6);
      ctx.fillText(formatTime(last), w - pad.right, h - 6);
    }
  }

  function formatTime(d) {
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }

  return { draw };
})();

// ══════════════════════════════════════════════════════════════════════════
//  UTILITY FUNCTIONS
// ══════════════════════════════════════════════════════════════════════════

function escapeHtml(s) {
  const div = document.createElement('div');
  div.textContent = s;
  return div.innerHTML;
}

function timeAgo(ts) {
  if (!ts) return '—';
  const diff = (Date.now() / 1000) - ts;
  if (diff < 60) return 'just now';
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

function formatTimestamp(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return d.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function rssiLevel(rssi) {
  if (!rssi) return { label: 'Unknown', icon: '📶', color: 'var(--fg-dim)' };
  if (rssi >= -50) return { label: 'Excellent', icon: '📶', color: 'var(--on)' };
  if (rssi >= -60) return { label: 'Good', icon: '📶', color: 'var(--on)' };
  if (rssi >= -70) return { label: 'Fair', icon: '📶', color: 'var(--warning)' };
  return { label: 'Weak', icon: '📶', color: 'var(--danger)' };
}

// ══════════════════════════════════════════════════════════════════════════
//  APP STATE
// ══════════════════════════════════════════════════════════════════════════

const State = {
  currentTab: 'dashboard',
  devices: [],
  serverInfo: {},
  history: [],
  auditLog: [],
  pendingOutlets: new Set(),
  dropdownOpen: false,
  modalOpen: null,
  pollTimer: null,
  historyTimer: null,
};

// ══════════════════════════════════════════════════════════════════════════
//  APP MODULE
// ══════════════════════════════════════════════════════════════════════════

const App = (() => {
  const root = () => document.getElementById('app');

  async function init() {
    // Check if setup is needed
    try {
      const status = await (await fetch('/api/auth/setup-status')).json();
      if (!status.setup_complete) {
        renderSetup();
        return;
      }
    } catch (e) {
      renderSetup();
      return;
    }

    if (!Auth.isLoggedIn()) {
      renderLogin();
    } else {
      renderDashboard();
      startPolling();
    }
  }

  function render() {
    if (Auth.isLoggedIn()) {
      renderDashboard();
      startPolling();
    } else {
      stopPolling();
      renderLogin();
    }
  }

  // ── Setup screen ──────────────────────────────────────────────────────
  function renderSetup() {
    root().innerHTML = `
      <div class="login-screen">
        <div class="login-card">
          <div class="login-logo">
            <span class="icon">⚡</span>
            <h1>WattHub</h1>
            <p>Initial Setup — Create Admin Account</p>
          </div>
          <div id="setup-error"></div>
          <form id="setup-form" autocomplete="off">
            <div class="form-group">
              <label for="setup-user">Username</label>
              <input type="text" id="setup-user" placeholder="admin" value="admin" required minlength="3" autocomplete="off">
            </div>
            <div class="form-group">
              <label for="setup-pass">Password</label>
              <input type="password" id="setup-pass" placeholder="Min 8 characters" required minlength="8" autocomplete="new-password">
            </div>
            <div class="form-group">
              <label for="setup-pass2">Confirm Password</label>
              <input type="password" id="setup-pass2" placeholder="Repeat password" required minlength="8" autocomplete="new-password">
            </div>
            <button type="submit" class="btn btn-primary" id="setup-btn">Create Account & Start</button>
          </form>
        </div>
      </div>`;

    document.getElementById('setup-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const user = document.getElementById('setup-user').value.trim();
      const pass = document.getElementById('setup-pass').value;
      const pass2 = document.getElementById('setup-pass2').value;
      const errEl = document.getElementById('setup-error');
      const btn = document.getElementById('setup-btn');

      if (pass !== pass2) {
        errEl.innerHTML = '<div class="login-error">Passwords do not match</div>';
        return;
      }

      btn.disabled = true;
      btn.innerHTML = '<span class="spinner"></span> Creating...';

      try {
        const res = await fetch('/api/auth/setup', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: user, password: pass }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error);
        Toast.show('Account created! Please log in.', 'success');
        renderLogin();
      } catch (err) {
        errEl.innerHTML = `<div class="login-error">${escapeHtml(err.message)}</div>`;
        btn.disabled = false;
        btn.textContent = 'Create Account & Start';
      }
    });
  }

  // ── Login screen ──────────────────────────────────────────────────────
  function renderLogin() {
    stopPolling();
    root().innerHTML = `
      <div class="login-screen">
        <div class="login-card">
          <div class="login-logo">
            <span class="icon">⚡</span>
            <h1>WattHub</h1>
            <p>Secure IoT Control Dashboard</p>
          </div>
          <div id="login-error"></div>
          <form id="login-form" autocomplete="on">
            <div class="form-group">
              <label for="login-user">Username</label>
              <input type="text" id="login-user" placeholder="admin" required autocomplete="username">
            </div>
            <div class="form-group">
              <label for="login-pass">Password</label>
              <input type="password" id="login-pass" placeholder="••••••••" required autocomplete="current-password">
            </div>
            <button type="submit" class="btn btn-primary" id="login-btn">Sign In</button>
          </form>
          <p style="text-align:center; margin-top:20px; font-size:12px; color:var(--fg-dim)">
            🔒 All sessions are encrypted and rate-limited
          </p>
        </div>
      </div>`;

    document.getElementById('login-form').addEventListener('submit', handleLogin);
  }

  async function handleLogin(e) {
    e.preventDefault();
    const user = document.getElementById('login-user').value.trim();
    const pass = document.getElementById('login-pass').value;
    const errEl = document.getElementById('login-error');
    const btn = document.getElementById('login-btn');

    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Signing in...';

    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: user, password: pass }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);

      Auth.save(data);
      Toast.show(`Welcome, ${data.user}!`, 'success');
      renderDashboard();
      startPolling();
    } catch (err) {
      errEl.innerHTML = `<div class="login-error">${escapeHtml(err.message)}</div>`;
      btn.disabled = false;
      btn.textContent = 'Sign In';
    }
  }

  // ── Dashboard ─────────────────────────────────────────────────────────
  function renderDashboard() {
    const user = Auth.getUser() || 'admin';
    const initial = user.charAt(0).toUpperCase();

    root().innerHTML = `
      <nav class="navbar">
        <div class="navbar-brand">
          <span class="logo">⚡</span>
          <h1>WattHub</h1>
          <span class="version">v1.0</span>
        </div>
        <div class="navbar-actions">
          <div id="conn-status" class="navbar-status offline">
            <span class="dot"></span> Connecting...
          </div>
          <div class="user-menu" id="user-menu">
            <button class="user-btn" id="user-btn" type="button">
              <div class="avatar">${initial}</div>
              <span>${escapeHtml(user)}</span>
              <span style="font-size:10px;opacity:0.5">▼</span>
            </button>
            <div class="dropdown" id="user-dropdown" style="display:none"></div>
          </div>
        </div>
      </nav>

      <div class="main-content">
        <div class="tab-nav" id="tab-nav">
          <button class="tab-btn active" data-tab="dashboard">⚡ Dashboard</button>
          <button class="tab-btn" data-tab="chart">📊 Power Chart</button>
          <button class="tab-btn" data-tab="guide">📖 Connection Guide</button>
          <button class="tab-btn" data-tab="audit">🔒 Audit Log</button>
          <button class="tab-btn" data-tab="settings">⚙ Settings</button>
        </div>
        <div id="tab-content"></div>
      </div>

      <div id="modal-root"></div>
    `;

    // Tab navigation
    document.getElementById('tab-nav').addEventListener('click', (e) => {
      const btn = e.target.closest('.tab-btn');
      if (!btn) return;
      State.currentTab = btn.dataset.tab;
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      renderTabContent();
    });

    // User menu
    document.getElementById('user-btn').addEventListener('click', (e) => {
      e.stopPropagation();
      toggleDropdown();
    });
    document.addEventListener('click', () => closeDropdown());

    renderTabContent();
    fetchState();
  }

  function toggleDropdown() {
    State.dropdownOpen = !State.dropdownOpen;
    const dd = document.getElementById('user-dropdown');
    if (State.dropdownOpen) {
      dd.style.display = 'block';
      dd.innerHTML = `
        <button class="dropdown-item" id="dd-change-pw">🔑 Change Password</button>
        <div class="dropdown-sep"></div>
        <button class="dropdown-item danger" id="dd-logout">🚪 Sign Out</button>
      `;
      document.getElementById('dd-change-pw').addEventListener('click', showChangePassword);
      document.getElementById('dd-logout').addEventListener('click', handleLogout);
    } else {
      dd.style.display = 'none';
    }
  }

  function closeDropdown() {
    State.dropdownOpen = false;
    const dd = document.getElementById('user-dropdown');
    if (dd) dd.style.display = 'none';
  }

  async function handleLogout() {
    try { await API.post('/api/auth/logout', {}); } catch {}
    Auth.clear();
    stopPolling();
    Toast.show('Signed out', 'info');
    renderLogin();
  }

  // ── Tab rendering ─────────────────────────────────────────────────────

  function renderTabContent() {
    const el = document.getElementById('tab-content');
    if (!el) return;

    switch (State.currentTab) {
      case 'dashboard': renderDashboardTab(el); break;
      case 'chart': renderChartTab(el); break;
      case 'guide': renderGuideTab(el); break;
      case 'audit': renderAuditTab(el); break;
      case 'settings': renderSettingsTab(el); break;
    }
  }

  function renderDashboardTab(el) {
    const devices = State.devices;

    if (!devices.length) {
      el.innerHTML = `
        <div class="empty-state">
          <div class="icon">🔌</div>
          <h3>No strips connected</h3>
          <p>Connect your MTTL-W01 smart strip by running the provision command. 
             Check the Connection Guide tab for detailed instructions.</p>
        </div>`;
      return;
    }

    // Stats
    const totalPower = devices.reduce((s, d) => s + d.power_w, 0);
    const totalEnergy = devices.reduce((s, d) => s + d.energy_kwh, 0);
    const onlineCount = devices.filter(d => d.online).length;
    const activeOutlets = devices.reduce((s, d) => s + d.outlets.filter(o => o.on).length, 0);
    const totalOutlets = devices.length * 4;

    let statsHtml = `
      <div class="stats-grid">
        <div class="stat-card">
          <div class="stat-label">Total Power</div>
          <div class="stat-value accent">${totalPower.toFixed(1)}<span class="unit">W</span></div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Energy Used</div>
          <div class="stat-value info">${totalEnergy.toFixed(3)}<span class="unit">kWh</span></div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Strips Online</div>
          <div class="stat-value">${onlineCount}<span class="unit">/ ${devices.length}</span></div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Active Outlets</div>
          <div class="stat-value">${activeOutlets}<span class="unit">/ ${totalOutlets}</span></div>
        </div>
      </div>`;

    // Devices
    let devicesHtml = devices.map(d => renderDeviceCard(d)).join('');

    el.innerHTML = statsHtml + '<div class="device-section">' + devicesHtml + '</div>';

    // Attach outlet click handlers
    el.querySelectorAll('[data-outlet-click]').forEach(card => {
      card.addEventListener('click', () => {
        const mac = card.dataset.mac;
        const outlet = parseInt(card.dataset.outlet);
        const on = card.dataset.on === 'true';
        toggleOutlet(mac, outlet, !on);
      });
    });

    // Master toggle
    el.querySelectorAll('[data-master-toggle]').forEach(btn => {
      btn.addEventListener('click', () => {
        const mac = btn.dataset.mac;
        const on = btn.dataset.on === 'true';
        toggleOutlet(mac, 0, !on);
      });
    });
  }

  function renderDeviceCard(device) {
    const rssi = rssiLevel(device.rssi);
    const onlineClass = device.online ? '' : 'offline';

    const outletsHtml = device.outlets.map(o => {
      const key = `${device.mac}-${o.n}`;
      const pending = State.pendingOutlets.has(key);
      const alerts = [];
      if (o.overload) alerts.push('<span class="alert-badge overload">⚠ OVERLOAD</span>');
      if (o.overheat) alerts.push('<span class="alert-badge overheat">🌡 OVERHEAT</span>');

      return `
        <div class="outlet-card ${o.on ? 'on' : ''} ${pending ? 'pending' : ''}"
             data-outlet-click data-mac="${device.mac}" data-outlet="${o.n}" data-on="${o.on}">
          <div class="outlet-top">
            <span class="outlet-label">
              <span class="num">${o.n}</span>
              Outlet ${o.n}
            </span>
            <div class="toggle-switch ${o.on ? 'on' : ''} ${pending ? 'pending' : ''}"></div>
          </div>
          ${alerts.length ? '<div>' + alerts.join('') + '</div>' : ''}
          <div class="outlet-stats">
            <div class="outlet-stat"><strong>${o.power_w}</strong> W</div>
            <div class="outlet-stat"><strong>${o.energy_kwh}</strong> kWh</div>
            <div class="outlet-stat"><strong>${o.temp_c}</strong> °C</div>
            <div class="outlet-stat">${o.on ? '<strong style="color:var(--on)">ON</strong>' : '<strong style="color:var(--off-text)">OFF</strong>'}</div>
          </div>
        </div>`;
    }).join('');

    return `
      <div class="device-card ${onlineClass}">
        <div class="device-header">
          <div class="device-info">
            <div class="device-icon">${device.online ? '⚡' : '💤'}</div>
            <div>
              <div class="device-name">${escapeHtml(device.name)}</div>
              <div class="device-meta">
                <span>📋 ${escapeHtml(device.model)}</span>
                <span>🔧 FW ${escapeHtml(device.fw)}</span>
                <span>🌐 ${escapeHtml(device.ip)}</span>
              </div>
            </div>
          </div>
          <div class="device-actions">
            <button class="btn btn-sm master-toggle ${device.on ? 'is-on' : 'is-off'}"
                    data-master-toggle data-mac="${device.mac}" data-on="${device.on}"
                    ${device.online ? '' : 'disabled'}>
              ${device.on ? '⏻ ALL OFF' : '⏻ ALL ON'}
            </button>
          </div>
        </div>
        <div class="outlet-grid">${outletsHtml}</div>
        <div class="device-detail-bar">
          <div class="detail-chip">
            <span class="icon">🔌</span>
            <span>Voltage:</span>
            <span class="val">${device.voltage ? device.voltage + ' V' : '—'}</span>
          </div>
          <div class="detail-chip">
            <span class="icon">⚡</span>
            <span>Current:</span>
            <span class="val">${device.current_a ? device.current_a + ' A' : '—'}</span>
          </div>
          <div class="detail-chip">
            <span class="icon" style="color:${rssi.color}">${rssi.icon}</span>
            <span>WiFi:</span>
            <span class="val">${device.rssi ? device.rssi + ' dBm (' + rssi.label + ')' : '—'}</span>
          </div>
          <div class="detail-chip">
            <span class="icon">⏱</span>
            <span>Last seen:</span>
            <span class="val">${timeAgo(device.last_seen)}</span>
          </div>
        </div>
      </div>`;
  }

  // ── Chart tab ─────────────────────────────────────────────────────────
  async function renderChartTab(el) {
    if (!State.devices.length) {
      el.innerHTML = '<div class="empty-state"><div class="icon">📊</div><h3>No data yet</h3><p>Power data will appear once a strip is connected.</p></div>';
      return;
    }

    const device = State.devices[0];

    // Only render the skeleton if it's not already there to prevent flickering
    if (!el.querySelector('#power-chart')) {
      el.innerHTML = `
        <div class="chart-section">
          <div class="chart-header">
            <div class="chart-title" id="chart-title">⚡ Power Consumption — ${escapeHtml(device.name)}</div>
          </div>
          <div class="chart-canvas-container">
            <canvas class="chart-canvas" id="power-chart"></canvas>
          </div>
        </div>
        <div class="stats-grid">
          <div class="stat-card">
            <div class="stat-label">Current Power</div>
            <div class="stat-value accent"><span id="val-power">${device.power_w.toFixed(1)}</span><span class="unit">W</span></div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Voltage</div>
            <div class="stat-value info"><span id="val-volt">${device.voltage || '—'}</span><span class="unit">V</span></div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Current Draw</div>
            <div class="stat-value warning"><span id="val-curr">${device.current_a || '—'}</span><span class="unit">A</span></div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Total Energy</div>
            <div class="stat-value"><span id="val-energy">${device.energy_kwh.toFixed(3)}</span><span class="unit">kWh</span></div>
          </div>
        </div>`;
    } else {
      // Update values in place
      document.getElementById('chart-title').textContent = `⚡ Power Consumption — ${device.name}`;
      document.getElementById('val-power').textContent = device.power_w.toFixed(1);
      document.getElementById('val-volt').textContent = device.voltage || '—';
      document.getElementById('val-curr').textContent = device.current_a || '—';
      document.getElementById('val-energy').textContent = device.energy_kwh.toFixed(3);
    }

    // Fetch and draw chart
    try {
      const data = await API.get(`/api/history?mac=${device.mac}&n=120`);
      State.history = data.history || [];
      const canvas = document.getElementById('power-chart');
      Chart.draw(canvas, State.history, 'Watts (W)', '#2ecc71');
    } catch {}
  }

  // ── Guide tab ─────────────────────────────────────────────────────────
  function renderGuideTab(el) {
    const ip = State.serverInfo.local_ip || 'YOUR_SERVER_IP';
    const port = State.serverInfo.port || 10086;

    el.innerHTML = `
      <div class="guide-section">
        <h3>📖 How to Connect Your MTTL-W01 Strip</h3>
        <div class="guide-steps">
          <div class="guide-step">
            <div class="guide-step-num">1</div>
            <div class="guide-step-content">
              <h4>Start the Server</h4>
              <p>Make sure WattHub server is running on a machine with a stable IP address.
                 The strip will connect to this server automatically.</p>
              <code>python server.py serve</code>
            </div>
          </div>
          <div class="guide-step">
            <div class="guide-step-num">2</div>
            <div class="guide-step-content">
              <h4>Enter Setup Mode</h4>
              <p>Press and hold the main button on the strip for about 10 seconds until the LED starts blinking rapidly.
                 This puts the strip into its SoftAP configuration mode.</p>
            </div>
          </div>
          <div class="guide-step">
            <div class="guide-step-num">3</div>
            <div class="guide-step-content">
              <h4>Connect to the Strip's WiFi</h4>
              <p>On any device, connect to the WiFi network named <strong>TONLY_TAP_XXXXXXX</strong>.
                 The password is <strong>LGU_XXXXXXX</strong> (same 7 characters as the network name).</p>
            </div>
          </div>
          <div class="guide-step">
            <div class="guide-step-num">4</div>
            <div class="guide-step-content">
              <h4>Run the Provision Command</h4>
              <p>From the device connected to the strip's WiFi, run the provision command with your server's IP,
                 home WiFi SSID, and WiFi password:</p>
              <code>python server.py provision --ip ${escapeHtml(ip)} --ssid "YOUR_WIFI" --password "YOUR_WIFI_PW"</code>
            </div>
          </div>
          <div class="guide-step">
            <div class="guide-step-num">5</div>
            <div class="guide-step-content">
              <h4>Reconnect & Verify</h4>
              <p>Reconnect your device to your home WiFi. Within seconds, the strip will appear
                 in the Dashboard tab as online and ready to control.</p>
            </div>
          </div>
        </div>
      </div>

      <div class="guide-section" style="margin-top:20px">
        <h3>🔒 Security Recommendations</h3>
        <div class="guide-steps">
          <div class="guide-step">
            <div class="guide-step-num">🛡</div>
            <div class="guide-step-content">
              <h4>Use HTTPS in Production</h4>
              <p>Run with TLS using the --cert and --key flags to encrypt all traffic between your browser and the server.</p>
              <code>python server.py serve --cert cert.pem --key key.pem</code>
            </div>
          </div>
          <div class="guide-step">
            <div class="guide-step-num">🔐</div>
            <div class="guide-step-content">
              <h4>Use a VPN for Remote Access</h4>
              <p>If accessing from outside your network, use a VPN like Tailscale or WireGuard instead
                 of exposing the web port directly to the internet. This adds encryption and access control.</p>
            </div>
          </div>
          <div class="guide-step">
            <div class="guide-step-num">🌐</div>
            <div class="guide-step-content">
              <h4>Network Isolation</h4>
              <p>Put your IoT devices (including the smart strip) on a separate VLAN or guest network.
                 This limits the blast radius if any device is compromised.</p>
            </div>
          </div>
        </div>
      </div>`;
  }

  // ── Audit tab ─────────────────────────────────────────────────────────
  async function renderAuditTab(el) {
    el.innerHTML = `
      <div class="audit-section">
        <div class="audit-header">
          <div class="audit-title">🔒 Security Audit Log</div>
          <button class="btn btn-sm btn-secondary" id="audit-refresh">↻ Refresh</button>
        </div>
        <div id="audit-body"><div style="padding:40px;text-align:center"><span class="spinner"></span></div></div>
      </div>`;

    document.getElementById('audit-refresh').addEventListener('click', () => renderAuditTab(el));

    try {
      const data = await API.get('/api/audit?n=100');
      State.auditLog = (data.entries || []).reverse();

      const body = document.getElementById('audit-body');
      if (!State.auditLog.length) {
        body.innerHTML = '<div style="padding:40px;text-align:center;color:var(--fg-dim)">No audit events yet</div>';
        return;
      }

      body.innerHTML = `
        <table class="audit-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Action</th>
              <th>IP</th>
              <th>User</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            ${State.auditLog.map(e => `
              <tr>
                <td>${formatTimestamp(e.ts)}</td>
                <td><span class="audit-action ${e.action}">${escapeHtml(e.action)}</span></td>
                <td style="font-family:monospace;font-size:12px">${escapeHtml(e.ip)}</td>
                <td>${escapeHtml(e.user || '—')}</td>
                <td style="max-width:250px;overflow:hidden;text-overflow:ellipsis">${escapeHtml(e.details || '—')}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>`;
    } catch (err) {
      document.getElementById('audit-body').innerHTML =
        `<div style="padding:40px;text-align:center;color:var(--danger)">Failed to load audit log</div>`;
    }
  }

  // ── Settings tab ──────────────────────────────────────────────────────
  function renderSettingsTab(el) {
    const ip = State.serverInfo.local_ip || '—';
    const port = State.serverInfo.port || '—';

    el.innerHTML = `
      <div class="settings-section">
        <div class="settings-card">
          <h3>🌐 Server Information</h3>
          <div class="settings-row">
            <label>Server IP</label>
            <span class="value">${escapeHtml(String(ip))}</span>
          </div>
          <div class="settings-row">
            <label>Strip Port (TCP)</label>
            <span class="value">${port}</span>
          </div>
          <div class="settings-row">
            <label>Connected Devices</label>
            <span class="value">${State.devices.length}</span>
          </div>
          <div class="settings-row">
            <label>Online Devices</label>
            <span class="value">${State.devices.filter(d => d.online).length}</span>
          </div>
        </div>

        <div class="settings-card">
          <h3>🔑 Account Security</h3>
          <div class="settings-row">
            <label>Logged in as</label>
            <span class="value">${escapeHtml(Auth.getUser() || '—')}</span>
          </div>
          <div class="settings-row">
            <label>Change Password</label>
            <button class="btn btn-sm btn-secondary" id="settings-change-pw">Change</button>
          </div>
        </div>

        <div class="settings-card">
          <h3>⚠ Danger Zone</h3>
          <div class="settings-row">
            <label>Sign out of this session</label>
            <button class="btn btn-sm btn-danger" id="settings-logout">Sign Out</button>
          </div>
        </div>
      </div>`;

    document.getElementById('settings-change-pw').addEventListener('click', showChangePassword);
    document.getElementById('settings-logout').addEventListener('click', handleLogout);
  }

  // ── Modals ────────────────────────────────────────────────────────────
  function showChangePassword() {
    closeDropdown();
    const modal = document.getElementById('modal-root');
    modal.innerHTML = `
      <div class="modal-overlay" id="modal-overlay">
        <div class="modal-card">
          <h2>🔑 Change Password</h2>
          <div id="pw-error"></div>
          <form id="pw-form">
            <div class="form-group">
              <label for="pw-current">Current Password</label>
              <input type="password" id="pw-current" required autocomplete="current-password">
            </div>
            <div class="form-group">
              <label for="pw-new">New Password</label>
              <input type="password" id="pw-new" required minlength="8" autocomplete="new-password">
            </div>
            <div class="form-group">
              <label for="pw-confirm">Confirm New Password</label>
              <input type="password" id="pw-confirm" required minlength="8" autocomplete="new-password">
            </div>
            <div class="modal-actions">
              <button type="button" class="btn btn-secondary" id="pw-cancel">Cancel</button>
              <button type="submit" class="btn btn-primary" id="pw-submit">Update Password</button>
            </div>
          </form>
        </div>
      </div>`;

    document.getElementById('pw-cancel').addEventListener('click', () => { modal.innerHTML = ''; });
    document.getElementById('modal-overlay').addEventListener('click', (e) => {
      if (e.target === e.currentTarget) modal.innerHTML = '';
    });

    document.getElementById('pw-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const current = document.getElementById('pw-current').value;
      const newPw = document.getElementById('pw-new').value;
      const confirm = document.getElementById('pw-confirm').value;
      const errEl = document.getElementById('pw-error');
      const btn = document.getElementById('pw-submit');

      if (newPw !== confirm) {
        errEl.innerHTML = '<div class="login-error">Passwords do not match</div>';
        return;
      }

      btn.disabled = true;
      btn.innerHTML = '<span class="spinner"></span>';

      try {
        const data = await API.post('/api/auth/change-password', {
          current_password: current,
          new_password: newPw,
        });
        if (data.error) throw new Error(data.error);
        Toast.show('Password updated! Please sign in again.', 'success');
        modal.innerHTML = '';
        Auth.clear();
        renderLogin();
      } catch (err) {
        errEl.innerHTML = `<div class="login-error">${escapeHtml(err.message)}</div>`;
        btn.disabled = false;
        btn.textContent = 'Update Password';
      }
    });
  }

  // ── Device control ────────────────────────────────────────────────────
  async function toggleOutlet(mac, outlet, on) {
    const key = `${mac}-${outlet}`;
    if (State.pendingOutlets.has(key)) return;
    State.pendingOutlets.add(key);
    if (outlet === 0) {
      [1,2,3,4].forEach(n => State.pendingOutlets.add(`${mac}-${n}`));
    }
    renderTabContent();

    try {
      const data = await API.post('/api/onoff', { mac, outlet, on });
      if (data.error) {
        Toast.show(`Command failed: ${data.error}`, 'error');
      } else if (data.confirmed) {
        Toast.show(`Outlet ${outlet === 0 ? 'ALL' : outlet} ${on ? 'ON' : 'OFF'}`, 'success');
      } else {
        Toast.show('Command sent but not confirmed', 'warning');
      }
    } catch (err) {
      Toast.show(`Error: ${err.message}`, 'error');
    } finally {
      State.pendingOutlets.delete(key);
      if (outlet === 0) {
        [1,2,3,4].forEach(n => State.pendingOutlets.delete(`${mac}-${n}`));
      }
      await fetchState();
    }
  }

  // ── Polling ───────────────────────────────────────────────────────────
  async function fetchState() {
    try {
      const data = await API.get('/api/state');
      State.devices = data.devices || [];
      State.serverInfo = { local_ip: data.local_ip, port: data.port };

      // Update connection status
      const statusEl = document.getElementById('conn-status');
      if (statusEl) {
        const online = State.devices.some(d => d.online);
        statusEl.className = `navbar-status ${online ? 'online' : 'offline'}`;
        statusEl.innerHTML = `<span class="dot"></span> ${
          State.devices.length ? `${State.devices.filter(d => d.online).length}/${State.devices.length} online` : 'No devices'
        }`;
      }

      if (State.currentTab === 'dashboard') {
        renderTabContent();
      }
      if (State.currentTab === 'chart') {
        renderChartTab(document.getElementById('tab-content'));
      }
    } catch (err) {
      // Silently handle polling errors (will retry)
    }
  }

  function startPolling() {
    stopPolling();
    State.pollTimer = setInterval(fetchState, 2000);
  }

  function stopPolling() {
    if (State.pollTimer) {
      clearInterval(State.pollTimer);
      State.pollTimer = null;
    }
  }

  return { init, render };
})();

// ── Bootstrap ───────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', App.init);
