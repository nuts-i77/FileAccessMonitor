'use strict';

// ── i18n ─────────────────────────────────────────────────────────
function getLang() {
  return localStorage.getItem('lang') || (navigator.language?.startsWith('ja') ? 'ja' : 'en');
}

function t(key, vars) {
  const dict = getLang() === 'en' ? window.I18N_EN : window.I18N_JA;
  let str = dict?.[key] ?? key;
  if (vars) Object.entries(vars).forEach(([k, v]) => { str = str.replace(`{${k}}`, v); });
  return str;
}

function applyI18n() {
  document.documentElement.lang = getLang() === 'en' ? 'en' : 'ja';
  document.querySelectorAll('[data-i18n]').forEach(el => { el.innerHTML = t(el.dataset.i18n); });
  document.querySelectorAll('[data-i18n-ph]').forEach(el => { el.placeholder = t(el.dataset.i18nPh); });
  document.querySelectorAll('[data-i18n-title]').forEach(el => { el.title = t(el.dataset.i18nTitle); });
  const btn = document.getElementById('langToggleBtn');
  if (btn) btn.textContent = getLang() === 'en' ? 'JA' : 'EN';
}

function toggleLang() {
  localStorage.setItem('lang', getLang() === 'ja' ? 'en' : 'ja');
  location.reload();
}

// ── Auth ──────────────────────────────────────────────────────────
function getToken() { return localStorage.getItem('jwt_token'); }

// API error/success messages are returned in the GUI language.
function authHeaders() {
  return { 'Authorization': `Bearer ${getToken()}`, 'Accept-Language': getLang() };
}

function getUser() {
  try { return JSON.parse(localStorage.getItem('jwt_user') || 'null'); } catch { return null; }
}

function isTokenValid() {
  const tok = getToken();
  if (!tok) return false;
  try {
    const payload = JSON.parse(atob(tok.split('.')[1]));
    return payload.exp * 1000 > Date.now();
  } catch { return false; }
}

function logout() {
  localStorage.removeItem('jwt_token');
  localStorage.removeItem('jwt_user');
  location.replace('/login.html');
}

// Redirect to login if not authenticated
if (!isTokenValid()) {
  location.replace('/login.html');
}

let timelineChart, typeChart, topFilesChart, topFoldersChart;
let currentTab = 'dashboard';
let autoReloadTimer = null;
let countdownTimer = null;
let countdownLeft = 0;
let recentPage = 1;
let searchPage = 1;
const PAGE_SIZE = 50;
let searchKeywords = [];
let searchPeriod = { mode: 'days', days: 7, from: '', to: '' };

const TYPE_COLORS = {
  Read:   '#0d6efd',
  Write:  '#198754',
  Delete: '#dc3545',
  Rename: '#fd7e14',
  Create: '#20c997',
  Permission: '#6f42c1'
};

const TYPE_LABELS = new Proxy({}, {
  get: (_, k) => {
    if (k === 'Read')   return t('type.read');
    if (k === 'Write')  return t('type.write');
    if (k === 'Delete') return t('type.delete');
    if (k === 'Rename') return t('type.rename');
    if (k === 'Create') return t('type.create');
    if (k === 'Permission') return t('type.permission');
    return typeof k === 'string' ? k : undefined;
  }
});

function getDays() {
  return parseInt(document.getElementById('daysFilter').value, 10);
}

async function api(path, options = {}) {
  const headers = { ...(options.headers || {}), ...authHeaders() };
  // Statistics follow the server filter (except the list of servers itself)
  if (path.startsWith('/api/stats/') && !path.startsWith('/api/stats/servers') && !/[?&]server=/.test(path) && serverParam())
    path += (path.includes('?') ? '&' : '?') + serverParam();
  const res = await fetch(path, { ...options, headers });
  if (res.status === 401) { logout(); throw new Error('Unauthorized'); }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data?.error || `HTTP ${res.status}`);
  return data;
}

function fmtNum(n) {
  return n == null ? '-' : Number(n).toLocaleString();
}

function fmtDate(s) {
  if (!s) return '-';
  const utc = /[Z+]/.test(s) ? s : s + 'Z';
  const d = new Date(utc);
  const locale = getLang() === 'en' ? 'en-US' : 'ja-JP';
  return d.toLocaleString(locale, {
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit' });
}

// UTC timestamp -> "YYYY-MM-DD" in the browser's local time zone
function localDay(s) {
  const d = new Date(/[Z+]/.test(s) ? s : s + 'Z');
  const pad = n => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

// Folders appear only when deleted or renamed
function itemIcon(isFolder) {
  return isFolder
    ? `<i class="bi bi-folder-fill text-warning me-1" title="${t('kind.folder')}"></i>`
    : `<i class="bi bi-file-earmark text-muted me-1"></i>`;
}

function typeBadge(type) {
  const cls = { Read: 'primary', Write: 'success', Delete: 'danger', Rename: 'warning text-dark' };
  // Create and Permission have their own colours (style.css)
  if (type === 'Create' || type === 'Permission')
    return `<span class="badge badge-${type.toLowerCase()}">${TYPE_LABELS[type]}</span>`;
  // a type this browser does not know (from a newer server) is shown as it is
  return `<span class="badge bg-${cls[type] || 'secondary'}">${TYPE_LABELS[type] || esc(type)}</span>`;
}

// The type cell of a log row: the type, a red "Denied" badge for a refused attempt, and a button
// for the details of a permission change
function recordTypeHtml(r) {
  let html = typeBadge(r.accessType);
  if (r.denied) html += ` <span class="badge bg-danger">${t('badge.denied')}</span>`;
  // permissions Windows set when the file was created (a copy): not a change by a user
  if (r.atCreation && r.accessType === 'Permission')
    html += ` <span class="badge bg-secondary-subtle text-secondary-emphasis fw-normal" title="${esc(t('badge.atCreationTip'))}">${esc(t('badge.atCreation'))}</span>`;
  if (r.detail)
    html += ` <button type="button" class="btn btn-link btn-sm p-0 align-baseline record-detail-btn" data-detail="${esc(r.detail)}" title="${esc(t('btn.detail'))}" onclick="showRecordDetail(this)"><i class="bi bi-info-circle"></i></button>`;
  return html;
}

// The file name; for a rename or move, where the file went, too (full paths in the tooltip)
function recordNameHtml(r) {
  const title = r.newPath ? `${r.filePath} -> ${r.newPath}` : r.filePath;
  const moved = r.newPath
    ? `<div class="small text-muted text-nowrap"><i class="bi bi-arrow-return-right me-1"></i>${esc(r.newPath)}</div>` : '';
  return `<span title="${esc(title)}">${itemIcon(r.isFolder)}${esc(r.fileName)}</span>${historyBtn(r)}${moved}`;
}

// The file history button (js/history.js); r: { filePath, serverName, accessTime?, isFolder? }
function historyBtn(r) {
  return typeof historyButtonHtml === 'function' ? historyButtonHtml(r) : '';
}

function rowClass(r) {
  return r.denied ? ' class="table-danger-subtle"' : '';
}

// The detail text of a record (a permission change) in a popover: monospace, line breaks kept
function showRecordDetail(btn) {
  document.querySelectorAll('.record-detail-btn').forEach(b => {
    if (b !== btn) bootstrap.Popover.getInstance(b)?.hide();
  });
  bootstrap.Popover.getOrCreateInstance(btn, {
    content: btn.dataset.detail, trigger: 'manual', placement: 'left', container: 'body',
    customClass: 'record-detail', html: false
  }).toggle();
}
document.addEventListener('click', e => {
  if (e.target.closest('.record-detail-btn, .record-detail')) return;
  document.querySelectorAll('.record-detail-btn').forEach(b => bootstrap.Popover.getInstance(b)?.hide());
});

// ── Summary Cards ─────────────────────────────────────────────────
async function loadSummary() {
  const d = await api(`/api/stats/summary?days=${getDays()}`);
  document.getElementById('totalCount').textContent = fmtNum(d.total);
  document.getElementById('uniqueFiles').textContent = fmtNum(d.uniqueFiles);
  document.getElementById('uniqueUsers').textContent = fmtNum(d.uniqueUsers);
  document.getElementById('deniedCount').textContent = fmtNum(d.denied);
  const badges = (d.byType || []).map(tp =>
    `<span class="badge me-1" style="background:${TYPE_COLORS[tp.type] || '#6c757d'}">${TYPE_LABELS[tp.type] || tp.type}: ${fmtNum(tp.count)}</span>`
  ).join('');
  document.getElementById('accessTypesBadge').innerHTML = badges;
}

// ── Timeline Chart ────────────────────────────────────────────────
async function loadTimeline() {
  const data = await api(`/api/stats/timeline?days=${getDays()}`);

  const dates = [...new Set(data.map(d => localDay(d.date)))].sort();
  const types = ['Read', 'Write', 'Create', 'Delete', 'Rename', 'Permission'];
  const byType = {};
  types.forEach(tp => byType[tp] = {});
  data.forEach(d => {
    const date = localDay(d.date);
    if (!byType[d.accessType]) byType[d.accessType] = {};
    byType[d.accessType][date] = (byType[d.accessType][date] || 0) + d.count;
  });

  const datasets = types.map(tp => ({
    label: TYPE_LABELS[tp],
    data: dates.map(date => byType[tp][date] || 0),
    borderColor: TYPE_COLORS[tp],
    backgroundColor: TYPE_COLORS[tp] + '33',
    fill: true,
    tension: 0.3,
    pointRadius: 2
  }));

  const ctx = document.getElementById('timelineChart').getContext('2d');
  if (timelineChart) timelineChart.destroy();
  timelineChart = new Chart(ctx, {
    type: 'line',
    data: { labels: dates, datasets },
    options: {
      responsive: true,
      interaction: { mode: 'index', intersect: false },
      plugins: { legend: { position: 'top' } },
      scales: {
        x: { ticks: { maxRotation: 45 } },
        y: { beginAtZero: true, ticks: { precision: 0 } }
      }
    }
  });
}

// ── Pie Chart ─────────────────────────────────────────────────────
async function loadTypeChart() {
  const d = await api(`/api/stats/summary?days=${getDays()}`);
  const types = (d.byType || []);
  const ctx = document.getElementById('typeChart').getContext('2d');
  if (typeChart) typeChart.destroy();
  typeChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: types.map(tp => TYPE_LABELS[tp.type] || tp.type),
      datasets: [{
        data: types.map(tp => tp.count),
        backgroundColor: types.map(tp => TYPE_COLORS[tp.type] || '#6c757d')
      }]
    },
    options: {
      responsive: true,
      plugins: {
        legend: { position: 'bottom' },
        tooltip: {
          callbacks: { label: ctx => ` ${ctx.label}: ${fmtNum(ctx.parsed)}` }
        }
      }
    }
  });
}

// ── Top Files/Folders Charts ──────────────────────────────────────
async function loadTopCharts() {
  const days = getDays();
  const [files, folders] = await Promise.all([
    api(`/api/stats/top-files?limit=10&days=${days}`),
    api(`/api/stats/top-folders?limit=10&days=${days}`)
  ]);

  const ctxF = document.getElementById('topFilesChart').getContext('2d');
  if (topFilesChart) topFilesChart.destroy();
  topFilesChart = new Chart(ctxF, {
    type: 'bar',
    data: {
      labels: files.map(f => serverPath(f, f.fileName || f.filePath)),
      datasets: [
        { label: t('type.read'),   data: files.map(f => f.read),   backgroundColor: TYPE_COLORS.Read },
        { label: t('type.write'),  data: files.map(f => f.write),  backgroundColor: TYPE_COLORS.Write },
        { label: t('type.delete'), data: files.map(f => f.delete), backgroundColor: TYPE_COLORS.Delete },
        { label: t('type.create'), data: files.map(f => f.create), backgroundColor: TYPE_COLORS.Create },
        { label: t('type.rename'), data: files.map(f => f.rename), backgroundColor: TYPE_COLORS.Rename },
        { label: t('type.permission'), data: files.map(f => f.permission), backgroundColor: TYPE_COLORS.Permission }
      ]
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      plugins: { legend: { position: 'top' } },
      scales: { x: { stacked: true, ticks: { precision: 0 } }, y: { stacked: true } }
    }
  });

  const ctxD = document.getElementById('topFoldersChart').getContext('2d');
  if (topFoldersChart) topFoldersChart.destroy();
  topFoldersChart = new Chart(ctxD, {
    type: 'bar',
    data: {
      labels: folders.map(f => serverPath(f, f.folderName || f.folderPath)),
      datasets: [
        { label: t('type.read'),   data: folders.map(f => f.read),   backgroundColor: TYPE_COLORS.Read },
        { label: t('type.write'),  data: folders.map(f => f.write),  backgroundColor: TYPE_COLORS.Write },
        { label: t('type.delete'), data: folders.map(f => f.delete), backgroundColor: TYPE_COLORS.Delete },
        { label: t('type.create'), data: folders.map(f => f.create), backgroundColor: TYPE_COLORS.Create },
        { label: t('type.rename'), data: folders.map(f => f.rename), backgroundColor: TYPE_COLORS.Rename },
        { label: t('type.permission'), data: folders.map(f => f.permission), backgroundColor: TYPE_COLORS.Permission }
      ]
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      plugins: { legend: { position: 'top' } },
      scales: { x: { stacked: true, ticks: { precision: 0 } }, y: { stacked: true } }
    }
  });
}

// ── Files Table ───────────────────────────────────────────────────
async function loadFiles() {
  const typeFilter = document.getElementById('fileTypeFilter').value;
  const url = `/api/stats/top-files?limit=200&days=${getDays()}${typeFilter ? '&accessType=' + typeFilter : ''}`;
  const data = await api(url);
  const maxTotal = Math.max(...data.map(f => f.total), 1);

  const tbody = document.getElementById('filesTableBody');
  tbody.innerHTML = data.map((f, i) => `
    <tr>
      <td>${i + 1}</td>
      <td><i class="bi bi-file-earmark text-muted me-1"></i>${esc(f.fileName)}</td>
      <td class="col-server">${esc(f.serverName || '')}</td>
      <td class="path-cell text-muted" title="${esc(f.filePath)}">${esc(f.filePath)}</td>
      <td class="text-end">
        <div class="d-flex align-items-center gap-2 justify-content-end">
          <span>${fmtNum(f.total)}</span>
          <div class="access-bar"><div class="access-bar-fill" style="width:${(f.total/maxTotal*100).toFixed(1)}%"></div></div>
        </div>
      </td>
      <td class="text-end text-primary">${fmtNum(f.read)}</td>
      <td class="text-end text-success">${fmtNum((f.write || 0) + (f.create || 0))}</td>
      <td class="text-end text-danger">${fmtNum(f.delete)}</td>
      <td class="text-end" style="color:#fd7e14">${fmtNum(f.rename)}</td>
      <td>${fmtDate(f.lastAccess)}</td>
      <td><span class="text-truncate d-inline-block" style="max-width:120px" title="${esc(f.topUser || '')}">${esc(f.topUser || '-')}</span></td>
      <td class="text-nowrap"><button class="btn btn-sm btn-outline-secondary py-0" data-path="${esc(f.filePath)}" data-server="${esc(f.serverName || '')}" onclick="showFileDetail(this.dataset.path, this.dataset.server)">${t('btn.detail')}</button>${historyBtn({ filePath: f.filePath, serverName: f.serverName || '' })}</td>
    </tr>`).join('');
}

// ── Folders Table ─────────────────────────────────────────────────
async function loadFolders() {
  const data = await api(`/api/stats/top-folders?limit=200&days=${getDays()}`);
  const maxTotal = Math.max(...data.map(f => f.total), 1);

  const tbody = document.getElementById('foldersTableBody');
  tbody.innerHTML = data.map((f, i) => `
    <tr>
      <td>${i + 1}</td>
      <td><i class="bi bi-folder-fill text-warning me-1"></i>${esc(f.folderName || f.folderPath)}</td>
      <td class="col-server">${esc(f.serverName || '')}</td>
      <td class="path-cell text-muted" title="${esc(f.folderPath)}">${esc(f.folderPath)}</td>
      <td class="text-end">
        <div class="d-flex align-items-center gap-2 justify-content-end">
          <span>${fmtNum(f.total)}</span>
          <div class="access-bar"><div class="access-bar-fill" style="width:${(f.total/maxTotal*100).toFixed(1)}%"></div></div>
        </div>
      </td>
      <td class="text-end text-primary">${fmtNum(f.read)}</td>
      <td class="text-end text-success">${fmtNum((f.write || 0) + (f.create || 0))}</td>
      <td class="text-end text-danger">${fmtNum(f.delete)}</td>
      <td class="text-end" style="color:#fd7e14">${fmtNum(f.rename)}</td>
      <td class="text-end">${fmtNum(f.uniqueFiles)}</td>
      <td>${fmtDate(f.lastAccess)}</td>
      <td><button class="btn btn-sm btn-outline-secondary py-0" data-path="${esc(f.folderPath)}" data-server="${esc(f.serverName || '')}" onclick="showFolderDetail(this.dataset.path, this.dataset.server)">${t('btn.detail')}</button></td>
    </tr>`).join('');
}

// ── Users Table ───────────────────────────────────────────────────
async function loadUsers() {
  const data = await api(`/api/stats/top-users?limit=50&days=${getDays()}`);

  const tbody = document.getElementById('usersTableBody');
  tbody.innerHTML = data.map((u, i) => `
    <tr>
      <td>${i + 1}</td>
      <td><i class="bi bi-person me-1"></i>${esc(u.user)}</td>
      <td class="text-end fw-bold">${fmtNum(u.total)}</td>
      <td class="text-end text-primary">${fmtNum(u.read)}</td>
      <td class="text-end text-success">${fmtNum((u.write || 0) + (u.create || 0))}</td>
      <td class="text-end text-danger">${fmtNum(u.delete)}</td>
      <td class="text-end" style="color:#fd7e14">${fmtNum(u.rename)}</td>
      <td><button class="btn btn-sm btn-outline-secondary py-0" data-user="${esc(u.user)}" onclick="showUserDetail(this.dataset.user)">${t('btn.detail')}</button></td>
    </tr>`).join('');
}

async function showUserDetail(username) {
  const modal = new bootstrap.Modal(document.getElementById('detailModal'));
  document.getElementById('detailModalTitle').textContent = t('detail.userDetail') + username;
  document.getElementById('detailModalBody').innerHTML =
    '<div class="text-center py-4"><div class="spinner-border"></div></div>';
  modal.show();

  const d = await api(`/api/stats/user-detail?user=${encodeURIComponent(username)}&days=${getDays()}`);
  document.getElementById('detailModalBody').innerHTML = buildUserDetailHtml(d);
  renderDetailCharts(d);
}

function buildUserDetailHtml(d) {
  const typeRows = (d.byType || []).map(tp =>
    `<tr><td>${typeBadge(tp.type)}</td><td class="text-end">${fmtNum(tp.count)}</td></tr>`
  ).join('');

  const fileRows = (d.topFiles || []).map((f, i) => `
    <tr>
      <td>${i + 1}</td>
      <td title="${esc(f.filePath)}">${esc(f.fileName)}</td>
      <td class="col-server">${esc(f.serverName || '')}</td>
      <td class="text-end fw-bold">${fmtNum(f.total)}</td>
      <td class="text-end text-primary">${fmtNum(f.read)}</td>
      <td class="text-end text-success">${fmtNum((f.write || 0) + (f.create || 0))}</td>
      <td class="text-end text-danger">${fmtNum(f.delete)}</td>
      <td class="text-end" style="color:#fd7e14">${fmtNum(f.rename)}</td>
      <td class="text-muted small">${fmtDate(f.lastAccess)}</td>
    </tr>`).join('');

  const recentRows = (d.recent || []).map(r =>
    `<tr>
      <td class="text-muted">${fmtDate(r.accessTime)}</td>
      <td title="${esc(r.filePath)}">${recordNameHtml(r)}</td>
      <td class="col-server">${esc(r.serverName || '')}</td>
      <td>${recordTypeHtml(r)}</td>
    </tr>`).join('');

  const noData = `<tr><td colspan="4" class="text-muted text-center">${t('msg.noData')}</td></tr>`;

  return `
    <div class="row g-3">
      <div class="col-12">
        <canvas id="detailTimelineChart" height="80"></canvas>
      </div>
      <div class="col-12 col-md-4">
        <div class="detail-section-title"><i class="bi bi-tags me-1"></i>${t('detail.byType')}</div>
        <table class="table table-sm">
          <thead><tr><th>${t('th.type')}</th><th class="text-end">${t('detail.count')}</th></tr></thead>
          <tbody>${typeRows || noData}</tbody>
        </table>
        <div class="mt-2"><canvas id="detailTypeChart" height="120"></canvas></div>
        <div class="col-server mt-3">
          <div class="detail-section-title"><i class="bi bi-hdd me-1"></i>${t('detail.byServer')}</div>
          <table class="table table-sm">
            <thead><tr><th>${t('th.server')}</th><th class="text-end">${t('detail.count')}</th></tr></thead>
            <tbody>${(d.byServer || []).map(s =>
              `<tr><td>${esc(s.server)}</td><td class="text-end">${fmtNum(s.count)}</td></tr>`).join('') || noData}</tbody>
          </table>
        </div>
      </div>
      <div class="col-12 col-md-8">
        <div class="detail-section-title"><i class="bi bi-file-earmark me-1"></i>${t('detail.fileList')}</div>
        <div style="max-height:300px;overflow-y:auto">
          <table class="table table-sm table-hover">
            <thead class="table-light sticky-top">
              <tr><th>#</th><th>${t('th.filename')}</th><th class="col-server">${t('th.server')}</th><th class="text-end">${t('th.total')}</th><th class="text-end">${t('th.read')}</th><th class="text-end">${t('th.write')}</th><th class="text-end">${t('th.delete')}</th><th class="text-end">${t('th.rename')}</th><th>${t('th.lastAccess')}</th></tr>
            </thead>
            <tbody>${fileRows || `<tr><td colspan="9" class="text-muted text-center">${t('msg.noData')}</td></tr>`}</tbody>
          </table>
        </div>
      </div>
      <div class="col-12">
        <div class="detail-section-title"><i class="bi bi-clock-history me-1"></i>${t('detail.recent')}</div>
        <table class="table table-sm">
          <thead><tr><th>${t('th.datetime')}</th><th>${t('th.filename')}</th><th class="col-server">${t('th.server')}</th><th>${t('th.type')}</th></tr></thead>
          <tbody>${recentRows || noData}</tbody>
        </table>
      </div>
    </div>`;
}

// ── Pagination ────────────────────────────────────────────────────
function buildPageRange(current, total) {
  if (total <= 7) return Array.from({ length: total }, (_, i) => i + 1);
  const pages = [1];
  if (current > 3) pages.push('...');
  for (let i = Math.max(2, current - 1); i <= Math.min(total - 1, current + 1); i++) pages.push(i);
  if (current < total - 2) pages.push('...');
  pages.push(total);
  return pages;
}

function renderPagination(paginationEl, infoEl, page, total, pageSize, gotoFn) {
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const from = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const to = Math.min(page * pageSize, total);

  if (infoEl) {
    infoEl.textContent = t('pagination.info', { from: fmtNum(from), to: fmtNum(to), total: fmtNum(total) });
  }

  if (!paginationEl) return;
  if (totalPages <= 1) { paginationEl.innerHTML = ''; return; }

  const mkLi = (label, disabled, active, onClick) => {
    const li = document.createElement('li');
    li.className = `page-item${disabled ? ' disabled' : ''}${active ? ' active' : ''}`;
    const inner = document.createElement(disabled || !onClick ? 'span' : 'a');
    inner.className = 'page-link';
    if (!disabled && onClick) { inner.href = '#'; inner.addEventListener('click', e => { e.preventDefault(); onClick(); }); }
    inner.innerHTML = label;
    li.appendChild(inner);
    return li;
  };

  paginationEl.innerHTML = '';
  paginationEl.appendChild(mkLi('‹', page <= 1, false, page > 1 ? () => gotoFn(page - 1) : null));
  for (const p of buildPageRange(page, totalPages)) {
    if (p === '...') paginationEl.appendChild(mkLi('…', true, false, null));
    else paginationEl.appendChild(mkLi(p, false, p === page, p !== page ? () => gotoFn(p) : null));
  }
  paginationEl.appendChild(mkLi('›', page >= totalPages, false, page < totalPages ? () => gotoFn(page + 1) : null));
}

// ── Recent Table ──────────────────────────────────────────────────
async function loadRecent(page = 1) {
  recentPage = page;
  const denied = document.getElementById('recentResult')?.value || '';
  const data = await api(`/api/stats/recent?page=${page}&pageSize=${PAGE_SIZE}${denied ? '&denied=' + denied : ''}`);

  const tbody = document.getElementById('recentTableBody');
  tbody.innerHTML = (data.items || []).map(r => {
    const srcParts = [];
    if (r.clientIp) srcParts.push(`<span class="font-monospace">${esc(r.clientIp)}</span>`);
    if (r.clientMachine && r.clientMachine !== r.clientIp) srcParts.push(esc(r.clientMachine));
    const srcCell = srcParts.length
      ? `<td class="text-muted small">${srcParts.join('<br>')}</td>`
      : `<td class="text-muted small">-</td>`;
    return `
    <tr${rowClass(r)}>
      <td class="text-muted">${fmtDate(r.accessTime)}</td>
      <td>${recordNameHtml(r)}</td>
      <td class="col-server">${esc(r.serverName || '')}</td>
      <td class="path-cell text-muted" title="${esc(r.folderPath)}">${esc(r.folderPath)}</td>
      <td>${esc(r.userName)}</td>
      <td>${recordTypeHtml(r)}</td>
      ${srcCell}
    </tr>`;
  }).join('');

  renderPagination(
    document.getElementById('recentPagination'),
    document.getElementById('recentPaginationInfo'),
    data.page, data.total, data.pageSize,
    p => loadRecent(p)
  );
}

// ── Search Tab ────────────────────────────────────────────────────

function handleTagKeydown(e) {
  const input = e.target;
  if (e.key === 'Enter') {
    e.preventDefault();
    e.stopPropagation();
    const val = input.value.trim();
    if (val) { searchKeywords.push(val); renderSearchTags(); input.value = ''; }
  } else if (e.key === 'Backspace' && input.value === '' && searchKeywords.length > 0) {
    searchKeywords.pop();
    renderSearchTags();
  }
}

function renderSearchTags() {
  const el = document.getElementById('searchTags');
  if (!el) return;
  el.innerHTML = searchKeywords.map((kw, i) =>
    `<span class="badge bg-primary-subtle text-primary-emphasis d-inline-flex align-items-center gap-1 px-2 py-1 me-1">
      ${esc(kw)}
      <button type="button" class="btn-close" style="font-size:0.55rem" onclick="removeSearchKeyword(${i})"></button>
    </span>`
  ).join('');
}

function removeSearchKeyword(i) {
  searchKeywords.splice(i, 1);
  renderSearchTags();
}

function selectSearchPeriodQuick(days) {
  searchPeriod = { mode: 'days', days };
  document.getElementById('searchDateFrom').value = '';
  document.getElementById('searchDateTo').value = '';
  const labelMap = { 1: t('days.1'), 7: t('days.7'), 30: t('days.30'), 90: t('days.90'), 0: t('days.all') };
  document.getElementById('searchPeriodLabel').textContent = labelMap[days] ?? '';
  document.querySelectorAll('.search-period-quick').forEach(btn => {
    btn.classList.toggle('active', Number(btn.dataset.days) === days);
  });
  bootstrap.Dropdown.getInstance(document.getElementById('searchPeriodBtn'))?.hide();
}

function selectSearchPeriodCustom() {
  const from = document.getElementById('searchDateFrom').value;
  const to   = document.getElementById('searchDateTo').value;
  if (!from && !to) return;
  searchPeriod = { mode: 'range', from, to };
  document.querySelectorAll('.search-period-quick').forEach(btn => {
    btn.classList.remove('btn-primary');
    btn.classList.add('btn-outline-secondary');
  });
  document.getElementById('searchPeriodLabel').textContent =
    (from || '…') + ' 〜 ' + (to || '…');
}

async function runSearch() {
  searchPage = 1;
  await loadSearch(1);
}

// The dashboard's "Denied" card: the refused attempts of the selected period, in the search tab
function showDeniedLog() {
  document.getElementById('searchResult').value = 'only';
  document.getElementById('searchType').value = '';
  searchKeywords = [];
  renderSearchTags();
  selectSearchPeriodQuick(getDays());
  switchTab('search', document.querySelector('#mainTabs [data-tab="search"]'));
  runSearch();
}

// Query string for the current search conditions (shared by search and CSV export)
function searchQuery() {
  const inputVal = document.getElementById('searchTagInput')?.value.trim() ?? '';
  const keywords = [...searchKeywords, ...(inputVal ? [inputVal] : [])];
  const type = document.getElementById('searchType')?.value ?? '';

  let qs = '';
  if (searchPeriod.mode === 'days') {
    qs += `&days=${searchPeriod.days}`;
  } else {
    qs += `&days=0`;
    if (searchPeriod.from) qs += `&dateFrom=${encodeURIComponent(searchPeriod.from)}`;
    if (searchPeriod.to)   qs += `&dateTo=${encodeURIComponent(searchPeriod.to)}`;
  }
  keywords.forEach(kw => { qs += `&q=${encodeURIComponent(kw)}`; });
  if (type) qs += `&type=${encodeURIComponent(type)}`;
  const result = document.getElementById('searchResult')?.value ?? '';
  if (result) qs += `&denied=${encodeURIComponent(result)}`;
  return qs;
}

async function exportSearchCsv() {
  const btn = document.getElementById('exportCsvBtn');
  btn.disabled = true;
  try {
    const tz = -new Date().getTimezoneOffset();
    const server = serverParam() ? `&${serverParam()}` : '';
    const res = await fetch(`/api/stats/search/export?tzOffsetMinutes=${tz}${searchQuery()}${server}`, { headers: authHeaders() });
    if (res.status === 401) { logout(); return; }
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const name = /filename="([^"]+)"/.exec(res.headers.get('Content-Disposition') || '')?.[1] || 'file-access.csv';
    const url = URL.createObjectURL(await res.blob());
    const a = document.createElement('a');
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  } catch (e) {
    document.getElementById('searchResults').insertAdjacentHTML('afterbegin',
      `<div class="alert alert-danger py-2 small"><i class="bi bi-exclamation-triangle me-1"></i>${esc(e.message)}</div>`);
  } finally {
    btn.disabled = false;
  }
}

async function loadSearch(page = 1) {
  searchPage = page;

  const resultsEl = document.getElementById('searchResults');
  if (!resultsEl) return;
  resultsEl.innerHTML = '<div class="text-center py-4"><div class="spinner-border"></div></div>';

  try {
    const data = await api(`/api/stats/search?page=${page}&pageSize=${PAGE_SIZE}${searchQuery()}`);

    if (!data.items || data.items.length === 0) {
      resultsEl.innerHTML = `<div class="text-muted text-center py-5"><i class="bi bi-search me-2 fs-4"></i><div class="mt-2">${t('search.noResult')}</div></div>`;
      return;
    }

    const rows = data.items.map(r => {
      const srcParts = [];
      if (r.clientIp) srcParts.push(`<span class="font-monospace">${esc(r.clientIp)}</span>`);
      if (r.clientMachine && r.clientMachine !== r.clientIp) srcParts.push(esc(r.clientMachine));
      return `<tr${rowClass(r)}>
        <td class="text-muted">${fmtDate(r.accessTime)}</td>
        <td>${recordNameHtml(r)}</td>
        <td class="col-server">${esc(r.serverName || '')}</td>
        <td class="path-cell text-muted" title="${esc(r.folderPath)}">${esc(r.folderPath)}</td>
        <td>${esc(r.userName)}</td>
        <td>${recordTypeHtml(r)}</td>
        <td class="text-muted small">${srcParts.join('<br>') || '-'}</td>
      </tr>`;
    }).join('');

    resultsEl.innerHTML = `
      <div class="card">
        <div class="card-header py-2 d-flex align-items-center justify-content-between flex-wrap gap-2">
          <small class="text-muted" id="searchPaginationInfo"></small>
          <nav><ul class="pagination pagination-sm mb-0" id="searchPagination"></ul></nav>
        </div>
        <div class="card-body p-0">
          <div class="table-responsive">
            <table class="table table-hover table-sm mb-0">
              <thead class="table-dark sticky-top">
                <tr>
                  <th>${t('th.datetime')}</th>
                  <th>${t('th.filename')}</th>
                  <th class="col-server">${t('th.server')}</th>
                  <th>${t('th.path')}</th>
                  <th>${t('th.user')}</th>
                  <th>${t('th.type')}</th>
                  <th>${t('th.source')}</th>
                </tr>
              </thead>
              <tbody>${rows}</tbody>
            </table>
          </div>
        </div>
        <div class="card-footer py-2">
          <div class="d-flex align-items-center justify-content-between flex-wrap gap-2">
            <small class="text-muted" id="searchPaginationInfoBottom"></small>
            <nav><ul class="pagination pagination-sm mb-0" id="searchPaginationBottom"></ul></nav>
          </div>
        </div>
      </div>`;

    const gotoFn = p => loadSearch(p);
    renderPagination(
      document.getElementById('searchPagination'),
      document.getElementById('searchPaginationInfo'),
      data.page, data.total, data.pageSize, gotoFn
    );
    renderPagination(
      document.getElementById('searchPaginationBottom'),
      document.getElementById('searchPaginationInfoBottom'),
      data.page, data.total, data.pageSize, gotoFn
    );
  } catch (e) {
    resultsEl.innerHTML = `<div class="alert alert-danger"><i class="bi bi-exclamation-triangle me-1"></i>${esc(e.message)}</div>`;
  }
}

// ── Detail Modals ─────────────────────────────────────────────────
// The same path can exist on several file servers, so details are asked for one server
function detailServerParam(server) {
  return server ? `&server=${encodeURIComponent(server)}` : '';
}

async function showFileDetail(path, server = '') {
  const modal = new bootstrap.Modal(document.getElementById('detailModal'));
  document.getElementById('detailModalTitle').textContent = t('detail.fileDetail') + serverPath({ serverName: server }, path);
  document.getElementById('detailModalTitle').insertAdjacentHTML('beforeend', historyBtn({ filePath: path, serverName: server }));
  document.getElementById('detailModalBody').innerHTML =
    '<div class="text-center py-4"><div class="spinner-border"></div></div>';
  modal.show();

  const d = await api(`/api/stats/file-detail?path=${encodeURIComponent(path)}&days=${getDays()}${detailServerParam(server)}`);
  document.getElementById('detailModalBody').innerHTML = buildDetailHtml(d, 'file');
  renderDetailCharts(d);
}

async function showFolderDetail(path, server = '') {
  const modal = new bootstrap.Modal(document.getElementById('detailModal'));
  document.getElementById('detailModalTitle').textContent = t('detail.folderDetail') + serverPath({ serverName: server }, path);
  document.getElementById('detailModalTitle').insertAdjacentHTML('beforeend', historyBtn({ filePath: path, serverName: server, isFolder: true }));
  document.getElementById('detailModalBody').innerHTML =
    '<div class="text-center py-4"><div class="spinner-border"></div></div>';
  modal.show();

  const d = await api(`/api/stats/folder-detail?path=${encodeURIComponent(path)}&days=${getDays()}${detailServerParam(server)}`);
  document.getElementById('detailModalBody').innerHTML = buildDetailHtml(d, 'folder');
  renderDetailCharts(d);
}

function buildDetailHtml(d, mode) {
  const noData3 = `<tr><td colspan="3" class="text-muted text-center">${t('msg.noData')}</td></tr>`;
  const noData2 = `<tr><td colspan="2" class="text-muted text-center">${t('msg.noData')}</td></tr>`;

  const userRows = (d.byUser || []).map((u, i) =>
    `<tr><td>${i+1}</td><td>${esc(u.user)}</td><td class="text-end">${fmtNum(u.count)}</td></tr>`
  ).join('');

  const typeRows = (d.byType || []).map(tp =>
    `<tr><td>${typeBadge(tp.type)}</td><td class="text-end">${fmtNum(tp.count)}</td></tr>`
  ).join('');

  const recentRows = (d.recent || []).slice(0, 30).map(r =>
    `<tr><td class="text-muted">${fmtDate(r.accessTime)}</td><td>${esc(r.userName)}</td><td>${recordTypeHtml(r)}${r.newPath ? `<div class="small text-muted">-> ${esc(r.newPath)}</div>` : ""}</td></tr>`
  ).join('');

  const topFilesSection = mode === 'folder' && d.topFiles ? `
    <div class="col-12 col-md-6">
      <div class="detail-section-title"><i class="bi bi-file-earmark me-1"></i>${t('detail.topFiles')}</div>
      <table class="table table-sm">
        <thead><tr><th>#</th><th>${t('th.filename')}</th><th class="text-end">${t('detail.count')}</th></tr></thead>
        <tbody>
          ${d.topFiles.map((f,i) =>
            `<tr><td>${i+1}</td><td title="${esc(f.filePath)}">${esc(f.fileName)}</td><td class="text-end">${fmtNum(f.count)}</td></tr>`
          ).join('')}
        </tbody>
      </table>
    </div>` : '';

  return `
    <div class="row g-3">
      <div class="col-12">
        <canvas id="detailTimelineChart" height="80"></canvas>
      </div>
      <div class="col-12 col-md-4">
        <div class="detail-section-title"><i class="bi bi-people me-1"></i>${t('detail.byUser')}</div>
        <table class="table table-sm">
          <thead><tr><th>#</th><th>${t('detail.user')}</th><th class="text-end">${t('detail.count')}</th></tr></thead>
          <tbody>${userRows || noData3}</tbody>
        </table>
      </div>
      <div class="col-12 col-md-4">
        <div class="detail-section-title"><i class="bi bi-tags me-1"></i>${t('detail.byType')}</div>
        <table class="table table-sm">
          <thead><tr><th>${t('th.type')}</th><th class="text-end">${t('detail.count')}</th></tr></thead>
          <tbody>${typeRows || noData2}</tbody>
        </table>
        <div class="mt-2"><canvas id="detailTypeChart" height="120"></canvas></div>
      </div>
      <div class="col-12 col-md-4">
        <div class="detail-section-title"><i class="bi bi-clock-history me-1"></i>${t('detail.recent')}</div>
        <table class="table table-sm">
          <thead><tr><th>${t('th.datetime')}</th><th>${t('detail.user')}</th><th>${t('th.type')}</th></tr></thead>
          <tbody>${recentRows || noData3}</tbody>
        </table>
      </div>
      ${topFilesSection}
    </div>`;
}

function renderDetailCharts(d) {
  const perDay = {};
  (d.timeline || []).forEach(tp => {
    const day = localDay(tp.date);
    perDay[day] = (perDay[day] || 0) + tp.count;
  });
  const dates = Object.keys(perDay).sort();
  const counts = dates.map(day => perDay[day]);

  const ctx1 = document.getElementById('detailTimelineChart')?.getContext('2d');
  if (ctx1) {
    new Chart(ctx1, {
      type: 'bar',
      data: {
        labels: dates,
        datasets: [{ label: t('chart.accesses'), data: counts, backgroundColor: '#0d6efd88' }]
      },
      options: {
        responsive: true,
        plugins: { legend: { display: false } },
        scales: { y: { beginAtZero: true, ticks: { precision: 0 } } }
      }
    });
  }

  const types = d.byType || [];
  const ctx2 = document.getElementById('detailTypeChart')?.getContext('2d');
  if (ctx2 && types.length > 0) {
    new Chart(ctx2, {
      type: 'doughnut',
      data: {
        labels: types.map(tp => TYPE_LABELS[tp.type] || tp.type),
        datasets: [{
          data: types.map(tp => tp.count),
          backgroundColor: types.map(tp => TYPE_COLORS[tp.type] || '#6c757d')
        }]
      },
      options: {
        responsive: true,
        plugins: { legend: { position: 'bottom' } }
      }
    });
  }
}

// ── Unused Files (Admin only) ─────────────────────────────────────
function fmtSize(bytes) {
  if (bytes == null) return '-';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0, n = bytes;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return `${n.toLocaleString(undefined, { maximumFractionDigits: i === 0 ? 0 : 1 })} ${units[i]}`;
}

// Scope entries are "SERVER|path" or "path" (every server)
function parseScopeEntry(entry) {
  const bar = entry.indexOf('|');
  return bar < 0 ? { server: '', path: entry } : { server: entry.slice(0, bar), path: entry.slice(bar + 1) };
}

async function loadUnusedTab() {
  const sel = document.getElementById('unusedServer');
  if (sel.dataset.loaded) return;
  if (isAdmin()) {
    if (!serverList) await loadServerList();
    sel.innerHTML = serverOptions('');
  } else {
    // A Viewer with a scope: the servers of their entries, or every server with records they may see
    const entries = myScope.map(parseScopeEntry);
    const names = [...new Set([...entries.filter(e => e.server).map(e => e.server),
      ...(entries.some(e => !e.server) ? knownServers : [])])].sort();
    sel.innerHTML = names.map(n => `<option value="${esc(n)}">${esc(n)}</option>`).join('');
  }
  sel.dataset.loaded = '1';
  document.getElementById('unusedServerCol').classList.toggle('d-none', sel.options.length < 2);
  await loadUnusedFolders();
}

// Folder suggestions for the selected server
async function loadUnusedFolders() {
  const server = document.getElementById('unusedServer').value;
  const list = document.getElementById('unusedFolderList');
  let paths = [];
  try {
    // A Viewer with a scope may only look inside it (and cannot read the settings)
    paths = isAdmin()
      ? ((await api(`/api/settings${server ? `?server=${encodeURIComponent(server)}` : ''}`)).pathConfigs || []).map(c => c.path)
      : myScope.map(parseScopeEntry).filter(e => !e.server || e.server.toUpperCase() === server.toUpperCase()).map(e => e.path);
  } catch { /* the folder can still be typed */ }
  list.innerHTML = paths.map(p => `<option value="${esc(p)}">`).join('');
  document.getElementById('unusedFolder').value = paths[0] || '';
}

let lastUnused = null;
let unusedView = 'folders';

async function searchUnused(folderOverride) {
  const input = document.getElementById('unusedFolder');
  if (folderOverride) input.value = folderOverride;
  const folder = input.value.trim();
  const days = document.getElementById('unusedDays').value;
  const criterion = document.getElementById('unusedCriterion').value;
  const el = document.getElementById('unusedResults');
  const btn = document.getElementById('unusedSearchBtn');
  if (!folder) { el.innerHTML = `<div class="alert alert-warning py-2 small">${t('msg.pathRequired')}</div>`; return; }

  btn.disabled = true;
  el.innerHTML = `<div class="text-center py-4"><div class="spinner-border"></div><div class="small text-muted mt-2">${t('unused.scanning')}</div></div>`;
  try {
    const server = document.getElementById('unusedServer').value;
    lastUnused = await api(`/api/unused-files?folder=${encodeURIComponent(folder)}&days=${days}&criterion=${criterion}` +
      (server ? `&server=${encodeURIComponent(server)}` : ''));
    renderUnused();
  } catch (e) {
    el.innerHTML = `<div class="alert alert-danger py-2 small"><i class="bi bi-exclamation-triangle me-1"></i>${esc(e.message)}</div>`;
  } finally {
    btn.disabled = false;
  }
}

function setUnusedView(view) {
  unusedView = view;
  renderUnused();
}

function renderUnused() {
  const d = lastUnused;
  if (!d) return;
  const notes = [];
  if (d.recordingSince) notes.push(t('unused.recordingSince', { d: fmtDate(d.recordingSince) }));
  if (d.truncated) notes.push(`<span class="text-warning">${t('unused.truncated', { n: fmtNum(d.scanned) })}</span>`);
  if (unusedView === 'files' && d.total > d.shownCount) notes.push(t('unused.shownOnly', { n: fmtNum(d.shownCount) }));

  const viewBtn = (view, icon, label) =>
    `<button class="btn btn-sm ${unusedView === view ? 'btn-secondary' : 'btn-outline-secondary'}" onclick="setUnusedView('${view}')">
      <i class="bi ${icon} me-1"></i>${t(label)}</button>`;

  document.getElementById('unusedResults').innerHTML = `
    <div class="card">
      <div class="card-header py-2 small d-flex justify-content-between align-items-start flex-wrap gap-2">
        <div>
          <strong>${t('unused.summary', { n: fmtNum(d.total), s: fmtSize(d.totalSize), scanned: fmtNum(d.scanned) })}</strong>
          ${notes.length ? `<div class="text-muted mt-1">${notes.join('<br>')}</div>` : ''}
        </div>
        <div class="btn-group">
          ${viewBtn('folders', 'bi-folder2', 'unused.viewFolders')}
          ${viewBtn('files', 'bi-file-earmark', 'unused.viewFiles')}
        </div>
      </div>
      <div class="card-body p-0">
        <div class="table-responsive">${unusedView === 'files' ? unusedFilesTable(d) : unusedFoldersTable(d)}</div>
      </div>
    </div>`;
}

function unusedFilesTable(d) {
  const rows = d.items.map((f, i) => {
    const folderPath = f.path.slice(0, f.path.length - f.fileName.length - 1);
    return `<tr>
      <td>${i + 1}</td>
      <td><i class="bi bi-file-earmark text-muted me-1"></i>${esc(f.fileName)}</td>
      <td class="path-cell text-muted" title="${esc(folderPath)}">${esc(folderPath)}</td>
      <td class="text-end" data-sort="${f.size}">${fmtSize(f.size)}</td>
      <td>${fmtDate(f.modified)}</td>
      <td class="text-muted">${f.lastAccess ? fmtDate(f.lastAccess) : t('unused.never')}</td>
    </tr>`;
  }).join('');
  return `<table class="table table-hover table-sm mb-0" id="unusedTable">
    <thead class="table-dark sticky-top"><tr>
      <th>#</th>
      <th onclick="sortTable('unusedTable',1)" class="sortable">${t('th.filename')}</th>
      <th onclick="sortTable('unusedTable',2)" class="sortable">${t('unused.folderCol')}</th>
      <th onclick="sortTable('unusedTable',3)" class="sortable text-end">${t('unused.size')}</th>
      <th onclick="sortTable('unusedTable',4)" class="sortable">${t('unused.modified')}</th>
      <th onclick="sortTable('unusedTable',5)" class="sortable">${t('unused.lastAccess')}</th>
    </tr></thead>
    <tbody>${rows || `<tr><td colspan="6" class="text-muted text-center py-3">${t('unused.none')}</td></tr>`}</tbody>
  </table>`;
}

// One row per subfolder; clicking a subfolder lists inside it
function unusedFoldersTable(d) {
  const rows = (d.folders || []).map(f => {
    const pct = f.size > 0 ? Math.round(f.unusedSize / f.size * 100) : 0;
    const name = f.isSelf
      ? `<i class="bi bi-files text-muted me-1"></i>${t('unused.directFiles')}`
      : `<i class="bi bi-folder-fill text-warning me-1"></i><a href="#" data-path="${esc(f.path)}" onclick="searchUnused(this.dataset.path); return false;">${esc(f.path.slice(f.path.lastIndexOf('\\') + 1))}</a>`;
    return `<tr>
      <td title="${esc(f.path)}">${name}</td>
      <td class="text-end">${fmtNum(f.files)}</td>
      <td class="text-end" data-sort="${f.size}">${fmtSize(f.size)}</td>
      <td class="text-end">${fmtNum(f.unusedFiles)}</td>
      <td class="text-end" data-sort="${f.unusedSize}">${fmtSize(f.unusedSize)}</td>
      <td class="text-end" data-sort="${pct}">
        <div class="d-flex align-items-center gap-2 justify-content-end">
          <span>${pct}%</span>
          <div class="access-bar"><div class="access-bar-fill" style="width:${pct}%"></div></div>
        </div>
      </td>
      <td class="text-muted">${f.lastAccess ? fmtDate(f.lastAccess) : t('unused.never')}</td>
    </tr>`;
  }).join('');
  return `<table class="table table-hover table-sm mb-0" id="unusedFolderTable">
    <thead class="table-dark sticky-top"><tr>
      <th onclick="sortTable('unusedFolderTable',0)" class="sortable">${t('unused.folderCol')}</th>
      <th onclick="sortTable('unusedFolderTable',1)" class="sortable text-end">${t('unused.files')}</th>
      <th onclick="sortTable('unusedFolderTable',2)" class="sortable text-end">${t('unused.totalSize')}</th>
      <th onclick="sortTable('unusedFolderTable',3)" class="sortable text-end">${t('unused.unusedFiles')}</th>
      <th onclick="sortTable('unusedFolderTable',4)" class="sortable text-end">${t('unused.unusedSize')}</th>
      <th onclick="sortTable('unusedFolderTable',5)" class="sortable text-end">${t('unused.unusedPct')}</th>
      <th onclick="sortTable('unusedFolderTable',6)" class="sortable">${t('unused.lastAccess')}</th>
    </tr></thead>
    <tbody>${rows || `<tr><td colspan="7" class="text-muted text-center py-3">${t('unused.none')}</td></tr>`}</tbody>
  </table>`;
}

// ── Update check (Admin only) ─────────────────────────────────────
// The Admin's browser asks GitHub for the latest release at most once a day; the file server
// itself never connects out. Turned off under Settings → App info.
const RELEASES_API = 'https://api.github.com/repos/nuts-i77/FileAccessMonitor/releases/latest';
const UPDATE_CACHE_KEY = 'fam_update';
const UPDATE_DISMISSED_KEY = 'fam_update_dismissed';
let appInfo = null;

// Browser storage may be unavailable (private mode etc.); the check then simply runs again
function readStore(key) { try { return JSON.parse(localStorage.getItem(key)); } catch { return null; } }
function writeStore(key, value) { try { localStorage.setItem(key, JSON.stringify(value)); } catch { /* ignore */ } }

// "v1.10.0" > "1.9.2"; non-numeric parts count as 0
function isNewerVersion(latest, current) {
  const parse = v => String(v).replace(/^v/i, '').split('.').map(n => parseInt(n, 10) || 0);
  const a = parse(latest), b = parse(current);
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    if ((a[i] || 0) !== (b[i] || 0)) return (a[i] || 0) > (b[i] || 0);
  }
  return false;
}

async function loadAppInfo() {
  try {
    appInfo = await api('/api/settings/app');
  } catch { return; }
  document.getElementById('appVersion').textContent =
    appInfo.version === '0.0.0' ? t('app.devBuild') : `v${appInfo.version}`;
  document.getElementById('appUpdateCheck').checked = appInfo.updateCheck;
  document.getElementById('appLocalCollection').textContent =
    `${t(appInfo.localCollection ? 'app.localOn' : 'app.localOff')} — ${appInfo.os || ''}`;
  showLatest(readStore(UPDATE_CACHE_KEY));
}

function showLatest(cache) {
  const el = document.getElementById('appLatest');
  if (!el) return;
  if (!cache?.latest) { el.textContent = '-'; return; }
  el.innerHTML = `<a href="${esc(cache.url)}" target="_blank" rel="noopener">${esc(cache.latest)}</a>
    <span class="text-muted">(${t('app.checkedAt', { d: fmtDate(new Date(cache.checkedAt).toISOString()) })})</span>`;
}

async function checkForUpdate(force = false) {
  if (!appInfo) await loadAppInfo();
  if (!appInfo || (!appInfo.updateCheck && !force)) return;

  let cache = readStore(UPDATE_CACHE_KEY);
  if (force || !cache || Date.now() - cache.checkedAt > 24 * 3600 * 1000) {
    try {
      const res = await fetch(RELEASES_API, { headers: { Accept: 'application/vnd.github+json' } });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const r = await res.json();
      cache = { latest: r.tag_name, url: r.html_url, checkedAt: Date.now() };
      writeStore(UPDATE_CACHE_KEY, cache);
    } catch (e) {
      if (force) showSettingsAlert(`<i class="bi bi-exclamation-triangle me-1"></i>${t('app.checkFailed', { e: esc(e.message) })}`, 'warning');
      return;
    }
  }
  showLatest(cache);
  showUpdateBanner(cache);
}

function showUpdateBanner(cache) {
  const el = document.getElementById('updateBanner');
  const current = appInfo?.version;
  // Local builds (0.0.0) have no version to compare
  if (!el || !cache?.latest || !current || current === '0.0.0'
      || !isNewerVersion(cache.latest, current) || readStore(UPDATE_DISMISSED_KEY) === cache.latest) {
    if (el) el.innerHTML = '';
    return;
  }
  el.innerHTML = `<div class="alert alert-info py-2 small d-flex align-items-center gap-2 flex-wrap">
    <i class="bi bi-arrow-up-circle"></i>
    <span>${t('app.updateAvailable', { latest: esc(cache.latest), current: esc('v' + current) })}</span>
    <a href="${esc(cache.url)}" target="_blank" rel="noopener" class="alert-link">${t('app.releaseNotes')}</a>
    <button class="btn btn-sm btn-link ms-auto py-0" onclick="dismissUpdate('${esc(cache.latest)}')">${t('app.dismiss')}</button>
  </div>`;
}

// Agents should run the monitoring server's version: tell Admins when some do not
// (a local build, 0.0.0, has no version to compare)
function showAgentUpdateBanner(d) {
  const el = document.getElementById('agentUpdateBanner');
  if (!el) return;
  const outdated = (d?.agents || []).filter(a => !a.disabled && a.version && a.version !== d.serverVersion);
  if (!d || d.serverVersion === '0.0.0' || outdated.length === 0) { el.innerHTML = ''; return; }
  el.innerHTML = `<div class="alert alert-warning py-2 small d-flex align-items-center gap-2 flex-wrap">
    <i class="bi bi-hdd-stack"></i>
    <span>${t('agents.outdatedBanner', { n: outdated.length, v: esc('v' + d.serverVersion) })}</span>
    <span class="text-muted">${outdated.map(a => esc(a.name)).join(', ')}</span>
    <a href="#" class="alert-link ms-auto" onclick="openAgentsSettings(); return false;">${t('agents.showAgents')}</a>
  </div>`;
}

async function checkAgentVersions() {
  try { showAgentUpdateBanner(await api('/api/agents')); } catch { /* not shown */ }
}

function openAgentsSettings() {
  switchTab('settings', document.querySelector('[data-tab="settings"]'));
  setTimeout(() => document.getElementById('agentsSection')?.scrollIntoView({ behavior: 'smooth' }), 500);
}

// ── Web GUI connection (HTTPS) ───────────────────────────────────
const HTTP_WARNING_DISMISSED_KEY = 'httpWarningDismissed';

// A bar for Admins when this page came over plain HTTP: the password and the token cross the network in clear text
function showHttpWarning() {
  const el = document.getElementById('httpWarning');
  if (!el) return;
  if (location.protocol !== 'http:' || sessionStorage.getItem(HTTP_WARNING_DISMISSED_KEY)) { el.innerHTML = ''; return; }
  el.innerHTML = `<div class="alert alert-warning py-2 small d-flex align-items-center gap-2 flex-wrap">
    <i class="bi bi-shield-exclamation"></i>
    <span>${t('web.httpWarning')}</span>
    <a href="#" class="alert-link" onclick="openWebTlsSettings(); return false;">${t('web.showCard')}</a>
    <button class="btn btn-sm btn-link ms-auto py-0" onclick="dismissHttpWarning()">${t('web.dismiss')}</button>
  </div>`;
}

function dismissHttpWarning() {
  try { sessionStorage.setItem(HTTP_WARNING_DISMISSED_KEY, '1'); } catch { /* private mode: shown again next time */ }
  document.getElementById('httpWarning').innerHTML = '';
}

function openWebTlsSettings() {
  switchTab('settings', document.querySelector('[data-tab="settings"]'));
  setTimeout(() => document.getElementById('webTlsSection')?.scrollIntoView({ behavior: 'smooth' }), 500);
}

// Read-only: switching HTTPS needs a restart and could lock the Admin out, so the installer or the command line does it
async function loadWebTls() {
  const section = document.getElementById('webTlsSection');
  const body = document.getElementById('webTlsBody');
  if (!section || !body) return;
  try {
    const d = await api('/api/web-tls');
    section.classList.remove('d-none');
    const row = (label, value) => `<div class="mb-1"><span class="text-muted">${t(label)}:</span> ${value}</div>`;
    const state = d.https
      ? `<span class="badge text-bg-success">${t('web.card.on')}</span>`
      : `<span class="badge text-bg-secondary">${t('web.card.off')}</span>`;
    let html = row('web.card.state', state);
    if (d.https) {
      html += row('web.card.mode', t(d.mode === 'pfx' ? 'web.card.pfx' : 'web.card.selfSigned'));
      if (d.subject) html += row('web.card.subject', `<span class="font-monospace">${esc(d.subject)}</span>`);
      html += row('web.card.names', (d.names || []).map(n => `<span class="font-monospace">${esc(n)}</span>`).join(', ') || '-');
      html += row('web.card.fingerprint', `<span class="font-monospace text-break">${esc(d.fingerprint || '-')}</span>`);
      html += row('web.card.expires', d.notAfter ? fmtDate(d.notAfter) : '-');
      if (d.redirectPort > 0) html += row('web.card.redirect', esc(d.redirectPort));
    }
    html += `<div class="mt-2 mb-1 text-muted">${t('web.card.change')}</div>
      <div class="font-monospace text-break">Windows: "C:\\Program Files\\FileAccessMonitor\\FileAccessMonitor.exe" web-https ${d.https ? 'off' : 'on'}</div>
      <div class="font-monospace text-break">Linux: sudo fileaccessmonitor-server --https ${d.https ? 'off' : 'on'}</div>
      <div class="form-text">${t('web.card.changeHint')}</div>`;
    body.innerHTML = html;
  } catch (e) {
    section.classList.add('d-none'); // not available (an older server)
  }
}

function dismissUpdate(version) {
  writeStore(UPDATE_DISMISSED_KEY, version);
  document.getElementById('updateBanner').innerHTML = '';
}

async function saveUpdateCheck(enabled) {
  try {
    appInfo = await api('/api/settings/app', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ updateCheck: enabled })
    });
    if (enabled) checkForUpdate(); else document.getElementById('updateBanner').innerHTML = '';
    loadAuditLog(1);
  } catch (e) {
    showSettingsAlert(`<i class="bi bi-exclamation-triangle me-1"></i>${esc(e.message)}`, 'danger');
  }
}

// ── File servers (filter) ─────────────────────────────────────────
// The server filter appears once records come from more than one file server
let knownServers = [];

async function loadServers() {
  try { knownServers = await api('/api/stats/servers'); } catch { knownServers = []; }
  const sel = document.getElementById('serverFilter');
  const current = sel.value;
  sel.innerHTML = `<option value="">${t('servers.all')}</option>` +
    knownServers.map(s => `<option value="${esc(s)}">${esc(s)}</option>`).join('');
  sel.value = knownServers.includes(current) ? current : '';
  sel.classList.toggle('d-none', knownServers.length < 2);
  document.body.classList.toggle('single-server', knownServers.length < 2);
}

function selectedServer() {
  return document.getElementById('serverFilter')?.value || '';
}

// Appended to every /api/stats request
function serverParam() {
  const s = selectedServer();
  return s ? `server=${encodeURIComponent(s)}` : '';
}

// Path shown in lists: with the server name when there are several
function serverPath(r, path) {
  return knownServers.length > 1 && r.serverName ? `${r.serverName}: ${path}` : path;
}

// ── Agents (Admin only) ───────────────────────────────────────────
let enrollment = null;

function showAgentsAlert(html, type = 'success') {
  const el = document.getElementById('agentsAlert');
  if (!el) return;
  el.innerHTML = `<div class="alert alert-${type} alert-dismissible fade show py-2 small">
    ${html}<button type="button" class="btn-close" data-bs-dismiss="alert"></button>
  </div>`;
}

async function loadAgents() {
  const tbody = document.getElementById('agentsTableBody');
  try {
    const d = await api('/api/agents');
    showAgentUpdateBanner(d);
    if (!d.featureOn) showAgentsAlert(t('agents.featureOff', { p: d.port }), 'info');
    else if (!d.endpointReady) showAgentsAlert(t('agents.notReady'), 'warning');
    else document.getElementById('agentsAlert').innerHTML = '';
    // An agent that has not been in touch for 5 minutes is shown as offline
    const status = a => a.disabled
      ? `<span class="badge bg-secondary">${t('agents.stDisabled')}</span>`
      : a.lastSeenAt && Date.now() - new Date(a.lastSeenAt + (/[Z+]/.test(a.lastSeenAt) ? '' : 'Z')) < 5 * 60 * 1000
        ? `<span class="badge bg-success">${t('agents.stOnline')}</span>`
        : `<span class="badge bg-warning text-dark">${t('agents.stOffline')}</span>`;
    // Agents should run the monitoring server's version (local builds, 0.0.0, are not compared)
    const version = a => esc(a.version || '-') + (a.version && d.serverVersion !== '0.0.0' && a.version !== d.serverVersion
      ? ` <span class="badge bg-warning text-dark" title="${t('agents.updateHint', { v: esc(d.serverVersion) })}">${t('agents.needsUpdate')}</span>` : '');
    // A growing outbox means records are not getting through
    const outbox = a => a.outboxCount > 0
      ? `<span class="${a.outboxCount >= 100 ? 'text-danger fw-semibold' : 'text-warning'}">${fmtNum(a.outboxCount)}</span>` : '0';
    // Windows or Linux (Samba), with the full name on hover; agents before 1.7 do not report it
    const isLinux = a => !!a.os && !/^windows/i.test(a.os);
    const os = a => !a.os ? '-'
      : isLinux(a)
        ? `<span class="badge bg-dark" title="${esc(a.os)}"><i class="bi bi-terminal me-1"></i>Linux</span> <span class="small text-muted">${esc(a.os)}</span>`
        : `<span class="badge bg-primary" title="${esc(a.os)}"><i class="bi bi-windows me-1"></i>Windows</span> <span class="small text-muted">${esc(a.os)}</span>`;
    const auditPolicy = a => a.auditPolicyOk == null ? '-'
      : a.auditPolicyOk ? `<span class="badge bg-success-subtle text-success-emphasis">${t('agents.auditOn')}</span>`
        : `<span class="badge bg-danger" title="${t(isLinux(a) ? 'agents.auditOffHintLinux' : 'agents.auditOffHint')}">${t('agents.auditOff')}</span>`;
    tbody.innerHTML = d.agents.map(a => `<tr>
      <td><i class="bi bi-hdd me-1 text-muted"></i>${esc(a.name)}</td>
      <td>${os(a)}</td>
      <td>${fmtDate(a.lastSeenAt)}</td>
      <td>${version(a)}</td>
      <td>${status(a)}</td>
      <td class="text-end">${outbox(a)}</td>
      <td>${auditPolicy(a)}</td>
      <td><div class="d-flex gap-1">
        <button class="btn btn-sm btn-outline-secondary py-0" title="${t(a.disabled ? 'agents.enable' : 'agents.disable')}"
          onclick="setAgentDisabled('${esc(a.id)}', ${!a.disabled})"><i class="bi ${a.disabled ? 'bi-play' : 'bi-pause'}"></i></button>
        <button class="btn btn-sm btn-outline-danger py-0" title="${t('agents.remove')}"
          data-name="${esc(a.name)}" onclick="deleteAgent('${esc(a.id)}', this.dataset.name)"><i class="bi bi-trash"></i></button>
      </div></td>
    </tr>`).join('') || `<tr><td colspan="8" class="text-muted text-center py-3">${t('agents.none')}</td></tr>`;
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="5" class="text-danger small p-3">${esc(e.message)}</td></tr>`;
  }
}

async function createEnrollment() {
  try {
    enrollment = await api('/api/agents/enrollment', { method: 'POST' });
    document.getElementById('enrollUrl').value = enrollment.url;
    showConnection(enrollment.connection);
    document.getElementById('enrollExpires').textContent = fmtDate(enrollment.expiresAt);
    bootstrap.Modal.getOrCreateInstance(document.getElementById('enrollModal')).show();
    loadAuditLog(1);
  } catch (e) {
    showAgentsAlert(`<i class="bi bi-exclamation-triangle me-1"></i>${esc(e.message)}`, 'warning');
  }
}

function showConnection(connection) {
  document.getElementById('enrollConnection').value = connection;
  document.getElementById('enrollCommand').textContent =
    `& "C:\\Program Files\\FileAccessMonitor\\FileAccessMonitor.exe" enroll ${connection}; Restart-Service FileAccessMonitor`;
}

// Same code and certificate, another address (e.g. the IP address instead of a host name)
async function rebuildConnection() {
  if (!enrollment) return;
  try {
    const d = await api('/api/agents/connection', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: document.getElementById('enrollUrl').value.trim(), fingerprint: enrollment.fingerprint, code: enrollment.code })
    });
    showConnection(d.connection);
  } catch (e) {
    alertInModal(e.message);
  }
}

function alertInModal(message) {
  document.getElementById('enrollConnection').value = message;
}

// navigator.clipboard exists only on HTTPS or localhost; the GUI is usually opened over plain
// HTTP, so fall back to copying the selected text
async function copyConnection(btn) {
  const box = document.getElementById('enrollConnection');
  let copied = false;
  try {
    await navigator.clipboard.writeText(box.value);
    copied = true;
  } catch {
    box.focus();
    box.select();
    try { copied = document.execCommand('copy'); } catch { /* text stays selected for Ctrl+C */ }
  }
  if (!copied || !btn) return;
  btn.innerHTML = `<i class="bi bi-check-lg me-1"></i>${t('agents.copied')}`;
  setTimeout(() => { btn.innerHTML = '<i class="bi bi-clipboard"></i>'; }, 2000);
}

async function setAgentDisabled(id, disabled) {
  try {
    const d = await api(`/api/agents/${encodeURIComponent(id)}/disabled`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ disabled })
    });
    showAgentsAlert(`<i class="bi bi-check-circle me-1"></i>${esc(d.message)}`);
    loadAgents();
    loadAuditLog(1);
  } catch (e) {
    showAgentsAlert(`<i class="bi bi-exclamation-triangle me-1"></i>${esc(e.message)}`, 'danger');
  }
}

async function deleteAgent(id, name) {
  if (!confirm(t('agents.confirmRemove', { n: name }))) return;
  try {
    const d = await api(`/api/agents/${encodeURIComponent(id)}`, { method: 'DELETE' });
    showAgentsAlert(`<i class="bi bi-check-circle me-1"></i>${esc(d.message)}`);
    loadAgents();
    loadAuditLog(1);
  } catch (e) {
    showAgentsAlert(`<i class="bi bi-exclamation-triangle me-1"></i>${esc(e.message)}`, 'danger');
  }
}

// ── Tab switching ─────────────────────────────────────────────────
function switchTab(tab, el) {
  document.querySelectorAll('[id^="tab-"]').forEach(tp => tp.classList.add('d-none'));
  document.querySelectorAll('.nav-link').forEach(a => a.classList.remove('active'));
  document.getElementById('tab-' + tab).classList.remove('d-none');
  el.classList.add('active');
  currentTab = tab;
  location.hash = tab;
  loadTabData(tab);
  return false;
}

function loadTabData(tab) {
  switch (tab) {
    case 'dashboard': loadTimeline(); loadTypeChart(); loadTopCharts(); break;
    case 'files':     loadFiles(); break;
    case 'folders':   loadFolders(); break;
    case 'users':     loadUsers(); break;
    case 'recent':    loadRecent(1); break;
    case 'search':    /* search is user-driven; keep last results */ break;
    case 'unused':    loadUnusedTab(); break;
    case 'settings':  loadSettings(); break;
    default:          window.TabHooks?.[tab]?.(); break;   // tabs of feature scripts (js/permissions.js)
  }
}

function loadAll() {
  loadSummary();
  loadTabData(currentTab);
}

// ── Utilities ─────────────────────────────────────────────────────
function esc(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function filterTable(tableId, query) {
  const q = query.toLowerCase();
  document.querySelectorAll(`#${tableId} tbody tr`).forEach(row => {
    row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
  });
}

function sortTable(tableId, colIdx) {
  const table = document.getElementById(tableId);
  const tbody = table.querySelector('tbody');
  const rows = [...tbody.querySelectorAll('tr')];
  const asc = table.dataset.sortCol == colIdx && table.dataset.sortDir !== 'asc';
  table.dataset.sortCol = colIdx;
  table.dataset.sortDir = asc ? 'asc' : 'desc';

  rows.sort((a, b) => {
    // data-sort holds a raw value where the text is formatted (e.g. sizes)
    const cellValue = row => { const c = row.cells[colIdx]; return (c?.dataset.sort ?? c?.textContent ?? '').trim(); };
    const av = cellValue(a);
    const bv = cellValue(b);
    const an = parseFloat(av.replace(/,/g, ''));
    const bn = parseFloat(bv.replace(/,/g, ''));
    const cmp = isNaN(an) ? av.localeCompare(bv, 'ja') : an - bn;
    return asc ? cmp : -cmp;
  });
  rows.forEach(r => tbody.appendChild(r));
}

// ── Settings Tab ──────────────────────────────────────────────────
// Monitored folders and recording rules are per file server: '' is this monitoring server,
// otherwise an agent's server name
function settingsServer() {
  return document.getElementById('settingsServer')?.value || '';
}

function withSettingsServer(url) {
  const s = settingsServer();
  return s ? `${url}${url.includes('?') ? '&' : '?'}server=${encodeURIComponent(s)}` : url;
}

// Shown while an agent does the work on its server (it can take a while for large folders)
function runningMessage() {
  return settingsServer() ? t('msg.agentRunning', { s: settingsServer() }) : t('msg.applying');
}

// Server pickers: this machine first ('' = local), then the agents
let serverList = null;

async function loadServerList() {
  if (!isAdmin()) return [];
  try { serverList = await api('/api/settings/servers'); } catch { serverList = null; }
  return serverList?.servers || [];
}

function serverOptions(selected, { includeAll = false } = {}) {
  if (!serverList) return '';
  const opts = includeAll ? [`<option value="">${t('servers.all')}</option>`] : [];
  serverList.servers.forEach(name => {
    const value = !includeAll && name === serverList.local ? '' : name;
    const label = name === serverList.local ? `${name} ${t('servers.thisServer')}` : name;
    opts.push(`<option value="${esc(value)}" ${value === selected ? 'selected' : ''}>${esc(label)}</option>`);
  });
  return opts.join('');
}

async function loadSettings() {
  if (isAdmin()) {
    const current = settingsServer();
    const servers = await loadServerList();
    const sel = document.getElementById('settingsServer');
    sel.innerHTML = serverOptions(current);
    document.getElementById('settingsServerBar').classList.toggle('d-none', servers.length < 2);
  }
  await loadServerSettings();
  loadRetentionPolicy();
  if (isAdmin()) {
    ['usermgmtSettingsSection', 'agentsSection', 'appInfoSection', 'recordingSettingsSection', 'alertsSettingsSection',
      'reportsSettingsSection', 'integritySettingsSection', 'auditLogSection']
      .forEach(id => document.getElementById(id)?.classList.remove('d-none'));
    // Settings cards of feature scripts (js/reports.js, js/integrity.js)
    Object.values(window.SettingsHooks || {}).forEach(load => load());
    loadUsersMgmt();
    loadAgents();
    loadAppInfo();
    loadWebTls();
    loadAlertSettings();
    loadAuditLog(1);
  } else {
    const s = document.getElementById('retentionAdminSection');
    if (s) s.classList.add('d-none');
  }
}

// Monitored folders and recording rules of the server picked in the settings tab
async function loadServerSettings() {
  // A monitoring-only server with no agents yet has no file server to set up
  if (isAdmin() && serverList && !serverList.local && !settingsServer()) {
    document.getElementById('monitoredPathsList').innerHTML =
      `<div class="alert alert-info small mb-0">${t('settings.monitorOnly')}</div>`;
    try { document.getElementById('dnsServerInput').value = (await api('/api/settings')).dnsServer || ''; } catch { }
    return;
  }
  try {
    const d = await api(withSettingsServer('/api/settings'));
    // Support both new pathConfigs and legacy monitoredPaths response
    const configs = d.pathConfigs
      || (d.monitoredPaths || []).map(p => ({ path: p, eventTypes: ['Read', 'Write', 'Delete'] }));
    pathAudit = { applied: lowerKeys(d.auditApplied), version: d.auditVersion || 0, os: d.os || '' };
    renderPathsList(configs);
    const dnsInput = document.getElementById('dnsServerInput');
    if (dnsInput) dnsInput.value = d.dnsServer || '';
  } catch (e) {
    document.getElementById('monitoredPathsList').innerHTML =
      `<div class="text-danger small">${esc(e.message)}</div>`;
  }
  if (isAdmin()) loadRecordingSettings();
}

// ── Retention Policy ──────────────────────────────────────────────
async function loadRetentionPolicy() {
  const el = document.getElementById('retentionStats');
  if (!el) return;
  try {
    const d = await api('/api/retention');
    const policyText = d.retentionDays > 0
      ? `<strong>${t('msg.daysPolicy', { n: fmtNum(d.retentionDays) })}</strong>`
      : `<strong>${t('msg.unlimited')}</strong>`;

    const input = document.getElementById('retentionDaysInput');
    if (input) input.value = d.retentionDays > 0 ? d.retentionDays : '';

    const unit = t('unit.count');
    const cleanupBtn = d.retentionDays > 0 && isAdmin()
      ? `<button class="btn btn-sm btn-outline-danger mt-2" onclick="runRetentionCleanup()">
           <i class="bi bi-trash me-1"></i>${t('msg.cleanupBtn', { n: fmtNum(d.recordsToDelete) + unit })}
         </button>`
      : '';

    el.innerHTML = `
      <div class="d-flex flex-wrap gap-3">
        <div><span class="text-muted">${t('msg.curPolicy')}</span> ${policyText}</div>
        <div><span class="text-muted">${t('msg.totalRecords')}</span> <strong>${fmtNum(d.totalRecords)}${unit}</strong></div>
        ${d.oldestRecord ? `<div><span class="text-muted">${t('msg.oldest')}</span> <strong>${fmtDate(d.oldestRecord)}</strong></div>` : ''}
        ${d.retentionDays > 0 ? `<div><span class="text-muted">${t('msg.toDelete')}</span> <strong class="${d.recordsToDelete > 0 ? 'text-danger' : ''}">${fmtNum(d.recordsToDelete)}${unit}</strong></div>` : ''}
      </div>
      ${cleanupBtn}`;
  } catch (e) {
    el.innerHTML = `<span class="text-danger small">${esc(e.message)}</span>`;
  }
}

async function saveRetentionPolicy() {
  const input = document.getElementById('retentionDaysInput');
  const days = input.value === '' ? 0 : parseInt(input.value, 10);
  if (isNaN(days) || days < 0) {
    showSettingsAlert(t('msg.retentionInvalid'), 'warning');
    return;
  }
  try {
    const d = await api('/api/retention', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ retentionDays: days })
    });
    showSettingsAlert(`<i class="bi bi-check-circle me-1"></i>${esc(d.message)}`);
    loadRetentionPolicy();
  } catch (e) {
    showSettingsAlert(`<i class="bi bi-exclamation-triangle me-1"></i>${esc(e.message)}`, 'danger');
  }
}

async function saveDnsServer() {
  const input = document.getElementById('dnsServerInput');
  const server = (input?.value ?? '').trim();
  try {
    await api('/api/settings/dns', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ dnsServer: server })
    });
    showSettingsAlert(`<i class="bi bi-check-circle me-1"></i>${t('msg.dnsSaved')}`);
  } catch (e) {
    showSettingsAlert(`<i class="bi bi-exclamation-triangle me-1"></i>${esc(e.message)}`, 'danger');
  }
}

async function runRetentionCleanup() {
  if (!confirm(t('msg.cleanupConfirm'))) return;
  try {
    showSettingsAlert(`<span class="spinner-border spinner-border-sm me-1"></span>${t('msg.cleaningUp')}`, 'info');
    const d = await api('/api/retention/cleanup', { method: 'POST' });
    showSettingsAlert(`<i class="bi bi-check-circle me-1"></i>${esc(d.message)}`);
    loadRetentionPolicy();
  } catch (e) {
    showSettingsAlert(`<i class="bi bi-exclamation-triangle me-1"></i>${esc(e.message)}`, 'danger');
  }
}

const EVENT_TYPES = ['Read', 'Write', 'Delete', 'Permission'];
const EVENT_TYPE_COLORS = { Read: 'primary', Write: 'success', Delete: 'danger', Permission: 'purple' };
const EVENT_TYPE_LABELS = { Read: 'type.read', Write: 'type.writeCreate', Delete: 'type.deleteRename', Permission: 'type.permissionChanges' };

// Per folder of the shown server: the version of its auditing set-up (see AuditApplied.cs)
let pathAudit = { applied: {}, version: 0, os: '' };

function lowerKeys(obj) {
  const r = {};
  Object.keys(obj || {}).forEach(k => { r[k.toLowerCase()] = obj[k]; });
  return r;
}

// Whether a folder's auditing was set up before 1.9 (no refused attempts or permission changes yet)
function needsReapply(path) {
  return pathAudit.version > 0 && (pathAudit.applied[String(path).toLowerCase()] || 0) < pathAudit.version;
}

function renderPathsList(configs) {
  const el = document.getElementById('monitoredPathsList');
  const linux = !!pathAudit.os && !/windows/i.test(pathAudit.os);
  const stale = (configs || []).filter(c => needsReapply(c.path || c));
  document.getElementById('reapplyBanner').innerHTML = stale.length === 0 ? '' :
    `<div class="alert alert-warning py-2 small"><i class="bi bi-exclamation-triangle me-1"></i>${t('msg.reapplyBanner', { n: stale.length })}</div>`;
  if (!configs || configs.length === 0) {
    el.innerHTML = `<div class="text-muted small py-2">${t('msg.noPath')}</div>`;
    return;
  }
  el.innerHTML = configs.map(cfg => {
    const p = cfg.path || cfg; // support legacy string format
    const types = cfg.eventTypes || ['Read', 'Write', 'Delete'];
    const typeCheckboxes = EVENT_TYPES.map(et => {
      const checked = types.includes(et) ? 'checked' : '';
      const color = EVENT_TYPE_COLORS[et];
      const label = t(EVENT_TYPE_LABELS[et]);
      return `<div class="form-check form-check-inline mb-0">
        <input class="form-check-input" type="checkbox" id="et_${esc(p)}_${et}"
          ${checked} onchange="updatePathEventTypes(this.closest('[data-path]').dataset.path)">
        <label class="form-check-label small" for="et_${esc(p)}_${et}">
          <span class="badge bg-${color}-subtle text-${color}-emphasis border border-${color}-subtle">${label}</span>
        </label>
      </div>`;
    }).join('');

    return `<div class="mb-3 p-2 border rounded" data-path="${esc(p)}">
      <div class="d-flex align-items-center gap-2 mb-1">
        <i class="bi bi-folder-fill text-warning"></i>
        <span class="flex-grow-1 font-monospace small text-break fw-semibold">${esc(p)}</span>
        ${needsReapply(p) ? `<span class="badge text-bg-warning" title="${esc(t(linux ? 'msg.reapplyNeededLinux' : 'msg.reapplyNeeded'))}"><i class="bi bi-exclamation-triangle me-1"></i>${t(linux ? 'msg.reapplyNeededLinux' : 'msg.reapplyNeeded')}</span>` : ''}
        <button class="btn btn-sm btn-outline-secondary py-0" onclick="reapplySacl(this.closest('[data-path]').dataset.path)" title="${t('btn.reapplySacl')}">
          <i class="bi bi-shield-check"></i>
        </button>
        <button class="btn btn-sm btn-outline-danger py-0" onclick="removePath(this.closest('[data-path]').dataset.path)">
          <i class="bi bi-trash"></i>
        </button>
      </div>
      <div class="ms-4">${typeCheckboxes}</div>
    </div>`;
  }).join('');
}

function showSettingsAlert(html, type = 'success') {
  const el = document.getElementById('settingsAlert');
  el.innerHTML = `<div class="alert alert-${type} alert-dismissible fade show py-2 small">
    ${html}
    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
  </div>`;
}

async function addPath() {
  const input = document.getElementById('newPathInput');
  const path = input.value.trim();
  if (!path) { showSettingsAlert(t('msg.pathRequired'), 'warning'); return; }

  const eventTypes = EVENT_TYPES.filter(et =>
    document.getElementById(`newPath${et}`)?.checked
  );
  if (eventTypes.length === 0) {
    showSettingsAlert(t('msg.eventTypesRequired'), 'warning');
    return;
  }

  const btn = event.currentTarget;
  btn.disabled = true;
  btn.innerHTML = `<span class="spinner-border spinner-border-sm me-1"></span>${runningMessage()}`;

  try {
    const res = await fetch('/api/settings/paths', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ path, eventTypes, server: settingsServer() || null })
    });
    const d = await res.json();
    if (!res.ok) {
      showSettingsAlert(`<i class="bi bi-exclamation-triangle me-1"></i>${esc(d.error || '')}`, 'danger');
    } else {
      input.value = '';
      let msg = `<i class="bi bi-check-circle me-1"></i>${esc(d.message)}`;
      if (d.saclErrors?.length) {
        msg += `<br><small class="text-warning">${t('msg.saclErrCount', { n: d.saclErrors.length })}</small>`;
      }
      showSettingsAlert(msg, 'success');
      loadServerSettings(); // the new folder is up to date, and the notice about the others stays
    }
  } catch (e) {
    showSettingsAlert(`<i class="bi bi-exclamation-triangle me-1"></i>${esc(e.message)}`, 'danger');
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<i class="bi bi-plus-circle me-1"></i>${t('btn.add')}`;
  }
}

let _deleteTargetPath = null;

function removePath(path) {
  _deleteTargetPath = path;
  document.getElementById('deletePathName').textContent = path;
  new bootstrap.Modal(document.getElementById('deletePathModal')).show();
}

async function confirmDeletePath(removeSacl) {
  const modal = bootstrap.Modal.getInstance(document.getElementById('deletePathModal'));
  modal?.hide();
  const path = _deleteTargetPath;
  if (!path) return;

  if (removeSacl) {
    showSettingsAlert(`<span class="spinner-border spinner-border-sm me-1"></span>${settingsServer() ? runningMessage() : t('msg.removingSacl')}`, 'info');
  }

  try {
    const res = await fetch(
      withSettingsServer(`/api/settings/paths?path=${encodeURIComponent(path)}&removeSacl=${removeSacl}`),
      { method: 'DELETE', headers: { ...authHeaders() } }
    );
    const d = await res.json();
    if (!res.ok) {
      showSettingsAlert(`<i class="bi bi-exclamation-triangle me-1"></i>${esc(d.error)}`, 'danger');
    } else {
      let msg = `<i class="bi bi-check-circle me-1"></i>${esc(d.message)}`;
      if (removeSacl && d.saclErrors?.length) {
        msg += `<br><small class="text-warning">${t('msg.saclErrCount', { n: d.saclErrors.length })}</small>`;
      }
      showSettingsAlert(msg, 'success');
      if (d.pathConfigs) renderPathsList(d.pathConfigs); else loadSettings();
    }
  } catch (e) {
    showSettingsAlert(`${esc(e.message)}`, 'danger');
  }
}

async function updatePathEventTypes(path) {
  const eventTypes = EVENT_TYPES.filter(et => {
    const cb = document.getElementById(`et_${path}_${et}`);
    return cb?.checked;
  });
  if (eventTypes.length === 0) {
    // Re-check at least one to prevent empty state
    const firstCb = document.getElementById(`et_${path}_${EVENT_TYPES[0]}`);
    if (firstCb) firstCb.checked = true;
    showSettingsAlert(t('msg.eventTypesRequired'), 'warning');
    return;
  }
  try {
    const d = await api('/api/settings/paths/event-types', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path, eventTypes, server: settingsServer() || null })
    });
    // Silently update — no alert needed for checkbox toggle
    if (d.pathConfigs) renderPathsList(d.pathConfigs);
  } catch (e) {
    showSettingsAlert(`<i class="bi bi-exclamation-triangle me-1"></i>${esc(e.message)}`, 'danger');
    loadSettings(); // reload to restore correct state
  }
}

async function reapplySacl(path) {
  const confirmed = confirm(t('msg.saclConfirm', { p: path }));
  if (!confirmed) return;
  try {
    showSettingsAlert(`<span class="spinner-border spinner-border-sm me-1"></span>${settingsServer() ? runningMessage() : t('msg.applyingSacl')}`, 'info');
    const res = await fetch('/api/settings/paths/apply-sacl', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ path, server: settingsServer() || null })
    });
    const d = await res.json();
    if (!res.ok) {
      showSettingsAlert(`<i class="bi bi-exclamation-triangle me-1"></i>${esc(d.error)}`, 'danger');
    } else {
      let msg = `<i class="bi bi-check-circle me-1"></i>${esc(d.message)}`;
      if (d.saclErrors?.length) {
        msg += `<br><small class="text-warning">${t('msg.saclErrCount', { n: d.saclErrors.length })}</small>`;
      }
      showSettingsAlert(msg, 'success');
      loadServerSettings(); // the "re-apply" notice of this folder is gone
    }
  } catch (e) {
    showSettingsAlert(`${esc(e.message)}`, 'danger');
  }
}

// ── User Management (Admin only) ──────────────────────────────────
function isAdmin() {
  return getUser()?.roles?.includes('Admin') === true;
}

let usersCache = [];

// Admins always see everything; a Viewer sees everything unless folders are assigned
function scopeCell(u, role) {
  if (role === 'Admin') return `<td class="text-muted small">${t('scope.all')}</td>`;
  const paths = (u.scopePaths || []).map(parseScopeEntry);
  const summary = paths.length
    ? paths.map(e => `<div class="font-monospace text-break">${esc(e.server ? `${e.server}: ${e.path}` : e.path)}</div>`).join('')
    : `<span class="text-muted">${t('scope.all')}</span>`;
  const mail = u.notifyEmail ? `<div class="text-muted"><i class="bi bi-envelope me-1"></i>${esc(u.notifyEmail)}</div>` : '';
  return `<td class="small">
    <div class="d-flex align-items-start gap-2">
      <div class="flex-grow-1">${summary}${mail}</div>
      <button class="btn btn-sm btn-outline-secondary py-0" title="${t('scope.edit')}" onclick="showScopeEditor('${esc(u.id)}')"><i class="bi bi-pencil"></i></button>
    </div>
  </td>`;
}

// One folder of the scope: a server ('' = every server) and a path
function addScopeRow(server = '', path = '') {
  const row = document.createElement('div');
  row.className = 'scope-row input-group input-group-sm';
  row.innerHTML = `
    <select class="form-select" style="max-width:40%">${serverOptions(server, { includeAll: true })}</select>
    <input type="text" class="form-control font-monospace" placeholder="D:\\Share\\Sales">
    <button type="button" class="btn btn-outline-secondary" title="${t('scope.removeRow')}"><i class="bi bi-x"></i></button>`;
  row.querySelector('input').value = path;
  // A server named in the scope but no longer known still shows (and is kept) as is
  const sel = row.querySelector('select');
  if (server && ![...sel.options].some(o => o.value.toUpperCase() === server.toUpperCase()))
    sel.insertAdjacentHTML('beforeend', `<option value="${esc(server)}" selected>${esc(server)}</option>`);
  else if (server)
    sel.value = [...sel.options].find(o => o.value.toUpperCase() === server.toUpperCase()).value;
  row.querySelector('button').onclick = () => row.remove();
  document.getElementById('scopeRows').appendChild(row);
}

function showScopeEditor(id) {
  const u = usersCache.find(x => x.id === id);
  if (!u) return;
  document.getElementById('scopeModal').dataset.userId = id;
  document.getElementById('scopeUsername').textContent = u.username;
  document.getElementById('scopeRows').innerHTML = '';
  (u.scopePaths || []).map(parseScopeEntry).forEach(e => addScopeRow(e.server, e.path));
  if (!u.scopePaths?.length) addScopeRow();
  document.getElementById('scopeNotifyEmail').value = u.notifyEmail || '';
  document.getElementById('scopeSendReport').checked = u.sendReport !== false;
  document.getElementById('scopeError').classList.add('d-none');
  bootstrap.Modal.getOrCreateInstance(document.getElementById('scopeModal')).show();
}

async function saveScope() {
  const modal = document.getElementById('scopeModal');
  const err = document.getElementById('scopeError');
  try {
    const d = await api(`/api/users/${encodeURIComponent(modal.dataset.userId)}/scope`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        paths: [...document.querySelectorAll('#scopeRows .scope-row')]
          .map(row => ({ server: row.querySelector('select').value, path: row.querySelector('input').value.trim() }))
          .filter(e => e.path)
          .map(e => e.server ? `${e.server}|${e.path}` : e.path),
        notifyEmail: document.getElementById('scopeNotifyEmail').value.trim(),
        sendReport: document.getElementById('scopeSendReport').checked
      })
    });
    bootstrap.Modal.getInstance(modal)?.hide();
    showUsermgmtAlert(`<i class="bi bi-check-circle me-1"></i>${esc(d.message)}`);
    loadUsersMgmt();
    loadAuditLog(1);
  } catch (e) {
    err.textContent = e.message;
    err.classList.remove('d-none');
  }
}

async function loadUsersMgmt() {
  const tbody = document.getElementById('usermgmtTableBody');
  tbody.innerHTML = '<tr><td colspan="5" class="text-center py-3"><div class="spinner-border spinner-border-sm"></div></td></tr>';
  try {
    const users = await api('/api/users');
    usersCache = users;
    const me = getUser();
    tbody.innerHTML = users.map(u => {
      const role = u.roles?.[0] || '';
      const isSelf = u.username === me?.username;
      return `<tr>
        <td><i class="bi bi-person me-1 text-muted"></i>${esc(u.username)}${isSelf ? ` <span class="badge bg-info small">${t('msg.self')}</span>` : ''}</td>
        <td>${esc(u.displayName)}</td>
        <td>
          <select class="form-select form-select-sm" style="width:auto" ${isSelf ? `disabled title="${t('msg.selfRoleNote')}"` : `onchange="changeRole('${esc(u.id)}', this)"`}>
            <option value="Admin" ${role === 'Admin' ? 'selected' : ''}>Admin</option>
            <option value="Viewer" ${role === 'Viewer' ? 'selected' : ''}>Viewer</option>
          </select>
        </td>
        ${scopeCell(u, role)}
        <td>
          <div class="d-flex gap-1">
            <button class="btn btn-sm btn-outline-secondary py-0" onclick="showResetPassword('${esc(u.id)}', '${esc(u.username)}')">
              <i class="bi bi-key"></i>
            </button>
            ${isSelf ? '' : `<button class="btn btn-sm btn-outline-danger py-0" onclick="deleteUser('${esc(u.id)}', '${esc(u.username)}')"><i class="bi bi-trash"></i></button>`}
          </div>
        </td>
      </tr>`;
    }).join('') || `<tr><td colspan="5" class="text-muted text-center py-3">${t('msg.noUsers')}</td></tr>`;
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="5" class="text-danger small p-3"><i class="bi bi-exclamation-triangle me-1"></i>${esc(e.message)}</td></tr>`;
  }
}

function showUsermgmtAlert(html, type = 'success') {
  const el = document.getElementById('usermgmtAlert');
  if (!el) return;
  el.innerHTML = `<div class="alert alert-${type} alert-dismissible fade show py-2 small">
    ${html}<button type="button" class="btn-close" data-bs-dismiss="alert"></button>
  </div>`;
}

function showCreateUser() {
  ['newUserUsername', 'newUserDisplayName', 'newUserPassword'].forEach(id => {
    document.getElementById(id).value = '';
  });
  document.getElementById('newUserRole').value = 'Viewer';
  const errEl = document.getElementById('createUserError');
  errEl.textContent = '';
  errEl.className = 'd-none text-danger small mt-2';
  new bootstrap.Modal(document.getElementById('createUserModal')).show();
}

async function createUser() {
  const username = document.getElementById('newUserUsername').value.trim();
  const displayName = document.getElementById('newUserDisplayName').value.trim();
  const password = document.getElementById('newUserPassword').value;
  const role = document.getElementById('newUserRole').value;
  const errEl = document.getElementById('createUserError');
  const btn = document.getElementById('createUserBtn');

  errEl.textContent = '';
  errEl.className = 'd-none text-danger small mt-2';
  if (!username || !password) {
    errEl.textContent = t('msg.required');
    errEl.className = 'text-danger small mt-2';
    return;
  }
  btn.disabled = true;
  try {
    await api('/api/users', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, displayName, password, role })
    });
    bootstrap.Modal.getInstance(document.getElementById('createUserModal'))?.hide();
    showUsermgmtAlert(`<i class="bi bi-check-circle me-1"></i>${t('msg.userCreated', { u: username })}`);
    loadUsersMgmt();
  } catch (e) {
    errEl.textContent = e.message;
    errEl.className = 'text-danger small mt-2';
  } finally {
    btn.disabled = false;
  }
}

async function deleteUser(id, username) {
  if (!confirm(t('msg.deleteConfirm', { u: username }))) return;
  try {
    await api(`/api/users/${encodeURIComponent(id)}`, { method: 'DELETE' });
    showUsermgmtAlert(`<i class="bi bi-check-circle me-1"></i>${t('msg.userDeleted', { u: username })}`);
    loadUsersMgmt();
  } catch (e) {
    showUsermgmtAlert(`<i class="bi bi-exclamation-triangle me-1"></i>${esc(e.message)}`, 'danger');
  }
}

async function changeRole(id, selectEl) {
  const role = selectEl.value;
  try {
    await api(`/api/users/${encodeURIComponent(id)}/role`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ role })
    });
    showUsermgmtAlert(`<i class="bi bi-check-circle me-1"></i>${t('msg.roleChanged')}`);
  } catch (e) {
    showUsermgmtAlert(`<i class="bi bi-exclamation-triangle me-1"></i>${esc(e.message)}`, 'danger');
    loadUsersMgmt();
  }
}

let _resetPasswordUserId = null;

function showResetPassword(id, username) {
  _resetPasswordUserId = id;
  document.getElementById('resetPasswordUsername').textContent = username;
  document.getElementById('resetNewPassword').value = '';
  const errEl = document.getElementById('resetPasswordError');
  errEl.textContent = '';
  errEl.className = 'd-none text-danger small mt-2';
  new bootstrap.Modal(document.getElementById('resetPasswordModal')).show();
}

async function doResetPassword() {
  const newPassword = document.getElementById('resetNewPassword').value;
  const errEl = document.getElementById('resetPasswordError');
  const btn = document.getElementById('resetPasswordBtn');

  errEl.textContent = '';
  errEl.className = 'd-none text-danger small mt-2';
  if (!newPassword) {
    errEl.textContent = t('msg.pwRequired');
    errEl.className = 'text-danger small mt-2';
    return;
  }
  btn.disabled = true;
  try {
    await api(`/api/users/${encodeURIComponent(_resetPasswordUserId)}/reset-password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ newPassword })
    });
    bootstrap.Modal.getInstance(document.getElementById('resetPasswordModal'))?.hide();
    showUsermgmtAlert(`<i class="bi bi-check-circle me-1"></i>${t('msg.pwReset')}`);
  } catch (e) {
    errEl.textContent = e.message;
    errEl.className = 'text-danger small mt-2';
  } finally {
    btn.disabled = false;
  }
}

// ── Self password change (all authenticated users) ────────────────
function showChangePasswordSelf() {
  document.getElementById('changeCurrentPassword').value = '';
  document.getElementById('changeNewPassword').value = '';
  const errEl = document.getElementById('changePasswordError');
  errEl.textContent = '';
  errEl.className = 'd-none text-danger small mt-2';
  new bootstrap.Modal(document.getElementById('changePasswordModal')).show();
}

async function changePasswordSelf() {
  const currentPassword = document.getElementById('changeCurrentPassword').value;
  const newPassword = document.getElementById('changeNewPassword').value;
  const errEl = document.getElementById('changePasswordError');
  const btn = document.getElementById('changePasswordBtn');

  errEl.textContent = '';
  errEl.className = 'd-none text-danger small mt-2';
  if (!currentPassword || !newPassword) {
    errEl.textContent = t('msg.currentPwRequired');
    errEl.className = 'text-danger small mt-2';
    return;
  }
  btn.disabled = true;
  try {
    const d = await api('/api/me/change-password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ currentPassword, newPassword })
    });
    // Changing the password revokes existing tokens; keep this session with the new one
    if (d.token) localStorage.setItem('jwt_token', d.token);
    bootstrap.Modal.getInstance(document.getElementById('changePasswordModal'))?.hide();
    // Show a brief toast-style alert in the navbar area (no panel visible)
    const navBtn = document.getElementById('navUserBtn');
    if (navBtn) {
      const orig = navBtn.innerHTML;
      navBtn.innerHTML = `<i class="bi bi-check-circle me-1 text-success"></i>${t('msg.pwChanged')}`;
      setTimeout(() => { navBtn.innerHTML = orig; }, 2500);
    }
  } catch (e) {
    errEl.textContent = e.message;
    errEl.className = 'text-danger small mt-2';
  } finally {
    btn.disabled = false;
  }
}

// ── Recording rules ───────────────────────────────────────────────
const DEFAULT_EXCLUDE_PATTERNS = ['Thumbs.db', 'desktop.ini', '~$*', '*.tmp'];

function showRecordingAlert(html, type = 'success') {
  const el = document.getElementById('recordingAlert');
  if (!el) return;
  el.innerHTML = `<div class="alert alert-${type} alert-dismissible fade show py-2 small">
    ${html}<button type="button" class="btn-close" data-bs-dismiss="alert"></button>
  </div>`;
}

const linesOf = id => document.getElementById(id).value.split('\n').map(s => s.trim()).filter(Boolean);
const setLines = (id, list) => { document.getElementById(id).value = (list || []).join('\n'); };

async function loadRecordingSettings() {
  try {
    const s = await api(withSettingsServer('/api/settings/recording'));
    setLines('recExcludeFiles', s.excludeFilePatterns);
    setLines('recExcludeUsers', s.excludeUsers);
    setLines('recExcludeProcesses', s.excludeProcesses);
    document.getElementById('recMergeReadMinutes').value = s.mergeReadMinutes;
    document.getElementById('recRecordDenied').checked = s.recordDenied !== false;
  } catch (e) {
    showRecordingAlert(`<i class="bi bi-exclamation-triangle me-1"></i>${esc(e.message)}`, 'danger');
  }
}

async function saveRecordingSettings() {
  try {
    const d = await api(withSettingsServer('/api/settings/recording'), {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        excludeFilePatterns: linesOf('recExcludeFiles'),
        excludeUsers: linesOf('recExcludeUsers'),
        excludeProcesses: linesOf('recExcludeProcesses'),
        mergeReadMinutes: parseInt(document.getElementById('recMergeReadMinutes').value, 10) || 0,
        recordDenied: document.getElementById('recRecordDenied').checked
      })
    });
    showRecordingAlert(`<i class="bi bi-check-circle me-1"></i>${esc(d.message)}`);
    loadRecordingSettings();
    loadAuditLog(1);
  } catch (e) {
    showRecordingAlert(`<i class="bi bi-exclamation-triangle me-1"></i>${esc(e.message)}`, 'danger');
  }
}

// Adds the common temporary files to the list (not saved until "Save" is pressed)
function addDefaultExcludePatterns() {
  const current = linesOf('recExcludeFiles');
  const lower = current.map(s => s.toLowerCase());
  setLines('recExcludeFiles', [...current, ...DEFAULT_EXCLUDE_PATTERNS.filter(p => !lower.includes(p.toLowerCase()))]);
}

// ── Notifications ─────────────────────────────────────────────────
function showAlertsAlert(html, type = 'success') {
  const el = document.getElementById('alertsAlert');
  if (!el) return;
  el.innerHTML = `<div class="alert alert-${type} alert-dismissible fade show py-2 small">
    ${html}<button type="button" class="btn-close" data-bs-dismiss="alert"></button>
  </div>`;
}

async function loadAlertSettings() {
  try {
    const s = await api('/api/alerts');
    const set = (id, v) => { document.getElementById(id).value = v ?? ''; };
    document.getElementById('alertEnabled').checked = s.enabled;
    set('alertDeleteThreshold', s.deleteThreshold);
    set('alertWriteThreshold', s.writeThreshold);
    set('alertReadThreshold', s.readThreshold);
    set('alertDeniedThreshold', s.deniedThreshold);
    document.getElementById('alertRansomwareEnabled').checked = s.ransomwareEnabled !== false;
    set('alertWindowMinutes', s.windowMinutes);
    set('alertCooldownMinutes', s.cooldownMinutes);
    set('alertAgentOfflineMinutes', s.agentOfflineMinutes);
    set('alertLanguage', s.language);
    set('alertWebhookFormat', s.webhookFormat);
    set('alertSmtpHost', s.smtpHost);
    set('alertSmtpPort', s.smtpPort);
    document.getElementById('alertSmtpUseSsl').checked = s.smtpUseSsl;
    set('alertSmtpUser', s.smtpUser);
    set('alertMailFrom', s.mailFrom);
    set('alertMailTo', s.mailTo);
    // Secrets are never sent back; leaving the field empty keeps the stored value
    const url = document.getElementById('alertWebhookUrl');
    url.value = '';
    url.placeholder = s.webhookUrlSet ? t('alerts.secretSet') : 'https://';
    const pw = document.getElementById('alertSmtpPassword');
    pw.value = '';
    pw.placeholder = s.smtpPasswordSet ? t('alerts.secretSet') : '';
    set('alertProxyUrl', s.proxyUrl);
    set('alertProxyUser', s.proxyUser);
    const proxyPw = document.getElementById('alertProxyPassword');
    proxyPw.value = '';
    proxyPw.placeholder = s.proxyPasswordSet ? t('alerts.secretSet') : '';
  } catch (e) {
    showAlertsAlert(`<i class="bi bi-exclamation-triangle me-1"></i>${esc(e.message)}`, 'danger');
  }
}

// Empty = keep the stored secret (null), "-" = remove it ("")
function secretField(id) {
  const v = document.getElementById(id).value;
  return v === '' ? null : v === '-' ? '' : v;
}

function alertFormBody() {
  const val = id => document.getElementById(id).value.trim();
  const num = id => parseInt(val(id), 10) || 0;
  return {
    enabled: document.getElementById('alertEnabled').checked,
    deleteThreshold: num('alertDeleteThreshold'),
    writeThreshold: num('alertWriteThreshold'),
    readThreshold: num('alertReadThreshold'),
    deniedThreshold: num('alertDeniedThreshold'),
    ransomwareEnabled: document.getElementById('alertRansomwareEnabled').checked,
    windowMinutes: num('alertWindowMinutes'),
    cooldownMinutes: num('alertCooldownMinutes'),
    agentOfflineMinutes: num('alertAgentOfflineMinutes'),
    language: val('alertLanguage'),
    webhookFormat: val('alertWebhookFormat'),
    webhookUrl: secretField('alertWebhookUrl'),
    smtpHost: val('alertSmtpHost'),
    smtpPort: num('alertSmtpPort'),
    smtpUseSsl: document.getElementById('alertSmtpUseSsl').checked,
    smtpUser: val('alertSmtpUser'),
    smtpPassword: secretField('alertSmtpPassword'),
    mailFrom: val('alertMailFrom'),
    mailTo: val('alertMailTo'),
    proxyUrl: val('alertProxyUrl'),
    proxyUser: val('alertProxyUser'),
    proxyPassword: secretField('alertProxyPassword'),
  };
}

async function saveAlertSettings() {
  try {
    const d = await api('/api/alerts', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(alertFormBody())
    });
    showAlertsAlert(`<i class="bi bi-check-circle me-1"></i>${esc(d.message)}`);
    loadAlertSettings();
    loadAuditLog(1);
  } catch (e) {
    showAlertsAlert(`<i class="bi bi-exclamation-triangle me-1"></i>${esc(e.message)}`, 'danger');
  }
}

async function sendTestAlert() {
  try {
    // Tests what is in the form, so settings can be checked before saving
    const d = await api('/api/alerts/test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(alertFormBody())
    });
    showAlertsAlert(`<i class="bi bi-check-circle me-1"></i>${esc(d.message)}`);
  } catch (e) {
    showAlertsAlert(`<i class="bi bi-exclamation-triangle me-1"></i>${esc(e.message)}`, 'danger');
  }
  loadAuditLog(1);
}

// ── Operation log ─────────────────────────────────────────────────
async function loadAuditLog(page = 1) {
  const tbody = document.getElementById('auditLogBody');
  if (!tbody) return;
  try {
    const d = await api(`/api/auditlog?page=${page}&pageSize=${PAGE_SIZE}`);
    tbody.innerHTML = d.items.map(e => {
      const label = t('audit.a.' + e.action);
      return `<tr>
        <td class="text-muted small">${fmtDate(e.time)}</td>
        <td class="small">${esc(e.userName)}</td>
        <td class="small" title="${esc(e.action)}">${esc(label.startsWith('audit.a.') ? e.action : label)}</td>
        <td class="small text-muted text-break">${esc(e.detail || '')}</td>
        <td class="small font-monospace">${esc(e.clientIp || '-')}</td>
      </tr>`;
    }).join('') || `<tr><td colspan="5" class="text-muted text-center py-3">${t('audit.empty')}</td></tr>`;
    renderPagination(document.getElementById('auditPagination'), document.getElementById('auditPaginationInfo'),
      d.page, d.total, d.pageSize, p => loadAuditLog(p));
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="5" class="text-danger small p-3"><i class="bi bi-exclamation-triangle me-1"></i>${esc(e.message)}</td></tr>`;
  }
}

// ── Auto-reload ───────────────────────────────────────────────────
function setAutoReload(seconds) {
  clearInterval(autoReloadTimer);
  clearInterval(countdownTimer);
  autoReloadTimer = null;
  countdownTimer = null;
  document.getElementById('reloadCountdown').textContent = '';

  const s = parseInt(seconds, 10);
  if (s <= 0) return;

  countdownLeft = s;
  document.getElementById('reloadCountdown').textContent = fmtCountdown(countdownLeft);

  countdownTimer = setInterval(() => {
    // Reloading the settings tab would wipe what the user is typing, so pause there
    if (currentTab === 'settings') {
      document.getElementById('reloadCountdown').textContent = t('nav.autoPaused');
      return;
    }
    countdownLeft--;
    document.getElementById('reloadCountdown').textContent = fmtCountdown(countdownLeft);
    if (countdownLeft <= 0) {
      loadAll();
      countdownLeft = s;
    }
  }, 1000);
}

function fmtCountdown(sec) {
  if (getLang() === 'en') {
    return sec >= 60 ? `${Math.floor(sec/60)}m${sec%60 ? sec%60+'s' : ''}` : `${sec}s`;
  }
  return sec >= 60 ? `${Math.floor(sec/60)}分${sec%60 ? sec%60+'秒' : ''}` : `${sec}秒`;
}

// ── Init ──────────────────────────────────────────────────────────

applyI18n();

document.getElementById('daysFilter').addEventListener('change', loadAll);

// Show logged-in user
const _user = getUser();
if (_user) {
  const el = document.getElementById('navUserName');
  if (el) el.textContent = _user.displayName || _user.username;
}

// Restore tab from URL hash on page load (survives F5)
// Folders the signed-in Viewer is limited to (empty = everything); read from the server each
// time, so a scope changed by an Admin applies without signing in again
let myScope = [];

(async () => {
  try { myScope = (await api('/api/auth/me')).scopePaths || []; } catch { /* keep defaults */ }
  await loadServers();
  if (myScope.length) {
    const badge = document.getElementById('navScopeBadge');
    badge.classList.remove('d-none');
    badge.title = myScope.map(parseScopeEntry).map(e => e.server ? `${e.server}: ${e.path}` : e.path).join('\n');
  }

  const VALID_TABS = ['dashboard', 'files', 'folders', 'users', 'recent', 'search', 'settings'];
  if (isAdmin() || myScope.length) {
    document.getElementById('navUnused')?.classList.remove('d-none');
    document.getElementById('navPermissions')?.classList.remove('d-none');
    VALID_TABS.push('unused', 'permissions');
  }
  if (isAdmin()) { checkForUpdate(); checkAgentVersions(); showHttpWarning(); }
  // Banners of feature scripts (js/integrity.js: the record chain is broken)
  Object.values(window.StartupHooks || {}).forEach(start => start());
  const hashTab = location.hash.slice(1);
  const startTab = VALID_TABS.includes(hashTab) ? hashTab : 'dashboard';
  const startLink = document.querySelector(`[data-tab="${startTab}"]`);
  if (startLink) {
    switchTab(startTab, startLink);
    loadSummary();
  } else {
    loadAll();
  }
})();
