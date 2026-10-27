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
  Delete: '#dc3545'
};

const TYPE_LABELS = new Proxy({}, {
  get: (_, k) => {
    if (k === 'Read')   return t('type.read');
    if (k === 'Write')  return t('type.write');
    if (k === 'Delete') return t('type.delete');
    return typeof k === 'string' ? k : undefined;
  }
});

function getDays() {
  return parseInt(document.getElementById('daysFilter').value, 10);
}

async function api(path, options = {}) {
  const headers = { ...(options.headers || {}), ...authHeaders() };
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

function typeBadge(type) {
  const cls = { Read: 'primary', Write: 'success', Delete: 'danger' };
  return `<span class="badge bg-${cls[type] || 'secondary'}">${TYPE_LABELS[type] || type}</span>`;
}

// ── Summary Cards ─────────────────────────────────────────────────
async function loadSummary() {
  const d = await api(`/api/stats/summary?days=${getDays()}`);
  document.getElementById('totalCount').textContent = fmtNum(d.total);
  document.getElementById('uniqueFiles').textContent = fmtNum(d.uniqueFiles);
  document.getElementById('uniqueUsers').textContent = fmtNum(d.uniqueUsers);
  const badges = (d.byType || []).map(tp =>
    `<span class="badge me-1" style="background:${TYPE_COLORS[tp.type] || '#6c757d'}">${TYPE_LABELS[tp.type] || tp.type}: ${fmtNum(tp.count)}</span>`
  ).join('');
  document.getElementById('accessTypesBadge').innerHTML = badges;
}

// ── Timeline Chart ────────────────────────────────────────────────
async function loadTimeline() {
  const data = await api(`/api/stats/timeline?days=${getDays()}`);

  const dates = [...new Set(data.map(d => localDay(d.date)))].sort();
  const types = ['Read', 'Write', 'Delete'];
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
      labels: files.map(f => f.fileName || f.filePath),
      datasets: [
        { label: t('type.read'),   data: files.map(f => f.read),   backgroundColor: TYPE_COLORS.Read },
        { label: t('type.write'),  data: files.map(f => f.write),  backgroundColor: TYPE_COLORS.Write },
        { label: t('type.delete'), data: files.map(f => f.delete), backgroundColor: TYPE_COLORS.Delete }
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
      labels: folders.map(f => f.folderName || f.folderPath),
      datasets: [
        { label: t('type.read'),   data: folders.map(f => f.read),   backgroundColor: TYPE_COLORS.Read },
        { label: t('type.write'),  data: folders.map(f => f.write),  backgroundColor: TYPE_COLORS.Write },
        { label: t('type.delete'), data: folders.map(f => f.delete), backgroundColor: TYPE_COLORS.Delete }
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
      <td class="path-cell text-muted" title="${esc(f.filePath)}">${esc(f.filePath)}</td>
      <td class="text-end">
        <div class="d-flex align-items-center gap-2 justify-content-end">
          <span>${fmtNum(f.total)}</span>
          <div class="access-bar"><div class="access-bar-fill" style="width:${(f.total/maxTotal*100).toFixed(1)}%"></div></div>
        </div>
      </td>
      <td class="text-end text-primary">${fmtNum(f.read)}</td>
      <td class="text-end text-success">${fmtNum(f.write)}</td>
      <td class="text-end text-danger">${fmtNum(f.delete)}</td>
      <td>${fmtDate(f.lastAccess)}</td>
      <td><span class="text-truncate d-inline-block" style="max-width:120px" title="${esc(f.topUser || '')}">${esc(f.topUser || '-')}</span></td>
      <td><button class="btn btn-sm btn-outline-secondary py-0" data-path="${esc(f.filePath)}" onclick="showFileDetail(this.dataset.path)">${t('btn.detail')}</button></td>
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
      <td class="path-cell text-muted" title="${esc(f.folderPath)}">${esc(f.folderPath)}</td>
      <td class="text-end">
        <div class="d-flex align-items-center gap-2 justify-content-end">
          <span>${fmtNum(f.total)}</span>
          <div class="access-bar"><div class="access-bar-fill" style="width:${(f.total/maxTotal*100).toFixed(1)}%"></div></div>
        </div>
      </td>
      <td class="text-end text-primary">${fmtNum(f.read)}</td>
      <td class="text-end text-success">${fmtNum(f.write)}</td>
      <td class="text-end text-danger">${fmtNum(f.delete)}</td>
      <td class="text-end">${fmtNum(f.uniqueFiles)}</td>
      <td>${fmtDate(f.lastAccess)}</td>
      <td><button class="btn btn-sm btn-outline-secondary py-0" data-path="${esc(f.folderPath)}" onclick="showFolderDetail(this.dataset.path)">${t('btn.detail')}</button></td>
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
      <td class="text-end text-success">${fmtNum(u.write)}</td>
      <td class="text-end text-danger">${fmtNum(u.delete)}</td>
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
      <td class="text-end fw-bold">${fmtNum(f.total)}</td>
      <td class="text-end text-primary">${fmtNum(f.read)}</td>
      <td class="text-end text-success">${fmtNum(f.write)}</td>
      <td class="text-end text-danger">${fmtNum(f.delete)}</td>
      <td class="text-muted small">${fmtDate(f.lastAccess)}</td>
    </tr>`).join('');

  const recentRows = (d.recent || []).map(r =>
    `<tr>
      <td class="text-muted">${fmtDate(r.accessTime)}</td>
      <td title="${esc(r.filePath)}">${esc(r.fileName)}</td>
      <td>${typeBadge(r.accessType)}</td>
    </tr>`).join('');

  const noData = `<tr><td colspan="3" class="text-muted text-center">${t('msg.noData')}</td></tr>`;

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
      </div>
      <div class="col-12 col-md-8">
        <div class="detail-section-title"><i class="bi bi-file-earmark me-1"></i>${t('detail.fileList')}</div>
        <div style="max-height:300px;overflow-y:auto">
          <table class="table table-sm table-hover">
            <thead class="table-light sticky-top">
              <tr><th>#</th><th>${t('th.filename')}</th><th class="text-end">${t('th.total')}</th><th class="text-end">${t('th.read')}</th><th class="text-end">${t('th.write')}</th><th class="text-end">${t('th.delete')}</th><th>${t('th.lastAccess')}</th></tr>
            </thead>
            <tbody>${fileRows || `<tr><td colspan="7" class="text-muted text-center">${t('msg.noData')}</td></tr>`}</tbody>
          </table>
        </div>
      </div>
      <div class="col-12">
        <div class="detail-section-title"><i class="bi bi-clock-history me-1"></i>${t('detail.recent')}</div>
        <table class="table table-sm">
          <thead><tr><th>${t('th.datetime')}</th><th>${t('th.filename')}</th><th>${t('th.type')}</th></tr></thead>
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
  const data = await api(`/api/stats/recent?page=${page}&pageSize=${PAGE_SIZE}`);

  const tbody = document.getElementById('recentTableBody');
  tbody.innerHTML = (data.items || []).map(r => {
    const srcParts = [];
    if (r.clientIp) srcParts.push(`<span class="font-monospace">${esc(r.clientIp)}</span>`);
    if (r.clientMachine && r.clientMachine !== r.clientIp) srcParts.push(esc(r.clientMachine));
    const srcCell = srcParts.length
      ? `<td class="text-muted small">${srcParts.join('<br>')}</td>`
      : `<td class="text-muted small">-</td>`;
    return `
    <tr>
      <td class="text-muted">${fmtDate(r.accessTime)}</td>
      <td>${esc(r.fileName)}</td>
      <td class="path-cell text-muted" title="${esc(r.folderPath)}">${esc(r.folderPath)}</td>
      <td>${esc(r.userName)}</td>
      <td>${typeBadge(r.accessType)}</td>
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

async function loadSearch(page = 1) {
  searchPage = page;
  const inputVal = document.getElementById('searchTagInput')?.value.trim() ?? '';
  const keywords = [...searchKeywords, ...(inputVal ? [inputVal] : [])];
  const type = document.getElementById('searchType')?.value ?? '';

  const resultsEl = document.getElementById('searchResults');
  if (!resultsEl) return;
  resultsEl.innerHTML = '<div class="text-center py-4"><div class="spinner-border"></div></div>';

  try {
    let url = `/api/stats/search?page=${page}&pageSize=${PAGE_SIZE}`;
    if (searchPeriod.mode === 'days') {
      url += `&days=${searchPeriod.days}`;
    } else {
      url += `&days=0`;
      if (searchPeriod.from) url += `&dateFrom=${encodeURIComponent(searchPeriod.from)}`;
      if (searchPeriod.to)   url += `&dateTo=${encodeURIComponent(searchPeriod.to)}`;
    }
    keywords.forEach(kw => { url += `&q=${encodeURIComponent(kw)}`; });
    if (type) url += `&type=${encodeURIComponent(type)}`;

    const data = await api(url);

    if (!data.items || data.items.length === 0) {
      resultsEl.innerHTML = `<div class="text-muted text-center py-5"><i class="bi bi-search me-2 fs-4"></i><div class="mt-2">${t('search.noResult')}</div></div>`;
      return;
    }

    const rows = data.items.map(r => {
      const srcParts = [];
      if (r.clientIp) srcParts.push(`<span class="font-monospace">${esc(r.clientIp)}</span>`);
      if (r.clientMachine && r.clientMachine !== r.clientIp) srcParts.push(esc(r.clientMachine));
      return `<tr>
        <td class="text-muted">${fmtDate(r.accessTime)}</td>
        <td>${esc(r.fileName)}</td>
        <td class="path-cell text-muted" title="${esc(r.folderPath)}">${esc(r.folderPath)}</td>
        <td>${esc(r.userName)}</td>
        <td>${typeBadge(r.accessType)}</td>
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
async function showFileDetail(path) {
  const modal = new bootstrap.Modal(document.getElementById('detailModal'));
  document.getElementById('detailModalTitle').textContent = t('detail.fileDetail') + path;
  document.getElementById('detailModalBody').innerHTML =
    '<div class="text-center py-4"><div class="spinner-border"></div></div>';
  modal.show();

  const d = await api(`/api/stats/file-detail?path=${encodeURIComponent(path)}&days=${getDays()}`);
  document.getElementById('detailModalBody').innerHTML = buildDetailHtml(d, 'file');
  renderDetailCharts(d);
}

async function showFolderDetail(path) {
  const modal = new bootstrap.Modal(document.getElementById('detailModal'));
  document.getElementById('detailModalTitle').textContent = t('detail.folderDetail') + path;
  document.getElementById('detailModalBody').innerHTML =
    '<div class="text-center py-4"><div class="spinner-border"></div></div>';
  modal.show();

  const d = await api(`/api/stats/folder-detail?path=${encodeURIComponent(path)}&days=${getDays()}`);
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
    `<tr><td class="text-muted">${fmtDate(r.accessTime)}</td><td>${esc(r.userName)}</td><td>${typeBadge(r.accessType)}</td></tr>`
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
    case 'settings':  loadSettings(); break;
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
    const av = a.cells[colIdx]?.textContent.trim() || '';
    const bv = b.cells[colIdx]?.textContent.trim() || '';
    const an = parseFloat(av.replace(/,/g, ''));
    const bn = parseFloat(bv.replace(/,/g, ''));
    const cmp = isNaN(an) ? av.localeCompare(bv, 'ja') : an - bn;
    return asc ? cmp : -cmp;
  });
  rows.forEach(r => tbody.appendChild(r));
}

// ── Settings Tab ──────────────────────────────────────────────────
async function loadSettings() {
  try {
    const d = await api('/api/settings');
    // Support both new pathConfigs and legacy monitoredPaths response
    const configs = d.pathConfigs
      || (d.monitoredPaths || []).map(p => ({ path: p, eventTypes: ['Read', 'Write', 'Delete'] }));
    renderPathsList(configs);
    const dnsInput = document.getElementById('dnsServerInput');
    if (dnsInput) dnsInput.value = d.dnsServer || '';
  } catch (e) {
    document.getElementById('monitoredPathsList').innerHTML =
      `<div class="text-danger small">${esc(e.message)}</div>`;
  }
  loadRetentionPolicy();
  if (isAdmin()) {
    const sec = document.getElementById('usermgmtSettingsSection');
    if (sec) sec.classList.remove('d-none');
    loadUsersMgmt();
  } else {
    const s = document.getElementById('retentionAdminSection');
    if (s) s.classList.add('d-none');
  }
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

const EVENT_TYPES = ['Read', 'Write', 'Delete'];
const EVENT_TYPE_COLORS = { Read: 'primary', Write: 'success', Delete: 'danger' };

function renderPathsList(configs) {
  const el = document.getElementById('monitoredPathsList');
  if (!configs || configs.length === 0) {
    el.innerHTML = `<div class="text-muted small py-2">${t('msg.noPath')}</div>`;
    return;
  }
  el.innerHTML = configs.map(cfg => {
    const p = cfg.path || cfg; // support legacy string format
    const types = cfg.eventTypes || EVENT_TYPES;
    const typeCheckboxes = EVENT_TYPES.map(et => {
      const checked = types.includes(et) ? 'checked' : '';
      const color = EVENT_TYPE_COLORS[et];
      const label = t('type.' + et.toLowerCase());
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
  btn.innerHTML = `<span class="spinner-border spinner-border-sm me-1"></span>${t('msg.applying')}`;

  try {
    const res = await fetch('/api/settings/paths', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ path, eventTypes })
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
      if (d.pathConfigs) renderPathsList(d.pathConfigs); else loadSettings();
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
    showSettingsAlert(`<span class="spinner-border spinner-border-sm me-1"></span>${t('msg.removingSacl')}`, 'info');
  }

  try {
    const res = await fetch(
      `/api/settings/paths?path=${encodeURIComponent(path)}&removeSacl=${removeSacl}`,
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
      body: JSON.stringify({ path, eventTypes })
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
    showSettingsAlert(`<span class="spinner-border spinner-border-sm me-1"></span>${t('msg.applyingSacl')}`, 'info');
    const res = await fetch('/api/settings/paths/apply-sacl', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ path })
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
    }
  } catch (e) {
    showSettingsAlert(`${esc(e.message)}`, 'danger');
  }
}

// ── User Management (Admin only) ──────────────────────────────────
function isAdmin() {
  return getUser()?.roles?.includes('Admin') === true;
}

async function loadUsersMgmt() {
  const tbody = document.getElementById('usermgmtTableBody');
  tbody.innerHTML = '<tr><td colspan="4" class="text-center py-3"><div class="spinner-border spinner-border-sm"></div></td></tr>';
  try {
    const users = await api('/api/users');
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
        <td>
          <div class="d-flex gap-1">
            <button class="btn btn-sm btn-outline-secondary py-0" onclick="showResetPassword('${esc(u.id)}', '${esc(u.username)}')">
              <i class="bi bi-key"></i>
            </button>
            ${isSelf ? '' : `<button class="btn btn-sm btn-outline-danger py-0" onclick="deleteUser('${esc(u.id)}', '${esc(u.username)}')"><i class="bi bi-trash"></i></button>`}
          </div>
        </td>
      </tr>`;
    }).join('') || `<tr><td colspan="4" class="text-muted text-center py-3">${t('msg.noUsers')}</td></tr>`;
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="4" class="text-danger small p-3"><i class="bi bi-exclamation-triangle me-1"></i>${esc(e.message)}</td></tr>`;
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
    await api('/api/me/change-password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ currentPassword, newPassword })
    });
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
const VALID_TABS = ['dashboard', 'files', 'folders', 'users', 'recent', 'search', 'settings'];
const hashTab = location.hash.slice(1);
const startTab = VALID_TABS.includes(hashTab) ? hashTab : 'dashboard';
const startLink = document.querySelector(`[data-tab="${startTab}"]`);
if (startLink) {
  switchTab(startTab, startLink);
  loadSummary();
} else {
  loadAll();
}
