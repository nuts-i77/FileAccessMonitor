// Permissions tab (Admin, and Viewers with a folder scope): who may do what below a monitored
// folder, as of the last scan. Scans are started by Admins; scoped Viewers read the stored result.
window.TabHooks = window.TabHooks || {};
window.TabHooks.permissions = () => permLoadTab();

let permBuilt = false;
let permView = null;
let permPage = 1;
let permFilterTimer = null;

// Texts by the codes the API sends
const PERM_LEVEL_KEYS = {
  full: 'perm.level.full', modify: 'perm.level.modify', readWrite: 'perm.level.readWrite', write: 'perm.level.write',
  read: 'perm.level.read', list: 'perm.level.list', traverse: 'perm.level.traverse', special: 'perm.level.special',
};
const PERM_SCOPE_KEYS = {
  1: 'perm.scope.1', 2: 'perm.scope.2', 3: 'perm.scope.3', 4: 'perm.scope.4', 5: 'perm.scope.5', 6: 'perm.scope.6', 7: 'perm.scope.7',
};
const PERM_BROAD_KEYS = {
  everyone: 'perm.broad.everyone', authenticatedUsers: 'perm.broad.authenticatedUsers', users: 'perm.broad.users',
  guests: 'perm.broad.guests', anonymous: 'perm.broad.anonymous', network: 'perm.broad.network',
  interactive: 'perm.broad.interactive', domainUsers: 'perm.broad.domainUsers', domainGuests: 'perm.broad.domainGuests',
  domainComputers: 'perm.broad.domainComputers', other: 'perm.broad.other', group: 'perm.broad.group', custom: 'perm.broad.custom',
};
const PERM_LIMIT_KEYS = {
  folders: 'perm.limit.folders', files: 'perm.limit.files', time: 'perm.limit.time', depth: 'perm.limit.depth', rows: 'perm.limit.rows',
};

function permBuildShell() {
  document.getElementById('permissionsRoot').innerHTML = `
    <div class="card mb-3">
      <div class="card-body">
        <p class="small text-muted mb-3">${t('perm.hint')}</p>
        <div class="row g-2 align-items-end">
          <div class="col-12 col-md-3 d-none" id="permServerCol">
            <label class="form-label small text-muted" for="permServer">${t('servers.target')}</label>
            <select id="permServer" class="form-select form-select-sm" onchange="permLoadRoots()"></select>
          </div>
          <div class="col-12 col-md">
            <label class="form-label small text-muted" for="permFolder">${t('perm.folder')}</label>
            <select id="permFolder" class="form-select form-select-sm font-monospace" onchange="permLoadReport(1)"></select>
          </div>
          <div class="col-auto">
            <button class="btn btn-sm btn-primary d-none" id="permScanBtn" onclick="permScan()"><i class="bi bi-arrow-repeat me-1"></i>${t('perm.scan')}</button>
            <button class="btn btn-sm btn-outline-secondary" id="permCsvBtn" onclick="permExport()" disabled><i class="bi bi-download me-1"></i>${t('perm.csv')}</button>
          </div>
        </div>
        <div class="row g-2 align-items-center mt-1">
          <div class="col-auto form-check ms-2">
            <input type="checkbox" class="form-check-input" id="permBroadOnly" onchange="permLoadReport(1)">
            <label class="form-check-label small" for="permBroadOnly">${t('perm.broadOnly')}</label>
          </div>
          <div class="col-auto form-check ms-2">
            <input type="checkbox" class="form-check-input" id="permBrokenOnly" onchange="permLoadReport(1)">
            <label class="form-check-label small" for="permBrokenOnly">${t('perm.brokenOnly')}</label>
          </div>
          <div class="col-auto form-check ms-2">
            <input type="checkbox" class="form-check-input" id="permShowOwner" onchange="permRender()">
            <label class="form-check-label small" for="permShowOwner">${t('perm.showOwner')}</label>
          </div>
          <div class="col-12 col-md-3 ms-md-auto">
            <input type="search" id="permText" class="form-control form-control-sm" placeholder="${esc(t('perm.filterPh'))}" oninput="permFilterSoon()">
          </div>
        </div>
      </div>
    </div>
    <div id="permResults"></div>`;
  permBuilt = true;
}

async function permLoadTab() {
  if (!permBuilt) permBuildShell();
  const sel = document.getElementById('permServer');
  if (sel.dataset.loaded) return;
  try {
    const d = await api('/api/permissions/servers');
    sel.innerHTML = d.servers.map(n => `<option value="${esc(n)}">${esc(n)}${n === d.local ? ' ' + esc(t('servers.thisServer')) : ''}</option>`).join('');
    sel.dataset.loaded = '1';
    document.getElementById('permServerCol').classList.toggle('d-none', d.servers.length < 2);
  } catch (e) {
    permShowError(e.message);
    return;
  }
  await permLoadRoots();
}

function permShowError(message) {
  document.getElementById('permResults').innerHTML =
    `<div class="alert alert-danger py-2 small"><i class="bi bi-exclamation-triangle me-1"></i>${esc(message)}</div>`;
}

// "3 days ago" for the age of a scan
function permAge(time) {
  if (!time) return t('perm.neverScanned');
  const minutes = Math.max(0, Math.round((Date.now() - new Date(/[Z+]/.test(time) ? time : time + 'Z').getTime()) / 60000));
  if (minutes < 60) return t('perm.agoMinutes', { n: minutes });
  if (minutes < 60 * 48) return t('perm.agoHours', { n: Math.round(minutes / 60) });
  return t('perm.agoDays', { n: Math.round(minutes / 1440) });
}

async function permLoadRoots() {
  const server = document.getElementById('permServer').value;
  const folderSel = document.getElementById('permFolder');
  document.getElementById('permResults').innerHTML = '';
  try {
    const d = await api(`/api/permissions/roots?server=${encodeURIComponent(server)}`);
    folderSel.innerHTML = d.roots.map(r =>
      `<option value="${esc(r.path)}">${esc(r.path)}  (${esc(permAge(r.scannedAt))})</option>`).join('');
    document.getElementById('permScanBtn').classList.toggle('d-none', !d.canScan);
    if (!d.roots.length) {
      document.getElementById('permResults').innerHTML = `<div class="text-muted small">${t('perm.noFolders')}</div>`;
      document.getElementById('permCsvBtn').disabled = true;
      return;
    }
  } catch (e) {
    permShowError(e.message);
    return;
  }
  await permLoadReport(1);
}

function permFilterSoon() {
  clearTimeout(permFilterTimer);
  permFilterTimer = setTimeout(() => permLoadReport(1), 300);
}

function permQuery() {
  const q = document.getElementById('permText').value.trim();
  return `server=${encodeURIComponent(document.getElementById('permServer').value)}` +
    `&folder=${encodeURIComponent(document.getElementById('permFolder').value)}` +
    `&broadOnly=${document.getElementById('permBroadOnly').checked}` +
    `&brokenOnly=${document.getElementById('permBrokenOnly').checked}` +
    (q ? `&q=${encodeURIComponent(q)}` : '');
}

async function permLoadReport(page) {
  if (!document.getElementById('permFolder').value) return;
  permPage = page;
  const el = document.getElementById('permResults');
  try {
    permView = await api(`/api/permissions?${permQuery()}&page=${page}&pageSize=200`);
    permRender();
  } catch (e) {
    permView = null;
    document.getElementById('permCsvBtn').disabled = true;
    // Not scanned yet: say so, the Scan button is right above
    el.innerHTML = `<div class="alert alert-info py-2 small"><i class="bi bi-info-circle me-1"></i>${esc(e.message)}</div>`;
  }
}

async function permScan() {
  const btn = document.getElementById('permScanBtn');
  const el = document.getElementById('permResults');
  btn.disabled = true;
  el.innerHTML = `<div class="text-center py-4"><div class="spinner-border"></div><div class="small text-muted mt-2">${t('perm.scanning')}</div></div>`;
  try {
    await api('/api/permissions/scan', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ server: document.getElementById('permServer').value, folder: document.getElementById('permFolder').value }),
    });
    await permLoadRoots();   // the age in the list; also shows the new result
  } catch (e) {
    permShowError(e.message);
  } finally {
    btn.disabled = false;
  }
}

async function permExport() {
  const btn = document.getElementById('permCsvBtn');
  btn.disabled = true;
  try {
    const res = await fetch(`/api/permissions/export?${permQuery()}`, { headers: authHeaders() });
    if (res.status === 401) { logout(); return; }
    if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || `HTTP ${res.status}`);
    const name = /filename="?([^";]+)"?/.exec(res.headers.get('Content-Disposition') || '')?.[1] || 'permissions.csv';
    const url = URL.createObjectURL(await res.blob());
    const a = document.createElement('a');
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  } catch (e) {
    document.getElementById('permResults').insertAdjacentHTML('afterbegin',
      `<div class="alert alert-danger py-2 small"><i class="bi bi-exclamation-triangle me-1"></i>${esc(e.message)}</div>`);
  } finally {
    btn.disabled = !permView;
  }
}

function permLevelText(a) {
  const key = PERM_LEVEL_KEYS[a.levelCode] || PERM_LEVEL_KEYS.special;
  return t(key, { h: a.level.toString(16).toUpperCase() });
}

function permLevelBadge(a) {
  // Deny entries are red, full control and modify orange, the rest grey; a mask-limited entry shows what it was
  const cls = a.kind === 'deny' ? 'bg-danger' : ['full', 'modify'].includes(a.levelCode) ? 'bg-warning text-dark' : 'bg-secondary';
  const before = a.levelBeforeMask ? ` title="${esc(t('perm.beforeMask', { h: a.levelBeforeMask.toString(16).toUpperCase() }))}"` : '';
  return `<span class="badge ${cls}"${before}>${esc(permLevelText(a))}${a.levelBeforeMask ? ' *' : ''}</span>`;
}

function permBroadBadge(a) {
  if (!a.broad) return '';
  const label = t(PERM_BROAD_KEYS[a.broad] || PERM_BROAD_KEYS.custom);
  if (!a.severity) return `<span class="badge bg-light text-muted border">${esc(label)}</span>`;
  const cls = a.severity === 'high' ? 'bg-danger' : 'bg-warning text-dark';
  return `<span class="badge ${cls}" title="${esc(t(a.severity === 'high' ? 'perm.severity.high' : 'perm.severity.medium'))}">${esc(label)}</span>`;
}

function permPathCell(item) {
  const d = permView;
  const name = item.rel ? item.rel.slice(Math.max(item.rel.lastIndexOf('\\'), item.rel.lastIndexOf('/')) + 1) : item.path;
  const flags = [];
  if (item.inheritanceBroken) flags.push(`<span class="badge bg-info text-dark" title="${esc(t('perm.brokenTip'))}"><i class="bi bi-scissors me-1"></i>${t('perm.brokenBadge')}</span>`);
  if (item.notReadable) flags.push(`<span class="badge bg-secondary">${t('perm.notReadable')}</span>`);
  if (item.hasAcl) flags.push(`<span class="badge bg-light text-dark border">${t('perm.acl')}</span>`);
  if (item.hasDefaultAcl) flags.push(`<span class="badge bg-light text-dark border">${t('perm.defaultAcl')}</span>`);
  const icon = item.isFolder ? '<i class="bi bi-folder-fill text-warning me-1"></i>' : '<i class="bi bi-file-earmark me-1"></i>';
  const indent = Math.min(item.depth, 12) * 14;
  const history = typeof historyButtonHtml === 'function'
    ? historyButtonHtml({ filePath: item.path, serverName: d.server, isFolder: item.isFolder }) : '';
  const owner = item.owner && document.getElementById('permShowOwner')?.checked
    ? `<div class="small text-muted">${t('perm.owner')}: ${esc(item.owner)}</div>` : '';
  return `<div style="padding-left:${indent}px">${icon}<span class="${item.depth === 0 ? 'fw-semibold' : ''}" title="${esc(item.path)}">${esc(name)}</span>
    ${flags.join(' ')}${history}${owner}</div>`;
}

function permChangeCell(item) {
  if (!item.lastChange) return '<span class="text-muted">-</span>';
  const link = `<a href="#" data-path="${esc(item.path)}" data-folder="${item.isFolder}" onclick="permShowDetail(this); return false;">${esc(fmtDate(item.lastChange.time))}</a>`;
  const changed = item.changedSinceScan
    ? `<div><span class="badge bg-warning text-dark" title="${esc(t('perm.changedTip'))}"><i class="bi bi-exclamation-triangle me-1"></i>${t('perm.changedSince')}</span></div>` : '';
  return `${link}<div class="small text-muted">${esc(item.lastChange.user)}</div>${changed}`;
}

// The file or folder dialog (shows the permission record) of a row
function permShowDetail(el) {
  const server = permView?.server || '';
  if (el.dataset.folder === 'true') showFolderDetail(el.dataset.path, server);
  else showFileDetail(el.dataset.path, server);
}

function permSharesTable(d) {
  if (!d.shares?.length) return '';
  const yesNo = v => t(v ? 'perm.yes' : 'perm.no');
  const rows = d.shares.map(s => {
    const sev = s.severity ? `<span class="badge ${s.severity === 'high' ? 'bg-danger' : 'bg-warning text-dark'}">${t(s.severity === 'high' ? 'perm.severity.high' : 'perm.severity.medium')}</span>` : '';
    return `<tr><td>${esc(s.name)}</td><td class="font-monospace">${esc(s.path)}</td><td>${yesNo(s.guestOk)}</td><td>${yesNo(s.readOnly)}</td>
      <td>${esc(s.validUsers) || '-'}</td><td>${esc(s.writeList) || '-'}</td><td>${sev}</td></tr>`;
  }).join('');
  return `<div class="card mb-3"><div class="card-header small fw-semibold">${t('perm.shares')}</div>
    <div class="table-responsive"><table class="table table-sm mb-0">
      <thead><tr><th>${t('perm.share')}</th><th>${t('perm.sharePath')}</th><th>${t('perm.guestOk')}</th><th>${t('perm.readOnly')}</th>
        <th>${t('perm.validUsers')}</th><th>${t('perm.writeList')}</th><th></th></tr></thead><tbody>${rows}</tbody></table></div></div>`;
}

function permWarnings(d) {
  const w = [];
  if (d.truncated) w.push(`<div class="alert alert-warning py-2 small mb-2"><i class="bi bi-exclamation-triangle me-1"></i>${t('perm.truncated', { limit: t(PERM_LIMIT_KEYS[d.limit] || PERM_LIMIT_KEYS.rows) })}</div>`);
  if (d.os === 'linux') {
    if (!d.shares?.length && !d.scoped) w.push(`<div class="alert alert-secondary py-2 small mb-2">${t('perm.notShared')}</div>`);
    if (d.shares?.some(s => s.ntAcl)) w.push(`<div class="alert alert-warning py-2 small mb-2"><i class="bi bi-exclamation-triangle me-1"></i>${t('perm.sambaNtAcl')}</div>`);
  }
  if (d.errors?.length) {
    w.push(`<details class="small mb-2"><summary class="text-muted">${t('perm.errors', { n: d.errors.length })}</summary>
      <ul class="mb-0 font-monospace">${d.errors.map(e => `<li>${esc(e)}</li>`).join('')}</ul></details>`);
  }
  if (d.scoped) w.push(`<div class="alert alert-secondary py-2 small mb-2"><i class="bi bi-funnel me-1"></i>${t('perm.scopedBanner')}</div>`);
  return w.join('');
}

function permRender() {
  const d = permView;
  const el = document.getElementById('permResults');
  if (!d) return;
  document.getElementById('permCsvBtn').disabled = false;

  const rows = d.items.map(item => {
    const aces = item.aces.length ? item.aces : [null];
    return aces.map((a, i) => {
      const first = i === 0;
      const span = aces.length;
      const pathCell = first ? `<td rowspan="${span}" class="align-top">${permPathCell(item)}</td>` : '';
      const changeCell = first ? `<td rowspan="${span}" class="align-top">${permChangeCell(item)}</td>` : '';
      const border = first ? '' : ' class="border-top-0"';
      if (!a) return `<tr>${pathCell}<td colspan="5" class="text-muted small">${item.notReadable ? t('perm.notReadable') : t('perm.noEntries')}</td>${changeCell}</tr>`;
      return `<tr${border}>${pathCell}
        <td>${esc(a.principal)}${a.sid && a.sid !== a.principal ? `<div class="small text-muted font-monospace">${esc(a.sid)}</div>` : ''}</td>
        <td>${a.kind === 'deny' ? `<span class="text-danger fw-semibold">${t('perm.deny')}</span>` : t('perm.allow')}</td>
        <td>${permLevelBadge(a)}</td>
        <td class="small">${a.scope && (item.isFolder || d.os === 'linux') ? esc(t(PERM_SCOPE_KEYS[a.scope & 7])) : ''}</td>
        <td>${permBroadBadge(a)}</td>${changeCell}</tr>`;
    }).join('');
  }).join('');

  const pages = Math.max(1, Math.ceil(d.total / d.pageSize));
  const pager = pages > 1 ? `<div class="d-flex justify-content-between align-items-center p-2 small">
      <button class="btn btn-sm btn-outline-secondary" ${d.page <= 1 ? 'disabled' : ''} onclick="permLoadReport(${d.page - 1})">&laquo;</button>
      <span>${t('perm.page', { p: d.page, n: pages, total: fmtNum(d.total) })}</span>
      <button class="btn btn-sm btn-outline-secondary" ${d.page >= pages ? 'disabled' : ''} onclick="permLoadReport(${d.page + 1})">&raquo;</button></div>` : '';

  el.innerHTML = `
    <div class="d-flex flex-wrap align-items-center gap-2 mb-2">
      <span class="small text-muted">${t('perm.scannedAt', { t: esc(fmtDate(d.scannedAt)), age: esc(permAge(d.scannedAt)) })}</span>
      <span class="small text-muted">${t('perm.counts', { folders: fmtNum(d.folders), files: fmtNum(d.files) })}</span>
      <span class="badge bg-danger">${t('perm.countHigh', { n: d.counts.high })}</span>
      <span class="badge bg-warning text-dark">${t('perm.countMedium', { n: d.counts.medium })}</span>
      <span class="badge bg-info text-dark">${t('perm.countBroken', { n: d.counts.broken })}</span>
    </div>
    ${permWarnings(d)}
    ${permSharesTable(d)}
    <div class="card"><div class="table-responsive">
      <table class="table table-sm table-hover mb-0">
        <thead><tr><th>${t('perm.colPath')}</th><th>${t('perm.colPrincipal')}</th><th>${t('perm.colAccess')}</th><th>${t('perm.colLevel')}</th>
          <th>${t('perm.colAppliesTo')}</th><th>${t('perm.colBroad')}</th><th>${t('perm.colChange')}</th></tr></thead>
        <tbody>${rows || `<tr><td colspan="7" class="text-center text-muted py-3">${t('perm.none')}</td></tr>`}</tbody>
      </table></div>${pager}</div>`;
}
