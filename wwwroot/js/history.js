// File history dialog (#historyModal): the timeline of one file or folder, followed through renames and moves.
// historyButtonHtml(r) is called by app.js wherever files are listed; r = { filePath, serverName, accessTime?, isFolder? }

const HIST_KINDS = [
  { key: 'create', kinds: ['create'], color: '#198754', icon: 'bi-plus-circle-fill' },
  { key: 'read', kinds: ['read'], color: '#0d6efd', icon: 'bi-eye-fill' },
  { key: 'write', kinds: ['write'], color: '#20a39e', icon: 'bi-pencil-fill' },
  { key: 'rename', kinds: ['rename', 'move'], color: '#e0a800', icon: 'bi-arrow-left-right' },
  { key: 'permission', kinds: ['permission'], color: '#6f42c1', icon: 'bi-shield-lock-fill' },
  { key: 'denied', kinds: ['denied'], color: '#dc3545', icon: 'bi-slash-circle-fill' },
  { key: 'delete', kinds: ['delete'], color: '#842029', icon: 'bi-trash-fill' },
];

// state of the open dialog
let histState = null;

function historyButtonHtml(r) {
  if (!r || !r.filePath) return '';
  return `<button type="button" class="btn btn-link btn-sm p-0 ms-1 align-baseline history-btn" title="${esc(t('hist.button'))}"
    data-path="${esc(r.filePath)}" data-server="${esc(r.serverName || '')}" data-at="${esc(r.accessTime || '')}"
    onclick="event.stopPropagation(); showFileHistory(this)"><i class="bi bi-clock-history"></i></button>`;
}

function showFileHistory(btn) {
  openFileHistory({ path: btn.dataset.path, server: btn.dataset.server, at: btn.dataset.at || '' });
}

// Another dialog (the file details) is closed first: Bootstrap does not stack dialogs well
function openFileHistory(opts) {
  const modalEl = document.getElementById('historyModal');
  const others = [...document.querySelectorAll('.modal.show')].filter(m => m !== modalEl);
  const show = () => {
    histState = { ...opts, data: null, hidden: new Set() };
    document.getElementById('historyModalTitle').textContent = t('hist.title');
    document.getElementById('historyModalBody').innerHTML =
      `<div class="text-center text-muted py-4"><div class="spinner-border spinner-border-sm me-2"></div>${esc(t('hist.loading'))}</div>`;
    bootstrap.Modal.getOrCreateInstance(modalEl).show();
    loadFileHistory();
  };
  if (others.length === 0) { show(); return; }
  let pending = others.length;
  others.forEach(m => {
    m.addEventListener('hidden.bs.modal', () => { if (--pending === 0) show(); }, { once: true });
    bootstrap.Modal.getOrCreateInstance(m).hide();
  });
}

function historyQuery() {
  const s = histState;
  return `server=${encodeURIComponent(s.server)}&path=${encodeURIComponent(s.path)}&at=${encodeURIComponent(s.at)}&days=0&collapse=true`;
}

async function loadFileHistory() {
  const body = document.getElementById('historyModalBody');
  try {
    const data = await api(`/api/stats/file-history?${historyQuery()}&maxEvents=500`);
    histState.data = data;
    // a long list of reads hides them first; the checkbox shows them
    const reads = data.steps.filter(s => s.kind === 'read').length;
    if (reads > 50) histState.hidden.add('read');
    renderFileHistory();
  } catch (e) {
    body.innerHTML = `<div class="alert alert-warning mb-0">${esc(e.message)}</div>`;
  }
}

// Texts whose key is built from a name the server sent (the keys are all in lang/history.js)
function histT(prefix, name) {
  return t(prefix + name);
}

function histTime(utc) {
  if (!utc) return '';
  const d = new Date(/[Z+]/.test(utc) ? utc : utc + 'Z');
  return d.toLocaleString(getLang() === 'en' ? 'en-US' : 'ja-JP', {
    year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function histClock(utc) {
  const d = new Date(/[Z+]/.test(utc) ? utc : utc + 'Z');
  return d.toLocaleTimeString(getLang() === 'en' ? 'en-US' : 'ja-JP', { hour: '2-digit', minute: '2-digit' });
}

// "old -> new" of a rename or move: the folder part the two paths share is dimmed
function histRenameHtml(from, to) {
  if (!to) return `<span class="font-monospace small text-break">${esc(from)}</span>`;
  const sep = from.includes('/') && !from.includes('\\') ? '/' : '\\';
  const a = from.split(sep), b = to.split(sep);
  let i = 0;
  while (i < a.length - 1 && i < b.length - 1 && a[i].toLowerCase() === b[i].toLowerCase()) i++;
  const common = a.slice(0, i).join(sep) + (i > 0 ? sep : '');
  const dim = common ? `<span class="text-muted">${esc(common)}</span>` : '';
  return `<span class="font-monospace small text-break">${dim}${esc(a.slice(i).join(sep))}
    <i class="bi bi-arrow-right mx-1"></i>${dim}${esc(b.slice(i).join(sep))}</span>`;
}

function histKindInfo(kind) {
  return HIST_KINDS.find(k => k.kinds.includes(kind));
}

function histStepHtml(s) {
  if (s.kind === 'gap') {
    return `<li class="position-relative pb-3"><div class="border border-secondary-subtle rounded text-muted small px-2 py-1"
      style="border-style:dashed !important"><i class="bi bi-three-dots me-1"></i>${esc(histT('hist.gap.', s.gap.reason))}</div></li>`;
  }
  const info = histKindInfo(s.kind) || HIST_KINDS[1];
  const label = histT('hist.kind.', s.kind);
  let when = histTime(s.time);
  let what = esc(label);
  if (s.count > 1)
    what = esc(t('hist.readCollapsed', { n: s.count, from: histClock(s.firstTime), to: histClock(s.lastTime) }));
  const denied = s.kind === 'denied' && typeof typeBadge === 'function' ? ' ' + typeBadge(s.type) : '';
  const atCreation = s.kind === 'permission' && s.atCreation
    ? ` <span class="badge bg-secondary-subtle text-secondary-emphasis fw-normal" title="${esc(t('hist.atCreationTip'))}">${esc(t('hist.atCreation'))}</span>` : '';
  const detailBtn = s.detail
    ? ` <button type="button" class="btn btn-link btn-sm p-0 align-baseline record-detail-btn" data-detail="${esc(s.detail)}" title="${esc(t('btn.detail'))}" onclick="showRecordDetail(this)"><i class="bi bi-info-circle"></i></button>` : '';
  const client = s.clientIp ? `<span class="text-muted small ms-1">${esc(s.clientMachine ? `${s.clientIp} (${s.clientMachine})` : s.clientIp)}</span>` : '';
  let extra = '';
  if (s.kind === 'rename' || s.kind === 'move') extra = `<div>${histRenameHtml(s.path, s.newPath)}</div>`;
  if (s.viaFolder) extra += `<div class="small text-muted text-break">${esc(t('hist.via', { path: s.viaFolder }))}</div>`;
  return `<li class="position-relative pb-3">
    <span class="position-absolute rounded-circle" style="left:-1.6rem;top:.2rem;width:.9rem;height:.9rem;background:${info.color};border:2px solid var(--bs-body-bg)"></span>
    <div class="d-flex flex-wrap align-items-baseline gap-2"><strong style="color:${info.color}">${what}</strong>${denied}${atCreation}${detailBtn}
      <span class="text-muted small">${esc(when)}</span><span class="small">${esc(s.user || '')}</span>${client}</div>${extra}</li>`;
}

function renderFileHistory() {
  const { data, hidden } = histState;
  const body = document.getElementById('historyModalBody');
  document.getElementById('historyModalTitle').textContent = t('hist.title');

  const current = data.paths.length ? data.paths[data.paths.length - 1].path : data.path;
  const deleted = [...data.steps].reverse().find(s => s.kind === 'delete');
  let state = histT('hist.end.', data.end);
  if (data.end === 'deleted' && deleted) state += ` (${histTime(deleted.time)})`;
  const summary = `<div class="mb-2"><span class="badge text-bg-light border me-1">${esc(histT('hist.origin.', data.origin))}</span>
    <i class="bi bi-arrow-right text-muted me-1"></i><span class="badge text-bg-light border">${esc(state)}</span></div>`;

  const warnings = [];
  if (data.truncated.events) warnings.push(t('hist.warn.events'));
  if (data.truncated.hops) warnings.push(t('hist.warn.hops'));
  if (data.truncated.window) warnings.push(t('hist.warn.window'));

  const present = HIST_KINDS.filter(k => data.steps.some(s => k.kinds.includes(s.kind)));
  const filters = present.map(k => `<div class="form-check form-check-inline">
    <input class="form-check-input" type="checkbox" id="histKind_${k.key}" ${hidden.has(k.key) ? '' : 'checked'} onchange="toggleHistoryKind('${k.key}', this.checked)">
    <label class="form-check-label small" for="histKind_${k.key}"><span style="color:${k.color}"><i class="bi ${k.icon}"></i></span> ${esc(histT('hist.kind.', k.kinds[0]))}</label></div>`).join('');

  const hiddenKinds = new Set(HIST_KINDS.filter(k => hidden.has(k.key)).flatMap(k => k.kinds));
  const items = [];
  let lastPath = null;
  for (const s of data.steps) {
    if (s.kind !== 'gap' && hiddenKinds.has(s.kind)) continue;
    if (s.kind !== 'gap' && s.path && s.path.toLowerCase() !== lastPath) {
      items.push(`<li class="position-relative pb-2"><span class="small fw-semibold text-break"><i class="bi bi-folder2-open me-1"></i>${esc(t(lastPath === null ? 'hist.pathAt' : 'hist.pathNow', { path: s.path }))}</span></li>`);
      lastPath = s.path.toLowerCase();
    }
    items.push(histStepHtml(s));
  }
  const timeline = items.length
    ? `<ol class="list-unstyled ms-3 border-start border-2 ps-3 mb-0">${items.join('')}</ol>`
    : `<div class="text-muted">${esc(t('hist.noSteps'))}</div>`;

  body.innerHTML = `
    <div class="mb-1 fw-semibold text-break font-monospace">${esc(data.path)}</div>
    <div class="small text-muted mb-2">${esc(data.server)}</div>
    ${summary}
    ${warnings.map(w => `<div class="alert alert-warning py-1 small mb-2">${esc(w)}</div>`).join('')}
    <div class="d-flex flex-wrap align-items-center gap-2 mb-3">
      <div class="flex-grow-1">${filters}</div>
      <button class="btn btn-outline-secondary btn-sm" onclick="historyOpenInSearch()"><i class="bi bi-search me-1"></i>${esc(t('hist.openSearch'))}</button>
      <button class="btn btn-outline-secondary btn-sm" onclick="historyExportCsv()"><i class="bi bi-filetype-csv me-1"></i>${esc(t('hist.csv'))}</button>
    </div>
    ${timeline}
    <div class="small text-muted mt-3">${esc(t('hist.hint'))}</div>`;
  body.dataset.current = current;
}

function toggleHistoryKind(key, on) {
  if (on) histState.hidden.delete(key); else histState.hidden.add(key);
  renderFileHistory();
}

// The search tab with the current path of the file as the keyword
function historyOpenInSearch() {
  const current = document.getElementById('historyModalBody').dataset.current || histState.path;
  bootstrap.Modal.getInstance(document.getElementById('historyModal'))?.hide();
  searchKeywords = [current];
  renderSearchTags();
  selectSearchPeriodQuick(0);
  document.getElementById('searchResult').value = '';
  document.getElementById('searchType').value = '';
  switchTab('search', document.querySelector('#mainTabs [data-tab="search"]'));
  runSearch();
}

async function historyExportCsv() {
  try {
    const tz = -new Date().getTimezoneOffset();
    const res = await fetch(`/api/stats/file-history/export?${historyQuery()}&tzOffsetMinutes=${tz}`, { headers: authHeaders() });
    if (res.status === 401) { logout(); return; }
    if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || `HTTP ${res.status}`);
    const name = /filename="([^"]+)"/.exec(res.headers.get('Content-Disposition') || '')?.[1] || 'file-history.csv';
    const url = URL.createObjectURL(await res.blob());
    const a = document.createElement('a');
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  } catch (e) {
    alert(e.message);
  }
}
