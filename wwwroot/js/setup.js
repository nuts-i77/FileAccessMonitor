// Setup wizard (#setupModal): the admin password, the file server, its first folder, the size of the
// Security log, and the first record. Opens by itself for an Admin while no folder is monitored and the
// wizard was not finished; the button in Settings opens it at any time. Keys of lang/setup.js start with 'setup.'.
window.StartupHooks = window.StartupHooks || {};
window.StartupHooks.setup = () => { if (isAdmin()) setupStartup(); };
// The Security log card under the per-server settings (the same job as the wizard's step)
window.ServerSettingsHooks = window.ServerSettingsHooks || {};
window.ServerSettingsHooks.securityLog = () => loadSecurityLogCard();

const SETUP_LATER_KEY = 'setupWizardLater';   // "Later" in this browser session
const SETUP_POLL_MS = 5000;
const SETUP_WAIT_MS = 3 * 60 * 1000;
const SETUP_LOG_SIZES = [256 * 1024 * 1024, 1024 * 1024 * 1024, 4 * 1024 * 1024 * 1024];

// status: the answer of /api/settings/setup; steps: the names of the steps; server: the chosen file server
let setupState = null;

// Texts whose key is built from a step name (the keys are all in lang/setup.js)
function setupT(prefix, name) {
  return t(prefix + name);
}

async function setupStartup() {
  document.getElementById('setupOpenBtn')?.classList.remove('d-none');
  let later = false;
  try { later = !!sessionStorage.getItem(SETUP_LATER_KEY); } catch { /* private mode */ }
  if (later) return;
  try {
    const status = await api('/api/settings/setup');
    if (!status.done && status.folders === 0) openSetupWizard(status);
  } catch { /* the wizard is a convenience */ }
}

async function openSetupWizard(status) {
  try { status = status || await api('/api/settings/setup'); }
  catch (e) { alert(e.message); return; }
  const servers = setupServers(status);
  const steps = [];
  if (status.initialPasswordPending) steps.push('password');
  if (servers.length !== 1) steps.push('server');
  steps.push('folder', 'log', 'check');
  setupState = { status, steps, index: 0, server: servers.length === 1 ? servers[0] : null, folder: null, poll: null, since: 0 };
  const el = document.getElementById('setupModal');
  el.addEventListener('hidden.bs.modal', setupClosed, { once: true });
  setupRender();
  bootstrap.Modal.getOrCreateInstance(el).show();
}

// The file servers the wizard can set up: this machine (when it collects) and the agents
function setupServers(status) {
  const list = [];
  const common = s => ({ os: s.os || '', folders: s.folders, auditPolicyOk: s.auditPolicyOk, excludeUsers: s.excludeUsers || [] });
  if (status.local)
    list.push({ name: status.local.name, local: true, ok: status.local.connected, ...common(status.local) });
  (status.agents || []).forEach(a =>
    list.push({ name: a.name, local: false, ok: a.online && !a.disabled, online: a.online, disabled: a.disabled, ...common(a) }));
  return list;
}

const setupIsLinux = os => !!os && !/^windows/i.test(os);

// The server parameter of the settings API: nothing for this machine
const setupServerParam = () => setupState.server.local ? null : setupState.server.name;

function setupClosed() {
  if (setupState?.poll) clearInterval(setupState.poll);
  setupState = null;
  try { sessionStorage.setItem(SETUP_LATER_KEY, '1'); } catch { /* shown again next time */ }
}

async function setupNever() {
  try { await api('/api/settings/setup/done', { method: 'PUT' }); } catch { /* closes anyway */ }
  bootstrap.Modal.getInstance(document.getElementById('setupModal'))?.hide();
}

function setupGo(delta) {
  const st = setupState;
  if (st.poll) { clearInterval(st.poll); st.poll = null; }
  let i = st.index + delta;
  // The Security log is a Windows matter
  if (st.steps[i] === 'log' && st.server && setupIsLinux(st.server.os)) i += delta;
  st.index = Math.max(0, Math.min(st.steps.length - 1, i));
  setupRender();
}

function setupMessage(html, kind = 'info') {
  const el = document.getElementById('setupMsg');
  if (el) el.innerHTML = html ? `<div class="alert alert-${kind} py-2 small mb-0">${html}</div>` : '';
}

function setupRender() {
  const st = setupState;
  const step = st.steps[st.index];
  const bar = st.steps.map((s, i) => `<span class="badge rounded-pill ${i === st.index ? 'bg-primary' : i < st.index ? 'bg-success' : 'bg-secondary'}">${i + 1}</span>
    <span class="${i === st.index ? 'fw-semibold' : 'text-muted'} me-3">${esc(setupT('setup.step.', s))}</span>`).join('');
  let html = `<div class="mb-3 small">${bar}</div>`;
  let next = `<button class="btn btn-primary btn-sm" onclick="setupGo(1)">${esc(t('setup.next'))}</button>`;
  let after = null;   // what the step does once its elements are on the page

  if (step === 'password') {
    html += `<p class="small">${esc(t('setup.pw.hint'))}</p>
      <div class="row g-2">
        <div class="col-md-6"><label class="form-label small" for="setupPwCur">${esc(t('setup.pw.current'))}</label>
          <input type="password" id="setupPwCur" class="form-control form-control-sm" autocomplete="current-password"></div>
        <div class="col-md-6"><label class="form-label small" for="setupPwNew">${esc(t('setup.pw.new'))}</label>
          <input type="password" id="setupPwNew" class="form-control form-control-sm" autocomplete="new-password"></div>
      </div>
      <button class="btn btn-primary btn-sm mt-3" id="setupPwBtn" onclick="setupChangePassword()"><i class="bi bi-key me-1"></i>${esc(t('setup.pw.change'))}</button>
      <div id="setupMsg" class="mt-2"></div>`;
    next = `<button class="btn btn-outline-secondary btn-sm" onclick="setupGo(1)">${esc(t('setup.skip'))}</button>`;
  } else if (step === 'server') {
    const servers = setupServers(st.status);
    html += servers.length === 0
      ? `<div class="alert alert-info small">${esc(t('setup.srv.none'))}</div>`
      : `<p class="small">${esc(t('setup.srv.hint'))}</p>` + servers.map((s, i) => `
        <div class="form-check mb-2">
          <input class="form-check-input" type="radio" name="setupServer" id="setupServer${i}" value="${i}" ${!s.ok ? 'disabled' : ''}
            ${st.server?.name === s.name ? 'checked' : ''} onchange="setupPickServer(${i})">
          <label class="form-check-label" for="setupServer${i}">
            <i class="bi ${s.local ? 'bi-hdd-fill' : 'bi-hdd'} me-1 text-muted"></i><strong>${esc(s.name)}</strong>
            ${s.local ? `<span class="text-muted small">(${esc(t('setup.srv.local'))})</span>` : ''}
            ${s.os ? `<span class="badge ${setupIsLinux(s.os) ? 'bg-dark' : 'bg-primary'} ms-1">${setupIsLinux(s.os) ? 'Linux' : 'Windows'}</span>` : ''}
            ${setupServerBadge(s)}
            <span class="text-muted small ms-1">${esc(t('setup.srv.folders', { n: s.folders }))}</span>
          </label>
        </div>`).join('');
    next = `<button class="btn btn-primary btn-sm" onclick="setupGo(1)" ${st.server ? '' : 'disabled'}>${esc(t('setup.next'))}</button>`;
  } else if (step === 'folder') {
    const s = st.server;
    const linux = setupIsLinux(s.os);
    html += `<p class="small">${esc(t('setup.dir.hint', { s: s.name }))}</p>`;
    if (s.folders > 0) {
      html += `<div class="alert alert-info py-2 small" id="setupExisting">${esc(t('setup.dir.existing', { s: s.name, n: s.folders }))}</div>`;
      after = setupLoadExisting;
    }
    html += `<label class="form-label small" for="setupPath">${esc(t('setup.dir.label'))}</label>
      <div class="input-group">
        <input type="text" id="setupPath" class="form-control" placeholder="${linux ? '/srv/share' : 'D:\\Share'}" value="${esc(st.folder || '')}"
          onkeydown="if (event.key === 'Enter') setupAddFolder()">
        <button class="btn btn-primary" id="setupAddBtn" onclick="setupAddFolder()"><i class="bi bi-folder-plus me-1"></i>${esc(t('setup.dir.add'))}</button>
      </div>
      <div class="form-text">${esc(t('setup.dir.large'))}</div>
      <div id="setupMsg" class="mt-2"></div>`;
    next = `<button class="btn btn-primary btn-sm" id="setupNextBtn" onclick="setupGo(1)" ${st.folder || s.folders > 0 ? '' : 'disabled'}>${esc(t('setup.next'))}</button>`;
  } else if (step === 'log') {
    const sizes = SETUP_LOG_SIZES.map(b => `<option value="${b}" ${b === 1024 * 1024 * 1024 ? 'selected' : ''}>${setupSize(b)}</option>`).join('');
    html += `<p class="small">${esc(t('setup.log.hint'))}</p>
      <div id="setupLogInfo" class="small mb-2"><span class="spinner-border spinner-border-sm"></span></div>
      <div class="d-flex align-items-center gap-2">
        <label class="small mb-0" for="setupLogSize">${esc(t('setup.log.size'))}</label>
        <select id="setupLogSize" class="form-select form-select-sm" style="width:auto">${sizes}</select>
        <button class="btn btn-primary btn-sm" id="setupLogBtn" onclick="setupSetLog()" disabled>${esc(t('setup.log.set'))}</button>
      </div>
      <div id="setupMsg" class="mt-2"></div>`;
    after = setupLoadLog;
  } else if (step === 'check') {
    const s = st.server;
    html += `<p class="small">${esc(t('setup.chk.hint', { s: s.name, p: st.folder || '' }))}</p>`;
    // What would keep the record away, known before waiting
    // (adding a folder here turned the auditing on; the reported state is up to a minute old)
    if (s.auditPolicyOk === false && !st.added)
      html += `<div class="alert alert-warning py-2 small">${esc(t(setupIsLinux(s.os) ? 'setup.chk.auditOffLinux' : 'setup.chk.auditOff'))}</div>`;
    if (s.excludeUsers.length)
      html += `<div class="alert alert-secondary py-2 small">${esc(t('setup.chk.excluded', { u: s.excludeUsers.join(', ') }))}</div>`;
    html += `<div id="setupMsg" class="mt-2"><div class="alert alert-info py-2 small mb-0"><span class="spinner-border spinner-border-sm me-2"></span>${esc(t('setup.chk.waiting'))}</div></div>`;
    next = `<button class="btn btn-primary btn-sm" onclick="setupFinish()">${esc(t('setup.finish'))}</button>`;
    after = setupWatch;
  }

  document.getElementById('setupBody').innerHTML = html;
  document.getElementById('setupFooter').innerHTML = `
    <button class="btn btn-link text-muted btn-sm me-auto" data-bs-dismiss="modal">${esc(t('setup.later'))}</button>
    <button class="btn btn-link text-muted btn-sm" onclick="setupNever()">${esc(t('setup.never'))}</button>
    ${st.index > 0 && step !== 'check' ? `<button class="btn btn-outline-secondary btn-sm" onclick="setupGo(-1)">${esc(t('setup.back'))}</button>` : ''}
    ${next}`;
  if (after) after();
}

function setupServerBadge(s) {
  if (s.local) return s.ok ? '' : `<span class="badge bg-warning text-dark ms-1">${esc(t('setup.srv.collectorOff'))}</span>`;
  if (s.disabled) return `<span class="badge bg-secondary ms-1">${esc(t('setup.srv.disabled'))}</span>`;
  return s.online ? `<span class="badge bg-success ms-1">${esc(t('setup.srv.online'))}</span>`
    : `<span class="badge bg-warning text-dark ms-1">${esc(t('setup.srv.offline'))}</span>`;
}

function setupPickServer(i) {
  setupState.server = setupServers(setupState.status)[i];
  setupState.folder = null;
  setupState.added = false;
  setupRender();
}

async function setupChangePassword() {
  const currentPassword = document.getElementById('setupPwCur').value;
  const newPassword = document.getElementById('setupPwNew').value;
  if (!currentPassword || !newPassword) { setupMessage(esc(t('msg.currentPwRequired')), 'warning'); return; }
  const btn = document.getElementById('setupPwBtn');
  btn.disabled = true;
  try {
    const d = await api('/api/me/change-password', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ currentPassword, newPassword }),
    });
    if (d.token) localStorage.setItem('jwt_token', d.token);   // the old token ended with the change
    setupState.status.initialPasswordPending = false;
    setupMessage(`<i class="bi bi-check-circle me-1"></i>${esc(t('setup.pw.changed'))}`, 'success');
    setTimeout(() => setupGo(1), 800);
  } catch (e) {
    setupMessage(esc(e.message), 'danger');
    btn.disabled = false;
  }
}

async function setupAddFolder() {
  const path = document.getElementById('setupPath').value.trim();
  if (!path) { setupMessage(esc(t('msg.pathRequired')), 'warning'); return; }
  const btn = document.getElementById('setupAddBtn');
  btn.disabled = true;
  setupMessage(`<span class="spinner-border spinner-border-sm me-2"></span>${esc(setupState.server.local ? t('msg.applying') : t('msg.agentRunning', { s: setupState.server.name }))}`);
  try {
    const res = await fetch('/api/settings/paths', {
      method: 'POST', headers: { 'Content-Type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ path, server: setupServerParam() }),
    });
    if (res.status === 401) { logout(); return; }
    const d = await res.json().catch(() => ({}));
    // Already monitored (409): that folder does for the check as well
    if (!res.ok && res.status !== 409) throw new Error(d.error || `HTTP ${res.status}`);
    setupState.folder = path;
    if (res.ok) { setupState.server.folders++; setupState.added = true; }
    let msg = `<i class="bi bi-check-circle me-1"></i>${esc(res.ok ? d.message : t('setup.dir.added'))}`;
    if (d.saclErrors?.length) msg += `<br><small class="text-warning">${esc(t('msg.saclErrCount', { n: d.saclErrors.length }))}</small>`;
    setupMessage(msg, 'success');
    document.getElementById('setupNextBtn').disabled = false;
    if (currentTab === 'settings') loadServerSettings();
  } catch (e) {
    setupMessage(esc(e.message), 'danger');
  } finally {
    btn.disabled = false;
  }
}

// The folders the server already monitors: shown, and the first one is the folder of the check when no
// folder is added here
async function setupLoadExisting() {
  const server = setupServerParam();
  try {
    const d = await api(`/api/settings${server ? `?server=${encodeURIComponent(server)}` : ''}`);
    const paths = (d.pathConfigs || []).map(c => c.path);
    if (!setupState?.folder && paths.length) setupState.folder = paths[0];
    document.getElementById('setupExisting')?.insertAdjacentHTML('beforeend',
      `<div class="mt-1">${paths.map(p => `<code>${esc(p)}</code>`).join(', ')}</div>`);
  } catch { /* the hint of the check step then names no folder */ }
}

function setupSize(bytes) {
  if (bytes >= 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024 * 1024)).toLocaleString(undefined, { maximumFractionDigits: 1 })} GB`;
  return `${Math.round(bytes / (1024 * 1024)).toLocaleString()} MB`;
}

async function setupLoadLog() {
  const el = document.getElementById('setupLogInfo');
  const server = setupServerParam();
  try {
    const d = await api(`/api/settings/security-log${server ? `?server=${encodeURIComponent(server)}` : ''}`);
    let html = `<strong>${esc(t('setup.log.current', { size: setupSize(d.maxBytes) }))}</strong>`;
    if (d.usedBytes != null) html += ` <span class="text-muted">(${esc(t('setup.log.used', { size: setupSize(d.usedBytes), n: fmtNum(d.records) }))})</span>`;
    if (d.maxBytes >= d.recommendedBytes) html += `<div class="text-success mt-1"><i class="bi bi-check-circle me-1"></i>${esc(t('setup.log.enough', { size: setupSize(d.maxBytes) }))}</div>`;
    // Not overwriting: when the log is full, Windows keeps no new events (or, with a policy, stops sign-ins)
    if (d.mode && d.mode !== 'Circular') html += `<div class="alert alert-warning py-2 small mt-2 mb-0">${esc(t('setup.log.notCircular', { mode: d.mode }))}</div>`;
    el.innerHTML = html;
    document.getElementById('setupLogBtn').disabled = false;
  } catch (e) {
    el.innerHTML = `<div class="alert alert-warning py-2 small mb-0">${esc(t('setup.log.unavailable', { e: e.message }))}</div>`;
  }
}

async function setupSetLog() {
  const btn = document.getElementById('setupLogBtn');
  btn.disabled = true;
  const maxBytes = parseInt(document.getElementById('setupLogSize').value, 10);
  try {
    const d = await api('/api/settings/security-log', {
      method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ maxBytes, server: setupServerParam() }),
    });
    setupMessage(`<i class="bi bi-check-circle me-1"></i>${esc(t('setup.log.done', { size: setupSize(d.maxBytes) }))}`, 'success');
    setupLoadLog();
  } catch (e) {
    setupMessage(esc(e.message), 'danger');
    btn.disabled = false;
  }
}

// Polls the search for a record under the folder that is newer than this step (a minute of clock
// difference between the file server and this machine is allowed for)
function setupWatch() {
  const st = setupState;
  st.since = Date.now() - 60 * 1000;
  const folder = st.folder || '';
  const server = st.server.name;
  const deadline = Date.now() + SETUP_WAIT_MS;
  const poll = async () => {
    if (!setupState || setupState.poll !== st.poll) return;
    try {
      const d = await api(`/api/stats/search?days=1&pageSize=20&server=${encodeURIComponent(server)}${folder ? `&q=${encodeURIComponent(folder)}` : ''}`);
      const hit = (d.items || []).find(r => new Date(/[Z+]/.test(r.accessTime) ? r.accessTime : r.accessTime + 'Z').getTime() >= st.since);
      if (hit) {
        clearInterval(st.poll); st.poll = null;
        setupMessage(`<i class="bi bi-check-circle me-1"></i>${esc(t('setup.chk.found', {
          time: fmtDate(hit.accessTime), user: hit.userName, type: TYPE_LABELS[hit.accessType] || hit.accessType, file: hit.fileName }))}
          <div class="mt-1">${esc(t('setup.chk.done'))}</div>`, 'success');
        return;
      }
    } catch { /* try again */ }
    if (Date.now() > deadline) {
      clearInterval(st.poll); st.poll = null;
      setupMessage(`${esc(t('setup.chk.timeout'))}
        <div class="mt-2"><button class="btn btn-outline-secondary btn-sm" onclick="setupRender()">${esc(t('setup.chk.again'))}</button></div>`, 'warning');
    }
  };
  st.poll = setInterval(poll, SETUP_POLL_MS);
  poll();
}

// ── Security log card (Settings, per server) ─────────────────────
const LOG_CARD_SIZES = [256, 512, 1024, 2048, 4096, 8192].map(mb => mb * 1024 * 1024);

async function loadSecurityLogCard() {
  const el = document.getElementById('securityLogSection');
  if (!el) return;
  // pathAudit.os: the OS of the server picked in Settings (app.js); a Linux server has no Security log
  if (/\S/.test(pathAudit?.os || '') && !/^windows/i.test(pathAudit.os)) { el.classList.add('d-none'); return; }
  el.classList.remove('d-none');
  const server = settingsServer();
  el.innerHTML = `<div class="card">
      <div class="card-header fw-semibold"><i class="bi bi-journal-text me-1"></i>${esc(t('setup.card.title'))}</div>
      <div class="card-body">
        <p class="small text-muted mb-2">${esc(t('setup.card.hint'))}</p>
        <div id="logCardInfo" class="small"><span class="spinner-border spinner-border-sm"></span></div>
      </div>
    </div>`;
  let d;
  try { d = await api(`/api/settings/security-log${server ? `?server=${encodeURIComponent(server)}` : ''}`); }
  catch (e) {
    // An old agent, a collector that is not connected, ...: say why, there is nothing to set
    document.getElementById('logCardInfo').innerHTML = `<div class="alert alert-warning py-2 small mb-0">${esc(e.message)}</div>`;
    return;
  }
  if (settingsServer() !== server) return;   // another server was picked meanwhile
  const sizes = [...new Set([...LOG_CARD_SIZES, d.maxBytes])].sort((a, b) => a - b);
  const options = sizes.map(b => `<option value="${b}" ${b === Math.max(d.maxBytes, d.recommendedBytes) ? 'selected' : ''}>${setupSize(b)}</option>`).join('');
  let html = `<div><strong>${esc(t('setup.log.current', { size: setupSize(d.maxBytes) }))}</strong>`;
  if (d.usedBytes != null) html += ` <span class="text-muted">(${esc(t('setup.log.used', { size: setupSize(d.usedBytes), n: fmtNum(d.records) }))})</span>`;
  html += '</div>';
  if (d.maxBytes < d.recommendedBytes)
    html += `<div class="text-warning-emphasis mt-1"><i class="bi bi-exclamation-triangle me-1"></i>${esc(t('setup.card.small', { size: setupSize(d.recommendedBytes) }))}</div>`;
  if (d.mode && d.mode !== 'Circular') html += `<div class="alert alert-warning py-2 small mt-2 mb-0">${esc(t('setup.log.notCircular', { mode: d.mode }))}</div>`;
  html += `<div class="d-flex align-items-center gap-2 mt-2">
      <label class="small mb-0" for="logCardSize">${esc(t('setup.log.size'))}</label>
      <select id="logCardSize" class="form-select form-select-sm" style="width:auto">${options}</select>
      <button class="btn btn-primary btn-sm" id="logCardBtn" onclick="saveSecurityLogCard()">${esc(t('setup.log.set'))}</button>
    </div>
    <div id="logCardMsg" class="mt-2"></div>`;
  document.getElementById('logCardInfo').innerHTML = html;
}

async function saveSecurityLogCard() {
  const maxBytes = parseInt(document.getElementById('logCardSize').value, 10);
  const server = settingsServer();
  if (!confirm(t('setup.card.confirm', { s: server || serverList?.local || '', size: setupSize(maxBytes) }))) return;
  const btn = document.getElementById('logCardBtn');
  btn.disabled = true;
  try {
    const d = await api('/api/settings/security-log', {
      method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ maxBytes, server: server || null }),
    });
    await loadSecurityLogCard();
    document.getElementById('logCardMsg').innerHTML =
      `<div class="alert alert-success py-2 small mb-0"><i class="bi bi-check-circle me-1"></i>${esc(t('setup.log.done', { size: setupSize(d.maxBytes) }))}</div>`;
  } catch (e) {
    document.getElementById('logCardMsg').innerHTML = `<div class="alert alert-danger py-2 small mb-0">${esc(e.message)}</div>`;
    btn.disabled = false;
  }
}

async function setupFinish() {
  try { await api('/api/settings/setup/done', { method: 'PUT' }); } catch { /* the wizard can be opened again */ }
  bootstrap.Modal.getInstance(document.getElementById('setupModal'))?.hide();
  const link = document.querySelector('[data-tab="recent"]');
  if (link) switchTab('recent', link);
}
