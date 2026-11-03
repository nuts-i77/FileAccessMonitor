// Tamper detection: the settings card (Admin) and the red banner shown on every page when the chain is broken.
// Keys of lang/integrity.js start with 'integrity.'.

const INTEGRITY_STATE = {
  ok: ['bg-success', 'integrity.state.ok'],
  broken: ['bg-danger', 'integrity.state.broken'],
  notVerified: ['bg-secondary', 'integrity.state.notVerified'],
  disabled: ['bg-secondary', 'integrity.state.disabled'],
};

// What each finding means (label, explanation)
const INTEGRITY_KIND = {
  altered: ['integrity.k.altered', 'integrity.h.altered'],
  missing: ['integrity.k.missing', 'integrity.h.missing'],
  truncatedTail: ['integrity.k.truncatedTail', 'integrity.h.truncatedTail'],
  headMismatch: ['integrity.k.headMismatch', 'integrity.h.headMismatch'],
  headRollback: ['integrity.k.headRollback', 'integrity.h.headRollback'],
  unchained: ['integrity.k.unchained', 'integrity.h.unchained'],
  checkpoint: ['integrity.k.checkpoint', 'integrity.h.checkpoint'],
  keyChanged: ['integrity.k.keyChanged', 'integrity.h.keyChanged'],
  duplicate: ['integrity.k.duplicate', 'integrity.h.duplicate'],
};

const INTEGRITY_CHAIN = { access: 'integrity.chain.access', audit: 'integrity.chain.audit' };
const INTEGRITY_CHECK_KIND = { full: 'integrity.checkKind.full', incremental: 'integrity.checkKind.incremental' };
const INTEGRITY_CP = { genesis: 'integrity.cp.genesis', retention: 'integrity.cp.retention', accepted: 'integrity.cp.accepted' };
const INTEGRITY_ANCHOR_RESULT = {
  match: 'integrity.anchorResult.match', mismatch: 'integrity.anchorResult.mismatch',
  ahead: 'integrity.anchorResult.ahead', deleted: 'integrity.anchorResult.deleted',
};

let integrityPoll = null;

function integrityDuration(ms) {
  return ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(1)} s`;
}

function integrityBetween(b) {
  const f = x => x ? fmtDate(x) : '?';
  return `${f(b.timeBefore)} - ${f(b.timeAfter)}`;
}

function integrityWhere(b) {
  if (b.kind === 'unchained') return t('integrity.where.id', { from: b.fromId, to: b.toId });
  if (b.fromSeq === b.toSeq) return t('integrity.where.one', { n: b.fromSeq });
  return t('integrity.where.range', { from: b.fromSeq, to: b.toSeq });
}

// ── Banner ────────────────────────────────────────────────────────
async function refreshIntegrityBanner() {
  const el = document.getElementById('integrityBanner');
  if (!el || !isAdmin()) return;
  try {
    const s = (await api('/api/integrity/status')).summary;
    if (s.state !== 'broken') { el.classList.add('d-none'); el.innerHTML = ''; return; }
    el.innerHTML = `<div class="alert alert-danger rounded-0 mb-0 py-2 small d-flex align-items-center gap-2 flex-wrap">
      <i class="bi bi-shield-exclamation fs-5"></i>
      <span class="fw-semibold">${t('integrity.banner', { n: s.breaks })}</span>
      <a href="#" class="alert-link ms-auto" onclick="showIntegrityDetails(); return false;">${t('integrity.bannerLink')}</a>
    </div>`;
    el.classList.remove('d-none');
  } catch { /* the banner is an extra; the card shows errors */ }
}

function showIntegrityDetails() {
  const link = document.querySelector('[data-tab="settings"]');
  if (link) switchTab('settings', link);
  setTimeout(() => document.getElementById('integritySettingsSection')?.scrollIntoView({ behavior: 'smooth' }), 300);
}

// ── Card ──────────────────────────────────────────────────────────
function buildIntegrityCard() {
  const root = document.getElementById('integritySettingsSection');
  if (!root || document.getElementById('integrityCard')) return;
  root.innerHTML = `<div class="card" id="integrityCard">
    <div class="card-header py-2 d-flex align-items-center justify-content-between flex-wrap gap-2">
      <span class="fw-semibold"><i class="bi bi-shield-check me-1"></i>${t('integrity.title')}</span>
      <span id="integrityBadge"></span>
    </div>
    <div class="card-body">
      <p class="small text-muted">${t('integrity.intro')}</p>
      <div id="integrityMsg"></div>
      <div id="integritySummary" class="small mb-3"></div>
      <div class="d-flex flex-wrap gap-2 align-items-center mb-2">
        <button class="btn btn-primary btn-sm" id="integrityVerifyBtn" onclick="startIntegrityVerify()">
          <i class="bi bi-shield-check me-1"></i>${t('integrity.verifyNow')}
        </button>
        <button class="btn btn-outline-secondary btn-sm" onclick="downloadIntegrityAnchor()">
          <i class="bi bi-download me-1"></i>${t('integrity.anchorDownload')}
        </button>
      </div>
      <div id="integrityProgress" class="mb-3 d-none">
        <div class="progress" style="height:.6rem"><div class="progress-bar" id="integrityProgressBar" style="width:0%"></div></div>
        <small class="text-muted" id="integrityProgressText"></small>
      </div>
      <div id="integrityBreaks" class="mb-3"></div>
      <div id="integrityHeads" class="mb-3"></div>
      <div class="mb-3">
        <label class="form-label small fw-semibold" for="integrityAnchorText">${t('integrity.anchorCheckTitle')}</label>
        <div class="input-group input-group-sm">
          <input type="text" class="form-control font-monospace" id="integrityAnchorText" placeholder="${t('integrity.anchorPlaceholder')}">
          <button class="btn btn-outline-secondary" onclick="checkIntegrityAnchor()">${t('integrity.anchorCheck')}</button>
        </div>
        <div id="integrityAnchorResult" class="mt-2"></div>
      </div>
      <div id="integrityCheckpoints" class="small mb-3"></div>
      <p class="small text-muted mb-0">${t('integrity.anchorHint')}</p>
    </div>
  </div>`;
}

function showIntegrityMsg(html, type = 'success') {
  const el = document.getElementById('integrityMsg');
  if (!el) return;
  el.innerHTML = `<div class="alert alert-${type} alert-dismissible fade show py-2 small">${html}
    <button type="button" class="btn-close" data-bs-dismiss="alert"></button></div>`;
}

async function loadIntegrityCard() {
  buildIntegrityCard();
  await refreshIntegrity();
}

async function refreshIntegrity() {
  try {
    const status = await api('/api/integrity/status');
    renderIntegrity(status);
    if (status.running?.state === 'running') pollIntegrityRun(status.running.id);
  } catch (e) {
    const el = document.getElementById('integritySummary');
    if (el) el.innerHTML = `<span class="text-danger"><i class="bi bi-exclamation-triangle me-1"></i>${esc(e.message)}</span>`;
  }
}

function renderIntegrity(status) {
  const s = status.summary;
  const [cls, key] = INTEGRITY_STATE[s.state] || INTEGRITY_STATE.disabled;
  document.getElementById('integrityBadge').innerHTML = `<span class="badge ${cls}">${t(key)}</span>`;

  const lines = [];
  if (!status.keyAvailable) lines.push(`<div class="text-danger"><i class="bi bi-exclamation-triangle me-1"></i>${t('integrity.keyMissing')}</div>`);
  if (s.verifiedUpTo) lines.push(`<div>${t('integrity.verifiedUpTo', { time: fmtDate(s.verifiedUpTo), seq: fmtNum(s.headSeq) })}</div>`);
  const access = status.chains.find(c => c.chain === 'access');
  if (s.lastCheck) {
    const kind = t(INTEGRITY_CHECK_KIND[access?.lastCheckKind] || 'integrity.checkKind.full');
    lines.push(`<div>${t('integrity.lastCheck', { time: fmtDate(s.lastCheck), kind, ms: integrityDuration(access?.lastCheckMs || 0) })}</div>`);
  }
  lines.push(`<div>${t('integrity.breaksFound', { n: s.breaks })}</div>`);
  if (access && access.legacyRows > 0)
    lines.push(`<div class="text-muted">${t('integrity.legacy', { n: fmtNum(access.legacyRows), date: fmtDate(access.startedAt) })}</div>`);
  document.getElementById('integritySummary').innerHTML = lines.join('');

  renderIntegrityBreaks(status.chains);
  document.getElementById('integrityHeads').innerHTML = status.chains.length === 0 ? '' : `
    <div class="small fw-semibold mb-1">${t('integrity.heads')}</div>
    <table class="table table-sm small mb-0"><tbody>${status.chains.map(c => `<tr>
      <td>${t(INTEGRITY_CHAIN[c.chain] || 'integrity.chain.access')}</td>
      <td class="text-end">#${fmtNum(c.headSeq)}</td>
      <td class="font-monospace text-muted">${esc(c.headHashHex.slice(0, 12))}</td>
    </tr>`).join('')}</tbody></table>`;

  const cps = status.chains.flatMap(c => c.checkpoints.map(p => ({ ...p, chain: c.chain })))
    .filter(p => p.reason !== 'genesis').sort((a, b) => b.createdAt.localeCompare(a.createdAt)).slice(0, 8);
  document.getElementById('integrityCheckpoints').innerHTML = cps.length === 0 ? '' : `
    <div class="fw-semibold mb-1">${t('integrity.checkpoints')}</div>
    ${cps.map(p => `<div class="text-muted">${fmtDate(p.createdAt)} - ${esc(t(INTEGRITY_CHAIN[p.chain] || 'integrity.chain.access'))}:
      ${t(INTEGRITY_CP[p.reason] || 'integrity.cp.retention', { n: fmtNum(p.deletedRows), seq: fmtNum(p.upToSeq) })}
      ${p.note ? `<span class="fst-italic">(${esc(p.note)})</span>` : ''}</div>`).join('')}`;
}

function renderIntegrityBreaks(chains) {
  const el = document.getElementById('integrityBreaks');
  const rows = chains.flatMap(c => c.breaks.map(b => ({ ...b, chain: c.chain })));
  if (rows.length === 0) { el.innerHTML = ''; return; }
  const open = rows.filter(b => !b.accepted);
  const chainsOpen = [...new Set(open.map(b => b.chain))];
  const line = b => {
    const [labelKey, hintKey] = INTEGRITY_KIND[b.kind] || INTEGRITY_KIND.altered;
    return `<tr class="${b.accepted ? 'text-muted' : ''}">
      <td><span class="badge ${b.accepted ? 'bg-secondary' : 'bg-danger'}">${t(labelKey)}</span>
        <div class="text-muted">${t(hintKey)}</div></td>
      <td>${esc(t(INTEGRITY_CHAIN[b.chain] || 'integrity.chain.access'))}<br>${esc(integrityWhere(b))}</td>
      <td>${esc(integrityBetween(b))}<br><span class="text-muted">${t('integrity.detected', { time: fmtDate(b.detectedAt) })}</span></td>
      <td>${b.accepted
        ? `<span class="text-muted">${t('integrity.acceptedBy', { user: esc(b.acceptedBy || ''), time: fmtDate(b.acceptedAt) })}${b.note ? `<br>${esc(b.note)}` : ''}</span>`
        : `<button class="btn btn-outline-danger btn-sm" data-chain="${esc(b.chain)}" data-break="${esc(b.id)}" onclick="acceptIntegrityBreak(this)">${t('integrity.accept')}</button>`}</td>
    </tr>`;
  };
  el.innerHTML = `<div class="small fw-semibold mb-1">${t(open.length ? 'integrity.breaksOpen' : 'integrity.breaksHistory')}</div>
    <div class="table-responsive"><table class="table table-sm small align-middle mb-0"><tbody>${rows
      .sort((a, b) => (a.accepted - b.accepted) || b.detectedAt.localeCompare(a.detectedAt)).map(line).join('')}</tbody></table></div>
    ${chainsOpen.length ? `<div class="small text-muted mt-1">${t('integrity.acceptHint')}</div>` : ''}`;
}

// ── Verify ────────────────────────────────────────────────────────
async function startIntegrityVerify() {
  try {
    const d = await api('/api/integrity/verify', { method: 'POST' });
    pollIntegrityRun(d.id);
  } catch (e) {
    showIntegrityMsg(`<i class="bi bi-exclamation-triangle me-1"></i>${esc(e.message)}`, 'danger');
  }
}

function pollIntegrityRun(id) {
  if (integrityPoll) clearInterval(integrityPoll);
  const btn = document.getElementById('integrityVerifyBtn');
  if (btn) btn.disabled = true;
  document.getElementById('integrityProgress')?.classList.remove('d-none');
  const tick = async () => {
    try {
      const run = await api(`/api/integrity/verify/${id}`);
      const pct = run.rowsTotal > 0 ? Math.min(100, Math.round(run.rowsDone * 100 / run.rowsTotal)) : 0;
      const bar = document.getElementById('integrityProgressBar');
      if (bar) bar.style.width = (run.state === 'running' ? pct : 100) + '%';
      const text = document.getElementById('integrityProgressText');
      if (text) text.textContent = t('integrity.progress', { done: fmtNum(run.rowsDone), total: fmtNum(run.rowsTotal) });
      if (run.state === 'running') return;
      clearInterval(integrityPoll);
      integrityPoll = null;
      if (btn) btn.disabled = false;
      document.getElementById('integrityProgress')?.classList.add('d-none');
      const open = run.breaks.filter(b => !b.accepted).length;
      if (run.state === 'failed') showIntegrityMsg(`<i class="bi bi-exclamation-triangle me-1"></i>${t('integrity.verifyFailed', { e: esc(run.error || '') })}`, 'danger');
      else if (run.state === 'done' && open === 0)
        showIntegrityMsg(`<i class="bi bi-check-circle me-1"></i>${t('integrity.verifyOk', { ms: integrityDuration(run.elapsedMs), n: fmtNum(run.rowsDone) })}`);
      else if (run.state === 'done')
        showIntegrityMsg(`<i class="bi bi-exclamation-triangle me-1"></i>${t('integrity.verifyFound', { n: open })}`, 'danger');
      await refreshIntegrity();
      refreshIntegrityBanner();
      if (typeof loadAuditLog === 'function') loadAuditLog(1);
    } catch (e) {
      clearInterval(integrityPoll);
      integrityPoll = null;
      if (btn) btn.disabled = false;
      showIntegrityMsg(`<i class="bi bi-exclamation-triangle me-1"></i>${esc(e.message)}`, 'danger');
    }
  };
  integrityPoll = setInterval(tick, 700);
  tick();
}

// ── Accept ────────────────────────────────────────────────────────
async function acceptIntegrityBreak(btn) {
  const chain = btn.dataset.chain;
  const note = window.prompt(t('integrity.acceptPrompt', { chain: t(INTEGRITY_CHAIN[chain] || 'integrity.chain.access') }), '');
  if (note === null) return;
  try {
    const d = await api('/api/integrity/accept', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chain, breakId: btn.dataset.break, note }),
    });
    showIntegrityMsg(`<i class="bi bi-check-circle me-1"></i>${esc(d.message)}`);
    await refreshIntegrity();
    refreshIntegrityBanner();
    if (typeof loadAuditLog === 'function') loadAuditLog(1);
  } catch (e) {
    showIntegrityMsg(`<i class="bi bi-exclamation-triangle me-1"></i>${esc(e.message)}`, 'danger');
  }
}

// ── Anchor ────────────────────────────────────────────────────────
async function downloadIntegrityAnchor() {
  try {
    const res = await fetch('/api/integrity/anchor', { headers: authHeaders() });
    if (res.status === 401) { logout(); return; }
    if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || `HTTP ${res.status}`);
    const name = /filename="?([^";]+)"?/.exec(res.headers.get('Content-Disposition') || '')?.[1] || 'fam-anchor.json';
    const url = URL.createObjectURL(await res.blob());
    const a = document.createElement('a');
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    if (typeof loadAuditLog === 'function') loadAuditLog(1);
  } catch (e) {
    showIntegrityMsg(`<i class="bi bi-exclamation-triangle me-1"></i>${esc(e.message)}`, 'danger');
  }
}

async function checkIntegrityAnchor() {
  const el = document.getElementById('integrityAnchorResult');
  const text = document.getElementById('integrityAnchorText').value.trim();
  if (!text) { el.innerHTML = ''; return; }
  try {
    const d = await api('/api/integrity/check-anchor', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text }),
    });
    const lines = d.chains.map(c => `<div>${t('integrity.anchorChain', {
      chain: esc(t(INTEGRITY_CHAIN[c.chain] || 'integrity.chain.access')), seq: fmtNum(c.seq), result: t(INTEGRITY_ANCHOR_RESULT[c.result] || 'integrity.anchorResult.mismatch') })}</div>`);
    if (d.macValid === true) lines.push(`<div>${t('integrity.macOk')}</div>`);
    if (d.macValid === false) lines.push(`<div class="fw-semibold">${t('integrity.macBad')}</div>`);
    el.innerHTML = `<div class="alert alert-${d.ok ? 'success' : 'danger'} py-2 small mb-0">
      <div class="fw-semibold">${t(d.ok ? 'integrity.anchorOk' : 'integrity.anchorBad')}</div>${lines.join('')}</div>`;
  } catch (e) {
    el.innerHTML = `<div class="alert alert-danger py-2 small mb-0"><i class="bi bi-exclamation-triangle me-1"></i>${esc(e.message)}</div>`;
  }
}

window.SettingsHooks = window.SettingsHooks || {};
window.SettingsHooks.integrity = () => loadIntegrityCard();
window.StartupHooks = window.StartupHooks || {};
window.StartupHooks.integrity = () => { if (isAdmin()) refreshIntegrityBanner(); };
