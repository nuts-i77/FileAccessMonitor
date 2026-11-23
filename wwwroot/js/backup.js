// Backup card (#backupSettingsSection), read-only: the daily backup, whether backups are being made, the list,
// and the commands that make, schedule, restore and delete them (run as an administrator; the web service
// does not make backups). app.js calls SettingsHooks.backup() when an administrator opens Settings.
window.SettingsHooks = window.SettingsHooks || {};
window.SettingsHooks.backup = () => loadBackupCard();

// Texts whose key is built from a reason (the keys are all in lang/backup.js)
function backupT(prefix, name) {
  return t(prefix + name);
}

const BACKUP_REASONS = ['manual', 'scheduled', 'pre-update', 'before-restore'];
let backupCommandPrefix = '';

function backupSize(bytes) {
  if (bytes == null) return '-';
  if (bytes >= 1024 ** 3) return (bytes / 1024 ** 3).toFixed(1) + ' GB';
  if (bytes >= 1024 ** 2) return (bytes / 1024 ** 2).toFixed(1) + ' MB';
  if (bytes >= 1024) return Math.round(bytes / 1024) + ' KB';
  return bytes + ' B';
}

// One command with a copy button
function backupCommandRow(id, label, command) {
  return `<div class="mb-2">
      <div class="small text-muted mb-1">${esc(label)}</div>
      <div class="input-group input-group-sm">
        <input type="text" class="form-control font-monospace" id="${id}" value="${esc(command)}" readonly>
        <button class="btn btn-outline-secondary" onclick="copyBox(document.getElementById('${id}'), this)" title="${esc(t('backup.copy'))}">
          <i class="bi bi-clipboard"></i></button>
      </div>
    </div>`;
}

function buildBackupCard() {
  const el = document.getElementById('backupSettingsSection');
  if (el.dataset.built) return;
  el.dataset.built = '1';
  el.innerHTML = `
    <div class="card">
      <div class="card-header fw-semibold"><i class="bi bi-archive me-1"></i>${esc(t('backup.title'))}</div>
      <div class="card-body">
        <div class="small text-muted mb-3">${hintHtml('backup.hint')}</div>
        <div id="bkSchedule" class="mb-2"></div>
        <div id="bkWarning"></div>
        <details class="mb-1">
          <summary class="small">${esc(t('backup.commands'))}</summary>
          <div class="mt-2" id="bkCommands"></div>
        </details>
      </div>
      <div class="table-responsive">
        <table class="table table-sm table-hover mb-0">
          <thead class="table-dark"><tr>
            <th>${esc(t('backup.th.created'))}</th>
            <th>${esc(t('backup.th.reason'))}</th>
            <th>${esc(t('backup.th.version'))}</th>
            <th class="text-end">${esc(t('backup.th.size'))}</th>
            <th>${esc(t('backup.th.collector'))}</th>
            <th style="width:110px">${esc(t('th.actions'))}</th>
          </tr></thead>
          <tbody id="bkTableBody"></tbody>
        </table>
      </div>
      <div class="card-body d-none" id="bkCmdBox">
        <div class="small mb-1" id="bkCmdHint"></div>
        <div class="input-group input-group-sm">
          <input type="text" class="form-control font-monospace" id="bkCmd" readonly>
          <button class="btn btn-outline-secondary" onclick="copyBox(document.getElementById('bkCmd'), this)" title="${esc(t('backup.copy'))}">
            <i class="bi bi-clipboard"></i></button>
        </div>
      </div>
    </div>`;
}

async function loadBackupCard() {
  const el = document.getElementById('backupSettingsSection');
  if (!el) return;
  buildBackupCard();
  el.classList.remove('d-none');
  try {
    const d = await api('/api/backups');
    backupCommandPrefix = d.commandPrefix || '';
    const s = d.schedule;
    document.getElementById('bkSchedule').innerHTML = s
      ? `<i class="bi bi-calendar-check me-1 text-success"></i>${esc(t('backup.scheduleOn', {
          time: s.time, keep: s.keep, folder: s.folder || d.defaultRoot }))}`
      : `<i class="bi bi-calendar-x me-1 text-warning"></i>${esc(t('backup.scheduleOff'))}`;
    const warn = !d.latest ? t('backup.noneYet')
      : d.stale ? t('backup.stale', { date: fmtDate(d.latest) }) : '';
    document.getElementById('bkWarning').innerHTML = warn
      ? `<div class="alert alert-warning py-2 small"><i class="bi bi-exclamation-triangle me-1"></i>${esc(warn)}</div>` : '';
    const folder = s?.folder || 'D:\\Backups\\FileAccessMonitor';
    document.getElementById('bkCommands').innerHTML =
      backupCommandRow('bkCmdNow', t('backup.cmd.now'), `${backupCommandPrefix} backup`) +
      backupCommandRow('bkCmdSchedule', t('backup.cmd.schedule'),
        `${backupCommandPrefix} backup-schedule --time ${s?.time || '02:00'} --keep ${s?.keep || 7} --to "${folder}"`) +
      backupCommandRow('bkCmdOff', t('backup.cmd.off'), `${backupCommandPrefix} backup-schedule --off`) +
      `<div class="small text-muted">${hintHtml('backup.cmdHint')}</div>`;
    const rows = (d.backups || []).map(b => {
      const reason = BACKUP_REASONS.includes(b.reason) ? backupT('backup.reason.', b.reason) : b.reason;
      return `<tr>
        <td class="text-nowrap" title="${esc(b.folder || '')}">${esc(fmtDate(b.created))}</td>
        <td>${esc(reason)}</td>
        <td>${esc(b.dataVersion || '-')}</td>
        <td class="text-end">${esc(backupSize(b.bytes))}</td>
        <td>${b.collectorIncluded ? '<i class="bi bi-check-lg"></i>' : '<span class="text-muted">-</span>'}</td>
        <td class="text-nowrap">
          <button class="btn btn-sm btn-outline-secondary py-0" title="${esc(t('backup.restore'))}"
            onclick="showBackupCommand('restore', '${esc(b.name)}')"><i class="bi bi-arrow-counterclockwise"></i></button>
          <button class="btn btn-sm btn-outline-secondary py-0" title="${esc(t('backup.delete'))}"
            onclick="showBackupCommand('delete', '${esc(b.name)}')"><i class="bi bi-trash"></i></button>
        </td>
      </tr>`;
    });
    document.getElementById('bkTableBody').innerHTML = rows.length ? rows.join('')
      : `<tr><td colspan="6" class="text-muted small text-center py-3">${esc(t('backup.none'))}</td></tr>`;
  } catch (e) {
    document.getElementById('bkWarning').innerHTML =
      `<div class="alert alert-danger py-2 small"><i class="bi bi-exclamation-triangle me-1"></i>${esc(e.message)}</div>`;
  }
}

// The command for one backup (run on the monitoring server as an administrator)
function showBackupCommand(kind, name) {
  document.getElementById('bkCmdBox').classList.remove('d-none');
  document.getElementById('bkCmdHint').innerHTML = hintHtml(kind === 'restore' ? 'backup.restoreHint' : 'backup.deleteHint');
  document.getElementById('bkCmd').value = kind === 'restore'
    ? `${backupCommandPrefix} restore ${name}` : `${backupCommandPrefix} backups --delete ${name}`;
}
