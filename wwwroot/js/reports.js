// Scheduled report settings card (#reportsSettingsSection). app.js calls SettingsHooks.reports() when an
// administrator opens Settings (top-level code only registers the hook; app.js helpers are used inside functions).
window.SettingsHooks = window.SettingsHooks || {};
window.SettingsHooks.reports = () => loadReportSettings();

// Texts whose key is built from a number or name (the keys are all in lang/reports.js)
function reportT(prefix, name) {
  return t(prefix + name);
}

const REPORT_WEEKDAYS = [1, 2, 3, 4, 5, 6, 0];   // Monday first

function buildReportCard() {
  const el = document.getElementById('reportsSettingsSection');
  if (el.dataset.built) return;
  el.dataset.built = '1';
  const weekdays = REPORT_WEEKDAYS.map(d => `<option value="${d}">${esc(reportT('report.day.', d))}</option>`).join('');
  const monthDays = Array.from({ length: 28 }, (_, i) => `<option value="${i + 1}">${i + 1}</option>`).join('');
  el.innerHTML = `
    <div class="card">
      <div class="card-header fw-semibold"><i class="bi bi-envelope-paper me-1"></i>${esc(t('report.card.title'))}</div>
      <div class="card-body">
        <p class="small text-muted mb-3">${esc(t('report.hint'))}</p>
        <div id="rptSmtpWarning" class="alert alert-warning py-2 small d-none">${esc(t('report.smtpNeeded'))}</div>
        <div class="form-check form-switch mb-3">
          <input class="form-check-input" type="checkbox" id="rptEnabled">
          <label class="form-check-label" for="rptEnabled">${esc(t('report.enable'))}</label>
        </div>
        <div class="row g-3">
          <div class="col-6 col-md-3">
            <label class="form-label small text-muted" for="rptFrequency">${esc(t('report.frequency'))}</label>
            <select id="rptFrequency" class="form-select form-select-sm" onchange="updateReportDayFields()">
              <option value="daily">${esc(t('report.freq.daily'))}</option>
              <option value="weekly">${esc(t('report.freq.weekly'))}</option>
              <option value="monthly">${esc(t('report.freq.monthly'))}</option>
            </select>
          </div>
          <div class="col-6 col-md-3" id="rptDowWrap">
            <label class="form-label small text-muted" for="rptDayOfWeek">${esc(t('report.dayOfWeek'))}</label>
            <select id="rptDayOfWeek" class="form-select form-select-sm">${weekdays}</select>
          </div>
          <div class="col-6 col-md-3" id="rptDomWrap">
            <label class="form-label small text-muted" for="rptDayOfMonth">${esc(t('report.dayOfMonth'))}</label>
            <select id="rptDayOfMonth" class="form-select form-select-sm">${monthDays}</select>
          </div>
          <div class="col-6 col-md-3">
            <label class="form-label small text-muted" for="rptTime">${esc(t('report.time'))}</label>
            <input type="time" id="rptTime" class="form-control form-control-sm">
          </div>
          <div class="col-6 col-md-3">
            <label class="form-label small text-muted" for="rptTopN">${esc(t('report.topN'))}</label>
            <input type="number" id="rptTopN" class="form-control form-control-sm" min="1" max="50">
          </div>
          <div class="col-12">
            <div class="form-check"><input class="form-check-input" type="checkbox" id="rptCsv">
              <label class="form-check-label small" for="rptCsv">${esc(t('report.csv'))}</label></div>
            <div class="form-check"><input class="form-check-input" type="checkbox" id="rptScoped">
              <label class="form-check-label small" for="rptScoped">${esc(t('report.scoped'))}</label></div>
            <div class="form-check"><input class="form-check-input" type="checkbox" id="rptWebhook">
              <label class="form-check-label small" for="rptWebhook">${esc(t('report.webhook'))}</label></div>
          </div>
          <div class="col-12 small text-muted" id="rptStatus"></div>
          <div class="col-12 d-flex flex-wrap gap-2">
            <button class="btn btn-primary btn-sm" onclick="saveReportSettings()"><i class="bi bi-floppy me-1"></i>${esc(t('btn.save'))}</button>
            <button class="btn btn-outline-secondary btn-sm" onclick="sendTestReport()"><i class="bi bi-send me-1"></i>${esc(t('report.test'))}</button>
            <button class="btn btn-outline-secondary btn-sm" onclick="previewReport()"><i class="bi bi-eye me-1"></i>${esc(t('report.preview'))}</button>
          </div>
          <div class="col-12">
            <div class="input-group input-group-sm" style="max-width: 32rem">
              <input type="text" id="rptViewer" class="form-control" placeholder="${esc(t('report.viewerPlaceholder'))}">
              <button class="btn btn-outline-secondary" onclick="sendViewerTestReport()">${esc(t('report.viewerTest'))}</button>
            </div>
            <div class="form-text">${esc(t('report.viewerHint'))}</div>
          </div>
        </div>
        <div id="rptAlert" class="mt-2"></div>
      </div>
    </div>`;
}

function showReportAlert(html, type = 'success') {
  document.getElementById('rptAlert').innerHTML = `<div class="alert alert-${type} alert-dismissible fade show py-2 small">
    ${html}<button type="button" class="btn-close" data-bs-dismiss="alert"></button></div>`;
}

function updateReportDayFields() {
  const f = document.getElementById('rptFrequency').value;
  document.getElementById('rptDowWrap').classList.toggle('d-none', f !== 'weekly');
  document.getElementById('rptDomWrap').classList.toggle('d-none', f !== 'monthly');
}

async function loadReportSettings() {
  buildReportCard();
  try {
    const s = await api('/api/reports/settings');
    const enabled = document.getElementById('rptEnabled');
    enabled.checked = s.enabled;
    // without a mail server the switch cannot be turned on
    enabled.disabled = !s.smtpReady && !s.enabled;
    document.getElementById('rptSmtpWarning').classList.toggle('d-none', s.smtpReady);
    document.getElementById('rptFrequency').value = s.frequency;
    document.getElementById('rptDayOfWeek').value = s.dayOfWeek;
    document.getElementById('rptDayOfMonth').value = s.dayOfMonth;
    document.getElementById('rptTime').value = s.time;
    document.getElementById('rptTopN').value = s.topN;
    document.getElementById('rptCsv').checked = s.csv;
    document.getElementById('rptScoped').checked = s.scopedViewers;
    const webhook = document.getElementById('rptWebhook');
    webhook.checked = s.webhook;
    webhook.disabled = !s.webhookReady && !s.webhook;
    updateReportDayFields();

    const sent = s.lastSentAt ? fmtDate(s.lastSentAt) : t('report.never');
    document.getElementById('rptStatus').textContent = [
      t('report.lastSent', { when: sent }),
      s.nextSlot ? t('report.next', { when: s.nextSlot }) : '',
      t('report.localTime'),
    ].filter(Boolean).join(' / ');
  } catch (e) {
    showReportAlert(`<i class="bi bi-exclamation-triangle me-1"></i>${esc(e.message)}`, 'danger');
  }
}

function reportFormBody() {
  return {
    enabled: document.getElementById('rptEnabled').checked,
    frequency: document.getElementById('rptFrequency').value,
    dayOfWeek: parseInt(document.getElementById('rptDayOfWeek').value, 10),
    dayOfMonth: parseInt(document.getElementById('rptDayOfMonth').value, 10),
    time: document.getElementById('rptTime').value,
    topN: parseInt(document.getElementById('rptTopN').value, 10) || 10,
    csv: document.getElementById('rptCsv').checked,
    scopedViewers: document.getElementById('rptScoped').checked,
    webhook: document.getElementById('rptWebhook').checked,
  };
}

async function saveReportSettings() {
  try {
    const d = await api('/api/reports/settings', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(reportFormBody()),
    });
    showReportAlert(`<i class="bi bi-check-circle me-1"></i>${esc(d.message)}`);
    loadReportSettings();
    if (typeof loadAuditLog === 'function') loadAuditLog(1);
  } catch (e) {
    showReportAlert(`<i class="bi bi-exclamation-triangle me-1"></i>${esc(e.message)}`, 'danger');
  }
}

async function postReportTest(body) {
  try {
    const d = await api('/api/reports/test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    showReportAlert(`<i class="bi bi-check-circle me-1"></i>${esc(d.message)}`);
  } catch (e) {
    showReportAlert(`<i class="bi bi-exclamation-triangle me-1"></i>${esc(e.message)}`, 'danger');
  }
  if (typeof loadAuditLog === 'function') loadAuditLog(1);
}

// The test uses the saved settings (the schedule is not needed for it, the recipients are those of Notifications)
function sendTestReport() {
  return postReportTest({});
}

function sendViewerTestReport() {
  const name = document.getElementById('rptViewer').value.trim();
  if (!name) return Promise.resolve(showReportAlert(esc(t('report.viewerRequired')), 'warning'));
  return postReportTest({ scopedViewer: name });
}

// The HTML of the report in a sandboxed frame: scripts and links in it cannot run
async function previewReport() {
  try {
    const res = await fetch('/api/reports/preview', { headers: authHeaders() });
    if (res.status === 401) { logout(); return; }
    if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || `HTTP ${res.status}`);
    const html = await res.text();
    let modal = document.getElementById('reportPreviewModal');
    if (!modal) {
      document.body.insertAdjacentHTML('beforeend', `
        <div class="modal fade" id="reportPreviewModal" tabindex="-1"><div class="modal-dialog modal-xl modal-dialog-scrollable"><div class="modal-content">
          <div class="modal-header"><h5 class="modal-title">${esc(t('report.preview'))}</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
          <div class="modal-body p-0"><iframe id="reportPreviewFrame" sandbox="" style="width:100%;height:70vh;border:0"></iframe></div>
        </div></div></div>`);
      modal = document.getElementById('reportPreviewModal');
    }
    document.getElementById('reportPreviewFrame').srcdoc = html;
    bootstrap.Modal.getOrCreateInstance(modal).show();
  } catch (e) {
    showReportAlert(`<i class="bi bi-exclamation-triangle me-1"></i>${esc(e.message)}`, 'danger');
  }
}
