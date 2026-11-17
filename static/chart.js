// Sentryline Security Log Analyzer - Interactive SOC Operations Engine
document.documentElement.dataset.analyzerReady = 'true';

// 1. Interactive Alert Triage Status Handler
window.updateAlertStatus = async function(alertId, newStatus, select) {
  const row = select.closest('.alert-row-item');
  const previous = row.dataset.status;
  const feedback = document.getElementById('operation-status');
  select.disabled = true;
  try {
    const res = await fetch('/api/alert/' + encodeURIComponent(alertId) + '/status', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]').content },
      body: JSON.stringify({ status: newStatus, analysis_id: document.querySelector('meta[name="analysis-id"]').content })
    });
    const data = await res.json().catch(() => ({ error: res.status === 401 ? 'Authentication required. Reload to sign in.' : 'Server returned an unexpected response.' }));
    if (!res.ok) throw new Error(data.error || 'Status update failed');
    row.dataset.status = newStatus;
    select.className = `triage-select status-${newStatus}`;
    feedback.textContent = `${alertId} saved as ${({open:'not reviewed',in_progress:'checking',resolved:'review complete',false_positive:'benign / false alarm'})[newStatus] || newStatus}. Reload to refresh the activity log.`;

  } catch (err) {
    select.value = previous;
    feedback.textContent = err.message;
  } finally {
    select.disabled = false;
  }
};

// Bind analyst triage controls.
document.addEventListener('DOMContentLoaded', () => {
  // Initialize triage select classes on load
  document.querySelectorAll('.triage-select').forEach(select => {
    select.className = `triage-select status-${select.value}`;
    select.addEventListener("change", () => window.updateAlertStatus(select.dataset.alertId, select.value, select));
  });

});

document.querySelectorAll('form[method="post"]').forEach(form => {
  const file = form.querySelector('input[type="file"]');
  file?.addEventListener('change', () => {
    form.querySelector('.file-picker span').textContent = file.files[0]?.name || 'Choose log file';
  });
  form.addEventListener('submit', event => {
    if (file?.files[0]?.size > 5 * 1024 * 1024) {
      event.preventDefault();
      document.getElementById('operation-status').textContent = 'File too large. Choose a file below 5 MiB.';
      return;
    }
    const button = form.querySelector('button[type="submit"]');
    button.disabled = true;
    button.textContent = button.dataset.busyLabel || (file ? 'Analyzing…' : 'Processing…');
  });
});
