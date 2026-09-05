'use strict';
const byId = (id) => document.getElementById(id);
let statusBusy = false;
let lastStatus;

async function requestStatus() {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 12000);
  try {
    const response = await fetch('/api/request', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ command: 'status' }), signal: controller.signal,
      mode: 'same-origin', credentials: 'omit', redirect: 'error', cache: 'no-store'
    });
    return { ok: response.ok, value: await response.json() };
  } finally { clearTimeout(timer); }
}

function setBoolean(id, value, on, off) {
  const element = byId(id);
  if (typeof value !== 'boolean') {
    element.textContent = 'Unknown';
    element.className = '';
    return;
  }
  element.textContent = value ? on : off;
  element.className = value ? 'status-good' : 'status-warning';
}

async function refreshStatus(manual = false) {
  if (statusBusy || document.hidden) return;
  statusBusy = true;
  const refresh = byId('status-refresh');
  refresh.disabled = true;
  if (manual) byId('status-message').textContent = 'Refreshing status…';
  try {
    const { ok, value } = await requestStatus();
    if (!ok || value.type !== 'status') throw new Error('offline');
    const running = typeof value.running === 'boolean' ? value.running : null;
    const endpointOnline = typeof value.endpoint_online === 'boolean' ? value.endpoint_online : null;
    const topicJoined = typeof value.topic_joined === 'boolean' ? value.topic_joined : null;
    setBoolean('daemon-value', running, 'Running', 'Not running');
    setBoolean('endpoint-value', endpointOnline, 'Online', 'Offline');
    setBoolean('topic-value', topicJoined, 'Joined', 'Not joined');
    const neighbors = Number.isInteger(value.neighbors) && value.neighbors >= 0 ? String(value.neighbors) : 'Unknown';
    const peer = typeof value.peer === 'string' && value.peer ? value.peer : 'Unknown';
    byId('neighbors-value').textContent = neighbors;
    byId('peer-value').textContent = peer;
    const status = JSON.stringify([running, endpointOnline, topicJoined, neighbors, peer]);
    if (manual || status !== lastStatus) {
      byId('status-message').textContent = manual
        ? 'Status refreshed. Read-only; peer count is not delivery proof.'
        : 'Status changed. Read-only; peer count is not delivery proof.';
    }
    lastStatus = status;
  } catch (_) {
    for (const id of ['daemon-value', 'endpoint-value', 'topic-value', 'neighbors-value', 'peer-value']) {
      byId(id).textContent = 'Unavailable';
      byId(id).className = 'status-warning';
    }
    byId('status-message').textContent = 'Daemon unavailable or web connection lost. Start or restart it separately.';
  } finally {
    refresh.disabled = false;
    statusBusy = false;
  }
}

byId('status-refresh').addEventListener('click', () => refreshStatus(true));
document.addEventListener('visibilitychange', () => { if (!document.hidden) refreshStatus(); });
window.addEventListener('online', () => refreshStatus());
setInterval(() => refreshStatus(), 15000);
refreshStatus();
