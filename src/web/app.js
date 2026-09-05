'use strict';
const byId = (id) => document.getElementById(id);
const draft = byId('draft');
const feed = byId('feed');
const encoder = new TextEncoder();
let sending = false;
let source = null;
let reconnectTimer = null;
let reconnectDelay = 1000;
let statusBusy = false;

function addEntry(label, body, timestampMs, kind) {
  const item = document.createElement('li');
  if (kind) item.className = kind;
  const meta = document.createElement('small');
  const timestamp = Number.isFinite(timestampMs) ? new Date(timestampMs) : new Date();
  meta.textContent = `${timestamp.toLocaleTimeString()} · ${label}`;
  item.append(meta);
  if (body !== undefined) {
    const text = document.createElement('p');
    text.textContent = body;
    item.append(text);
  }
  feed.prepend(item);
  while (feed.children.length > 100) feed.lastElementChild.remove();
}

function connection(message, connected) {
  const element = byId('connection');
  element.textContent = message;
  element.className = connected ? 'connected' : '';
}

async function request(value) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 12000);
  try {
    const response = await fetch('/api/request', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(value), signal: controller.signal,
      mode: 'same-origin', credentials: 'omit', redirect: 'error', cache: 'no-store'
    });
    return { ok: response.ok, value: await response.json() };
  } finally { clearTimeout(timer); }
}

async function refreshStatus() {
  if (statusBusy || document.hidden) return;
  statusBusy = true;
  try {
    const { ok, value } = await request({ command: 'status' });
    if (!ok || value.type !== 'status') throw new Error('offline');
    byId('identity').textContent = value.peer || 'Unknown';
    byId('status').textContent = `Daemon running · endpoint ${value.endpoint_online ? 'online' : 'offline'} · topic ${value.topic_joined ? 'joined' : 'not joined'} · ${value.neighbors ?? '?'} neighbors (not delivery proof)`;
  } catch (_) {
    byId('status').textContent = 'Daemon unavailable or web connection lost. Start/restart the daemon separately.';
    byId('identity').textContent = 'Unconfirmed while offline';
  } finally { statusBusy = false; }
}

function gap(message) {
  byId('gap').textContent = message;
}

function reconnect() {
  if (source) source.close();
  source = null;
  connection('Live feed disconnected · reconnecting', false);
  gap('Feed gap possible. Messages during disconnection cannot be replayed. Sends are NOT retried.');
  if (reconnectTimer || document.hidden) return;
  reconnectTimer = setTimeout(() => {
    reconnectTimer = null;
    connect();
  }, reconnectDelay + Math.random() * 500);
  reconnectDelay = Math.min(reconnectDelay * 2, 15000);
}

function connect() {
  if (source || document.hidden) return;
  source = new EventSource('/api/events');
  source.onmessage = (event) => {
    let value;
    try { value = JSON.parse(event.data); } catch (_) { reconnect(); return; }
    switch (value.type) {
      case 'connected':
        reconnectDelay = 1000;
        connection('Connected · live only', true);
        byId('identity').textContent = value.peer || 'Unknown';
        refreshStatus();
        break;
      case 'message':
        addEntry(`From ${value.from}`, value.body, value.timestamp_ms, 'message');
        break;
      case 'queued':
        addEntry(`Queued locally by ${value.from} · not delivered`, value.body, value.timestamp_ms, 'queued');
        break;
      case 'peer_up':
      case 'peer_down':
        addEntry(`${value.type === 'peer_up' ? 'Peer joined' : 'Peer left'}: ${value.peer}`, undefined, undefined, 'peer');
        break;
      case 'lagged':
        gap(value.message);
        addEntry('Feed gap · messages dropped; no replay', undefined, undefined, 'gap');
        break;
      case 'offline':
        byId('status').textContent = 'Daemon offline or restarting.';
        reconnect();
        break;
    }
  };
  source.onerror = reconnect;
}

draft.addEventListener('input', () => {
  byId('size').textContent = `${encoder.encode(draft.value).length} / 4096 UTF-8 bytes (envelope may reduce limit)`;
});
byId('composer').addEventListener('submit', async (event) => {
  event.preventDefault();
  if (sending) return;
  const body = draft.value;
  if (!body.trim() || encoder.encode(body).length > 4096) {
    byId('outcome').textContent = 'Not sent: use nonblank text, at most 4096 UTF-8 bytes.';
    return;
  }
  sending = true;
  byId('broadcast').disabled = true;
  byId('outcome').textContent = 'Submitting once…';
  try {
    const { ok, value } = await request({ command: 'send', body });
    if (ok && value.type === 'queued') {
      byId('outcome').textContent = 'Queued locally — NOT delivered or acknowledged. The live feed uses the daemon event; feed gaps are not replayed.';
      // The daemon's queued event is the one canonical feed entry in every tab.
      // Never erase edits made while the submission was in flight.
      if (draft.value === body) {
        draft.value = '';
        draft.dispatchEvent(new Event('input'));
      }
    } else if (value.outcome === 'not_sent') {
      byId('outcome').textContent = `Not sent: ${value.message} Draft preserved.`;
    } else {
      byId('outcome').textContent = 'Outcome unknown: it may have queued. Draft preserved. Check with peers before manually resending; duplicates are possible.';
    }
  } catch (_) {
    byId('outcome').textContent = 'Outcome unknown: connection failed or timed out; it may have queued. Draft preserved. No automatic retry. Check with peers before resending.';
  } finally {
    sending = false;
    byId('broadcast').disabled = false;
  }
});
byId('clear').addEventListener('click', () => feed.replaceChildren());
document.addEventListener('visibilitychange', () => {
  if (document.hidden) {
    if (source) source.close();
    source = null;
    clearTimeout(reconnectTimer);
    reconnectTimer = null;
    connection('Live feed paused while hidden', false);
    gap('Feed gap: this tab was hidden or the phone slept. No history or replay.');
  } else { refreshStatus(); connect(); }
});
window.addEventListener('online', () => { refreshStatus(); if (!source && !reconnectTimer) connect(); });
setInterval(refreshStatus, 15000);
refreshStatus();
connect();
