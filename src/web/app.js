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
let peersBusy = false;
let peerDirectoryReady = false;
const currentPeers = new Map();

function prependEntry(item) {
  feed.prepend(item);
  while (feed.children.length > 100) feed.lastElementChild.remove();
}

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
  prependEntry(item);
}

function attachmentType(kind) {
  if (kind === 'file') return 'File';
  if (kind === 'directory_tar_v1') return 'Directory';
  return 'Attachment';
}

function attachmentSize(size) {
  if (!Number.isFinite(size) || size < 0) return null;
  const units = ['B', 'KiB', 'MiB', 'GiB'];
  let amount = size;
  let unit = 0;
  while (amount >= 1024 && unit < units.length - 1) {
    amount /= 1024;
    unit += 1;
  }
  const digits = unit === 0 || amount >= 10 ? 0 : 1;
  return `${amount.toFixed(digits).replace(/\.0$/, '')} ${units[unit]}`;
}

function addAttachment(value) {
  const outgoing = value.type === 'attachment_shared';
  const directory = value.kind === 'directory_tar_v1';
  const item = document.createElement('li');
  item.className = `attachment ${outgoing ? 'outgoing' : 'incoming'}`;

  const meta = document.createElement('small');
  const timestamp = Number.isFinite(value.timestamp_ms) ? new Date(value.timestamp_ms) : new Date();
  meta.textContent = `${timestamp.toLocaleTimeString()} · ${outgoing ? 'Shared by' : 'From'} ${value.from || 'Unknown peer'}`;
  item.append(meta);

  const summary = document.createElement('div');
  summary.className = 'attachment-summary';
  const icon = document.createElement('span');
  icon.className = `attachment-icon ${directory ? 'folder' : 'file'}`;
  icon.setAttribute('aria-hidden', 'true');
  summary.append(icon);
  const description = document.createElement('div');
  description.className = 'attachment-description';
  const name = document.createElement('p');
  name.className = 'attachment-name';
  name.textContent = value.name || 'Unnamed attachment';
  description.append(name);
  const details = document.createElement('p');
  details.className = 'attachment-details';
  const size = attachmentSize(value.size);
  details.textContent = size ? `${attachmentType(value.kind)} · ${size}` : attachmentType(value.kind);
  description.append(details);
  summary.append(description);
  item.append(summary);

  const status = document.createElement('p');
  status.className = 'attachment-status';
  status.textContent = outgoing ? 'Offer shared · delivery not acknowledged' : 'Offer received';
  item.append(status);
  prependEntry(item);
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
    if (!peerDirectoryReady) {
      const peers = Number.isInteger(value.neighbors) && value.neighbors >= 0 ? value.neighbors : '?';
      byId('status').textContent = `${peers} direct ${peers === 1 ? 'peer' : 'peers'}`;
    }
  } catch (_) {
    byId('status').textContent = 'Peer summary unavailable';
  } finally { statusBusy = false; }
}

function updatePeerSummary() {
  const count = currentPeers.size;
  byId('status').textContent = `${count} current ${count === 1 ? 'peer' : 'peers'}`;
}

function replacePeers(value) {
  currentPeers.clear();
  if (Array.isArray(value.peers)) {
    for (const peer of value.peers) {
      if (peer && typeof peer.public_key === 'string' && peer.online === true) {
        currentPeers.set(peer.public_key, peer);
      }
    }
  }
  peerDirectoryReady = true;
  updatePeerSummary();
}

function updatePeer(value, expired) {
  const peer = value && value.peer;
  if (!peer || typeof peer.public_key !== 'string') return;
  if (expired) currentPeers.delete(peer.public_key);
  else currentPeers.set(peer.public_key, peer);
  peerDirectoryReady = true;
  updatePeerSummary();
  const alias = typeof peer.alias === 'string' ? ` (${peer.alias})` : '';
  addEntry(`${expired ? 'Peer expired' : value.type === 'peer_discovered' ? 'Peer discovered' : 'Peer updated'}: ${peer.public_key}${alias}`, undefined, undefined, 'peer');
}

async function refreshPeers() {
  if (peersBusy || document.hidden) return;
  peersBusy = true;
  try {
    const { ok, value } = await request({ command: 'peers' });
    if (!ok || value.type !== 'peers_snapshot') throw new Error('unavailable');
    replacePeers(value);
  } catch (_) {
    currentPeers.clear();
    peerDirectoryReady = false;
    byId('status').textContent = 'Peer directory unavailable';
  } finally { peersBusy = false; }
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
        refreshStatus();
        break;
      case 'message':
        addEntry(`From ${value.from}`, value.body, value.timestamp_ms, 'message');
        break;
      case 'queued':
        addEntry(`Queued locally by ${value.from} · not delivered`, value.body, value.timestamp_ms, 'queued');
        break;
      case 'attachment_offer':
      case 'attachment_shared':
        addAttachment(value);
        break;
      case 'peers_snapshot':
        replacePeers(value);
        break;
      case 'peer_discovered':
      case 'peer_updated':
        updatePeer(value, false);
        break;
      case 'peer_expired':
        updatePeer(value, true);
        break;
      case 'peer_up':
      case 'peer_down':
        addEntry(`${value.type === 'peer_up' ? 'Peer joined' : 'Peer left'}: ${value.peer}`, undefined, undefined, 'peer');
        break;
      case 'lagged':
        gap(value.message);
        addEntry('Feed gap · messages dropped; refreshing peer directory', undefined, undefined, 'gap');
        refreshPeers();
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
draft.addEventListener('keydown', (event) => {
  if (event.ctrlKey && event.key === 'Enter') {
    event.preventDefault();
    byId('composer').requestSubmit();
  }
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
