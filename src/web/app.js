'use strict';
const byId = (id) => document.getElementById(id);
const draft = byId('draft');
const feed = byId('feed');
const encoder = new TextEncoder();
let sending = false;
let sharing = false;
let selectedFile = null;
let pendingSend = null;
let pendingShare = null;
let source = null;
let reconnectTimer = null;
let reconnectDelay = 1000;
const snapshotTimeoutMs = 8000;
let statusRequest = null;
let peerStateGeneration = 0;
let peerDirectoryReady = false;
let directoryEpoch = null;
let directoryRevision = null;
const currentPeers = new Map();

function operationId() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

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

async function downloadAttachment(id, button, status, item) {
  button.disabled = true;
  status.textContent = 'Starting download…';
  try {
    const started = await request({ command: 'download', id });
    if (!started.ok || started.value.type !== 'download_started'
      || !Number.isSafeInteger(started.value.poll_timeout_ms)
      || started.value.poll_timeout_ms < 1 || started.value.poll_timeout_ms > 71 * 60 * 1000) {
      throw new Error(started.value.message || 'Download could not be started.');
    }
    const pollDeadline = Date.now() + started.value.poll_timeout_ms;
    while (Date.now() < pollDeadline) {
      const result = await request({ command: 'download_status', id: started.value.id });
      if (!result.ok) throw new Error(result.value.message || 'Download failed.');
      if (result.value.type === 'download_ready') {
        status.textContent = 'Download ready for at least one hour. Choose Save file.';
        const link = document.createElement('a');
        link.className = 'attachment-save';
        link.href = result.value.url;
        link.textContent = 'Save file';
        item.append(link);
        button.remove();
        return;
      }
      if (result.value.type !== 'download_pending') throw new Error('Unexpected download status.');
      status.textContent = 'Downloading and verifying…';
      await new Promise((resolve) => setTimeout(resolve, 500));
    }
    throw new Error('Download preparation deadline expired.');
  } catch (error) {
    status.textContent = `Download failed: ${error.message}`;
    button.disabled = false;
  }
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
  if (!outgoing && typeof value.download_id === 'string') {
    const button = document.createElement('button');
    button.className = 'attachment-download quiet';
    button.type = 'button';
    button.textContent = directory ? 'Download .tar' : 'Download';
    button.addEventListener('click', () => downloadAttachment(value.download_id, button, status, item));
    item.append(button);
  }
  prependEntry(item);
}

function connection(message, connected) {
  const element = byId('connection');
  element.textContent = message;
  element.className = connected ? 'connected' : '';
}

async function request(value) {
  const controller = new AbortController();
  const request_id = operationId();
  value = { schema_version: 1, request_id, request: value };
  const timer = setTimeout(() => controller.abort(), 12000);
  try {
    const response = await fetch('/api/request', {
      method: 'POST', headers: {
        'Content-Type': 'application/json', 'X-Meshmsg-Request-Id': request_id
      },
      body: JSON.stringify(value), signal: controller.signal,
      // CORS mode makes browsers send the real Origin even under our
      // Referrer-Policy: no-referrer. The URL remains same-origin and the
      // server still rejects every non-matching Host/Origin pair.
      mode: 'cors', credentials: 'omit', redirect: 'error', cache: 'no-store'
    });
    return { ok: response.ok, value: await response.json() };
  } finally { clearTimeout(timer); }
}

function showSelectedFile(file) {
  selectedFile = file;
  byId('selected-file-name').textContent = file.name;
  byId('selected-file-size').textContent = attachmentSize(file.size) || '';
  byId('selected-attachment').hidden = false;
}

function clearSelectedFile() {
  selectedFile = null;
  byId('attachment').value = '';
  byId('selected-attachment').hidden = true;
  byId('selected-file-name').textContent = '';
  byId('selected-file-size').textContent = '';
}

async function shareAttachment(file) {
  const operation_id = pendingShare?.file === file ? pendingShare.id : operationId();
  pendingShare = { file, id: operation_id };
  const outcome = byId('outcome');
  const button = byId('broadcast');
  sharing = true;
  button.disabled = true;
  outcome.textContent = `Uploading ${file.name} once…`;
  try {
    const request_id = operationId();
    const response = await fetch('/api/attachment', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/octet-stream',
        'X-Meshmsg-File-Name': encodeURIComponent(file.name),
        'X-Meshmsg-Operation-Id': operation_id,
        'X-Meshmsg-Request-Id': request_id
      },
      body: file,
      mode: 'cors', credentials: 'omit', redirect: 'error', cache: 'no-store'
    });
    const value = await response.json();
    if (response.ok && value.type === 'attachment_shared'
      && value.schema_version === 3 && value.operation_id === operation_id) {
      outcome.textContent = 'Attachment offer shared locally — delivery unconfirmed and not acknowledged. The live feed uses the daemon event.';
      pendingShare = null;
      if (selectedFile === file) clearSelectedFile();
    } else if (value.outcome === 'not_shared' || value.outcome === 'not_started') {
      pendingShare = null;
      outcome.textContent = `Not shared: ${value.message} File selection preserved.`;
    } else {
      outcome.textContent = 'Share outcome unknown: the offer may have been published. File selection and retry ID preserved; manually retry unchanged while the same daemon cache is active.';
    }
  } catch (_) {
    outcome.textContent = 'Share outcome unknown: upload connection failed or the reply was lost. File selection and retry ID preserved; no automatic retry.';
  } finally {
    sharing = false;
    button.disabled = false;
  }
}

async function refreshStatus() {
  if (statusRequest || document.hidden) return;
  const requestState = { generation: peerStateGeneration };
  statusRequest = requestState;
  try {
    const { ok, value } = await request({ command: 'status' });
    if (!ok || value.type !== 'status') throw new Error('offline');
    if (requestState.generation === peerStateGeneration && !document.hidden
        && !peerDirectoryReady) {
      const peers = Number.isInteger(value.neighbors) && value.neighbors >= 0 ? value.neighbors : '?';
      byId('status').textContent = `${peers} direct ${peers === 1 ? 'peer' : 'peers'}`;
    }
  } catch (_) {
    if (requestState.generation === peerStateGeneration && !document.hidden) {
      byId('status').textContent = 'Peer summary unavailable';
    }
  } finally {
    if (statusRequest === requestState) statusRequest = null;
  }
}

function updatePeerSummary() {
  const count = currentPeers.size;
  byId('status').textContent = `${count} current ${count === 1 ? 'peer' : 'peers'}`;
}

function invalidatePeers() {
  peerStateGeneration += 1;
  // Do not let a request from the superseded connection/visibility generation
  // block a fresh status request. Its eventual result is ignored above.
  statusRequest = null;
  currentPeers.clear();
  directoryEpoch = null;
  directoryRevision = null;
  peerDirectoryReady = false;
  byId('status').textContent = 'Peer directory unavailable';
}

function validSnapshot(value) {
  return value.schema_version === 2
    && typeof value.directory_epoch === 'string'
    && Number.isInteger(value.directory_revision) && value.directory_revision >= 0
    && value.self && typeof value.self.public_key === 'string'
    && Array.isArray(value.peers)
    && value.peers.every((peer) => peer && typeof peer.public_key === 'string'
      && peer.online === true);
}

function replacePeers(value) {
  if (!validSnapshot(value)) return false;
  directoryEpoch = value.directory_epoch;
  directoryRevision = value.directory_revision;
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
  return true;
}

function updatePeer(value, expired) {
  if (value.directory_epoch !== directoryEpoch || value.directory_revision !== directoryRevision + 1) {
    gap('Peer directory changed or an event was missed; reconnecting for authoritative state.');
    return false;
  }
  directoryRevision = value.directory_revision;
  const peer = value && value.peer;
  if (!peer || typeof peer.public_key !== 'string'
      || peer.online !== !expired) return false;
  if (expired) currentPeers.delete(peer.public_key);
  else currentPeers.set(peer.public_key, peer);
  peerDirectoryReady = true;
  updatePeerSummary();
  const alias = typeof peer.alias === 'string' ? ` (${peer.alias})` : '';
  addEntry(`${expired ? 'Peer expired' : value.type === 'peer_discovered' ? 'Peer discovered' : 'Peer updated'}: ${peer.public_key}${alias}`, undefined, undefined, 'peer');
  return true;
}

function gap(message) {
  byId('gap').textContent = message;
}

function reconnect(expectedSource) {
  // Closed EventSources can still dispatch queued callbacks. Only the current
  // subscription may alter connection state or schedule its replacement.
  if (expectedSource !== undefined && expectedSource !== source) return;
  if (source && source.snapshotTimer) clearTimeout(source.snapshotTimer);
  if (source) source.close();
  source = null;
  invalidatePeers();
  connection('Live feed disconnected · reconnecting', false);
  gap('Feed gap possible. Messages during disconnection cannot be replayed. Sends are NOT retried.');
  if (reconnectTimer || document.hidden) return;
  const delay = Math.min(reconnectDelay + Math.random() * 500, 15000);
  const timer = setTimeout(() => {
    if (reconnectTimer !== timer) return;
    reconnectTimer = null;
    connect();
  }, delay);
  reconnectTimer = timer;
  reconnectDelay = Math.min(reconnectDelay * 2, 15000);
}

function connect() {
  if (source || document.hidden) return;
  const nextSource = new EventSource('/api/events');
  let connected = false;
  let initialized = false;
  nextSource.snapshotTimer = setTimeout(() => reconnect(nextSource), snapshotTimeoutMs);
  source = nextSource;
  nextSource.onmessage = (event) => {
    if (source !== nextSource) return;
    let value;
    try { value = JSON.parse(event.data); } catch (_) { reconnect(nextSource); return; }
    switch (value.type) {
      case 'connected':
        if (connected || initialized) { reconnect(nextSource); break; }
        connected = true;
        connection('Connected · synchronizing peers', true);
        refreshStatus();
        break;
      case 'message':
        addEntry(`From ${value.from}`, value.body, value.timestamp_ms, 'message');
        break;
      case 'queued':
        addEntry(`Queued locally by ${value.from} · delivery unconfirmed`, value.body, value.timestamp_ms, 'queued');
        break;
      case 'attachment_offer':
      case 'attachment_shared':
        addAttachment(value);
        break;
      case 'peers_snapshot':
        if (!connected || initialized || !replacePeers(value)) {
          reconnect(nextSource);
          break;
        }
        initialized = true;
        clearTimeout(nextSource.snapshotTimer);
        nextSource.snapshotTimer = null;
        reconnectDelay = 1000;
        connection('Connected · live only', true);
        break;
      case 'peer_discovered':
      case 'peer_updated':
        if (!initialized || !updatePeer(value, false)) reconnect(nextSource);
        break;
      case 'peer_expired':
        if (!initialized || !updatePeer(value, true)) reconnect(nextSource);
        break;
      case 'lagged':
        gap(value.message);
        addEntry('Feed gap · messages dropped; reconnecting for peer directory', undefined, undefined, 'gap');
        reconnect(nextSource);
        break;
      case 'error':
        if (value.code === 'internal_contract_error') {
          const suppressed = Number.isSafeInteger(value.suppressed_since_last)
            && value.suppressed_since_last > 0
            ? ` · ${value.suppressed_since_last} similar event${value.suppressed_since_last === 1 ? '' : 's'} suppressed`
            : '';
          addEntry(`Warning · malformed internal event rejected${suppressed}`, value.message, undefined, 'warning');
          break;
        }
        if (value.code !== 'daemon_offline' && value.code !== 'daemon_disconnected') break;
        byId('status').textContent = 'Daemon offline or restarting.';
        reconnect(nextSource);
        break;
    }
  };
  nextSource.onerror = () => reconnect(nextSource);
}

draft.addEventListener('input', () => {
  byId('size').textContent = `${encoder.encode(draft.value).length} / 3900 UTF-8 bytes`;
});
document.addEventListener('keydown', (event) => {
  if (event.ctrlKey && event.key === 'Enter') {
    event.preventDefault();
    byId('composer').requestSubmit();
  }
});
byId('composer').addEventListener('submit', async (event) => {
  event.preventDefault();
  if (sending || sharing) return;
  if (selectedFile) {
    const file = selectedFile;
    if (!file.name || encoder.encode(file.name).length > 100) {
      byId('outcome').textContent = 'Not shared: filename must be nonblank and at most 100 UTF-8 bytes.';
      return;
    }
    await shareAttachment(file);
    return;
  }
  const body = draft.value;
  if (!body || encoder.encode(body).length > 3900) {
    byId('outcome').textContent = 'Not sent: write a nonempty message or attach a file. Text may be at most 3900 UTF-8 bytes.';
    return;
  }
  sending = true;
  byId('broadcast').disabled = true;
  byId('outcome').textContent = 'Submitting once…';
  try {
    const operation_id = pendingSend?.body === body ? pendingSend.id : operationId();
    pendingSend = { body, id: operation_id };
    const { ok, value } = await request({ command: 'send', operation_id, body });
    if (ok && value.type === 'queued' && value.schema_version === 3
      && value.operation_id === operation_id && value.message_id === operation_id) {
      pendingSend = null;
      byId('outcome').textContent = '';
      // The daemon's queued event is the one canonical feed entry in every tab.
      // Never erase edits made while the submission was in flight.
      if (draft.value === body) {
        draft.value = '';
        draft.dispatchEvent(new Event('input'));
      }
    } else if (value.outcome === 'not_sent' || value.outcome === 'not_started') {
      pendingSend = null;
      byId('outcome').textContent = `Not sent: ${value.message} Draft preserved.`;
    } else {
      byId('outcome').textContent = 'Outcome unknown: it may have queued. Draft and retry ID preserved; manually retry unchanged while the same daemon cache is active.';
    }
  } catch (_) {
    byId('outcome').textContent = 'Outcome unknown: connection failed or timed out; it may have queued. Draft preserved. No automatic retry. Check with peers before resending.';
  } finally {
    sending = false;
    byId('broadcast').disabled = false;
  }
});
byId('attachment').addEventListener('change', (event) => {
  const file = event.target.files && event.target.files[0];
  if (file) showSelectedFile(file);
});
byId('remove-attachment').addEventListener('click', clearSelectedFile);
const composerBox = byId('composer-box');
for (const eventName of ['dragenter', 'dragover']) {
  composerBox.addEventListener(eventName, (event) => {
    event.preventDefault();
    if (event.dataTransfer) event.dataTransfer.dropEffect = 'copy';
    composerBox.classList.add('dragging');
  });
}
composerBox.addEventListener('dragleave', (event) => {
  if (!composerBox.contains(event.relatedTarget)) composerBox.classList.remove('dragging');
});
composerBox.addEventListener('drop', (event) => {
  event.preventDefault();
  composerBox.classList.remove('dragging');
  const file = event.dataTransfer && event.dataTransfer.files && event.dataTransfer.files[0];
  if (file) showSelectedFile(file);
});
byId('clear').addEventListener('click', () => feed.replaceChildren());
document.addEventListener('visibilitychange', () => {
  if (document.hidden) {
    if (source && source.snapshotTimer) clearTimeout(source.snapshotTimer);
    if (source) source.close();
    source = null;
    clearTimeout(reconnectTimer);
    reconnectTimer = null;
    invalidatePeers();
    connection('Live feed paused while hidden', false);
    gap('Feed gap: this tab was hidden or the phone slept. No history or replay.');
  } else { refreshStatus(); connect(); }
});
window.addEventListener('online', () => { refreshStatus(); if (!source && !reconnectTimer) connect(); });
setInterval(refreshStatus, 15000);
refreshStatus();
connect();
