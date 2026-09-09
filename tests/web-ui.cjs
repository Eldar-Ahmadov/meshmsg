// Browser-independent behavior checks for the embedded vanilla UI. No packages.
// This exercises DOM logic, not browser layout, CSP enforcement or phone sleep.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const html = fs.readFileSync('src/web/index.html', 'utf8');
const settingsHtml = fs.readFileSync('src/web/settings.html', 'utf8');
const css = fs.readFileSync('src/web/app.css', 'utf8');
const js = fs.readFileSync('src/web/app.js', 'utf8');
const settingsJs = fs.readFileSync('src/web/settings.js', 'utf8');
for (const source of [js, settingsJs]) {
  assert.match(source, /mode: 'cors'/, 'POST fetches must preserve Origin under no-referrer policy');
  assert.doesNotMatch(source, /mode: 'same-origin'/);
}
assert.match(html, /<ol id="feed"[^>]*aria-live="polite"[^>]*aria-relevant="additions"/);
assert.match(html, /<a class="settings-link" href="\/settings" aria-label="[^"]+">/);
assert.doesNotMatch(html, /Local daemon|Sending identity/);
assert.match(settingsHtml, /<h1>MESHMSG STATUS<\/h1>/);
assert.match(settingsHtml, /<button id="status-refresh"[^>]*aria-label="Refresh status"/);
assert.match(settingsHtml, /<p id="status-message" role="status" aria-live="polite">/);
for (const privateLabel of ['state dir', 'invite', 'offer', 'token', 'ticket']) {
  assert.ok(!settingsHtml.toLowerCase().includes(privateLabel), `status page exposed ${privateLabel}`);
}
const mobileCss = css.slice(css.indexOf('@media (max-width: 38rem)'), css.indexOf('@media (prefers-reduced-transparency'));
assert.match(mobileCss, /\.compose h2, \.shortcut \{ display: none; \}/);
assert.doesNotMatch(mobileCss, /#outcome[^}]*display:\s*none/);

function cssBlock(selector) {
  const match = css.match(new RegExp(`(?:^|\\n)${selector} \\{([^}]*)\\}`));
  assert.ok(match, `missing ${selector} CSS block`);
  return match[1];
}
function luminance(hex) {
  const channels = hex.slice(1).match(/../g).map((value) => Number.parseInt(value, 16) / 255);
  const linear = channels.map((value) => value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4);
  return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2];
}
const buttonCss = cssBlock('button');
const buttonBackground = buttonCss.match(/background:\s*(#[0-9a-f]{6})/i)[1];
const buttonText = buttonCss.match(/color:\s*(#[0-9a-f]{6})/i)[1];
const buttonLuminance = [luminance(buttonBackground), luminance(buttonText)];
const buttonContrast = (Math.max(...buttonLuminance) + 0.05) / (Math.min(...buttonLuminance) + 0.05);
assert.ok(buttonContrast >= 4.5, `primary button contrast ${buttonContrast.toFixed(2)} is below 4.5:1`);
const composerCss = cssBlock('\\.compose');
assert.match(composerCss, /max-height:\s*calc\(var\(--composer-space\) \+ env\(safe-area-inset-bottom\)\)/);
assert.match(composerCss, /overflow-y:\s*auto/);
assert.match(cssBlock('main'), /padding:[^;]*var\(--composer-space\)/);

class Element extends EventTarget {
  constructor() { super(); this.children = []; this.attributes = {}; this._textContent = ''; this.textContentWrites = []; this.value = ''; this.href = ''; this.files = null; }
  get textContent() { return this._textContent; }
  set textContent(value) { this._textContent = value; this.textContentWrites.push(value); }
  append(child) { child.parent = this; this.children.push(child); }
  setAttribute(name, value) { this.attributes[name] = value; }
  prepend(child) { child.parent = this; this.children.unshift(child); }
  get lastElementChild() { return this.children.at(-1); }
  remove() { this.parent.children.splice(this.parent.children.indexOf(this), 1); }
  replaceChildren() { this.children = []; }
  requestSubmit() { this.dispatchEvent(new Event('submit', { cancelable: true })); }
  click() { this.clicked = true; this.dispatchEvent(new Event('click')); }
}
class Document extends EventTarget {
  constructor() { super(); this.elements = new Map(); this.hidden = false; this.body = new Element(); }
  getElementById(id) {
    if (!this.elements.has(id)) this.elements.set(id, new Element());
    return this.elements.get(id);
  }
  createElement() { return new Element(); }
}
class EventSource {
  static instances = [];
  constructor(url) { this.url = url; EventSource.instances.push(this); }
  close() { this.closed = true; }
  emit(value) { this.onmessage({ data: JSON.stringify(value) }); }
}
const document = new Document();
const window = new EventTarget();
const timers = new Map();
const scheduledTimerIds = [];
let timerId = 0;
const deterministicMath = Object.create(Math);
deterministicMath.random = () => 0;
const sent = [];
const downloadRequests = [];
let downloadedHref = null;
let uploaded = null;
let uploadReply = async (operationId) => ({ ok: true, json: async () => ({
  type: 'attachment_shared', schema_version: 3, operation_id: operationId
}) });
let peersRequests = 0;
let statusReply = async () => ({ ok: true, json: async () => ({ type: 'status', peer: 'local-peer', running: true, endpoint_online: true, topic_joined: true, neighbors: 1 }) });
let sendReply = async (request) => ({ ok: true, json: async () => ({
  type: 'queued', schema_version: 3,
  operation_id: request.operation_id, message_id: request.operation_id
}) });
let operationByte = 0;
const crypto = { getRandomValues: (bytes) => { bytes.fill(++operationByte); return bytes; } };
const context = vm.createContext({
  document, window, EventSource, Event, TextEncoder, AbortController, crypto, console,
  Math: deterministicMath,
  setTimeout: (fn, delay) => {
    const id = ++timerId;
    scheduledTimerIds.push(id);
    timers.set(id, { fn, delay, cancelled: false });
    return id;
  },
  clearTimeout: (id) => { const timer = timers.get(id); if (timer) timer.cancelled = true; }, setInterval: () => {},
  fetch: async (url, options) => {
    if (url === '/api/attachment') {
      uploaded = { body: options.body, headers: options.headers };
      return uploadReply(options.headers['X-Meshmsg-Operation-Id']);
    }
    const request = JSON.parse(options.body);
    if (request.command === 'status') return statusReply();
    if (request.command === 'peers') {
      peersRequests += 1;
      return { ok: true, json: async () => ({
        type: 'peers_snapshot', schema_version: 2, generated_at_ms: 1700000001000,
        directory_epoch: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', directory_revision: 0,
        self: { public_key: 'local-peer', alias: 'local', online: true },
        peers: [{ public_key: 'recovered-peer', alias: null, online: true, last_seen_ms: 2, expires_at_ms: 3 }]
      }) };
    }
    if (request.command === 'download') {
      downloadRequests.push(request);
      return { ok: true, json: async () => ({ type: 'download_started', id: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', poll_timeout_ms: 4260000 }) };
    }
    if (request.command === 'download_status') {
      downloadRequests.push(request);
      downloadedHref = `/api/download/${request.id}`;
      return { ok: true, json: async () => ({ type: 'download_ready', url: downloadedHref }) };
    }
    sent.push(request);
    return sendReply(request);
  }
});
vm.runInContext(js, context);
const el = (id) => document.getElementById(id);
const settle = () => new Promise(setImmediate);
function runTimer(id, { stale = false } = {}) {
  const timer = timers.get(id);
  assert.ok(timer, `timer ${id} was not recorded`);
  assert.ok(stale || !timer.cancelled, `timer ${id} was cancelled`);
  timer.cancelled = true;
  timer.fn();
}
const activeTimers = () => [...timers].filter(([, timer]) => !timer.cancelled);
function submit(body) {
  el('draft').value = body;
  el('composer').dispatchEvent(new Event('submit', { cancelable: true }));
}

(async () => {
  await settle();
  assert.equal(el('status').textContent, '1 direct peer');
  let source = EventSource.instances.at(-1);
  const snapshot = {
    type: 'peers_snapshot', schema_version: 2, generated_at_ms: 1700000000000,
    directory_epoch: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', directory_revision: 0,
    self: { public_key: 'local-peer', alias: 'local', online: true },
    peers: [
      { public_key: 'peer-a', alias: null, online: true, last_seen_ms: 1, expires_at_ms: 2 },
      { public_key: 'peer-b', alias: 'bravo', online: true, last_seen_ms: 1, expires_at_ms: 2 }
    ]
  };
  source.emit(snapshot);
  assert.equal(source.closed, true, 'snapshot before connected was accepted');
  assert.equal(el('status').textContent, 'Peer directory unavailable');
  let reconnectTimerId = scheduledTimerIds.at(-1);
  assert.equal(timers.get(reconnectTimerId).delay, 1000);
  runTimer(reconnectTimerId);

  source = EventSource.instances.at(-1);
  source.emit({ type: 'connected' });
  source.emit({
    type: 'peer_discovered', schema_version: 2,
    directory_epoch: snapshot.directory_epoch, directory_revision: 1,
    peer: { public_key: 'too-early', alias: null, online: true }
  });
  assert.equal(source.closed, true, 'pre-snapshot lifecycle event was accepted');
  assert.equal(el('status').textContent, 'Peer directory unavailable');
  reconnectTimerId = scheduledTimerIds.at(-1);
  assert.equal(timers.get(reconnectTimerId).delay, 2000, 'connected reset backoff before a snapshot');
  runTimer(reconnectTimerId);

  source = EventSource.instances.at(-1);
  source.emit({ type: 'connected' });
  assert.equal(el('status').textContent, 'Peer directory unavailable');
  source.emit(snapshot);
  assert.equal(el('status').textContent, '2 current peers');
  source.emit({
    type: 'peer_discovered', schema_version: 2,
    directory_epoch: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', directory_revision: 1,
    peer: { public_key: '<peer-c>', alias: '<text-only>', online: true, last_seen_ms: 1, expires_at_ms: 2 }
  });
  assert.equal(el('status').textContent, '3 current peers');
  assert.match(el('feed').children[0].children[0].textContent, / · Peer discovered: <peer-c> \(<text-only>\)$/);
  source.emit({
    type: 'peer_updated', schema_version: 2,
    directory_epoch: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', directory_revision: 2,
    peer: { public_key: '<peer-c>', alias: '<updated>', online: true, last_seen_ms: 2, expires_at_ms: 3 }
  });
  assert.equal(el('status').textContent, '3 current peers');
  assert.match(el('feed').children[0].children[0].textContent, / · Peer updated: <peer-c> \(<updated>\)$/);
  source.emit({
    type: 'peer_expired', schema_version: 2,
    directory_epoch: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', directory_revision: 3,
    peer: { public_key: '<peer-c>', alias: '<updated>', online: false, last_seen_ms: 2, expires_at_ms: 3 }
  });
  assert.equal(el('status').textContent, '2 current peers');
  assert.match(el('feed').children[0].children[0].textContent, / · Peer expired: <peer-c> \(<updated>\)$/);
  el('clear').dispatchEvent(new Event('click'));
  submit('hello <script>text only</script>');
  await settle();
  assert.equal(sent.length, 1);
  assert.match(sent[0].operation_id, /^[0-9a-f]{32}$/);
  assert.equal(el('draft').value, '');
  assert.equal(el('outcome').textContent, '');

  el('draft').value = 'keyboard send';
  const shortcut = new Event('keydown', { cancelable: true });
  Object.defineProperties(shortcut, { ctrlKey: { value: true }, key: { value: 'Enter' } });
  document.dispatchEvent(shortcut);
  await settle();
  assert.equal(sent.length, 2);
  assert.equal(sent.at(-1).body, 'keyboard send');
  assert.equal(shortcut.defaultPrevented, true);
  assert.equal(el('feed').children.length, 0, 'POST response created a duplicate optimistic entry');
  const file = { name: 'browser résumé.txt', size: 24 };
  el('attachment').files = [file];
  el('attachment').value = 'selected';
  el('attachment').dispatchEvent(new Event('change'));
  const attachmentShortcut = new Event('keydown', { cancelable: true });
  Object.defineProperties(attachmentShortcut, { ctrlKey: { value: true }, key: { value: 'Enter' } });
  document.dispatchEvent(attachmentShortcut);
  await settle();
  assert.equal(attachmentShortcut.defaultPrevented, true);
  assert.equal(uploaded.body, file);
  assert.equal(uploaded.headers['Content-Type'], 'application/octet-stream');
  assert.equal(uploaded.headers['X-Meshmsg-File-Name'], 'browser%20r%C3%A9sum%C3%A9.txt');
  assert.match(uploaded.headers['X-Meshmsg-Operation-Id'], /^[0-9a-f]{32}$/);
  assert.equal(el('attachment').value, '');
  assert.match(el('outcome').textContent, /shared locally.*delivery unconfirmed.*live feed/);
  assert.equal(el('feed').children.length, 0, 'upload response created an optimistic attachment');

  uploadReply = async () => ({ ok: false, json: async () => ({ outcome: 'not_shared', message: 'Attachment too large.' }) });
  const rejectedFile = { name: 'large.bin', size: 999 };
  el('attachment').files = [rejectedFile];
  el('attachment').value = 'preserved';
  el('attachment').dispatchEvent(new Event('change'));
  el('composer').dispatchEvent(new Event('submit', { cancelable: true }));
  await settle();
  assert.equal(el('attachment').value, 'preserved');
  assert.match(el('outcome').textContent, /Not shared.*File selection preserved/);

  uploadReply = async () => ({ ok: false, json: async () => ({ outcome: 'unknown', message: 'Post-broadcast failure.' }) });
  const ambiguousFile = { name: 'ambiguous.txt', size: 12 };
  el('attachment').files = [ambiguousFile];
  el('attachment').value = 'ambiguous-preserved';
  el('attachment').dispatchEvent(new Event('change'));
  el('composer').dispatchEvent(new Event('submit', { cancelable: true }));
  await settle();
  assert.equal(el('attachment').value, 'ambiguous-preserved');
  assert.match(el('outcome').textContent, /outcome unknown.*retry ID preserved.*retry unchanged/i);
  const ambiguousOperationId = uploaded.headers['X-Meshmsg-Operation-Id'];
  uploadReply = async (operationId) => ({ ok: true, json: async () => ({
    type: 'attachment_shared', schema_version: 3, operation_id: operationId
  }) });
  el('composer').dispatchEvent(new Event('submit', { cancelable: true }));
  await settle();
  assert.equal(uploaded.headers['X-Meshmsg-Operation-Id'], ambiguousOperationId);
  el('remove-attachment').click();

  source.emit({ type: 'queued', from: 'local-peer', body: 'hello <script>text only</script>', timestamp_ms: 1700000000000, delivery_acknowledged: false });
  assert.equal(el('feed').children.length, 1);
  assert.equal(el('feed').children[0].children[1].textContent, 'hello <script>text only</script>');
  assert.match(el('feed').children[0].children[0].textContent, /Queued locally by local-peer.*delivery unconfirmed/);
  const feedLength = el('feed').children.length;
  source.emit({ type: 'peer_up', peer: '<low-level-neighbor>' });
  source.emit({ type: 'peer_down', peer: '<low-level-neighbor>' });
  assert.equal(el('feed').children.length, feedLength, 'low-level neighbor events were displayed');

  source.emit({
    type: 'attachment_offer', direction: 'incoming', from: '<peer>',
    timestamp_ms: 1700000000100, name: '<img src=x onerror=alert(1)>',
    kind: 'file', size: 1536, download_id: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    offer: 'must-not-arrive', ticket: 'must-not-arrive'
  });
  let card = el('feed').children[0];
  assert.equal(card.className, 'attachment incoming');
  assert.equal(card.children[0].textContent, `${new Date(1700000000100).toLocaleTimeString()} · From <peer>`);
  assert.equal(card.children[1].children[0].attributes['aria-hidden'], 'true');
  assert.equal(card.children[1].children[1].children[0].textContent, '<img src=x onerror=alert(1)>');
  assert.equal(card.children[1].children[1].children[1].textContent, 'File · 1.5 KiB');
  assert.equal(card.children[2].textContent, 'Offer received');
  assert.equal(card.children[3].textContent, 'Download');
  const realDateNow = Date.now;
  let downloadClockReads = 0;
  Date.now = () => (downloadClockReads++ === 0 ? 0 : 60 * 60 * 1000 + 1);
  card.children[3].click();
  await settle();
  await settle();
  Date.now = realDateNow;
  assert.deepEqual(downloadRequests, [
    { command: 'download', id: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' },
    { command: 'download_status', id: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' }
  ]);
  assert.equal(downloadedHref, '/api/download/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb');
  assert.match(card.children[2].textContent, /Download ready.*Choose Save file/);
  assert.equal(card.children[3].textContent, 'Save file');
  assert.equal(card.children[3].href, downloadedHref);
  assert.equal(card.children[3].clicked, undefined, 'ready download was opened without another user click');

  source.emit({
    type: 'attachment_shared', direction: 'outgoing', from: 'local-peer',
    timestamp_ms: 1700000000200, name: 'results.tar', kind: 'directory_tar_v1', size: 4096
  });
  card = el('feed').children[0];
  assert.equal(card.className, 'attachment outgoing');
  assert.match(card.children[0].textContent, /Shared by local-peer/);
  assert.equal(card.children[1].children[0].className, 'attachment-icon folder');
  assert.equal(card.children[1].children[1].children[0].textContent, 'results.tar');
  assert.equal(card.children[1].children[1].children[1].textContent, 'Directory · 4 KiB');
  assert.equal(card.children[2].textContent, 'Offer shared · delivery not acknowledged');

  sendReply = async () => ({ ok: false, json: async () => ({ outcome: 'not_sent', message: 'Wait one second.' }) });
  submit('failed draft');
  await settle();
  assert.equal(el('draft').value, 'failed draft');
  assert.match(el('outcome').textContent, /Not sent.*Draft preserved/);

  sendReply = async () => { throw new Error('reply lost'); };
  submit('uncertain draft');
  await settle();
  assert.equal(sent.length, 4);
  assert.equal(el('draft').value, 'uncertain draft');
  assert.match(el('outcome').textContent, /Outcome unknown.*No automatic retry/);
  const uncertainOperationId = sent.at(-1).operation_id;
  sendReply = async (request) => ({ ok: true, json: async () => ({
    type: 'queued', schema_version: 3,
    operation_id: request.operation_id, message_id: request.operation_id
  }) });
  submit('uncertain draft');
  await settle();
  assert.equal(sent.length, 5);
  assert.equal(sent.at(-1).operation_id, uncertainOperationId);

  let resolve;
  sendReply = () => new Promise((r) => { resolve = r; });
  submit('pending draft');
  assert.equal(el('broadcast').disabled, true);
  el('composer').dispatchEvent(new Event('submit', { cancelable: true }));
  assert.equal(sent.length, 6, 'double tap sent twice');
  el('draft').value = 'new edits while submitting';
  const pendingRequest = sent.at(-1);
  resolve({ ok: true, json: async () => ({
    type: 'queued', schema_version: 3,
    operation_id: pendingRequest.operation_id, message_id: pendingRequest.operation_id
  }) });
  await settle();
  assert.equal(el('draft').value, 'new edits while submitting');
  assert.equal(el('broadcast').disabled, false);

  submit('二'.repeat(1366));
  await settle();
  assert.equal(sent.length, 6, 'oversized UTF-8 body sent');
  for (let i = 0; i < 110; i++) source.emit({ type: 'message', from: '<peer>', body: `<img onerror=alert(1)> ${i}`, timestamp_ms: 1700000000000 + i });
  assert.equal(el('feed').children.length, 100);
  assert.equal(el('feed').children[0].children[1].textContent, '<img onerror=alert(1)> 109');
  assert.equal(el('feed').children[0].children[0].textContent, `${new Date(1700000000109).toLocaleTimeString()} · From <peer>`);
  let resolveStaleStatus;
  statusReply = () => new Promise((resolveStatus) => { resolveStaleStatus = resolveStatus; });
  window.dispatchEvent(new Event('online'));
  await settle();
  source.emit({ type: 'lagged', message: 'Feed gap: dropped messages.' });
  assert.match(el('gap').textContent, /Feed gap/);
  assert.equal(source.closed, true);
  assert.equal(el('status').textContent, 'Peer directory unavailable', 'lag left stale peers current');
  assert.equal(peersRequests, 0, 'lag recovery raced the event stream with an HTTP snapshot');
  reconnectTimerId = scheduledTimerIds.at(-1);
  assert.equal(timers.get(reconnectTimerId).delay, 1000, 'authoritative snapshot did not reset backoff');
  resolveStaleStatus({ ok: true, json: async () => ({ type: 'status', neighbors: 99 }) });
  statusReply = async () => ({ ok: true, json: async () => ({ type: 'status', neighbors: 1 }) });
  await settle();
  assert.equal(el('status').textContent, 'Peer directory unavailable', 'stale status response overwrote lag invalidation');
  runTimer(reconnectTimerId);
  const recoveredSource = EventSource.instances.at(-1);
  const staleRecoveredSnapshotTimer = recoveredSource.snapshotTimer;
  assert.notEqual(recoveredSource, source);
  recoveredSource.emit({ type: 'connected' });
  recoveredSource.emit({
    type: 'peers_snapshot', schema_version: 2, generated_at_ms: 1700000001100,
    directory_epoch: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', directory_revision: 11,
    self: { public_key: 'local-peer', alias: 'local', online: true },
    peers: [
      { public_key: 'revision-11-a', alias: null, online: true },
      { public_key: 'revision-11-b', alias: null, online: true }
    ]
  });
  assert.equal(el('status').textContent, '2 current peers');
  await settle();
  source.emit({
    type: 'peers_snapshot', schema_version: 2, generated_at_ms: 1700000001000,
    directory_epoch: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', directory_revision: 10,
    self: { public_key: 'local-peer', alias: 'local', online: true },
    peers: [{ public_key: 'stale-revision-10', alias: null, online: true }]
  });
  assert.equal(el('status').textContent, '2 current peers', 'delayed revision 10 replaced revision 11');
  source.onerror();
  assert.equal(activeTimers().length, 0, 'stale EventSource callback scheduled a reconnect');
  assert.equal(sent.length, 6, 'peer snapshot recovery was treated as a send');

  let resolveHiddenStatus;
  statusReply = () => new Promise((resolveStatus) => { resolveHiddenStatus = resolveStatus; });
  window.dispatchEvent(new Event('online'));
  await settle();
  document.hidden = true;
  document.dispatchEvent(new Event('visibilitychange'));
  assert.equal(recoveredSource.closed, true);
  assert.equal(el('status').textContent, 'Peer directory unavailable', 'hidden tab left stale peers current');
  assert.match(el('gap').textContent, /phone slept/);
  resolveHiddenStatus({ ok: true, json: async () => ({ type: 'status', neighbors: 77 }) });
  statusReply = async () => ({ ok: true, json: async () => ({ type: 'status', neighbors: 1 }) });
  await settle();
  assert.equal(el('status').textContent, 'Peer directory unavailable', 'stale status response overwrote hide invalidation');
  document.hidden = false;
  document.dispatchEvent(new Event('visibilitychange'));
  assert.equal(EventSource.instances.length, 5);
  await settle();
  recoveredSource.onerror();
  assert.equal(activeTimers().length, 1, 'hidden/closed EventSource callback disturbed the current subscription');
  const timedOutSource = EventSource.instances.at(-1);
  runTimer(staleRecoveredSnapshotTimer, { stale: true });
  assert.equal(EventSource.instances.at(-1), timedOutSource, 'cancelled stale snapshot timer replaced the newer source');
  assert.equal(activeTimers().length, 1, 'cancelled stale snapshot timer disturbed current timers');
  runTimer(timedOutSource.snapshotTimer);
  assert.equal(timedOutSource.closed, true, 'startup snapshot timeout did not close the source');
  assert.equal(el('status').textContent, 'Peer directory unavailable');
  reconnectTimerId = scheduledTimerIds.at(-1);
  assert.equal(timers.get(reconnectTimerId).delay, 1000);
  timedOutSource.onerror();
  assert.equal(activeTimers().length, 1, 'timed-out EventSource callback scheduled another reconnect');
  runTimer(reconnectTimerId);
  const newestSource = EventSource.instances.at(-1);
  runTimer(reconnectTimerId, { stale: true });
  assert.equal(EventSource.instances.at(-1), newestSource, 'stale reconnect timer replaced the newer source');
  await settle();
  assert.equal(sent.length, 6, 'reconnection retried a send');
  assert.match(el('gap').textContent, /NOT retried/);
  el('clear').dispatchEvent(new Event('click'));
  assert.equal(el('feed').children.length, 0);

  const statusDocument = new Document();
  const statusRequests = [];
  let statusInterval;
  const statusContext = vm.createContext({
    document: statusDocument, window: new EventTarget(), Event, AbortController, console,
    setTimeout: (fn, delay) => { const id = ++timerId; timers.set(id, { fn, delay, cancelled: false }); return id; },
    clearTimeout: (id) => { const timer = timers.get(id); if (timer) timer.cancelled = true; }, setInterval: (fn) => { statusInterval = fn; },
    fetch: async (_, options) => {
      statusRequests.push(JSON.parse(options.body));
      return { ok: true, json: async () => ({
        type: 'status', running: true, endpoint_online: true, topic_joined: true,
        neighbors: 2, peer: '<safe-text-peer>', socket: '/private', invite: 'private-token'
      }) };
    }
  });
  vm.runInContext(settingsJs, statusContext);
  await settle();
  const statusEl = (id) => statusDocument.getElementById(id);
  assert.deepEqual(statusRequests, [{ command: 'status' }]);
  assert.equal(statusEl('daemon-value').textContent, 'Running');
  assert.equal(statusEl('endpoint-value').textContent, 'Online');
  assert.equal(statusEl('topic-value').textContent, 'Joined');
  assert.equal(statusEl('neighbors-value').textContent, '2');
  assert.equal(statusEl('peer-value').textContent, '<safe-text-peer>');
  assert.ok(![...statusDocument.elements.values()].some((element) => /private-token|\/private/.test(element.textContent)));
  statusEl('status-message').textContentWrites = [];
  await statusInterval();
  assert.equal(statusRequests.length, 2);
  assert.deepEqual(statusEl('status-message').textContentWrites, [], 'unchanged periodic status was announced');
  statusEl('status-refresh').dispatchEvent(new Event('click'));
  await settle();
  assert.equal(statusRequests.length, 3);
  assert.deepEqual(statusEl('status-message').textContentWrites, [
    'Refreshing status…', 'Status refreshed. Read-only; peer count is not delivery proof.'
  ]);

  console.log('PASS: accessible live feed and status route, deterministic peer snapshot/current count, text-only discovery/update/expiry lifecycle, atomic lag recovery without stale snapshot/callback rollback, silent unchanged periodic polling, mobile compose, AA primary button contrast, bounded composer, safe read-only status rendering/refresh, canonical daemon events without optimistic duplicates, browser attachment upload success/rejection and incoming/outgoing cards with safe text, queued/rejected/ambiguous wording, sender/timestamps, draft/file preservation, in-flight edits/double-tap, UTF-8 bound, text-only bounded feed, gap/reconnect, no automatic retry, and retained operation IDs');
})().catch((error) => { console.error(error); process.exitCode = 1; });
