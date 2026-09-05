// Browser-independent behavior checks for the embedded vanilla UI. No packages.
// This exercises DOM logic, not browser layout, CSP enforcement or phone sleep.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const html = fs.readFileSync('src/web/index.html', 'utf8');
const css = fs.readFileSync('src/web/app.css', 'utf8');
const js = fs.readFileSync('src/web/app.js', 'utf8');
assert.match(html, /<ol id="feed"[^>]*aria-live="polite"[^>]*aria-relevant="additions"/);

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
  constructor() { super(); this.children = []; this.attributes = {}; this.textContent = ''; this.value = ''; }
  append(child) { child.parent = this; this.children.push(child); }
  setAttribute(name, value) { this.attributes[name] = value; }
  prepend(child) { child.parent = this; this.children.unshift(child); }
  get lastElementChild() { return this.children.at(-1); }
  remove() { this.parent.children.splice(this.parent.children.indexOf(this), 1); }
  replaceChildren() { this.children = []; }
  requestSubmit() { this.dispatchEvent(new Event('submit', { cancelable: true })); }
}
class Document extends EventTarget {
  constructor() { super(); this.elements = new Map(); this.hidden = false; }
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
let timerId = 0;
const sent = [];
let sendReply = async () => ({ ok: true, json: async () => ({ type: 'queued' }) });
const context = vm.createContext({
  document, window, EventSource, Event, TextEncoder, AbortController, console,
  setTimeout: (fn) => { timers.set(++timerId, fn); return timerId; },
  clearTimeout: (id) => timers.delete(id), setInterval: () => {},
  fetch: async (_, options) => {
    const request = JSON.parse(options.body);
    if (request.command === 'status') return { ok: true, json: async () => ({ type: 'status', peer: 'local-peer', running: true, endpoint_online: true, topic_joined: true, neighbors: 1 }) };
    sent.push(request);
    return sendReply();
  }
});
vm.runInContext(js, context);
const el = (id) => document.getElementById(id);
const settle = () => new Promise(setImmediate);
function submit(body) {
  el('draft').value = body;
  el('composer').dispatchEvent(new Event('submit', { cancelable: true }));
}

(async () => {
  await settle();
  assert.match(el('status').textContent, /Daemon running/);
  const source = EventSource.instances.at(-1);
  submit('hello <script>text only</script>');
  await settle();
  assert.equal(sent.length, 1);
  assert.equal(el('draft').value, '');
  assert.match(el('outcome').textContent, /Queued locally.*NOT delivered.*daemon event/);

  el('draft').value = 'keyboard send';
  const shortcut = new Event('keydown', { cancelable: true });
  Object.defineProperties(shortcut, { ctrlKey: { value: true }, key: { value: 'Enter' } });
  el('draft').dispatchEvent(shortcut);
  await settle();
  assert.equal(sent.length, 2);
  assert.equal(sent.at(-1).body, 'keyboard send');
  assert.equal(shortcut.defaultPrevented, true);
  assert.equal(el('feed').children.length, 0, 'POST response created a duplicate optimistic entry');
  source.emit({ type: 'queued', from: 'local-peer', body: 'hello <script>text only</script>', timestamp_ms: 1700000000000, delivery_acknowledged: false });
  assert.equal(el('feed').children.length, 1);
  assert.equal(el('feed').children[0].children[1].textContent, 'hello <script>text only</script>');
  assert.match(el('feed').children[0].children[0].textContent, /Queued locally by local-peer.*not delivered/);

  source.emit({
    type: 'attachment_offer', direction: 'incoming', from: '<peer>',
    timestamp_ms: 1700000000100, name: '<img src=x onerror=alert(1)>',
    kind: 'file', size: 1536, offer: 'must-not-arrive', ticket: 'must-not-arrive'
  });
  let card = el('feed').children[0];
  assert.equal(card.className, 'attachment incoming');
  assert.equal(card.children[0].textContent, `${new Date(1700000000100).toLocaleTimeString()} · From <peer>`);
  assert.equal(card.children[1].children[0].attributes['aria-hidden'], 'true');
  assert.equal(card.children[1].children[1].children[0].textContent, '<img src=x onerror=alert(1)>');
  assert.equal(card.children[1].children[1].children[1].textContent, 'File · 1.5 KiB');
  assert.equal(card.children[2].textContent, 'Offer received');

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

  let resolve;
  sendReply = () => new Promise((r) => { resolve = r; });
  submit('pending draft');
  assert.equal(el('broadcast').disabled, true);
  el('composer').dispatchEvent(new Event('submit', { cancelable: true }));
  assert.equal(sent.length, 5, 'double tap sent twice');
  el('draft').value = 'new edits while submitting';
  resolve({ ok: true, json: async () => ({ type: 'queued' }) });
  await settle();
  assert.equal(el('draft').value, 'new edits while submitting');
  assert.equal(el('broadcast').disabled, false);

  submit('二'.repeat(1366));
  await settle();
  assert.equal(sent.length, 5, 'oversized UTF-8 body sent');
  for (let i = 0; i < 110; i++) source.emit({ type: 'message', from: '<peer>', body: `<img onerror=alert(1)> ${i}`, timestamp_ms: 1700000000000 + i });
  assert.equal(el('feed').children.length, 100);
  assert.equal(el('feed').children[0].children[1].textContent, '<img onerror=alert(1)> 109');
  assert.equal(el('feed').children[0].children[0].textContent, `${new Date(1700000000109).toLocaleTimeString()} · From <peer>`);
  source.emit({ type: 'lagged', message: 'Feed gap: dropped messages.' });
  assert.match(el('gap').textContent, /Feed gap/);

  document.hidden = true;
  document.dispatchEvent(new Event('visibilitychange'));
  assert.equal(source.closed, true);
  assert.match(el('gap').textContent, /phone slept/);
  document.hidden = false;
  document.dispatchEvent(new Event('visibilitychange'));
  assert.equal(EventSource.instances.length, 2);
  EventSource.instances.at(-1).onerror();
  await settle();
  assert.equal(sent.length, 5, 'reconnection retried a send');
  assert.match(el('gap').textContent, /NOT retried/);
  el('clear').dispatchEvent(new Event('click'));
  assert.equal(el('feed').children.length, 0);
  console.log('PASS: accessible live feed, AA primary button contrast, bounded composer, canonical daemon queued event without optimistic duplicate, read-only incoming/outgoing attachment cards with safe text and human metadata, queued/rejected/ambiguous wording, sender/timestamps, draft preservation, in-flight edits/double-tap, UTF-8 bound, text-only bounded feed, gap/reconnect and no send retry');
})().catch((error) => { console.error(error); process.exitCode = 1; });
