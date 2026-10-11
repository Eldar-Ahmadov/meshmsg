const $ = (s) => document.querySelector(s);
const still = matchMedia('(prefers-reduced-motion: reduce)');
const DUR = { pin: 1.3, offer: 2.6, wait: 1.4, check: 0.9, connect: 1.1, commit: 1.0, install: 1.1 };
const streamDur = (size) => Math.min(7, Math.max(2.4, 2.2 + 0.45 * Math.log2(size / MiB)));
const ease = (t) => t * t * (3 - 2 * t);
const clamp01 = (t) => Math.max(0, Math.min(1, t));
const tr = (x = 0, z = 0) => `translate(${(V.x[0] * x + V.z[0] * z).toFixed(2)} ${(V.x[1] * x + V.z[1] * z).toFixed(2)})`;
const el = {
  card: $('#card'), provPin: $('#prov-pin'), recvPin: $('#recv-pin'), provLamp: $('#prov-lamp'), gateLamp: $('#gate-lamp'),
  lever: $('#lever'), barrier: $('#barrier'), carriage: $('#carriage'), staged: $('#staged'), existing: $('#existing'), installed: $('#installed'),
  chunks: [...document.querySelectorAll('[data-chunk]')], copies: [...document.querySelectorAll('[data-copy]')], readout: $('[data-readout]'),
};
const TAMPER_CHUNK = 4, GATE_STOP = GEO.GATE_X - 17;
const span = GEO.BELT_TO - GEO.BELT_FROM, lag = 0.6 / (GEO.CHUNKS - 1);
// progress at which the tampered block reaches the gate
const P_STOP = TAMPER_CHUNK * lag + 0.4 * ((GATE_STOP - GEO.BELT_FROM) / span);

let opts = defaults(), pl = plan(opts);
let phase = 0, t = 0, accepted = false, ended = false, playing = !still.matches, touring = !still.matches, idle = 0;
let frame = 0, last = 0, visible = false;

const name = () => pl.steps[phase];
const durOf = (id) => (id === 'stream' ? streamDur(pl.file.size) : DUR[id]);
const failsHere = () => pl.fail && pl.fail.at === name();

function progress() {
  // stream progress p in [0,1] (bytes received / size), and per-phase u
  const id = name();
  const idx = (s) => pl.steps.indexOf(s);
  if (!pl.transfers) return 0;
  if (phase > idx('stream')) return 1;
  if (id !== 'stream') return 0;
  const p = still.matches ? 1 : clamp01(t / durOf('stream'));
  return pl.fail?.at === 'stream' ? Math.min(p, P_STOP) : p;
}
function phaseU() {
  if (ended) return 1;
  return still.matches ? 1 : clamp01(t / durOf(name()));
}
function after(id) { const i = PHASES.indexOf(id), cur = PHASES.indexOf(name()); return cur > i || (cur === i && (ended || phaseU() >= 1)); }

function draw() {
  const id = name(), u = phaseU(), p = progress();
  // provider pin drops into its slot during "pin"
  const pinU = id === 'pin' ? ease(u) : 1;
  el.provPin.setAttribute('transform', tr(0, (1 - pinU) * 14));
  el.provPin.style.opacity = String(pinU);
  el.provLamp.style.opacity = opts.providerOnline ? '1' : '0.12';
  // offer card on the gossip rail
  const cu = id === 'pin' ? 0 : id === 'offer' ? ease(u) : 1;
  const cx = GEO.CARD_FROM + cu * (GEO.CARD_TO - GEO.CARD_FROM);
  el.card.setAttribute('transform', tr(cx - GEO.CARD_FROM, 0));
  el.card.style.opacity = id === 'pin' ? String(still.matches ? 0 : clamp01((u - 0.85) / 0.15)) : '1';
  el.copies.forEach((c, i) => (c.style.opacity = cx >= GEO.KIOSKS[i] && id !== 'pin' ? '1' : '0'));
  // accept lever
  const lu = accepted ? (id === 'wait' ? ease(clamp01(u * 3)) : 1) : 0;
  el.lever.setAttribute('transform', tr(lu * GEO.LEVER, 0));
  // destination already exists
  let alert = 1;
  if (opts.destExists && id === 'check') alert = still.matches ? 1 : 0.55 + 0.45 * Math.cos(t * 9);
  el.existing.style.opacity = opts.destExists ? String(alert) : '0';
  // blocks on the conveyor
  const stopped = pl.fail?.at === 'stream' && id === 'stream' && p >= P_STOP - 1e-6;
  let underGate = false;
  el.chunks.forEach((c, i) => {
    const cu2 = (p - i * lag) / 0.4;
    const show = id === 'stream' && cu2 > 0 && cu2 < 1;
    if (!show) { c.style.opacity = '0'; return; }
    const x = GEO.BELT_FROM + cu2 * span;
    if (Math.abs(x - GEO.GATE_X) < 9) underGate = true;
    let o = Math.min(1, cu2 * 12, (1 - cu2) * 12);
    if (stopped && i === TAMPER_CHUNK) o = 0.55 + 0.45 * Math.cos(t * 10);
    c.style.opacity = String(o);
    c.setAttribute('transform', tr(x, 0));
  });
  el.carriage.setAttribute('transform', tr(p * (GEO.CARRIAGE_TO - GEO.CARRIAGE_FROM), 0));
  el.gateLamp.style.opacity = stopped ? String(0.5 + 0.5 * Math.cos(t * 10)) : underGate ? '1' : '0.25';
  el.barrier.setAttribute('transform', tr(0, stopped ? -11 : 0));
  // receiver store, staging and destination
  const commitU = id === 'commit' ? ease(u) : after('commit') ? 1 : 0;
  el.recvPin.style.opacity = opts.dedup ? '1' : String(commitU);
  el.recvPin.setAttribute('transform', tr(0, opts.dedup ? 0 : (1 - commitU) * 14));
  const installU = id === 'install' ? ease(u) : 0;
  el.staged.style.opacity = String(id === 'commit' ? commitU : id === 'install' ? 1 - installU : 0);
  el.installed.style.opacity = String(id === 'install' ? installU : 0);
  el.installed.setAttribute('transform', tr(0, (1 - (id === 'install' ? installU : 0)) * 10));
  // numbers
  const c = counters(pl.file.size, p * pl.file.size, p >= 1);
  $('#m-bytes').textContent = bytes(c.received);
  $('#m-blocks').textContent = c.blocks.toLocaleString('en-GB');
  $('#m-events').textContent = c.events.toLocaleString('en-GB');
  el.readout.textContent = readout(id, c);
  steps();
  buttons();
}

function readout(id, c) {
  if (ended && pl.fail) return 'download_failed · nothing installed';
  if (ended) return `Installed · ${pl.file.name} · ${bytes(pl.file.size)}`;
  return {
    pin: `Pinning ${pl.file.name} · ${bytes(pl.file.size)}`,
    offer: 'Gossiping the signed offer',
    wait: accepted ? 'Download requested' : 'Offer received · waiting',
    check: 'Preflight checks',
    connect: 'Connecting to the provider',
    stream: `Streaming · ${bytes(c.received)} / ${bytes(pl.file.size)}`,
    commit: opts.dedup ? 'Already stored · pinning locally' : 'Pinning the incoming copy',
    install: 'Installing · no overwrite',
  }[id];
}
const MESSAGES = {
  pin: () => `The sender hashes ${pl.file.name} with BLAKE3 and pins it in its own blob store. Pinning happens before the offer is sent.`,
  offer: () => 'A signed offer (name, size, hash, provider, topic) spreads by gossip. Every peer on the topic gets a copy. The file itself stays put.',
  wait: () => (accepted ? 'Download requested with an output path.' : 'The offer is here, but nothing downloads until you ask. Press Download.'),
  check: () => 'Before any network work: the output path must not exist, and the signed size must be within this receiver’s limit.',
  connect: () => (opts.dedup ? '' : 'The receiver connects straight to the provider named in the offer and asks for the verified size.'),
  stream: () => `Blocks stream over the direct link. Each 16 KiB block is checked against the BLAKE3 hash before it counts.`,
  commit: () => (opts.dedup ? 'This receiver already has a complete copy with the same hash, so it skips the network entirely and pins its local copy.' : 'The complete, verified file is copied to a staging file, synced, and pinned in the receiver’s store.'),
  install: () => 'The staging file is hard-linked into the output path. If something now exists there, installation is refused rather than replacing it.',
};
function say() {
  let msg = MESSAGES[name()]();
  if (ended && pl.fail) msg = `download_failed: ${pl.fail.why}`;
  else if (ended) msg = `Done. ${pl.file.name} is installed at the output path and pinned on both peers. ${pl.transfers ? `${counters(pl.file.size, pl.file.size, true).blocks.toLocaleString('en-GB')} blocks verified.` : 'No bytes crossed the network.'}`;
  if (msg && $('#status').textContent !== msg) $('#status').textContent = msg;
}
function steps() {
  const map = { pin: ['pin'], offer: ['offer'], wait: ['wait'], check: ['check'], stream: ['connect', 'stream'], install: ['commit', 'install'] };
  const cur = name();
  for (const li of document.querySelectorAll('[data-step]')) {
    const ids = map[li.dataset.step];
    const runs = ids.some((i) => pl.steps.includes(i));
    const activeHere = ids.includes(cur);
    const fail = ended && pl.fail && ids.includes(pl.fail.at);
    const isDone = !fail && (ended && !pl.fail ? runs : ids.every((i) => !pl.steps.includes(i) || pl.steps.indexOf(i) < phase) && runs && !activeHere);
    const skipped = !runs && (opts.dedup && li.dataset.step === 'stream');
    li.dataset.state = fail ? 'fail' : activeHere && !ended ? 'active' : isDone ? 'done' : skipped ? 'skip' : (pl.fail && PHASES.indexOf(ids[0]) > PHASES.indexOf(pl.fail.at)) ? 'never' : 'todo';
  }
}
function buttons() {
  const waiting = name() === 'wait' && !accepted && !ended;
  $('#accept').disabled = !waiting;
  $('#accept').classList.toggle('ready', waiting);
  $('#play').textContent = playing ? 'Pause' : 'Play';
  $('#play').setAttribute('aria-pressed', String(playing));
  $('#step').disabled = ended || waiting;
}

function advance() {
  // finish the current phase and move on
  if (ended) return;
  if (failsHere()) { ended = true; return; }
  if (name() === 'wait' && !accepted) return;
  if (phase >= pl.steps.length - 1) { ended = true; return; }
  phase++; t = 0;
}
function phaseDone() {
  if (name() === 'wait') return accepted && (still.matches || t >= 0.45);
  if (name() === 'stream' && pl.fail?.at === 'stream') return progress() >= P_STOP && t >= durOf('stream') * P_STOP + 1.2;
  if (name() === 'connect' && pl.fail?.at === 'connect') return t >= 2.2;
  return t >= durOf(name());
}
function restart(fromWait) {
  pl = plan(opts);
  phase = fromWait ? pl.steps.indexOf('wait') : 0; t = 0; ended = false; accepted = false; idle = 0;
  draw(); say(); run();
}
function tick(now) {
  frame = 0;
  if (!visible || document.hidden) return;
  const dt = last ? Math.min((now - last) / 1000, 1 / 30) : 0;
  last = now;
  if (ended) {
    idle += dt;
    if (touring && idle > 3.5) { restart(false); return; }
  } else if (playing || name() === 'wait' && accepted) {
    t += dt;
    if (touring && name() === 'wait' && !accepted && t > DUR.wait) { accepted = true; t = 0; }
    if (phaseDone()) { advance(); say(); }
  }
  draw();
  if (!ended && (playing || accepted && name() === 'wait') || touring || (!still.matches && (name() === 'check' && opts.destExists || ended && pl.fail))) run(false);
}
function run(resetTime = true) { if (!frame && visible && !document.hidden) { if (resetTime) last = 0; frame = requestAnimationFrame(tick); } }
function stopTour() { touring = false; }

$('#play').addEventListener('click', () => { stopTour(); playing = !playing; if (ended && playing) restart(false); buttons(); run(); });
$('#step').addEventListener('click', () => { stopTour(); playing = false; if (name() === 'wait' && !accepted) { say(); return; } advance(); say(); draw(); run(); });
$('#accept').addEventListener('click', () => { stopTour(); accepted = true; t = 0; playing = true; say(); draw(); run(); });
$('#reset').addEventListener('click', () => { stopTour(); playing = !still.matches; restart(false); });
$('#file').addEventListener('change', (e) => { stopTour(); opts.file = e.target.value; playing = !still.matches; restart(false); });
$('#limit').addEventListener('change', (e) => { stopTour(); opts.limit = e.target.value; restart(true); });
for (const [id, key, invert] of [['provider', 'providerOnline', true], ['dest', 'destExists'], ['tamper', 'tamper'], ['dedup', 'dedup']]) {
  $('#' + id).addEventListener('click', (e) => {
    stopTour();
    const on = e.currentTarget.getAttribute('aria-pressed') !== 'true';
    e.currentTarget.setAttribute('aria-pressed', String(on));
    opts[key] = invert ? !on : on;
    restart(true);
  });
}
$('.iso-figure').addEventListener('pointerenter', () => { if (touring) { stopTour(); playing = true; } });
new IntersectionObserver((entries) => { visible = entries.at(-1).isIntersecting; if (visible) run(); else if (frame) { cancelAnimationFrame(frame); frame = 0; } }, { threshold: 0.05 }).observe($('.iso-plate'));
document.addEventListener('visibilitychange', () => { if (document.hidden) { cancelAnimationFrame(frame); frame = 0; } else run(); });
still.addEventListener('change', () => { if (still.matches) { touring = false; playing = false; } draw(); run(); });
draw(); say();
