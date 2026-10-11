import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import * as k from '../vendor/iso-kit.mjs';
import { FILES, LIMITS } from './model.mjs';

const here = fileURLToPath(new URL('.', import.meta.url));
const W = 900, H = 500;
const BASE = { x: -205, y: -104, w: 410, d: 196, r: 8 };
const P = k.fitProjection([...k.boxCorners(BASE, -19, 30), [-170, -40, 56], [160, -40, 56]], W, H, { pad: 30, azimuth: 60, elevation: 36 });
const at = (p) => k.iso(p, P);
const plan = (x, y, w, d, r = 1) => ({ x, y, w, d, r });
const L = (d, tone = 'lo', extra = {}) => k.lineSvg(d, { tone, ...extra });
const slab = (p, z, h, tone = 'mid', extra = {}) => k.solidSvg(k.slabOf(p, z, h, P, 5, Math.min(0.7, h / 3)), { tone, ...extra });
const outline = (p, z, tone = 'lo') => L(k.planOutline(p, z, P), tone);
const dots = (pts, z, tone = 'mid', size = 0.6) => k.dotsSvg(pts.map(([x, y]) => at([x, y, z])), { size, tone });
const screws = (p, z, inset = 3) => dots(k.corners(p, inset), z);
const seamed = (p, z, h, seamZ, tone = 'mid') => slab(p, z, h, tone, { inner: L(k.sideSeam(p, seamZ, P, 5), 'faint') });
const vec = (p) => { const a = at([0, 0, 0]), b = at(p); return [b[0] - a[0], b[1] - a[1]]; };
const g = (attrs, body) => `<g ${attrs}>${body}</g>`;

const out = [];
// ── Base ────────────────────────────────────────────────────────────────
out.push(`<path class="iso-halo" d="${k.haloOf(BASE, -19, 15, P)}"/>`);
for (const [x, y] of k.corners(BASE, 22).sort((a, b) => k.depthOf([...a, 0], P) - k.depthOf([...b, 0], P))) out.push(slab(plan(x - 8, y - 8, 16, 16, 2), -19, 5, 'lo'));
out.push(slab(BASE, -14, 10, 'lo'), slab(k.insetPlan(BASE, 1), -4, 1, 'lo'), slab(BASE, -3, 3, 'mid'));
out.push(outline(k.insetPlan(BASE, 4), 0, 'faint'), screws(k.insetPlan(BASE, 4), 0));
const label = plan(-40, 76, 80, 8);
out.push(slab(label, 0, 0.6, 'lo'), screws(label, 0.6, 2), k.faceTextSvg(k.topMatrix([0, 81], 0.7, P, 'x'), 'OFFER BY GOSSIP · BYTES BY REQUEST', { size: 2.3, anchor: 'middle', tone: 'mid' }));

// ── Back: gossip rail with two other peers ──────────────────────────────
const RAIL_Y = -74, RAIL_Z = 15, CARD_FROM = -140, CARD_TO = 102;
const KIOSKS = [-48, 34];
for (const x of KIOSKS) {
  const foot = plan(x - 15, -100, 30, 20, 2), body = plan(x - 12, -97, 24, 14, 2);
  out.push(slab(foot, 0, 2, 'lo'), screws(foot, 2, 2.5), seamed(body, 2, 14, 6), slab(plan(x - 13, -98, 26, 16, 2), 16, 1.5, 'hi'));
  out.push(slab(plan(x - 8, -94, 16, 6, 1), 17.5, 0.6, 'lo'));
  out.push(g(`class="copy lit-fill" data-copy="${x}"`, slab(plan(x - 7, -93, 14, 4, 0.6), 18.1, 0.5, 'hi', { lit: true })));
  out.push(dots([[x + 8, -86], [x + 5, -86]], 17.5, 'mid', 0.55));
}
for (const x of [-150, -90, -10, 70, 116]) {
  const foot = plan(x - 5, RAIL_Y - 5, 10, 10, 1.5);
  out.push(slab(foot, 0, 1.5, 'lo'), screws(foot, 1.5, 2), slab(plan(x - 2.5, RAIL_Y - 2.5, 5, 5, 1), 1.5, RAIL_Z - 1.5, 'mid'));
}
const rail = plan(-156, RAIL_Y - 3.5, 278, 7, 1.5);
out.push(slab(rail, RAIL_Z, 2.5, 'mid', { inner: L(k.lineOnTop([rail.x, RAIL_Y], [rail.x + rail.w, RAIL_Y], RAIL_Z + 2.5, P), 'faint') }));
for (const x of [-150, -90, -10, 70, 116]) out.push(dots([[x, RAIL_Y - 2]], RAIL_Z + 2.5, 'mid', 0.5));
// mailboxes at both ends (sender's out-tray, receiver's in-tray)
for (const x of [CARD_FROM, CARD_TO]) {
  const tray = plan(x - 9, RAIL_Y - 7, 18, 14, 1.5);
  out.push(slab(tray, RAIL_Z + 2.5, 1.2, 'lo'), outline(k.insetPlan(tray, 2), RAIL_Z + 3.7, 'faint'));
}
out.push(g('id="card" class="lit-fill"', [slab(plan(CARD_FROM - 7, RAIL_Y - 5, 14, 10, 1), RAIL_Z + 3.7, 1.2, 'hi', { lit: true }),
  L(k.lineOnTop([CARD_FROM - 4, RAIL_Y - 2], [CARD_FROM + 4, RAIL_Y - 2], RAIL_Z + 4.9, P), 'lo', { free: true }),
  L(k.lineOnTop([CARD_FROM - 4, RAIL_Y + 1], [CARD_FROM + 1, RAIL_Y + 1], RAIL_Z + 4.9, P), 'lo', { free: true }),
  dots([[CARD_FROM + 4, RAIL_Y + 2.5]], RAIL_Z + 4.9, 'lo', 0.7)].join('')));

// ── Stations: provider (left) and receiver (right) store cabinets ───────
function cabinet(x0, y0, w, d, prefix) {
  const c = plan(x0, y0, w, d, 3), top = 34;
  const s = [slab(plan(x0 - 3, y0 - 3, w + 6, d + 6, 3), 0, 3, 'lo'), screws(plan(x0 - 3, y0 - 3, w + 6, d + 6, 3), 3, 2.5)];
  s.push(slab(c, 3, top - 3, 'mid', { inner: L(k.sideSeam(c, 12, P, 5), 'faint') + L(k.sideSeam(c, 24, P, 5), 'faint') }));
  const lid = plan(x0 - 1, y0 - 1, w + 2, d + 2, 3);
  s.push(slab(lid, top, 2, 'hi'), screws(lid, top + 2, 3.5));
  const slots = [];
  for (let i = 0; i < 3; i++) {
    const sp = plan(x0 + 8, y0 + 7 + i * 16, 30, 11, 1.5);
    s.push(slab(sp, top + 2, 0.6, 'lo'), outline(k.insetPlan(sp, 1.5), top + 2.6, 'faint'));
    slots.push(sp);
  }
  // two dark cartridges already stored; the third slot holds this file's pin
  for (const i of [0, 2]) {
    const cp = k.insetPlan(slots[i], 2.2);
    s.push(slab(cp, top + 2.6, 3.4, 'mid'), L(k.lineOnTop([cp.x + 3, cp.y + cp.d / 2], [cp.x + cp.w - 3, cp.y + cp.d / 2], top + 6, P), 'faint', { free: true }));
  }
  const pin = k.insetPlan(slots[1], 2.2);
  s.push(g(`id="${prefix}-pin" class="pin lit-fill"`, slab(pin, top + 2.6, 3.4, 'hi', { lit: true }) + dots([[pin.x + pin.w - 3, pin.y + pin.d / 2]], top + 6, 'lo', 0.8)));
  // status lamp and a ruler of grip ribs on the side panel
  const lampBase = plan(x0 + w - 13, y0 + d - 13, 8, 8, 1.5);
  s.push(slab(lampBase, top + 2, 1, 'lo'), g(`id="${prefix}-lamp" class="lamp lit-fill"`, slab(k.insetPlan(lampBase, 1.6), top + 3, 1.2, 'hi', { lit: true })));
  return { svg: s.join(''), top, lampBase };
}
const PROV = cabinet(-188, -50, 52, 66, 'prov');
out.push(PROV.svg);
const port = plan(-136, 3, 12, 28, 1.5);
out.push(slab(port, 0, 12, 'mid', { inner: L(k.sideSeam(port, 6, P, 3), 'faint') }), screws(port, 12, 2.2), outline(plan(-133, 9, 6, 16, 1), 12, 'lo'));
const RECV = cabinet(132, -50, 52, 66, 'recv');
out.push(RECV.svg);
// receiver accept lever: a knob that slides forward in its slot when you press Download
const leverSlot = plan(140, 14, 40, 6, 1.5);
out.push(slab(plan(136, 12, 48, 10, 2), 0, 22, 'mid', { inner: L(k.sideSeam(plan(136, 12, 48, 10, 2), 11, P, 5), 'faint') }));
out.push(slab(leverSlot, 22, 0.6, 'lo'), outline(k.insetPlan(leverSlot, 1.4), 22.6, 'faint'));
out.push(g('id="lever"', slab(plan(141, 14.5, 7, 5, 1.2), 22.6, 4, 'hi') + slab(plan(142.2, 15.5, 4.6, 3, 1), 26.6, 1.2, 'mid')));
out.push(dots([[138, 17], [182, 17]], 22, 'mid', 0.55));

// ── Middle: the direct transfer conveyor with a verification gate ───────
const BELT = plan(-112, 6, 214, 22, 2), BELT_Z = 9, GATE_X = 52;
// legs
for (const x of [-104, -34, 36, 94]) for (const y of [2, 32]) out.push(slab(plan(x - 3, y - 3, 6, 6, 1), 0, BELT_Z - 2, 'lo'));
// back post of the gate (behind the belt)
out.push(slab(plan(GATE_X - 4, -6, 8, 6, 1.5), 0, 36, 'mid', { inner: L(k.sideSeam(plan(GATE_X - 4, -6, 8, 6, 1.5), 18, P, 3), 'faint') }));
const backRail = plan(-116, 1, 222, 5, 1.2), frontRail = plan(-116, 28, 222, 5, 1.2);
out.push(slab(backRail, BELT_Z - 2, 4, 'mid'), dots([[-110, 3.5], [100, 3.5]], BELT_Z + 2, 'mid', 0.5));
out.push(slab(BELT, BELT_Z - 2, 2, 'lo'));
// belt cleats: closed slots on the belt surface
for (let x = -104; x < 98; x += 12) out.push(outline(plan(x, 9, 1.4, 16, 0.5), BELT_Z, 'faint'));
const CHUNKS = 9, CH = { w: 13, d: 14 };
out.push('<g id="chunks">');
for (let i = 0; i < CHUNKS; i++) {
  const c = plan(-6.5, 10, CH.w, CH.d, 1.2);
  out.push(g(`class="chunk" data-chunk="${i}" style="opacity:0"`, slab(c, BELT_Z, 6, 'hi', { crease: 'lo' }) + outline(k.insetPlan(c, 2.4), BELT_Z + 6, 'faint')));
}
out.push('</g>');
out.push(slab(frontRail, BELT_Z - 2, 4, 'mid'));
// ruler on the front rail with a sliding progress carriage
const strip = plan(-110, 28.6, 200, 3.8, 0.6);
out.push(slab(strip, BELT_Z + 2, 0.4, 'lo', { crease: 'none' }));
const ticks = k.topTicks(strip.x + 2, strip.x + strip.w - 2, 5, 5, strip.y + 0.4, BELT_Z + 2.4, [1.4, 2.6], P);
out.push(L(ticks.minor, 'lo'), L(ticks.major, 'mid'));
out.push(g('id="carriage" class="lit-fill"', slab(plan(-112, 27, 5, 7, 1), BELT_Z + 2.4, 2.4, 'hi', { lit: true })));
// end caps
out.push(slab(plan(-120, 1, 5, 32, 1.5), BELT_Z - 3, 6, 'mid'), slab(plan(104, 1, 5, 32, 1.5), BELT_Z - 3, 6, 'mid'));
// gate crossbar, sensor head, lamp and barrier
const bar = plan(GATE_X - 5, -7, 10, 48, 1.5);
out.push(g('id="barrier"', slab(plan(GATE_X - 1.5, 9, 3, 16, 0.6), 22, 10, 'mid')));
out.push(slab(bar, 32, 5, 'mid', { inner: L(k.sideSeam(bar, 34.5, P, 3), 'faint') }), screws(bar, 37, 2.5));
const head = plan(GATE_X - 3.5, 12, 7, 10, 1.2);
out.push(slab(plan(GATE_X - 4, 10.5, 8, 13, 1.5), 37, 1, 'lo'), g('id="gate-lamp" class="lamp lit-fill"', slab(head, 38, 1.4, 'hi', { lit: true })));
out.push(slab(plan(GATE_X - 4, 34, 8, 6, 1.5), 0, 37, 'mid', { inner: L(k.sideSeam(plan(GATE_X - 4, 34, 8, 6, 1.5), 18, P, 3), 'faint') }));

// ── Front right: staging tray and destination tray ──────────────────────
const STAGE = plan(111, 4, 20, 26, 2);
out.push(slab(STAGE, 0, 4, 'lo'), slab(k.insetPlan(STAGE, 2.5), 4, 0.4, 'faint', { crease: 'none' }));
out.push(g('id="staged" style="opacity:0"', slab(plan(114, 9, 14, 16, 1.2), 4.4, 5, 'hi', { crease: 'lo' })));
const DEST = plan(138, 34, 48, 44, 3);
out.push(slab(DEST, 0, 5, 'mid'), screws(DEST, 5, 3));
const bed = k.insetPlan(DEST, 5);
out.push(slab(bed, 5, 0.4, 'lo', { crease: 'none' }), outline(k.insetPlan(bed, 2), 5.4, 'faint'));
out.push(g('id="existing" style="opacity:0"', slab(plan(146, 44, 16, 20, 1.5), 5.4, 7, 'mid') + outline(plan(149, 47, 10, 14, 1), 12.4, 'lo')));
out.push(g('id="installed" class="lit-fill" style="opacity:0"', slab(plan(164, 44, 16, 20, 1.5), 5.4, 7, 'hi', { lit: true }) + outline(plan(167, 47, 10, 14, 1), 12.4, 'lo')));

const svg = k.figureSvg({ width: W, height: H, label: 'An isometric file-sharing bench. Left, the provider cabinet stores a pinned file. A small signed offer card rides a gossip rail at the back to every peer, including the receiver on the right. Only after the receiver slides its accept lever do blocks of the file travel on a direct conveyor, through a hash-verification gate, into staging and then into an empty destination tray.', body: out });

// screen vectors for the live script
const V = { x: vec([1, 0, 0]), z: vec([0, 0, 1]) };
const GEO = { CARD_FROM, CARD_TO, KIOSKS, GATE_X, BELT_FROM: -104, BELT_TO: 100, CHUNKS, CARRIAGE_FROM: -112, CARRIAGE_TO: 86, LEVER: 30 };

const plateHtml = k.plateHtml({
  fig: 'FIG 02 / LIVE MODEL', title: 'Share, then fetch', hint: 'Press Download when the offer lands', readout: 'Ready',
  body: `<div class="iso-stage">${svg}</div>`,
  keys: [{ mark: 'lit', label: 'Lit cartridge · pinned copy of the file' }, { mark: 'raised', label: 'Card · signed offer (metadata only)' }, { mark: 'line', label: 'Blocks · bytes on the direct link' }],
  caption: 'The file never travels through gossip. Gossip carries a small signed offer: name, size, BLAKE3 hash and provider. Bytes move only when a receiver asks for them, straight from that provider, and each 16 KiB block is checked against the hash before it counts.',
});
const opt = (list, sel) => list.map((o) => `<option value="${o.id}"${o.id === sel ? ' selected' : ''}>${o.label ?? `${o.name} · ${o.sizeLabel}`}</option>`).join('');
const files = FILES.map((f) => ({ ...f, sizeLabel: f.size >= 1 << 30 ? `${(f.size / (1 << 30)).toFixed(1)} GiB` : `${(f.size / (1 << 20)).toFixed(f.size % (1 << 20) ? 1 : 0)} MiB` }));
const toggle = (id, label, pressed = false) => `<button class="toggle" id="${id}" aria-pressed="${pressed}"><i aria-hidden="true"></i>${label}</button>`;
const STEPS = [['pin', 'Pin', 'Provider hashes and stores the file'], ['offer', 'Announce', 'Signed offer goes out by gossip'], ['wait', 'Wait', 'Nothing downloads automatically'], ['check', 'Preflight', 'Path, limit and space checks'], ['stream', 'Stream', 'Fetch from provider, verify blocks'], ['install', 'Install', 'Pin, then link into place']];
const body = `<header>__NAV__<h1>Announce widely.<br>Send on request.</h1><p class="intro"><a href="gossip.html">Gossip</a> tells every peer that a file exists. Only the peers that ask<br>download it—directly from the sender, checked block by block.</p><button id="theme" class="theme" aria-label="Switch colour theme">Light mode</button></header>${plateHtml}
<section class="controls" aria-label="Simulation controls"><div class="buttons"><button id="play" class="primary">Pause</button><button id="step">Step →</button><button id="accept" class="accept" disabled>Download</button><button id="reset">↺ Reset</button></div><div class="settings"><label>FILE <select id="file">${opt(files, 'results')}</select></label><label>RECEIVER LIMIT <select id="limit">${opt(LIMITS, 'default')}</select></label></div></section>
<section class="toggles" aria-label="What-if switches">${toggle('provider', 'Sender offline')}${toggle('dest', 'Output path taken')}${toggle('tamper', 'Corrupt a block')}${toggle('dedup', 'Receiver already has it')}</section>
<ol class="steps" aria-label="Transfer steps">${STEPS.map(([id, t, d], i) => `<li data-step="${id}"><span>0${i + 1}</span><b>${t}</b><em>${d}</em></li>`).join('')}</ol>
<section class="metrics" aria-label="Transfer statistics"><div><strong id="m-bytes">0 B</strong><span>BYTES ON THE DIRECT LINK</span></div><div><strong id="m-blocks">0</strong><span>16 KIB BLOCKS VERIFIED</span></div><div><strong id="m-events">0</strong><span>PROGRESS EVENTS (EVERY 8 MIB)</span></div></section>
<p id="status" role="status" aria-live="polite"></p>
<section class="explanation"><article><span>01 / PIN FIRST</span><h2>Ready before it’s announced.</h2><p>The sender stores and pins the file <b>before</b> it broadcasts the offer, so any peer that sees the offer can fetch it immediately.</p></article><article><span>02 / OPT IN</span><h2>Offers are not downloads.</h2><p>Every peer gets the offer. Bytes move only after an explicit download with an output path that doesn’t exist yet. Nothing is ever overwritten.</p></article><article><span>03 / VERIFY</span><h2>Trust the hash, not the pipe.</h2><p>The BLAKE3 hash is part of the signed offer. Each block is checked against it as it streams; one bad block fails the whole download.</p></article></section>
<footer>MESHMSG ATTACHMENTS <span>iroh-gossip offer · iroh-blobs transfer · BLAKE3 verified streaming</span><p>Faithful to meshmsg’s download order: signed-offer check, no-clobber path check, size limit, local-copy check, provider connection, verified size, free space, stream, pin, then hard-link install. Not shown: quotas, retention, directory tar snapshots and retries. Offers are reusable capabilities: anyone who holds one can fetch the plaintext from the provider, so treat them like a link to the file.</p></footer>`;

const css = readFileSync(here + 'style.css', 'utf8');
const model = readFileSync(here + 'model.mjs', 'utf8').replaceAll('export ', '');
const live = readFileSync(here + 'live.js', 'utf8');
const script = `${model}\nconst V=${JSON.stringify(V)};const GEO=${JSON.stringify(GEO)};\n${live}`;
// thumbnail: freeze a moment mid-stream (same placement formula as live.js)
const trOf = (x) => `translate(${(V.x[0] * x).toFixed(2)} ${(V.x[1] * x).toFixed(2)})`;
let thumb = svg;
for (let i = 0; i < CHUNKS; i++) {
  const u = (0.55 - (i * 0.6) / (CHUNKS - 1)) / 0.4;
  if (u <= 0.05 || u >= 0.95) continue;
  thumb = thumb.replace(`data-chunk="${i}" style="opacity:0"`, `data-chunk="${i}" transform="${trOf(GEO.BELT_FROM + u * (GEO.BELT_TO - GEO.BELT_FROM))}"`);
}
thumb = thumb.replace('id="recv-pin" class="pin lit-fill"', 'id="recv-pin" class="pin lit-fill" style="opacity:0"').replace(/id="card" class="lit-fill"/, `id="card" class="lit-fill" transform="${trOf(CARD_TO - CARD_FROM)}"`);
export const concept = { slug: 'file-sharing', num: '02', kicker: 'File sharing', title: 'Sharing files', pageTitle: 'File sharing — offer by gossip, bytes by request', summary: 'Why a file is announced to everyone but sent only on request: signed offers, explicit downloads, verified blocks and no-overwrite installs.', cta: 'Open the bench', svg, thumb, body, css, script };
