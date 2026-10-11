// Builds the explainer set: an index of thumbnails plus one full page per concept.
//   node docs/explainers/build.mjs
// Writes index.html, gossip.html and file-sharing.html next to this file.
// Theme: dark by default; the toggle is remembered across pages, and ?theme=light|dark forces one.
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import * as k from './vendor/iso-kit.mjs';
import { concept as gossip } from './gossip/build.mjs';
import { concept as sharing } from './file-sharing/build.mjs';

const here = fileURLToPath(new URL('.', import.meta.url));
const CONCEPTS = [gossip, sharing];
const shared = readFileSync(here + 'gossip/style.css', 'utf8') + readFileSync(here + 'site.css', 'utf8');

// Applied before first paint, so a remembered light theme never flashes dark.
const THEME_EARLY = `<script>(()=>{let t='dark';try{const q=new URLSearchParams(location.search).get('theme');if(q==='light'||q==='dark'){t=q;localStorage.setItem('mesh-theme',q);}else t=localStorage.getItem('mesh-theme')||t;}catch{}document.body.dataset.theme=t;})()</script>`;
const THEME_TOGGLE = `<script>(()=>{const b=document.getElementById('theme');if(!b)return;const label=()=>{b.textContent=document.body.dataset.theme==='light'?'Dark mode':'Light mode';};label();b.addEventListener('click',()=>{const t=document.body.dataset.theme==='light'?'dark':'light';document.body.dataset.theme=t;try{localStorage.setItem('mesh-theme',t);}catch{}label();});})()</script>`;

function page({ title, body, css = '', script = '' }) {
  return k.pageHtml({ title, theme: 'dark', body, width: 1000, script })
    .replace('</head>', `<style>${shared}${css}</style></head>`)
    .replace('<main class="iso-page">', `${THEME_EARLY}<main class="iso-page">`)
    .replace('</body>', `${THEME_TOGGLE}</body>`);
}

// A thumbnail is the same drawing, made inert: no focus stops, roles or tooltips inside the link.
const inert = (svg) => svg
  .replace(/ tabindex="0"/g, '').replace(/ role="(button|group|img)"/g, '').replace(/ aria-(label|pressed)="[^"]*"/g, '')
  .replace(/<title>[^<]*<\/title>/g, '').replace('<svg', '<svg aria-hidden="true" focusable="false"');

const total = String(CONCEPTS.length).padStart(2, '0');
CONCEPTS.forEach((c, i) => {
  const prev = CONCEPTS[i - 1], next = CONCEPTS[i + 1];
  const nav = `<nav class="crumbs" aria-label="Breadcrumb"><a href="index.html">← Mesh notes</a><span>${c.num} / ${total} — ${c.kicker.toUpperCase()}</span></nav>`;
  const pager = `<nav class="pager" aria-label="More explainers">${prev ? `<a href="${prev.slug}.html"><span>← Previous</span><b>${prev.title}</b></a>` : `<a href="index.html"><span>← Back</span><b>All explainers</b></a>`}${next ? `<a class="next" href="${next.slug}.html"><span>Next →</span><b>${next.title}</b></a>` : `<a class="next" href="index.html"><span>Back to →</span><b>All explainers</b></a>`}</nav>`;
  const body = c.body.replace('__NAV__', nav) + pager;
  writeFileSync(here + `${c.slug}.html`, page({ title: c.pageTitle, body, css: c.css, script: c.script }));
  console.log(`Wrote ${here}${c.slug}.html`);
});

const cards = CONCEPTS.map((c) => `<a class="card" href="${c.slug}.html">
  <div class="thumb iso-plate">${inert(c.thumb)}</div>
  <div class="meta"><span>${c.num} — ${c.kicker.toUpperCase()}</span><h2>${c.title}</h2><p>${c.summary}</p><b>${c.cta} →</b></div>
</a>`).join('');
const index = `<header><nav class="crumbs"><span>MESH NOTES</span><span>INTERACTIVE EXPLAINERS</span></nav><h1>How a mesh<br>moves information.</h1><p class="intro">Working models of the ideas behind meshmsg. Each is a small machine:<br>step it, break it, and watch what changes.</p><button id="theme" class="theme" aria-label="Switch colour theme">Light mode</button></header>
<section class="cards" aria-label="Explainers">${cards}</section>
<section class="order"><span>SUGGESTED ORDER</span><p>Start with <a href="gossip.html">gossip</a>. File offers are themselves gossip messages, so <a href="file-sharing.html">file sharing</a> builds on it: the offer spreads the way messages do, and only the bytes take a different, direct route.</p></section>
<footer>MESH NOTES <span>${CONCEPTS.length} explainers · static pages · no network requests</span><p>Simplified, faithful models for learning. They are not protocol traces. Each page states what it leaves out.</p></footer>`;
writeFileSync(here + 'index.html', page({ title: 'Mesh notes — interactive explainers', body: index }));
console.log(`Wrote ${here}index.html`);
