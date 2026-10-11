import {readFileSync,writeFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import * as k from '../vendor/iso-kit.mjs';
import {PEERS,EDGES,BRIDGE} from './model.mjs';
const here=fileURLToPath(new URL('.',import.meta.url));
const W=900,H=480;
const base={x:-163,y:-89,w:326,d:178,r:7};
const P=k.fitProjection(k.boxCorners(base,-19,31),W,H,{pad:38,azimuth:60,elevation:38});
const at=p=>k.iso(p,P), L=(d,tone='lo')=>k.lineSvg(d,{tone});
const plan=(x,y,w,d,r=1)=>({x,y,w,d,r});
const slab=(p,z,h,tone='mid',extra={})=>k.solidSvg(k.slabOf(p,z,h,P,5,Math.min(.7,h/3)),{tone,...extra});
const outline=(p,z,tone='lo')=>L(k.planOutline(p,z,P),tone);
const screws=(p,z)=>k.dotsSvg(k.corners(p,3).map(([x,y])=>at([x,y,z])),{size:.65,tone:'mid'});
const out=[`<path class="iso-halo" d="${k.haloOf(base,-19,15,P)}"/>`];
for(const [x,y] of k.corners(base,20)) out.push(slab(plan(x-7,y-7,14,14,2),-19,5,'lo'));
out.push(slab(base,-14,10,'lo'),slab(k.insetPlan(base,1),-4,1,'lo'),slab(base,-3,3,'mid'));
out.push(outline(k.insetPlan(base,4),0,'faint'),screws(k.insetPlan(base,4),0));
for(const y of [-82,76]) out.push(slab(plan(-150,y,300,6),0,3,'lo'),screws(plan(-150,y,300,6),3));
for(const x of [-130,0,130])out.push(slab(plan(x-5,79,10,5),3,2,'mid'));
const label=plan(-35,69,70,6);
out.push(slab(label,0,.6,'lo'),screws(label,.6),k.faceTextSvg(k.topMatrix([0,73.2],.7,P,'x'),'PUSH / MEMORY / REPEAT',{size:2.4,anchor:'middle',tone:'mid'}));
const routes=EDGES.map(([a,b])=>{
  const A=PEERS[a],B=PEERS[b],dx=Math.sign(B.x-A.x),dy=Math.sign(B.y-A.y);
  return [[A.x+dx*24,A.y+dy*21,.3],[B.x-dx*24,B.y-dy*21,.3]];
});
for(let i=0;i<routes.length;i++){
  const [a,b]=routes[i];
  out.push(`<g data-link="${i}">${L(k.pathOf([at(a),at(b)]),'mid')}`);
  for(const p of [a,b])out.push(outline(plan(p[0]-2,p[1]-2,4,4,.5),.3,'hi'));
  out.push('</g>');
}
// Packet highlights are surface contacts, beneath every raised module.
out.push('<g id="packets" aria-hidden="true"></g>');
const bridgePlan=plan(-15,-55,30,16,2);
out.push(slab(bridgePlan,0,2,'lo'),outline(k.insetPlan(bridgePlan,2),2));
out.push(`<g id="bridge-paddle">${slab(plan(-7,-52,12,10),2,2,'hi')}</g>`);
for(const peer of [...PEERS].sort((a,b)=>k.depthOf([a.x,a.y,0],P)-k.depthOf([b.x,b.y,0],P))){
  const {x,y,id}=peer, socket=plan(x-24,y-21,48,42,2),housing=plan(x-21,y-18,42,36,3);
  out.push(`<g class="peer" data-peer="${id}" role="button" tabindex="0" aria-label="Peer ${peer.name}: online. Toggle offline." aria-pressed="false"><title>Peer ${peer.name} · click to take offline</title>`);
  out.push(slab(socket,0,3,'lo'),screws(socket,3));
  for(const xx of [-18,-12,-6,0,6,12,18])for(const yy of [-19,19])out.push(outline(plan(x+xx-1.2,y+yy-1,2.4,2,.2),3,'mid'));
  out.push(slab(housing,3,17,'mid',{inner:L(k.sideSeam(housing,8,P,5),'faint')}));
  out.push(slab(plan(x-22,y-19,44,38,3),20,2,'hi'),screws(plan(x-22,y-19,44,38,3),22));
  out.push(slab(plan(x-16,y-12,32,17,1.5),22,1.5,'mid'));
  out.push(slab(plan(x-13,y-9,26,11,1),23.5,.5,'lo'));
  out.push(`<g class="memory" id="memory-${id}">${slab(plan(x-11,y-7,22,7,1),24,.6,'hi',{lit:true})}</g>`);
  out.push(slab(plan(x-14,y+9,17,6,1),22,.5,'lo'));
  out.push(`<g class="paddle" id="paddle-${id}">${slab(plan(x-12,y+10,7,4,.5),22.5,2,'hi')}</g>`);
  for(let v=0;v<3;v++)out.push(outline(plan(x+8,y+8+v*2.8,8,1,.4),22,'lo'));
  out.push(`<path class="focus-outline" d="${k.planOutline(k.insetPlan(housing,-2),22.4,P)}"/></g>`);
}
const svg=k.figureSvg({width:W,height:H,label:'An isometric gossip relay trainer. Eight physical peer modules on a circuit board, joined in two loops by one switchable bridge. Solid memory windows have the message; travelling contacts are copies.',body:out}).replace('role="img"','role="group"');
const plate=k.plateHtml({fig:'FIG 01 / LIVE MODEL',title:'The gossip relay',hint:'Click a module to toggle it offline',readout:'Round 0 · 1 / 8 peers',body:svg,keys:[{mark:'lit',label:'Solid window · message stored'},{mark:'line',label:'Moving contact · one copy'},{mark:'raised',label:'Shifted switch · peer offline'}],caption:'No central broadcaster. Each informed peer picks a few neighbours, sends a copy, and repeats. Recipients remember the message ID, so repeated arrivals do not create new messages.'});
const body=`<header>__NAV__<h1>A rumour needs<br>no centre.</h1><p class="intro">One peer knows. Then a few. Then almost everyone.<br>Explore how gossip spreads—and where it stops.</p><button id="theme" class="theme" aria-label="Switch colour theme">Light mode</button></header>${plate}
<section class="controls" aria-label="Simulation controls"><div class="buttons"><button id="play" class="primary">Pause</button><button id="step">Step round →</button><button id="reset">↺ Reset</button></div><div class="settings"><label>FANOUT <select id="fanout"><option value="1">1 neighbour</option><option value="2">2 neighbours</option><option value="3">3 neighbours</option></select></label><label>START AT <select id="source">${PEERS.map(p=>`<option value="${p.id}">Peer ${p.name}</option>`).join('')}</select></label><button id="bridge" aria-pressed="false">Split network</button></div></section>
<section class="metrics" aria-label="Simulation statistics"><div><strong id="reached">1 / 8</strong><span>ONLINE PEERS REACHED</span></div><div><strong id="sent">0</strong><span>COPIES DELIVERED</span></div><div><strong id="duplicates">0</strong><span>DUPLICATES IGNORED</span></div></section>
<p id="status" role="status" aria-live="polite">Peer A starts with the message.</p><div id="peer-controls" class="peer-controls" aria-label="Peer availability">${PEERS.map(p=>`<button data-toggle="${p.id}" aria-pressed="false" title="Toggle peer ${p.name} offline">${p.name}<span>waiting</span></button>`).join('')}</div>
<section class="explanation"><article><span>01 / SPREAD</span><h2>Pass it on.</h2><p>Every informed, online peer sends to up to <b id="fanout-text">one neighbour</b> per round. New recipients can send from the next round.</p></article><article><span>02 / REPEAT</span><h2>Redundancy is useful.</h2><p>A peer can hear the same message twice. It keeps one copy. Repeated sends give a message more chances to reach an uninformed neighbour.</p></article><article><span>03 / RECONNECT</span><h2>A gap is a boundary.</h2><p>Split the network before a reset: gossip cannot cross the open bridge. Reconnect it and press Play to resume from stored copies.</p></article></section><footer>SIMPLIFIED PUSH GOSSIP <span>8 peers · lossless links · synchronous rounds · repeatable randomness</span><p>Offline peers keep memory but cannot send or receive. The demo stops when every online peer has a copy, or all reachable peers do. Real protocols use different peer sampling, timing, expiry and repair strategies. This is not a meshmsg protocol trace.</p></footer>`;
const css=''; // gossip/style.css is the shared base stylesheet (added by ../build.mjs)
const model=readFileSync(here+'model.mjs','utf8').replaceAll('export ','');
const live=readFileSync(here+'live.js','utf8');
const script=model+`\nconst ROUTES=${JSON.stringify(routes.map(r=>r.map(at)))}; const SHIFT=${JSON.stringify(at([8,0,0]).map((v,i)=>v-at([0,0,0])[i]))};\n`+live;
const thumb=svg.replace(/id="memory-([3467])"/g,'id="memory-$1" style="opacity:0"');
export const concept={slug:'gossip',num:'01',kicker:'Distributed systems',title:'Gossip propagation',pageTitle:'Gossip propagation — an interactive relay',summary:'How one peer’s message reaches everyone without a central server: fanout, redundant copies, and what a network split does.',cta:'Open the relay',svg,thumb,body,css,script};
