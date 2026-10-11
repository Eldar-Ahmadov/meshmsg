const $=s=>document.querySelector(s);
const still=matchMedia('(prefers-reduced-motion: reduce)');
let state=createState(),pending=null,elapsed=0,clock=0,frame=0,last=0,visible=false;
let playing=!still.matches,touring=!still.matches;
const peers=PEERS.map(p=>$(`[data-peer="${p.id}"]`));
const memories=PEERS.map(p=>$(`#memory-${p.id}`));
const paddles=PEERS.map(p=>$(`#paddle-${p.id}`));
const toggles=PEERS.map(p=>$(`[data-toggle="${p.id}"]`));
const links=EDGES.map((_,i)=>$(`[data-link="${i}"]`));
const packetLayer=$('#packets');
let packets=[];
function render(note){
  const s=summary(state);
  $('[data-readout]').textContent=`Round ${state.round} · ${s.reached} / ${s.online} peers`;
  $('#reached').textContent=`${s.reached} / ${s.online}`;
  $('#sent').textContent=state.sent; $('#duplicates').textContent=state.duplicates;
  $('#play').textContent=playing?'Pause':'Play';
  $('#play').setAttribute('aria-pressed',String(playing));
  $('#step').disabled=!!pending;
  $('#fanout').disabled=!!pending; $('#source').disabled=!!pending; $('#bridge').disabled=!!pending;
  $('#bridge').textContent=state.bridge?'Split network':'Reconnect bridge';
  $('#bridge').setAttribute('aria-pressed',String(!state.bridge));
  $('#bridge-paddle').setAttribute('transform',state.bridge?'':`translate(${SHIFT[0]} ${SHIFT[1]})`);
  for(const p of PEERS){
    const i=p.id,online=state.online[i],known=state.known[i];
    memories[i].style.opacity=known?(online?'1':'.35'):'0';
    paddles[i].setAttribute('transform',online?'':`translate(${SHIFT[0]} ${SHIFT[1]})`);
    peers[i].classList.toggle('offline',!online);
    peers[i].setAttribute('aria-pressed',String(!online));
    peers[i].setAttribute('aria-disabled',String(!!pending));
    const status=!online?'offline':known?'stored':'waiting';
    peers[i].setAttribute('aria-label',`Peer ${p.name}: ${status}. Toggle ${online?'offline':'online'}.`);
    toggles[i].setAttribute('aria-pressed',String(!online));
    toggles[i].setAttribute('aria-label',`Peer ${p.name}: ${status}. Toggle ${online?'offline':'online'}.`);
    toggles[i].querySelector('span').textContent=status;
    toggles[i].classList.toggle('has-message',known&&online);
    toggles[i].disabled=!!pending;
  }
  EDGES.forEach(([a,b],i)=>links[i].style.opacity=state.online[a]&&state.online[b]&&(i!==BRIDGE||state.bridge)?'1':'.16');
  if(note) $('#status').textContent=note;
}
function stopTour(){touring=false;playing=false;clock=0;}
function reset(){
  const online=[...state.online],bridge=state.bridge;
  const source=Number($('#source').value);
  state=createState(source);state.online=online;state.online[source]=true;state.bridge=bridge;
  pending=null;packets=[];packetLayer.replaceChildren();clock=0;
  render(`Peer ${PEERS[source].name} starts with one stored copy. ${bridge?'Bridge connected.':'The bridge is open: two separate groups.'}`);
}
function finish(){
  const batch=pending;state=batch.next;pending=null;packets=[];packetLayer.replaceChildren();
  const s=summary(state),fresh=batch.events.filter(e=>!e.duplicate).length;
  let note=`Round ${state.round}: ${batch.events.length} copies delivered; ${fresh} new recipient${fresh===1?'':'s'}, ${batch.events.length-fresh} duplicates ignored.`;
  if(s.complete){note+=` All ${s.online} online peers now have the message.`;if(!touring)playing=false;}
  else if(s.stalled){note+=s.online===0?' No peers are online.':` ${s.blocked} online peer${s.blocked===1?' is':'s are'} unreachable. Reconnect the bridge or a peer to continue.`;if(!touring)playing=false;}
  render(note);
}
function begin(){
  if(pending)return;
  pending=step(state,Number($('#fanout').value));elapsed=0;
  if(still.matches){finish();return;}
  packets=pending.events.map(e=>{
    const dot=document.createElementNS('http://www.w3.org/2000/svg','rect');
    dot.setAttribute('width','5');dot.setAttribute('height','5');dot.setAttribute('rx','1');
    dot.setAttribute('class','packet');dot.style.opacity='0';packetLayer.append(dot);
    const r=ROUTES[e.edge],forward=EDGES[e.edge][0]===e.from;
    return {dot,a:r[forward?0:1],b:r[forward?1:0]};
  });
  render(`Round ${state.round+1} in flight: ${pending.events.length} copies. Counters update on delivery.`);run();
}
function tick(now){
  frame=0;
  if(!visible||document.hidden)return;
  const dt=last?Math.min((now-last)/1000,1/30):0;last=now;
  if(pending){
    elapsed+=dt;const t=Math.min(1,elapsed/.95),u=t*t*(3-2*t);
    for(const {dot,a,b} of packets){dot.setAttribute('x',a[0]+(b[0]-a[0])*u-2.5);dot.setAttribute('y',a[1]+(b[1]-a[1])*u-2.5);dot.style.opacity=String(Math.min(1,t*8,(1-t)*8));}
    if(t===1){finish();clock=0;}
  }else if(playing&&!still.matches){
    clock+=dt;const s=summary(state);
    if(s.complete||s.stalled){if(touring&&clock>3)reset();else if(!touring){playing=false;render();}}
    else if(clock>1.1){clock=0;begin();}
  }
  if(pending||playing&&!still.matches)run(false);
}
function run(resetTime=true){if(!frame&&visible&&!document.hidden){if(resetTime)last=0;frame=requestAnimationFrame(tick);}}
$('#play').addEventListener('click',()=>{touring=false;playing=!playing;clock=.9;if(still.matches&&playing){playing=false;begin();}render();run();});
$('#step').addEventListener('click',()=>{stopTour();begin();render();run();});
$('#reset').addEventListener('click',()=>{stopTour();reset();});
$('#source').addEventListener('change',()=>{stopTour();reset();});
$('#fanout').addEventListener('change',()=>{stopTour();$('#fanout-text').textContent=['','one neighbour','two neighbours','three neighbours'][Number($('#fanout').value)];render('Fanout changed. Step a round or press Play to compare propagation.');});
$('#bridge').addEventListener('click',()=>{stopTour();state.bridge=!state.bridge;render(state.bridge?'Bridge connected. Stored copies can cross again; press Play or Step.':'Bridge open. Copies cannot cross between the two groups. Reset to try a fresh message.');});
function toggle(i){if(pending)return;stopTour();state.online[i]=!state.online[i];render(`Peer ${PEERS[i].name} is now ${state.online[i]?'online':'offline'}. ${state.known[i]?'Its stored message is retained.':'It has not received the message.'}`);}
PEERS.forEach(({id})=>{
  for(const el of [peers[id],toggles[id]]){
    const inspect=on=>{peers[id].classList.toggle('inspecting',on);toggles[id].classList.toggle('inspecting',on);};
    el.addEventListener('pointerenter',()=>inspect(true));el.addEventListener('pointerleave',()=>inspect(false));
    el.addEventListener('focus',()=>inspect(true));el.addEventListener('blur',()=>inspect(false));
  }
  peers[id].addEventListener('click',()=>toggle(id));
  peers[id].addEventListener('keydown',e=>{if(e.key===' '||e.key==='Enter'){e.preventDefault();toggle(id);}});
  toggles[id].addEventListener('click',()=>toggle(id));
});
$('.iso-figure').addEventListener('pointerenter',()=>{if(touring){stopTour();render();}});
$('.iso-figure').addEventListener('focusin',()=>{if(touring){stopTour();render();}});
new IntersectionObserver(entries=>{visible=entries.at(-1).isIntersecting;if(visible)run();else if(frame){cancelAnimationFrame(frame);frame=0;last=0;}},{threshold:.05}).observe($('.iso-plate'));
document.addEventListener('visibilitychange',()=>{if(document.hidden){cancelAnimationFrame(frame);frame=0;last=0;}else run();});
still.addEventListener('change',()=>{if(still.matches){stopTour();if(pending)finish();render();}run();});
render();
