export const PEERS = Array.from({length: 8}, (_, i) => ({ id: i, name: String.fromCharCode(65+i), x: (i%4)*78-117, y: Math.floor(i/4)*94-47 }));
export const EDGES = [[0,1],[0,4],[1,5],[4,5],[2,3],[2,6],[3,7],[6,7],[1,2]];
export const BRIDGE = 8;
export function createState(source=0, seed=57) {
  return { known: PEERS.map((_,i)=>i===source), online: PEERS.map(()=>true), bridge:true, round:0, sent:0, duplicates:0, rng:seed, source };
}
export function neighbors(s, i) {
  if (!s.online[i]) return [];
  return EDGES.flatMap(([a,b],e)=> e===BRIDGE&&!s.bridge ? [] : a===i&&s.online[b] ? [b] : b===i&&s.online[a] ? [a] : []);
}
function random(s) {
  let x=s.rng; x^=x<<13; x^=x>>>17; x^=x<<5; s.rng=x>>>0;
  return s.rng/4294967296;
}
export function step(state, fanout=1) {
  if (![1,2,3].includes(fanout)) throw new RangeError('fanout must be 1, 2 or 3');
  const next={...state,known:[...state.known],online:[...state.online],round:state.round+1};
  const events=[];
  for (const peer of PEERS) {
    if (!state.known[peer.id]||!state.online[peer.id]) continue;
    const pool=neighbors(state,peer.id);
    for(let n=0;n<fanout&&pool.length;n++) {
      const to=pool.splice(Math.floor(random(next)*pool.length),1)[0];
      events.push({from:peer.id,to,edge:EDGES.findIndex(([a,b])=>a===peer.id&&b===to||b===peer.id&&a===to),duplicate:next.known[to]});
      if(next.known[to]) next.duplicates++;
      next.known[to]=true; next.sent++;
    }
  }
  return {next,events};
}
export function summary(s) {
  const online=s.online.filter(Boolean).length;
  const reached=s.known.filter((v,i)=>v&&s.online[i]).length;
  const reachable=new Set(PEERS.filter(p=>s.online[p.id]&&s.known[p.id]).map(p=>p.id));
  const queue=[...reachable];
  for(let n=0;n<queue.length;n++) for(const id of neighbors(s,queue[n])) if(!reachable.has(id)){reachable.add(id);queue.push(id);}
  return {online,reached,blocked:online-reachable.size,complete:online>0&&reached===online,stalled:online===0||reached===reachable.size&&reached<online};
}
