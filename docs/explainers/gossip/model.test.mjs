import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createState,step,summary,neighbors,EDGES} from './model.mjs';

test('new recipients wait for the next round; fanout samples without replacement',()=>{
  const {next,events}=step(createState(),3);
  assert.deepEqual(events.map(e=>e.from),[0,0]);
  assert.deepEqual(new Set(events.map(e=>e.to)),new Set([1,4]));
  assert.equal(next.known.filter(Boolean).length,3);
  assert.equal(next.sent,2);
});
test('step is pure and seeded resets replay exactly',()=>{
  const s=createState(),snapshot=structuredClone(s);
  assert.deepEqual(step(s,2),step(createState(),2));assert.deepEqual(s,snapshot);
});
test('connected graph converges for every source and fanout',()=>{
  for(let source=0;source<8;source++)for(let fanout=1;fanout<=3;fanout++){
    let s=createState(source);
    for(let n=0;n<100&&!summary(s).complete;n++)s=step(s,fanout).next;
    assert.equal(summary(s).complete,true);
    assert.equal(s.sent-s.duplicates,7);
  }
});
test('a partition blocks four peers, reconnecting repairs it',()=>{
  let s=createState();s.bridge=false;
  for(let n=0;n<30;n++)s=step(s,2).next;
  assert.deepEqual(s.known,[true,true,false,false,true,true,false,false]);
  assert.equal(summary(s).blocked,4);assert.equal(summary(s).stalled,true);
  s.bridge=true;
  for(let n=0;n<30&&!summary(s).complete;n++)s=step(s,2).next;
  assert.equal(summary(s).complete,true);
});
test('offline peers neither send nor receive, and retain stored memory',()=>{
  let s=createState();s.online[0]=false;
  assert.deepEqual(step(s,3).events,[]);assert.equal(s.known[0],true);
  assert.equal(summary(s).blocked,7);
  s.online[0]=true;s.online[1]=false;
  for(let n=0;n<20;n++){
    const r=step(s,3);assert.ok(r.events.every(e=>e.from!==1&&e.to!==1));s=r.next;
  }
  assert.equal(s.known[1],false);assert.deepEqual(neighbors(s,1),[]);
});
test('every event is on an available edge; accounting conserves unique copies',()=>{
  for(let seed=1;seed<80;seed++){
    let s=createState(seed%8,seed);s.bridge=seed%2===0;s.online[(seed+3)%8]=false;
    const initial=s.known.filter(Boolean).length;
    for(let n=0;n<12;n++){
      const {next,events}=step(s,1+seed%3);
      for(const e of events){assert.ok(s.known[e.from]&&s.online[e.from]&&s.online[e.to]);assert.ok(EDGES[e.edge].includes(e.from)&&EDGES[e.edge].includes(e.to));}
      assert.equal(next.sent-next.duplicates,next.known.filter(Boolean).length-initial);s=next;
    }
  }
});
test('empty online set does not report convergence',()=>{
  const s=createState();s.online.fill(false);assert.equal(summary(s).complete,false);assert.equal(summary(s).online,0);
});
