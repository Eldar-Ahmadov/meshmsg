import { test } from 'node:test';
import assert from 'node:assert/strict';
import { plan, defaults, counters, bytes, MiB, GiB, BLOCK, PROGRESS_STEP } from './model.mjs';

const o = (x) => ({ ...defaults(), ...x });
test('happy path pins before announcing, waits for consent, then streams', () => {
  const p = plan(o({}));
  assert.deepEqual(p.steps, ['pin', 'offer', 'wait', 'check', 'connect', 'stream', 'commit', 'install']);
  assert.equal(p.fail, null);
});
test('existing output path fails before any network work', () => {
  const p = plan(o({ destExists: true, providerOnline: false, tamper: true }));
  assert.equal(p.fail.at, 'check'); assert.ok(!p.steps.includes('connect'));
});
test('signed size above the receiver limit fails at preflight', () => {
  assert.equal(plan(o({ limit: 'small' })).fail.at, 'check');
  assert.equal(plan(o({ limit: 'small', file: 'notes' })).fail, null);
});
test('a complete local copy skips the network, even with the sender offline', () => {
  const p = plan(o({ dedup: true, providerOnline: false, tamper: true }));
  assert.equal(p.fail, null); assert.equal(p.transfers, false);
  assert.deepEqual(p.steps.slice(-2), ['commit', 'install']);
});
test('offline sender fails at connect; corruption fails while streaming', () => {
  assert.equal(plan(o({ providerOnline: false })).fail.at, 'connect');
  const t = plan(o({ tamper: true }));
  assert.equal(t.fail.at, 'stream'); assert.ok(!t.steps.includes('install'));
});
test('counters match 16 KiB blocks and 8 MiB progress steps', () => {
  assert.deepEqual(counters(240 * MiB, 240 * MiB, true), { received: 240 * MiB, blocks: 15360, events: 30 });
  assert.deepEqual(counters(240 * MiB, 20 * MiB, false), { received: 20 * MiB, blocks: 1280, events: 2 });
  const small = Math.round(2.4 * MiB);
  assert.equal(counters(small, small, true).events, 1);
  assert.equal(counters(small, small, true).blocks, Math.ceil(small / BLOCK));
  assert.equal(BLOCK, 16384); assert.equal(PROGRESS_STEP, 8388608);
  assert.equal(bytes(4 * GiB), '4 GiB'); assert.equal(bytes(240 * MiB), '240 MiB');
});
