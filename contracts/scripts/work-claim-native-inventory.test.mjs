import assert from 'node:assert/strict';
import test from 'node:test';
import { fixture, digest } from './work-claim-fixture.mjs';
import { transactionInventory } from './work-claim-native-inventory.mjs';

test('block inventory catches duplicate idempotent claim and decision transactions without events', async t => {
  const f = await fixture(t);
  const allocation = await f.fund();
  await f.at(2);
  await f.submit(allocation);
  const claimReplay = await (await f.escrow.connect(f.B).submitClaim(allocation, digest('output'))).wait();
  assert.equal(claimReplay.logs.length, 0);
  await f.at(5);
  const decision = await f.sign(allocation);
  await (await f.escrow.recordDecision(...decision)).wait();
  const decisionReplay = await (await f.escrow.recordDecision(...decision)).wait();
  assert.equal(decisionReplay.logs.length, 0);
  const observed = await transactionInventory((method, params) => f.rpc.request({ method, params }), f.escrow, allocation);
  assert.equal(observed.submit.length, 2);
  assert.equal(observed.record.length, 2);
  assert.equal(new Set([...observed.submit, ...observed.record].map(tx => tx.hash)).size, 4);
  assert.ok([...observed.submit, ...observed.record].every(tx => tx.status === 1));
  assert.deepEqual(observed.pay, []);
  assert.deepEqual(observed.refund, []);
});
