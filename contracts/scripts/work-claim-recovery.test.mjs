// Kill an actual keyless worker while its independent private chain stays alive.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { runW0 } from './work-claim-w0.mjs';
import { recoverPayment } from './work-claim-recovery-harness.mjs';

for (const point of ['before_broadcast','after_broadcast','after_observation','after_recorded']) {
  test(`actual W0 payout recovers after SIGKILL ${point}`, async () => {
    const state=fs.mkdtempSync(path.join(os.tmpdir(),'chio-rail-crash-'));
    try {
      const result=await runW0('accepted',state,{payment:(context)=>recoverPayment(context,state,point)});
      assert.deepEqual(result.observations.at(-1).balances,{A:'900',B:'1100',C:'0',escrow:'0'});
      const recovery=result.recovery;
      assert.ok(recovery,'the payment must pass through durable worker recovery');
      assert.equal(recovery.killed.signal,'SIGKILL');
      assert.equal(recovery.journal.state,'Included');
      assert.equal(recovery.journal.prepared.transactionHash,recovery.transactionHash);
      assert.equal(recovery.canonicalTransactionCount,1);
      assert.equal(recovery.broadcasts,1);
      assert.equal(recovery.journal.prepared.nonce,recovery.originalNonce);
      assert.equal(recovery.keylessWorker,true);
      if (process.env.CHIO_RECOVERY_EVIDENCE) {
        fs.mkdirSync(process.env.CHIO_RECOVERY_EVIDENCE,{recursive:true});
        fs.writeFileSync(path.join(process.env.CHIO_RECOVERY_EVIDENCE,point+'.json'),JSON.stringify(result,null,2)+'\n');
      }
    } finally {fs.rmSync(state,{recursive:true,force:true});}
  });
}

test('an earned child recovers payout after parent refund and rail-worker loss',async()=>{
  const state=fs.mkdtempSync(path.join(os.tmpdir(),'chio-child-rail-'));
  try {
    const result=await runW0('child',state,{payment:(context)=>recoverPayment(context,state,'after_broadcast')});
    assert.deepEqual(result.observations.at(-1).balances,{A:'1000',B:'940',C:'60',escrow:'0'});
    assert.equal(result.observations.find((v)=>v.label==='parent_refunded').work.state,'Payable');
    assert.equal(result.recovery.killed.signal,'SIGKILL');
    assert.equal(result.recovery.broadcasts,1);
    assert.equal(result.recovery.journal.state,'Included');
    if(process.env.CHIO_RECOVERY_EVIDENCE)fs.writeFileSync(path.join(process.env.CHIO_RECOVERY_EVIDENCE,'child.json'),JSON.stringify(result,null,2)+'\n');
  } finally {fs.rmSync(state,{recursive:true,force:true});}
});
