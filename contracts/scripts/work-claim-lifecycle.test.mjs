// Removing a durable stage or accepting changed original authority must fail.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { runLifecycle } from './work-claim-lifecycle.mjs';

const actions={accepted:['submit','decision','pay'],rejected:['submit','decision','refund'],
  'missing-custody':['submit','refund'],child:['submit','decision','refund','pay']};
const balances={accepted:{A:'900',B:'1100',C:'0',escrow:'0'},rejected:{A:'1000',B:'1000',C:'0',escrow:'0'},
  'missing-custody':{A:'1000',B:'1000',C:'0',escrow:'0'},child:{A:'1000',B:'940',C:'60',escrow:'0'}};
for(const scenario of Object.keys(actions)) {
  for(const point of ['before_broadcast','after_broadcast','after_observation','after_recorded']) {
    test(`${scenario} W0 recovers every action after ${point}`,async()=>{
      const state=fs.mkdtempSync(path.join(os.tmpdir(),'chio-lifecycle-'));
      try {
        const result=await runLifecycle(scenario,state,point);
        assert.deepEqual(result.railRecoveries.map((r)=>r.journal.prepared.intent.action),actions[scenario]);
        assert.deepEqual(result.observations.at(-1).balances,balances[scenario]);
        assert.equal(result.accounting.remaining,'0');
        if(scenario==='missing-custody') {assert.equal(result.certificate,null);assert.ok(result.verifierFailure);}
        else assert.equal(result.certificate.decision.body.accepted,scenario!=='rejected');
        if(scenario==='child') {
          const parentRefund=result.observations.find((o)=>o.label==='parent_refunded');
          assert.equal(parentRefund.work.state,'Payable');assert.equal(parentRefund.work.paid,'0');
          assert.equal(parentRefund.parent.refunded,'100');
          assert.deepEqual(result.accounting,{escrowFunded:'160',paid:'60',refunded:'100',remaining:'0'});
          assert.equal(result.railRecoveries[2].journal.prepared.intent.agreementDigest,result.parentAgreement.agreementDigest);
        }
        const occupied=new Set();
        for(const r of result.railRecoveries) {
          assert.equal(r.killed.signal,'SIGKILL');
          assert.equal(r.killed.killedAt,point);
          assert.deepEqual(r.afterLoss.prepared,r.journal.prepared);
          assert.equal(r.journal.state,'Included');
          assert.equal(r.broadcasts,1);
          assert.equal(r.canonicalTransactionCount,1);
          const nonce=r.journal.prepared.intent.actor+':'+r.originalNonce;
          assert.ok(!occupied.has(nonce),'signer nonce reused');occupied.add(nonce);
        }
        const count=actions[scenario].length;
        assert.equal(result.lifecycle.reobservations.length,count*(count+1)/2);
        for(const r of result.lifecycle.reobservations)assert.equal(r.worker.broadcasts,0);
        if(process.env.CHIO_LIFECYCLE_EVIDENCE) {
          fs.mkdirSync(process.env.CHIO_LIFECYCLE_EVIDENCE,{recursive:true});
          fs.writeFileSync(path.join(process.env.CHIO_LIFECYCLE_EVIDENCE,scenario+'-'+point+'.json'),JSON.stringify(result,null,2)+'\n');
        }
      } finally {fs.rmSync(state,{recursive:true,force:true});}
    });
  }
}
