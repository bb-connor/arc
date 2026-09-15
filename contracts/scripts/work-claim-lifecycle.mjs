// Recover every post-funding action; the parent and private chain remain alive.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runW0 } from './work-claim-w0.mjs';
import { recoverRailAction, actionConfig, runWorker } from './work-claim-recovery-harness.mjs';

export async function runLifecycle(scenario,state,killPoint) {
  assert.ok(['before_broadcast','after_broadcast','after_observation','after_recorded'].includes(killPoint));
  const retained=[];
  const reobservations=[];
  const result=await runW0(scenario,state,{railAction:async(context)=>{
    const recovered=await recoverRailAction(context,state,killPoint);
    retained.push(recovered.recovery);
    // Earlier submit/decision observations must survive later Paid/Refunded states.
    for(const record of retained) {
      const prepared=record.journal.prepared;
      const worker=await runWorker(actionConfig(state,prepared.intent.actor),record.operationId,
        (method,params)=>context.f.provider.send(method,params),prepared.rawTransaction);
      assert.equal(worker.code,0,JSON.stringify(worker));
      assert.equal(worker.broadcasts,0,'later state caused a second send');
      assert.deepEqual(worker.result,record.journal,'later state changed retained authority');
      reobservations.push({afterOperation:recovered.recovery.operationId,operationId:record.operationId,worker});
    }
    return recovered;
  }});
  return {...result,lifecycle:{schema:'chio.experimental.rail-lifecycle-run.v1',killPoint,reobservations,
    scope:'All post-funding W0 actions use durable worker recovery. Funding, orchestration-parent loss and native admission are outside this experiment.'}};
}

if(process.argv[1] && path.resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  assert.equal(process.argv.length,7,'usage: work-claim-lifecycle.mjs SCENARIO KILL_POINT STATE --output FILE');
  assert.equal(process.argv[5],'--output');
  const result=await runLifecycle(process.argv[2],process.argv[4],process.argv[3]);
  fs.writeFileSync(process.argv[6],JSON.stringify(result,null,2)+'\n',{flag:'wx'});
  console.log(JSON.stringify({scenario:result.scenario,killPoint:result.lifecycle.killPoint,
    accounting:result.accounting,actions:result.railRecoveries.map((r)=>r.journal.prepared.intent.action),
    killedWorkers:result.railRecoveries.map((r)=>({pid:r.killed.pid,signal:r.killed.signal})),output:process.argv[6]}));
}
