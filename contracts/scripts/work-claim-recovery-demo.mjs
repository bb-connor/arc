// Retained standalone reproduction of a real W0 payout through rail-worker loss.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { runW0 } from './work-claim-w0.mjs';
import { recoverPayment } from './work-claim-recovery-harness.mjs';
assert.equal(process.argv.length,7,'usage: work-claim-recovery-demo.mjs accepted|child KILL_POINT STATE --output FILE');
const [, ,scenario,killPoint,state,flag,output]=process.argv;
assert.ok(['accepted','child'].includes(scenario));
assert.ok(['before_broadcast','after_broadcast','after_observation','after_recorded'].includes(killPoint));
assert.equal(flag,'--output');
const result=await runW0(scenario,state,{payment:(context)=>recoverPayment(context,state,killPoint)});
assert.equal(result.recovery.broadcasts,1);
assert.equal(result.recovery.canonicalTransactionCount,1);
fs.writeFileSync(output,JSON.stringify(result,null,2)+'\n',{flag:'wx'});
console.log(JSON.stringify({output,scenario,killPoint,accounting:result.accounting,
  transactionHash:result.recovery.transactionHash,workerSignal:result.recovery.killed.signal,
  broadcasts:result.recovery.broadcasts,observedInclusions:result.recovery.canonicalTransactionCount}));
