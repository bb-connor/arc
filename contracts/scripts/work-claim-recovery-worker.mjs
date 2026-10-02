// Keyless worker. The parent exposes only a restricted private-chain RPC bridge.
import fs from 'node:fs';
import { journal } from './work-claim-journal.mjs';
import { reconcile } from './work-claim-recovery.mjs';

const config=JSON.parse(fs.readFileSync(process.argv[2],'utf8'));
const operationId=process.argv[3];
let sequence=0;
const pending=new Map();
process.on('message',(message)=>{
  const entry=pending.get(message.id);
  if(!entry)return;
  pending.delete(message.id);
  if(message.error)entry.reject(new Error(message.error));else entry.resolve(message.result);
});
function request(kind,body) {
  return new Promise((resolve,reject)=>{
    const id=++sequence;
    pending.set(id,{resolve,reject});
    process.send({kind,id,...body});
  });
}
async function send(value) {await new Promise((resolve,reject)=>process.send(value,(error)=>error?reject(error):resolve()));}
try {
  const current=journal(config,'read',{operationId});
  const observation=await reconcile(current.prepared,config,
    (method,params)=>request('rpc',{method,params}),current.observation,
    (point)=>request('checkpoint',{point}));
  const result=journal(config,'observe',{operationId,observation});
  await request('checkpoint',{point:'after_recorded'});
  await send({kind:'result',result});
  process.disconnect();
} catch(error) {
  try {journal(config,'uncertain',{operationId,reason:error.reason ?? 'observer_unavailable'});} catch {}
  await send({kind:'failure',reason:error.reason ?? 'observer_unavailable'});
  process.disconnect();
  process.exitCode=1;
}
