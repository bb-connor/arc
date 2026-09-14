// Test harness owns the chain and signing keys; keyless workers receive scoped IPC.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fork } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { ethers } from 'ethers';
import { journal } from './work-claim-journal.mjs';
import { intentFor, validatePrepared } from './work-claim-recovery.mjs';

const worker=fileURLToPath(new URL('./work-claim-recovery-worker.mjs',import.meta.url));
const allowed=new Set(['eth_chainId','eth_getBlockByNumber','eth_getCode','eth_call',
  'eth_getTransactionReceipt','eth_getTransactionByHash','eth_getTransactionCount','eth_sendRawTransaction']);

export async function runWorker(configFile,operationId,rpc,rawTransaction,killPoint=null) {
  const child=fork(worker,[configFile,operationId],{silent:true,execArgv:[],
    env:{PATH:process.env.PATH ?? '/usr/bin:/bin'}});
  const checkpoints=[];
  let broadcasts=0;
  let killedAt=null;
  let result=null;
  let failure=null;
  let stderr='';
  let callbackFailure=null;
  const reply=(value)=>{if(child.connected)child.send(value,()=>{});};
  child.stderr.on('data',(data)=>{stderr=(stderr+data.toString()).slice(-8192);});
  child.on('message',async(message)=>{
    try {
      if(message.kind==='checkpoint') {
        checkpoints.push(message.point);
        if(message.point===killPoint) {killedAt=message.point;child.kill('SIGKILL');}
        else reply({id:message.id,result:true});
      } else if(message.kind==='rpc') {
        assert.ok(allowed.has(message.method),'worker RPC method is not allowed');
        if(message.method==='eth_sendRawTransaction') {
          assert.deepEqual(message.params,[rawTransaction],'worker tried to replace the signed transaction');
          broadcasts++;
        }
        const value=await rpc(message.method,message.params);
        if(message.method==='eth_sendRawTransaction' && killPoint==='after_broadcast') {
          checkpoints.push('after_broadcast');killedAt='after_broadcast';child.kill('SIGKILL');
        } else reply({id:message.id,result:value});
      } else if(message.kind==='result')result=message.result;
      else if(message.kind==='failure')failure=message.reason;
      else assert.fail('unsupported worker message');
    } catch(error) {
      callbackFailure=String(error.message);
      reply({id:message.id,error:'private-chain RPC failed'});
    }
  });
  const exit=await new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>{callbackFailure='worker timeout';child.kill('SIGKILL');},35000);
    child.once('error',(error)=>{clearTimeout(timer);reject(error);});
    child.once('exit',(code,signal)=>{clearTimeout(timer);resolve({code,signal});});
  });
  return {...exit,pid:child.pid,killedAt,checkpoints,broadcasts,result,failure,stderr,callbackFailure};
}

export async function recoverPayment({f,allocation,seller,agreement},state,killPoint) {
  return recoverAction({f,allocation,actor:seller,agreement,action:'pay',args:[allocation]},state,killPoint,true);
}

export async function recoverRailAction(context,state,killPoint) {
  return recoverAction(context,state,killPoint,false);
}

export function actionConfig(state,owner) {
  return path.join(state,'rail-'+owner,'rail-config.json');
}

async function recoverAction({f,allocation,actor,agreement,action,args},state,killPoint,legacy) {
  const methods={submit:'submitClaim',decision:'recordDecision',pay:'withdrawPayment',refund:'withdrawRefund'};
  assert.ok(Object.hasOwn(methods,action));
  assert.equal(args[0],allocation);
  const owner=actor.address.toLowerCase();
  const domain={chainId:String((await f.provider.getNetwork()).chainId),escrow:(await f.escrow.getAddress()).toLowerCase(),
    runtimeKeccak256:ethers.keccak256(await f.provider.getCode(await f.escrow.getAddress())),
    genesisHash:(await f.provider.send('eth_getBlockByNumber',['0x0',false])).hash};
  const directory=legacy?state:path.join(state,'rail-'+owner);
  if(!legacy) {
    try {fs.mkdirSync(directory,{mode:0o700});} catch(error) {if(error.code!=='EEXIST')throw error;}
    const info=fs.lstatSync(directory);
    assert.ok(info.isDirectory() && info.uid===process.getuid() && (info.mode&0o777)===0o700,'unsafe actor directory');
  }
  const config={owner,domain,path:path.join(directory,'rail.sqlite'),python:process.env.CHIO_W0_PYTHON ?? 'python3'};
  journal(config,'init');
  const configFile=path.join(directory,'rail-config.json');
  try {fs.writeFileSync(configFile,JSON.stringify(config),{flag:'wx',mode:0o600});}
  catch(error) {
    if(error.code!=='EEXIST')throw error;
    const info=fs.lstatSync(configFile);
    assert.ok(info.isFile() && info.uid===process.getuid() && (info.mode&0o777)===0o600 && info.nlink===1,'unsafe actor config');
    assert.deepEqual(JSON.parse(fs.readFileSync(configFile,'utf8')),config,'actor scope changed');
  }
  const data=f.escrow.interface.encodeFunctionData(methods[action],args);
  const raw=await f.signRawCall(actor,data);
  const transaction=ethers.Transaction.from(raw);
  const work=await f.escrow.getWork(allocation);
  assert.equal(work.terms.agreementDigest,'0x'+await canonicalBodyHash(agreement.body,config));
  const intent=intentFor(config,allocation,work.terms.agreementDigest,action,data);
  const prepared={intent,nonce:String(transaction.nonce),rawTransaction:raw,transactionHash:transaction.hash};
  validatePrepared(prepared,config);
  journal(config,'prepare',{prepared});
  const original=journal(config,'read',{operationId:intent.operationId});
  assert.deepEqual(original.prepared,prepared);
  const rpc=(method,params)=>f.provider.send(method,params);
  const killed=await runWorker(configFile,intent.operationId,rpc,raw,killPoint);
  assert.equal(killed.signal,'SIGKILL');
  assert.equal(killed.killedAt,killPoint,killed.stderr || killed.callbackFailure);
  assert.equal(killed.callbackFailure,null);
  const afterLoss=journal(config,'read',{operationId:intent.operationId});
  const restarted=await runWorker(configFile,intent.operationId,rpc,raw);
  assert.equal(restarted.code,0,JSON.stringify(restarted));
  assert.equal(restarted.result.state,'Included');
  // A second restart must observe the original inclusion without another send.
  const retried=await runWorker(configFile,intent.operationId,rpc,raw);
  assert.equal(retried.code,0,JSON.stringify(retried));
  assert.equal(retried.broadcasts,0);
  const final=journal(config,'read',{operationId:intent.operationId});
  assert.deepEqual(final.prepared,prepared);
  assert.deepEqual(final.observation,restarted.result.observation);
  const block=await f.provider.send('eth_getBlockByNumber',[ethers.toQuantity(final.observation.blockNumber),false]);
  const canonicalTransactionCount=block.transactions.filter((hash)=>hash===transaction.hash).length;
  const receipt=await f.provider.getTransactionReceipt(transaction.hash);
  return {receipt,recovery:{schema:'chio.experimental.rail-recovery-run.v1',killPoint,keylessWorker:true,
    operationId:intent.operationId,transactionHash:transaction.hash,originalNonce:prepared.nonce,
    killed,afterLoss,restarted,retried,journal:final,canonicalTransactionCount,
    broadcasts:killed.broadcasts+restarted.broadcasts+retried.broadcasts,
    scope:'Actual rail-worker SIGKILL, same signed transaction, one private Ganache chain; no native execution or public finality.'}};
}

async function canonicalBodyHash(body,config) {
  // Reuse the independent canonical encoder; never hash JSON.stringify for signed work.
  const {spawnSync}=await import('node:child_process');
  const modulePath=fileURLToPath(new URL('../../examples/funded-work',import.meta.url));
  const result=spawnSync(config.python,['-B','-c',
    'import sys;sys.path.insert(0,sys.argv[1]);import artifacts as p;print(p.digest(p.load(sys.stdin.buffer.read())))',modulePath],
    {input:JSON.stringify(body),encoding:'utf8',timeout:15000,maxBuffer:512*1024});
  assert.equal(result.status,0,result.stderr);
  return result.stdout.trim();
}
