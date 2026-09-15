import assert from 'node:assert/strict';
import test from 'node:test';
import { ethers } from 'ethers';
import { fixture } from './work-claim-fixture.mjs';
import { intentFor, validatePrepared, reconcile } from './work-claim-recovery.mjs';

export async function paidFixture(t) {
  const f=await fixture(t);
  const allocation=await f.fund();
  await f.at(2);
  await f.submit(allocation);
  await f.at(5);
  await (await f.escrow.recordDecision(...await f.sign(allocation))).wait();
  const data=f.escrow.interface.encodeFunctionData('withdrawPayment',[allocation]);
  const raw=await f.signRawCall(f.B,data);
  const tx=ethers.Transaction.from(raw);
  const domain={chainId:'31337',escrow:(await f.escrow.getAddress()).toLowerCase(),
    runtimeKeccak256:ethers.keccak256(await f.provider.getCode(await f.escrow.getAddress())),
    genesisHash:(await f.provider.send('eth_getBlockByNumber',['0x0',false])).hash};
  const policy={owner:f.B.address.toLowerCase(),domain};
  const intent=intentFor(policy,allocation,f.terms.agreementDigest,'pay',data);
  const prepared={intent,nonce:String(tx.nonce),rawTransaction:raw,transactionHash:tx.hash};
  return {f,allocation,policy,prepared};
}

test('raw recovery validates signature, operation, complete transaction and local rail pins',async(t)=>{
  const {f,policy,prepared}=await paidFixture(t);
  assert.equal(validatePrepared(prepared,policy).hash,prepared.transactionHash);
  for (const overrides of [{nonce:Number(prepared.nonce)+1},{chainId:1},{to:f.X.address},
    {value:1},{gasLimit:900000},{maxFeePerGas:1900000000},{maxPriorityFeePerGas:900000000},
    {data:f.escrow.interface.encodeFunctionData('withdrawRefund',[prepared.intent.allocationId])}]) {
    const raw=await f.signRawCall(f.B,prepared.intent.callData,overrides);
    const changed={...prepared,rawTransaction:raw,transactionHash:ethers.keccak256(raw)};
    assert.throws(()=>validatePrepared(changed,policy));
  }
  const wrongSigner=await f.signRawCall(f.X,prepared.intent.callData,{nonce:Number(prepared.nonce)});
  assert.throws(()=>validatePrepared({...prepared,rawTransaction:wrongSigner,transactionHash:ethers.keccak256(wrongSigner)},policy));
  assert.throws(()=>validatePrepared({...prepared,transactionHash:'0x'+'ab'.repeat(32)},policy));
  const changedIntent={...prepared.intent,action:'refund'};
  assert.throws(()=>validatePrepared({...prepared,intent:changedIntent},policy));
  for(const key of Object.keys(policy.domain))assert.throws(()=>validatePrepared(prepared,{...policy,domain:{...policy.domain,[key]:'changed'}}));
});

test('unavailable or mismatched rail observations cannot certify inclusion',async(t)=>{
  const {f,policy,prepared}=await paidFixture(t);
  await f.provider.send('eth_sendRawTransaction',[prepared.rawTransaction]);
  const rpc=(method,params)=>f.provider.send(method,params);
  const expected=await reconcile(prepared,policy,rpc,null,async()=>{});
  assert.equal(expected.status,'Included');
  for (const fault of ['unavailable','chain','code','genesis','receipt','transaction','block','block-index']) {
    let broadcast=0;
    const broken=async(method,params)=>{
      if(method==='eth_sendRawTransaction')broadcast++;
      if(fault==='unavailable' && method==='eth_getTransactionReceipt')throw new Error('observer unavailable');
      const value=await rpc(method,params);
      if(fault==='chain' && method==='eth_chainId')return '0x1';
      if(fault==='code' && method==='eth_getCode')return '0x00';
      if(fault==='genesis' && method==='eth_getBlockByNumber' && params[0]==='0x0')return {...value,hash:'0x'+'ab'.repeat(32)};
      if(fault==='receipt' && method==='eth_getTransactionReceipt')return {...value,transactionHash:'0x'+'ab'.repeat(32)};
      if(fault==='transaction' && method==='eth_getTransactionByHash')return {...value,input:'0x12345678'};
      if(fault==='block' && method==='eth_getBlockByNumber' && params[0]!=='0x0')return {...value,hash:'0x'+'ab'.repeat(32)};
      if(fault==='block-index' && method==='eth_getBlockByNumber' && params[0]!=='0x0')return {...value,transactions:[]};
      return value;
    };
    await assert.rejects(()=>reconcile(prepared,policy,broken,expected,async()=>{}),fault);
    assert.equal(broadcast,0);
  }
});

test('a reorg preserves uncertainty and a revert never becomes paid',async(t)=>{
  const {f,policy,prepared,allocation}=await paidFixture(t);
  const snapshot=await f.provider.send('evm_snapshot',[]);
  await f.provider.send('eth_sendRawTransaction',[prepared.rawTransaction]);
  const rpc=(method,params)=>f.provider.send(method,params);
  const observed=await reconcile(prepared,policy,rpc,null,async()=>{});
  await f.provider.send('evm_revert',[snapshot]);
  let sent=0;
  await assert.rejects(()=>reconcile(prepared,policy,async(method,params)=>{
    if(method==='eth_sendRawTransaction')sent++;
    return rpc(method,params);
  },observed,async()=>{}));
  assert.equal(sent,0);
  assert.equal(await f.token.balanceOf(f.B.address),1000n);
  // Refund is ineligible after an accepted decision; actual EVM status must be 0.
  const data=f.escrow.interface.encodeFunctionData('withdrawRefund',[allocation]);
  const raw=await f.signRawCall(f.B,data);
  const tx=ethers.Transaction.from(raw);
  const rejected={intent:intentFor(policy,allocation,f.terms.agreementDigest,'refund',data),nonce:String(tx.nonce),rawTransaction:raw,transactionHash:tx.hash};
  const result=await reconcile(rejected,policy,rpc,null,async()=>{});
  assert.equal(result.status,'Reverted');
  assert.equal(await f.token.balanceOf(f.B.address),1000n);
  assert.equal((await f.escrow.getWork(allocation)).state,3n);
});

test('an unresolved earlier nonce prevents dispatch of a future transaction',async(t)=>{
  const {f,policy,prepared}=await paidFixture(t);
  const raw=await f.signRawCall(f.B,prepared.intent.callData,{nonce:Number(prepared.nonce)+1});
  const tx=ethers.Transaction.from(raw);
  const future={...prepared,nonce:String(tx.nonce),rawTransaction:raw,transactionHash:tx.hash};
  let attempted=0;
  await assert.rejects(()=>reconcile(future,policy,async(method,params)=>{
    if(method==='eth_sendRawTransaction') {attempted++;throw new Error('unexpected dispatch');}
    return f.provider.send(method,params);
  },null,async()=>{}));
  assert.equal(attempted,0,'a future nonce was sent before its predecessor resolved');
});
