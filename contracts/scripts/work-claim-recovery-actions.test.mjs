// Live-chain non-payment observations must bind each action's actual effect.
import assert from 'node:assert/strict';
import test from 'node:test';
import { ethers } from 'ethers';
import { fixture } from './work-claim-fixture.mjs';
import { escrowInterface, intentFor, validatePrepared, reconcile } from './work-claim-recovery.mjs';

for(const action of ['submit','decision','refund']) {
  test(`${action} recovery rejects substituted agreement, calldata and effect`,async(t)=>{
    const f=await fixture(t);
    const allocation=await f.fund();
    await f.at(2);
    let args=[allocation,ethers.id('retained submission')];
    if(action!=='submit') {
      await f.submit(allocation);
      await f.at(5);
      args=await f.sign(allocation,false);
      if(action==='refund') {
        await (await f.escrow.recordDecision(...args)).wait();
        args=[allocation];
      }
    }
    const actor=action==='submit'?f.B:f.X;
    const method={submit:'submitClaim',decision:'recordDecision',refund:'withdrawRefund'}[action];
    const data=escrowInterface.encodeFunctionData(method,args);
    const domain={chainId:'31337',escrow:(await f.escrow.getAddress()).toLowerCase(),
      runtimeKeccak256:ethers.keccak256(await f.provider.getCode(await f.escrow.getAddress())),
      genesisHash:(await f.provider.send('eth_getBlockByNumber',['0x0',false])).hash};
    const policy={owner:actor.address.toLowerCase(),domain};
    const raw=await f.signRawCall(actor,data);
    const tx=ethers.Transaction.from(raw);
    const prepared={intent:intentFor(policy,allocation,f.terms.agreementDigest,action,data),
      nonce:String(tx.nonce),rawTransaction:raw,transactionHash:tx.hash};
    validatePrepared(prepared,policy);
    const changed={...prepared,intent:intentFor(policy,allocation,f.terms.agreementDigest,'pay',data)};
    assert.throws(()=>validatePrepared(changed,policy),'declared action must match actual calldata');
    const rpc=(method,params)=>f.provider.send(method,params);
    await rpc('eth_sendRawTransaction',[raw]);
    const observed=await reconcile(prepared,policy,rpc,null,async()=>{});
    assert.equal(observed.status,'Included');
    const faults={agreement:(w)=>{w[0][0]=ethers.id('another agreement');}};
    if(action==='submit')faults.commitment=(w)=>{w[2]=ethers.id('other submission');};
    if(action==='decision') {
      faults.digest=(w)=>{w[3]=ethers.id('another decision');};
      faults.verdict=(w)=>{w[4]=!w[4];};
    }
    if(action==='refund') {
      faults.state=(w)=>{w[1]=2n;};
      faults.amount=(w)=>{w[6]=0n;};
      faults.exclusive=(w)=>{w[5]=100n;};
    }
    for(const [name,mutate] of Object.entries(faults)) {
      let sent=0;
      await assert.rejects(()=>reconcile(prepared,policy,async(method,params)=>{
        if(method==='eth_sendRawTransaction')sent++;
        const value=await rpc(method,params);
        if(method!=='eth_call')return value;
        const decoded=escrowInterface.decodeFunctionResult('getWork',value)[0];
        const work=[Array.from(decoded.terms),decoded.state,decoded.commitment,decoded.decisionDigest,
          decoded.accepted,decoded.paid,decoded.refunded];
        mutate(work);
        return escrowInterface.encodeFunctionResult('getWork',[work]);
      },observed,async()=>{}),name);
      assert.equal(sent,0);
    }
  });
}
