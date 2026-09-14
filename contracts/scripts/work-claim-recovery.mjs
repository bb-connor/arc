// Example-local reconciliation of exact signed bytes. Inclusion is not finality.
import assert from 'node:assert/strict';
import { ethers } from 'ethers';

export const escrowInterface=new ethers.Interface([
  'function submitClaim(bytes32 allocationId,bytes32 commitment)',
  'function recordDecision(bytes32 allocationId,bytes32 decisionDigest,bool accepted,bytes signature)',
  'function withdrawPayment(bytes32 allocationId)',
  'function withdrawRefund(bytes32 allocationId)',
  'function getWork(bytes32 allocationId) view returns (tuple(tuple(bytes32 agreementDigest,address payer,address beneficiary,address verifier,address token,uint256 amount,uint64 submitBy,uint64 challengeUntil,uint64 resolveBy,uint64 refundAfter) terms,uint8 state,bytes32 commitment,bytes32 decisionDigest,bool accepted,uint256 paid,uint256 refunded))',
]);
const methods={submit:'submitClaim',decision:'recordDecision',pay:'withdrawPayment',refund:'withdrawRefund'};
function canonicalIntent(value) {
  // This grammar contains ASCII strings and objects only; never general JSON numbers.
  if(typeof value==='string') {assert.match(value,/^[\x20-\x7e]*$/);return JSON.stringify(value);}
  assert.ok(value && typeof value==='object' && !Array.isArray(value));
  return '{'+Object.keys(value).sort().map((key)=>JSON.stringify(key)+':'+canonicalIntent(value[key])).join(',')+'}';
}
export function intentFor(policy,allocationId,agreementDigest,action,callData) {
  assert.ok(Object.hasOwn(methods,action));
  const body={schema:'chio.experimental.rail-intent.v1',allocationId,agreementDigest,action,
    actor:policy.owner,domain:policy.domain,callData,gasLimit:'1000000',maxFeePerGas:'2000000000',maxPriorityFeePerGas:'1000000000'};
  return {...body,operationId:ethers.sha256(ethers.toUtf8Bytes(canonicalIntent(body)))};
}
export function validatePrepared(prepared,policy) {
  const i=prepared.intent;
  assert.equal(i.schema,'chio.experimental.rail-intent.v1');
  assert.deepEqual(i.domain,policy.domain,'rail scope changed');
  assert.equal(i.actor,policy.owner,'actor changed');
  const {operationId,...body}=i;
  assert.equal(operationId,ethers.sha256(ethers.toUtf8Bytes(canonicalIntent(body))),'operation changed');
  const tx=ethers.Transaction.from(prepared.rawTransaction);
  assert.equal(tx.type,2,'only type-2 transactions are supported');
  assert.ok(tx.isSigned());
  assert.equal(tx.hash,prepared.transactionHash,'transaction hash changed');
  assert.equal(tx.from.toLowerCase(),policy.owner,'signer changed');
  assert.equal(tx.chainId,BigInt(policy.domain.chainId),'chain changed');
  assert.equal(tx.to.toLowerCase(),policy.domain.escrow,'destination changed');
  assert.equal(String(tx.nonce),prepared.nonce,'nonce changed');
  assert.equal(tx.value,0n,'unexpected native-token value');
  assert.equal(tx.data,i.callData,'call changed');
  assert.deepEqual(tx.accessList,[],'access list changed');
  for(const field of ['gasLimit','maxFeePerGas','maxPriorityFeePerGas'])assert.equal(tx[field],BigInt(i[field]),field+' changed');
  assert.ok(tx.gasLimit>0n && tx.gasLimit<=1000000n);
  const call=escrowInterface.parseTransaction(tx);
  assert.equal(call.name,methods[i.action],'action changed');
  assert.equal(call.args[0],i.allocationId,'allocation changed');
  assert.equal(escrowInterface.encodeFunctionData(call.name,call.args),tx.data,'noncanonical call data');
  return tx;
}

export class Uncertain extends Error {
  constructor(reason,message){super(message);this.reason=reason;}
}

export async function reconcile(prepared,policy,rpc,previous,checkpoint) {
  let tx;
  try {tx=validatePrepared(prepared,policy);} catch {throw new Uncertain('mismatch','retained transaction validation failed');}
  const i=prepared.intent;
  async function checkDomain() {
    assert.equal(BigInt(await rpc('eth_chainId',[])),tx.chainId,'chain changed');
    const genesis=await rpc('eth_getBlockByNumber',['0x0',false]);
    assert.equal(genesis?.hash,policy.domain.genesisHash,'genesis changed');
    assert.equal(ethers.keccak256(await rpc('eth_getCode',[policy.domain.escrow,'latest'])),policy.domain.runtimeKeccak256,'deployment code changed');
  }
  async function work() {
    const encoded=await rpc('eth_call',[{to:policy.domain.escrow,data:escrowInterface.encodeFunctionData('getWork',[i.allocationId])},'latest']);
    const result=escrowInterface.decodeFunctionResult('getWork',encoded)[0];
    assert.equal(result.terms.agreementDigest,i.agreementDigest,'agreement changed');
    if(i.action==='pay' || i.action==='submit')assert.equal(result.terms.beneficiary.toLowerCase(),policy.owner,'beneficiary changed');
    return result;
  }
  try {
    await checkDomain();
    await work();
    let receipt=await rpc('eth_getTransactionReceipt',[tx.hash]);
    if(!receipt) {
      if(previous)throw new Uncertain('missing_inclusion','previous inclusion is no longer observable');
      if(await rpc('eth_getTransactionByHash',[tx.hash]))throw new Uncertain('pending','original transaction remains pending');
      const used=BigInt(await rpc('eth_getTransactionCount',[policy.owner,'latest']));
      if(used>BigInt(tx.nonce))throw new Uncertain('nonce_occupied','signer nonce is occupied without the original receipt');
      if(used<BigInt(tx.nonce))throw new Uncertain('pending','an earlier signer nonce remains unresolved');
      await checkpoint('before_broadcast');
      assert.equal(await rpc('eth_sendRawTransaction',[prepared.rawTransaction]),tx.hash,'broadcast returned a different hash');
      receipt=await rpc('eth_getTransactionReceipt',[tx.hash]);
      if(!receipt)throw new Uncertain('pending','broadcast inclusion is unknown');
    }
    const chainTx=await rpc('eth_getTransactionByHash',[tx.hash]);
    assert.ok(chainTx,'original transaction unavailable');
    assert.equal(chainTx.hash,tx.hash);
    assert.equal(chainTx.from.toLowerCase(),policy.owner);
    assert.equal(chainTx.to.toLowerCase(),policy.domain.escrow);
    assert.equal(chainTx.input,tx.data);
    for(const [name,want] of [['nonce',BigInt(tx.nonce)],['value',0n],['gas',tx.gasLimit],['type',2n],
      ['chainId',tx.chainId],['maxFeePerGas',tx.maxFeePerGas],['maxPriorityFeePerGas',tx.maxPriorityFeePerGas],
      ['r',BigInt(tx.signature.r)],['s',BigInt(tx.signature.s)],['v',BigInt(tx.signature.yParity)]])assert.equal(BigInt(chainTx[name]),want,'transaction '+name+' changed');
    assert.equal(receipt.transactionHash,tx.hash);
    assert.equal(receipt.from.toLowerCase(),policy.owner);
    assert.equal(receipt.to.toLowerCase(),policy.domain.escrow);
    assert.equal(chainTx.blockHash,receipt.blockHash);
    assert.equal(chainTx.blockNumber,receipt.blockNumber);
    assert.equal(chainTx.transactionIndex,receipt.transactionIndex);
    const block=await rpc('eth_getBlockByNumber',[receipt.blockNumber,false]);
    assert.equal(block?.hash,receipt.blockHash,'receipt is not on the observed canonical chain');
    assert.equal(block?.number,receipt.blockNumber);
    assert.equal(block.transactions[Number(BigInt(receipt.transactionIndex))],tx.hash,'transaction absent at claimed block position');
    const status=BigInt(receipt.status);
    assert.ok(status===0n || status===1n,'invalid transaction status');
    const current=await work();
    if(status===1n) {
      const call=escrowInterface.parseTransaction(tx);
      if(i.action==='pay') {assert.equal(current.state,4n);assert.equal(current.paid,current.terms.amount);assert.equal(current.refunded,0n);}
      if(i.action==='refund') {assert.equal(current.state,7n);assert.equal(current.refunded,current.terms.amount);assert.equal(current.paid,0n);}
      if(i.action==='submit')assert.equal(current.commitment,call.args[1]);
      if(i.action==='decision') {assert.equal(current.decisionDigest,call.args[1]);assert.equal(current.accepted,call.args[2]);}
    }
    await checkDomain();
    const observation={transactionHash:tx.hash,blockHash:receipt.blockHash,
      blockNumber:Number(BigInt(receipt.blockNumber)),transactionIndex:Number(BigInt(receipt.transactionIndex)),
      status:status===1n?'Included':'Reverted'};
    if(previous)assert.deepEqual(observation,previous,'original inclusion changed');
    await checkpoint('after_observation');
    return observation;
  } catch(error) {
    if(error instanceof Uncertain)throw error;
    throw new Uncertain(error.code==='ERR_ASSERTION'?'mismatch':'observer_unavailable','rail observation did not verify');
  }
}
