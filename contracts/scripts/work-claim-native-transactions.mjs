// Owned fixture transaction transport. Retained raw bytes, not fresh retries.
import assert from 'node:assert/strict';
import { createPublicKey, verify } from 'node:crypto';
import { ethers } from 'ethers';
import { escrowInterface, intentFor, validatePrepared, reconcile } from './work-claim-recovery.mjs';

// The native decision grammar contains ASCII strings, safe integers and booleans.
function canonical(value) {
  if (typeof value === 'string') { assert.match(value, /^[\x20-\x7e]*$/); return JSON.stringify(value); }
  if (typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') { assert.ok(Number.isSafeInteger(value)); return JSON.stringify(value); }
  assert.ok(value && typeof value === 'object' && !Array.isArray(value));
  return '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}';
}

const decisionTypes = { ChioWorkDecision: [
  { name: 'allocationId', type: 'bytes32' }, { name: 'agreementDigest', type: 'bytes32' },
  { name: 'commitment', type: 'bytes32' }, { name: 'decisionDigest', type: 'bytes32' },
  { name: 'accepted', type: 'bool' }, { name: 'beneficiary', type: 'address' },
  { name: 'token', type: 'address' }, { name: 'amount', type: 'uint256' },
] };

export function transactions({ rpc, provider, escrow, domain, payer, beneficiary, verifier }) {
  const send = (method, params) => rpc.request({ method, params });
  const scope = { chainId: domain.chainId, genesisHash: domain.genesisHash, escrow: domain.escrow, runtimeKeccak256: domain.escrowCodeHash };
  const owners = { submit: beneficiary, record: verifier, pay: beneficiary, refund: payer };
  const included = new Map();
  let verifierKey;
  let allowed = new Set(Object.keys(owners));
  const policyFor = action => ({ owner: owners[action].address.toLowerCase(), domain: scope });
  function retainedPolicy(prepared) {
    const action = prepared.intent.action === 'decision' ? 'record' : prepared.intent.action;
    assert.ok(Object.hasOwn(owners, action));
    return policyFor(action);
  }
  return {
    restrict(actions) {
      assert.ok(actions.every(action => allowed.has(action)), 'authority cannot widen after retirement');
      allowed = new Set(actions);
    },
    pin(key) {
      assert.match(key, /^[0-9a-f]{64}$/);
      assert.ok(!verifierKey || verifierKey === key, 'verifier pin is immutable');
      verifierKey = key;
    },
    async prepare(request) {
      assert.deepEqual(Object.keys(request).sort(), ['action', 'allocationId', 'commitment', 'decision', 'terms']);
      assert.ok(Object.hasOwn(owners, request.action));
      const { action, allocationId, terms, commitment, decision } = request;
      assert.ok(allowed.has(action), 'signing authority retired');
      assert.equal(await escrow.deriveAllocationId(terms), allocationId);
      const work = await escrow.getWork(allocationId);
      for (const name of Object.keys(terms)) assert.equal(String(work.terms[name]).toLowerCase(), String(terms[name]).toLowerCase(), 'immutable term ' + name);
      let callData;
      if (action === 'submit') callData = escrowInterface.encodeFunctionData('submitClaim', [allocationId, commitment]);
      if (action === 'record') {
        assert.ok(verifierKey && decision);
        const body = decision.body;
        assert.equal(body.schema, 'chio.experimental.native-funded-decision.v1');
        assert.equal(body.binding.allocationId, allocationId);
        assert.equal('0x' + body.binding.agreementSha256, terms.agreementDigest);
        assert.equal(body.commitment, commitment);
        assert.equal(work.commitment, commitment, 'decision requires observed original claim');
        const key = createPublicKey({ key: Buffer.from('302a300506032b6570032100' + verifierKey, 'hex'), format: 'der', type: 'spki' });
        assert.match(decision.signature, /^[0-9a-f]{128}$/);
        assert.ok(verify(null, Buffer.from(canonical(body)), key, Buffer.from(decision.signature, 'hex')), 'native verifier signature invalid');
        const decisionDigest = ethers.sha256(ethers.toUtf8Bytes(canonical(body)));
        const signature = await verifier.signTypedData({ name: 'ChioWorkClaimEscrow', version: '1', chainId: scope.chainId, verifyingContract: scope.escrow }, decisionTypes,
          { allocationId, agreementDigest: terms.agreementDigest, commitment, decisionDigest, accepted: body.accepted, beneficiary: terms.beneficiary, token: terms.token, amount: terms.amount });
        callData = escrowInterface.encodeFunctionData('recordDecision', [allocationId, decisionDigest, body.accepted, signature]);
      }
      if (action === 'pay') callData = escrowInterface.encodeFunctionData('withdrawPayment', [allocationId]);
      if (action === 'refund') callData = escrowInterface.encodeFunctionData('withdrawRefund', [allocationId]);
      const policy = policyFor(action);
      const intent = intentFor(policy, allocationId, terms.agreementDigest, action === 'record' ? 'decision' : action, callData);
      const nonce = Number(BigInt(await send('eth_getTransactionCount', [policy.owner, 'pending'])));
      const rawTransaction = await owners[action].signTransaction({ type: 2, chainId: BigInt(scope.chainId), to: scope.escrow, nonce, value: 0,
        data: callData, gasLimit: BigInt(intent.gasLimit), maxFeePerGas: BigInt(intent.maxFeePerGas), maxPriorityFeePerGas: BigInt(intent.maxPriorityFeePerGas), accessList: [] });
      const prepared = { intent, nonce: String(nonce), rawTransaction, transactionHash: ethers.keccak256(rawTransaction) };
      validatePrepared(prepared, policy);
      return prepared;
    },
    async transact(prepared) {
      assert.ok(allowed.has(prepared.intent.action === 'decision' ? 'record' : prepared.intent.action), 'transaction authority retired');
      const policy = retainedPolicy(prepared);
      const observed = await reconcile(prepared, policy, send, included.get(prepared.transactionHash), async () => {});
      included.set(prepared.transactionHash, observed);
      assert.equal(observed.status, 'Included', 'transaction reverted');
      let head = Number(BigInt(await send('eth_blockNumber', [])));
      while (head - observed.blockNumber < 2) { await send('evm_mine', []); head++; }
    },
    async validateObservation(prepared) {
      const policy = retainedPolicy(prepared);
      const readOnly = (method, params) => { assert.notEqual(method, 'eth_sendRawTransaction', 'observation cannot broadcast'); return send(method, params); };
      const observed = await reconcile(prepared, policy, readOnly, included.get(prepared.transactionHash), async () => {});
      assert.equal(observed.status, 'Included');
    },
    async advance(allocationId, phase) {
      assert.ok(['decision', 'refund'].includes(phase));
      const work = await escrow.getWork(allocationId);
      const target = Number(phase === 'decision' ? work.terms.challengeUntil : work.terms.refundAfter) + 1;
      const head = await send('eth_getBlockByNumber', ['latest', false]);
      if (Number(head.timestamp) < target) { await send('evm_increaseTime', [target - Number(head.timestamp)]); await send('evm_mine', []); }
    },
  };
}
