// Receiver-owned private-chain fixture. No external RPC, keys or arbitrary calls.
import assert from 'node:assert/strict';
import readline from 'node:readline';
import { ethers } from 'ethers';
import ganache from 'ganache';
import { artifacts, states } from './work-claim-fixture.mjs';
import { transactions } from './work-claim-native-transactions.mjs';
import { transactionInventory } from './work-claim-native-inventory.mjs';

const rpc = ganache.provider({ logging: { quiet: true },
  chain: { chainId: 31337, hardfork: 'shanghai', time: new Date() },
  wallet: { deterministic: true, totalAccounts: 5, defaultBalance: 1000 } });
const provider = new ethers.BrowserProvider(rpc, undefined, { cacheTimeout: -1 });
const [admin, payer, beneficiary, verifier, childBeneficiary] = await Promise.all([0, 1, 2, 3, 4].map(i => provider.getSigner(i)));
const send = (method, params) => rpc.request({ method, params });
const lower = value => value.toLowerCase();
const deposits = new Map();
let escrow;
let token;
let lifecycle;
let childLifecycle;
let initial;
const routes = new Map();
const wallet = signer => new ethers.Wallet(rpc.getInitialAccounts()[lower(signer.address)].secretKey, provider);

async function deploy(source, name, ...args) {
  const artifact = artifacts[source][name];
  const contract = await new ethers.ContractFactory(artifact.abi, artifact.evm.bytecode.object, admin).deploy(...args);
  await contract.waitForDeployment();
  return contract;
}

const block = value => ({ number: Number(value.number), hash: value.hash,
  parentHash: value.parentHash, timestamp: Number(value.timestamp) });

async function initialize() {
  assert.equal(escrow, undefined, 'fixture already initialized');
  escrow = await deploy('src/experimental/ChioWorkClaimEscrow.sol', 'ChioWorkClaimEscrow', admin.address);
  token = await deploy('src/mocks/MockERC20.sol', 'MockERC20', 'Native work test units', 'TEST', 0);
  await (await escrow.setTokenAllowed(await token.getAddress(), true)).wait();
  await (await escrow.setVerifierAllowed(verifier.address, true)).wait();
  await (await token.mint(payer.address, 1000)).wait();
  await (await token.connect(payer).approve(await escrow.getAddress(), ethers.MaxUint256)).wait();
  const escrowAddress = lower(await escrow.getAddress());
  const tokenAddress = lower(await token.getAddress());
  const head = await send('eth_getBlockByNumber', ['latest', false]);
  const start = Number(head.timestamp);
  const result = {
    domain: { profile: 'chio.experimental.local-confirmed-funding.v1', chainId: '31337',
      genesisHash: (await send('eth_getBlockByNumber', ['0x0', false])).hash,
      escrow: escrowAddress, escrowCodeHash: ethers.keccak256(await send('eth_getCode', [escrowAddress, 'latest'])),
      token: tokenAddress, tokenCodeHash: ethers.keccak256(await send('eth_getCode', [tokenAddress, 'latest'])) },
    work: { payer: lower(payer.address), beneficiary: lower(beneficiary.address), verifier: lower(verifier.address),
      amount: '100', submitBy: start + 600, challengeUntil: start + 700, resolveBy: start + 800, refundAfter: start + 900 },
  };
  lifecycle = transactions({ rpc, provider, escrow, domain: result.domain,
    payer: wallet(payer), beneficiary: wallet(beneficiary), verifier: wallet(verifier) });
  initial = result;
  return result;
}

async function observe(allocation, transactionHash = deposits.get(allocation)) {
  assert.ok(transactionHash, 'unknown locally funded allocation');
  const receipt = await send('eth_getTransactionReceipt', [transactionHash]);
  const first = Number(receipt.blockNumber);
  const head = await send('eth_getBlockByNumber', ['latest', false]);
  assert.ok(Number(head.number) - first <= 127, 'observation exceeds bounded ancestry');
  const ancestry = [];
  for (let number = first; number <= Number(head.number); number++) {
    ancestry.push(block(await send('eth_getBlockByNumber', [ethers.toQuantity(number), false])));
  }
  const escrowAddress = lower(await escrow.getAddress());
  const tokenAddress = lower(await token.getAddress());
  async function read(contract, callData) {
    return { contract, blockNumber: Number(head.number), blockHash: head.hash, callData,
      returnData: await send('eth_call', [{ to: contract, data: callData }, head.number]) };
  }
  const work = await read(escrowAddress, escrow.interface.encodeFunctionData('getWork', [allocation]));
  const balance = await read(tokenAddress, token.interface.encodeFunctionData('balanceOf', [escrowAddress]));
  const escrowCode = await send('eth_getCode', [escrowAddress, head.number]);
  const tokenCode = await send('eth_getCode', [tokenAddress, head.number]);
  // A separate head read after the pinned calls catches a moved/reorganized
  // snapshot. Both readers belong to the same private development chain.
  const independentHead = block(await send('eth_getBlockByNumber', ['latest', false]));
  return { chainId: String(BigInt(await send('eth_chainId', []))),
    genesisHash: (await send('eth_getBlockByNumber', ['0x0', false])).hash,
    escrowCode, tokenCode,
    receipt: { transactionHash: receipt.transactionHash, from: lower(receipt.from), to: lower(receipt.to),
      status: Number(receipt.status), blockNumber: first, blockHash: receipt.blockHash,
      logs: receipt.logs.map(log => ({ address: lower(log.address), topics: log.topics, data: log.data })) },
    ancestry, independentHead, work, balance };
}

async function run(request) {
  assert.ok(request && typeof request === 'object' && !Array.isArray(request));
  assert.ok(['initialize', 'initialize-child', 'retire-parent', 'family-balances', 'fund', 'observe', 'summary', 'pin-verifier', 'prepare', 'transact', 'observe-transaction', 'advance', 'expire'].includes(request.method), 'unsupported fixture operation');
  if (request.method === 'initialize') {
    assert.deepEqual(Object.keys(request), ['method']);
    return initialize();
  }
  assert.ok(escrow && token, 'fixture not initialized');
  if (request.method === 'initialize-child') {
    assert.deepEqual(Object.keys(request), ['method']);
    assert.equal(childLifecycle, undefined, 'child fixture already initialized');
    await (await token.mint(beneficiary.address, 1000)).wait();
    await (await token.connect(beneficiary).approve(await escrow.getAddress(), ethers.MaxUint256)).wait();
    childLifecycle = transactions({ rpc, provider, escrow, domain: initial.domain,
      payer: wallet(beneficiary), beneficiary: wallet(childBeneficiary), verifier: wallet(verifier) });
    return { domain: initial.domain, work: { ...initial.work,
      payer: lower(beneficiary.address), beneficiary: lower(childBeneficiary.address),
      submitBy: initial.work.submitBy - 50, challengeUntil: initial.work.challengeUntil - 50,
      resolveBy: initial.work.resolveBy - 50, refundAfter: initial.work.refundAfter - 50 } };
  }
  if (request.method === 'retire-parent') {
    assert.deepEqual(Object.keys(request), ['method']);
    assert.ok(childLifecycle);
    lifecycle.restrict([]);
    childLifecycle.restrict(['pay']);
    return { parentActionsDisabled: true, verifierSigningDisabled: true };
  }
  if (request.method === 'family-balances') {
    assert.deepEqual(Object.keys(request), ['method']);
    return { buyer: String(await token.balanceOf(payer.address)), intermediary: String(await token.balanceOf(beneficiary.address)),
      child: String(await token.balanceOf(childBeneficiary.address)), escrow: String(await token.balanceOf(await escrow.getAddress())), supply: String(await token.totalSupply()) };
  }
  if (request.method === 'pin-verifier') {
    assert.deepEqual(Object.keys(request).sort(), request.allocation ? ['allocation', 'key', 'method'] : ['key', 'method']);
    const route = request.allocation ? routes.get(request.allocation) : lifecycle;
    assert.ok(route, 'unknown verifier allocation');
    route.pin(request.key); return {};
  }
  if (request.method === 'prepare') {
    assert.deepEqual(Object.keys(request).sort(), ['method', 'request']);
    assert.ok(deposits.has(request.request.allocationId));
    return routes.get(request.request.allocationId).prepare(request.request);
  }
  if (request.method === 'transact' || request.method === 'observe-transaction') {
    assert.deepEqual(Object.keys(request).sort(), ['method', 'prepared']);
    assert.ok(deposits.has(request.prepared.intent.allocationId));
    const route = routes.get(request.prepared.intent.allocationId);
    if (request.method === 'transact') { await route.transact(request.prepared); return {}; }
    await route.validateObservation(request.prepared);
    return observe(request.prepared.intent.allocationId, request.prepared.transactionHash);
  }
  if (request.method === 'advance') {
    assert.deepEqual(Object.keys(request).sort(), ['allocation', 'method', 'phase']);
    assert.ok(deposits.has(request.allocation));
    await routes.get(request.allocation).advance(request.allocation, request.phase); return {};
  }
  if (request.method === 'fund') {
    assert.deepEqual(Object.keys(request).sort(), ['method', 'terms']);
    const terms = request.terms;
    assert.equal(terms.amount, '100');
    const isChild = childLifecycle && terms.payer === lower(beneficiary.address) && terms.beneficiary === lower(childBeneficiary.address);
    assert.equal(terms.payer, lower(isChild ? beneficiary.address : payer.address));
    assert.equal(terms.beneficiary, lower(isChild ? childBeneficiary.address : beneficiary.address));
    assert.equal(terms.verifier, lower(verifier.address));
    assert.equal(terms.token, lower(await token.getAddress()));
    const allocation = await escrow.deriveAllocationId(terms);
    assert.equal(deposits.has(allocation), false, 'duplicate funding request');
    const receipt = await (await escrow.connect(isChild ? beneficiary : payer).fund(terms)).wait();
    deposits.set(allocation, receipt.hash);
    routes.set(allocation, isChild ? childLifecycle : lifecycle);
    await send('evm_mine', []);
    await send('evm_mine', []);
    return { allocationId: allocation, fundingTransaction: receipt.hash };
  }
  assert.deepEqual(Object.keys(request).sort(), ['allocation', 'method']);
  assert.match(request.allocation, /^0x[0-9a-f]{64}$/);
  if (request.method === 'observe') return observe(request.allocation);
  assert.ok(deposits.has(request.allocation));
  if (request.method === 'expire') { await (await escrow.expire(request.allocation)).wait(); return {}; }
  const work = await escrow.getWork(request.allocation);
  const events = { Funded: 0, ClaimSubmitted: 0, DecisionRecorded: 0, Paid: 0, Refunded: 0, TimedOut: 0 };
  for (const log of await send('eth_getLogs', [{ address: lower(await escrow.getAddress()), fromBlock: '0x0', toBlock: 'latest' }])) {
    const parsed = escrow.interface.parseLog(log);
    if (parsed && Object.hasOwn(events, parsed.name) && parsed.args[0] === request.allocation) events[parsed.name]++;
  }
  return { state: states[Number(work.state)], paid: String(work.paid), refunded: String(work.refunded),
    events, transactions: await transactionInventory(send, escrow, request.allocation),
    escrowBalance: String(await token.balanceOf(await escrow.getAddress())),
    payerBalance: String(await token.balanceOf(work.terms.payer)),
    beneficiaryBalance: String(await token.balanceOf(work.terms.beneficiary)),
    fundingTransaction: deposits.get(request.allocation) };
}

try {
  for await (const line of readline.createInterface({ input: process.stdin, crlfDelay: Infinity })) {
    try {
      assert.ok(Buffer.byteLength(line) <= 256 * 1024, 'fixture request too large');
      process.stdout.write(JSON.stringify({ result: await run(JSON.parse(line)) }) + '\n');
    } catch (error) {
      process.stdout.write(JSON.stringify({ error: error.message }) + '\n');
    }
  }
} finally {
  provider.destroy();
  await rpc.disconnect();
}
