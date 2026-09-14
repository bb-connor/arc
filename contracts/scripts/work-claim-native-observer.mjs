// Receiver-owned private-chain fixture. No external RPC, keys or arbitrary calls.
import assert from 'node:assert/strict';
import readline from 'node:readline';
import { ethers } from 'ethers';
import ganache from 'ganache';
import { artifacts, states } from './work-claim-fixture.mjs';

const rpc = ganache.provider({ logging: { quiet: true },
  chain: { chainId: 31337, hardfork: 'shanghai', time: new Date() },
  wallet: { deterministic: true, totalAccounts: 4, defaultBalance: 1000 } });
const provider = new ethers.BrowserProvider(rpc, undefined, { cacheTimeout: -1 });
const [admin, payer, beneficiary, verifier] = await Promise.all([0, 1, 2, 3].map(i => provider.getSigner(i)));
const send = (method, params) => rpc.request({ method, params });
const lower = value => value.toLowerCase();
const deposits = new Map();
let escrow;
let token;

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
  return {
    domain: { profile: 'chio.experimental.local-confirmed-funding.v1', chainId: '31337',
      genesisHash: (await send('eth_getBlockByNumber', ['0x0', false])).hash,
      escrow: escrowAddress, escrowCodeHash: ethers.keccak256(await send('eth_getCode', [escrowAddress, 'latest'])),
      token: tokenAddress, tokenCodeHash: ethers.keccak256(await send('eth_getCode', [tokenAddress, 'latest'])) },
    work: { payer: lower(payer.address), beneficiary: lower(beneficiary.address), verifier: lower(verifier.address),
      amount: '100', submitBy: start + 600, challengeUntil: start + 700, resolveBy: start + 800, refundAfter: start + 900 },
  };
}

async function observe(allocation) {
  const transactionHash = deposits.get(allocation);
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
  assert.ok(['initialize', 'fund', 'observe', 'summary'].includes(request.method), 'unsupported fixture operation');
  if (request.method === 'initialize') {
    assert.deepEqual(Object.keys(request), ['method']);
    return initialize();
  }
  assert.ok(escrow && token, 'fixture not initialized');
  if (request.method === 'fund') {
    assert.deepEqual(Object.keys(request).sort(), ['method', 'terms']);
    const terms = request.terms;
    assert.equal(terms.amount, '100');
    assert.equal(terms.payer, lower(payer.address));
    assert.equal(terms.beneficiary, lower(beneficiary.address));
    assert.equal(terms.verifier, lower(verifier.address));
    assert.equal(terms.token, lower(await token.getAddress()));
    const allocation = await escrow.deriveAllocationId(terms);
    assert.equal(deposits.has(allocation), false, 'duplicate funding request');
    const receipt = await (await escrow.connect(payer).fund(terms)).wait();
    deposits.set(allocation, receipt.hash);
    await send('evm_mine', []);
    await send('evm_mine', []);
    return { allocationId: allocation, fundingTransaction: receipt.hash };
  }
  assert.deepEqual(Object.keys(request).sort(), ['allocation', 'method']);
  assert.match(request.allocation, /^0x[0-9a-f]{64}$/);
  if (request.method === 'observe') return observe(request.allocation);
  assert.ok(deposits.has(request.allocation));
  const work = await escrow.getWork(request.allocation);
  return { state: states[Number(work.state)], paid: String(work.paid), refunded: String(work.refunded),
    escrowBalance: String(await token.balanceOf(await escrow.getAddress())),
    payerBalance: String(await token.balanceOf(payer.address)),
    beneficiaryBalance: String(await token.balanceOf(beneficiary.address)),
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
