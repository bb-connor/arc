// Characterization of existing contracts on a private in-process development chain.
// No RPC URL, deployed address or account key is accepted from the environment.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { ethers } from "ethers";
import ganache from "ganache";
import solc from "solc";

const root = fileURLToPath(new URL("..", import.meta.url));
const sources = {};
function readSources(directory) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) readSources(full);
    else if (entry.name.endsWith(".sol")) {
      sources[path.relative(root, full).replaceAll(path.sep, "/")] = {
        content: fs.readFileSync(full, "utf8"),
      };
    }
  }
}
readSources(path.join(root, "src"));
const compiled = JSON.parse(solc.compile(JSON.stringify({
  language: "Solidity", sources,
  settings: {
    optimizer: { enabled: true, runs: 200 }, evmVersion: "paris",
    outputSelection: { "*": { "*": ["abi", "evm.bytecode.object"] } },
  },
})));
assert.deepEqual((compiled.errors ?? []).filter((e) => e.severity === "error"), []);

const bindingTypes = { ChioOperatorBinding: [
  { name: "operatorAddress", type: "address" },
  { name: "edKeyHash", type: "bytes32" },
  { name: "settlementKey", type: "address" },
] };
const releaseTypes = { ChioEscrowRelease: [
  { name: "escrowId", type: "bytes32" },
  { name: "receiptHash", type: "bytes32" },
  { name: "amount", type: "uint256" },
  { name: "operatorEpoch", type: "uint64" },
] };
const digest = (text) => ethers.keccak256(ethers.toUtf8Bytes(text));

async function reverted(contract, name, operation) {
  await assert.rejects(operation, (error) => {
    const decoded = contract.interface.parseError(error.data);
    assert.equal(decoded?.name, name, `expected ${name}, got ${error.shortMessage}`);
    return true;
  });
}

async function fixture(t) {
  const rpc = ganache.provider({
    logging: { quiet: true },
    chain: { chainId: 31337, hardfork: "shanghai", time: new Date("2026-09-14T00:00:00Z") },
    miner: { timestampIncrement: 0 },
    wallet: { deterministic: true, totalAccounts: 5, defaultBalance: 1000 },
  });
  const provider = new ethers.BrowserProvider(rpc, undefined, { cacheTimeout: -1 });
  t.after(async () => { provider.destroy(); await rpc.disconnect(); });
  const [admin, buyer, seller, operator, outsider] = await Promise.all(
    [0, 1, 2, 3, 4].map((i) => provider.getSigner(i)),
  );
  const accounts = rpc.getInitialAccounts();
  const offline = (signer) => new ethers.Wallet(accounts[signer.address.toLowerCase()].secretKey);
  async function deploy(name, ...args) {
    const stem = name.split("/").at(-1);
    const artifact = compiled.contracts[`src/${name}.sol`][stem];
    const contract = await new ethers.ContractFactory(artifact.abi, artifact.evm.bytecode.object, admin).deploy(...args);
    await contract.waitForDeployment();
    return contract;
  }
  const identity = await deploy("ChioIdentityRegistry", admin.address);
  const registry = await deploy("ChioRootRegistry", await identity.getAddress());
  const escrow = await deploy("ChioEscrow", await registry.getAddress(), await identity.getAddress(), admin.address);
  const token = await deploy("mocks/MockERC20", "Local test units", "TEST", 0);
  const operatorKeyHash = digest("fixture operator Ed25519 identity");
  async function register(keyHash) {
    const proof = await offline(admin).signTypedData({
      name: "ChioIdentityRegistry", version: "1", chainId: 31337,
      verifyingContract: await identity.getAddress(),
    }, bindingTypes, {
      operatorAddress: operator.address, edKeyHash: keyHash, settlementKey: operator.address,
    });
    await (await identity.registerOperator(operator.address, keyHash, operator.address, proof)).wait();
  }
  await register(operatorKeyHash);
  await (await escrow.setTokenAllowed(await token.getAddress(), true)).wait();
  await (await token.mint(buyer.address, 100)).wait();
  await (await token.connect(buyer).approve(await escrow.getAddress(), ethers.MaxUint256)).wait();
  const now = async () => Number((await provider.send("eth_getBlockByNumber", ["latest", false])).timestamp);
  const deadline = (await now()) + 100;
  const terms = {
    capabilityId: digest("work capability 1"), depositor: buyer.address,
    beneficiary: seller.address, token: await token.getAddress(), maxAmount: 100n,
    deadline, operator: operator.address, operatorKeyHash,
  };
  async function create(overrides = {}, depositor = buyer) {
    const selected = { ...terms, ...overrides };
    const id = await escrow.deriveEscrowId(selected);
    await (await escrow.connect(depositor).createEscrow(selected)).wait();
    return id;
  }
  async function certificate(id, label = "checked-result", amount = 100n) {
    const receiptHash = digest(label);
    const { operatorEpoch } = await identity.getOperator(operator.address);
    const signature = ethers.Signature.from(await offline(operator).signTypedData({
      name: "ChioEscrow", version: "1", chainId: 31337,
      verifyingContract: await escrow.getAddress(),
    }, releaseTypes, { escrowId: id, receiptHash, amount, operatorEpoch }));
    return [id, receiptHash, amount, operatorEpoch, signature.v, signature.r, signature.s];
  }
  async function expire() {
    await provider.send("evm_increaseTime", [deadline + 1 - await now()]);
    await provider.send("evm_mine", []);
    assert.equal(await now(), deadline + 1);
  }
  return { provider, admin, buyer, seller, operator, outsider, identity, escrow, token,
    terms, now, deadline, create, certificate, expire, register };
}

test("one real deposit cannot fund a second escrow or change its beneficiary", async (t) => {
  const f = await fixture(t);
  const id = await f.create();
  assert.equal(await f.token.balanceOf(f.buyer.address), 0n);
  const [, deposited, released, refunded] = await f.escrow.getEscrow(id);
  assert.deepEqual([deposited, released, refunded], [100n, 0n, false]);
  await reverted(f.escrow, "EscrowAlreadyExists", () => f.escrow.connect(f.buyer).createEscrow.staticCall(f.terms));
  await reverted(f.escrow, "TransferFailed", () => f.escrow.connect(f.buyer).createEscrow.staticCall({
    ...f.terms, capabilityId: digest("different job"),
  }));
  const cert = await f.certificate(id);
  await reverted(f.escrow, "UnauthorizedCaller", () => f.escrow.connect(f.outsider).releaseWithSignature.staticCall(...cert));
  assert.equal(await f.token.balanceOf(await f.escrow.getAddress()), 100n);
});

test("beneficiary claims a signed release without another buyer action and cannot be paid twice", async (t) => {
  const f = await fixture(t);
  const id = await f.create();
  const cert = await f.certificate(id);
  await (await f.escrow.connect(f.seller).releaseWithSignature(...cert)).wait();
  assert.equal(await f.token.balanceOf(f.seller.address), 100n);
  await reverted(f.escrow, "InvalidReleaseAmount", () => f.escrow.connect(f.seller).releaseWithSignature.staticCall(...cert));
  assert.equal((await f.escrow.getEscrow(id))[2], 100n);
});

test("a pre-expiry operator certificate does not preserve a claim past refund time", async (t) => {
  const f = await fixture(t);
  const id = await f.create();
  const cert = await f.certificate(id);
  const certifiedAt = await f.now();
  assert.ok(certifiedAt < f.deadline);
  // Positive control: this exact certificate is eligible before the deadline.
  await f.escrow.connect(f.seller).releaseWithSignature.staticCall(...cert);
  await f.expire();
  await reverted(f.escrow, "EscrowExpired", () => f.escrow.connect(f.seller).releaseWithSignature.staticCall(...cert));
  // Refund is permissionless, but its fixed recipient is the original depositor.
  await (await f.escrow.connect(f.outsider).refund(id)).wait();
  await reverted(f.escrow, "EscrowAlreadyRefunded", () => f.escrow.connect(f.seller).releaseWithSignature.staticCall(...cert));
  const paid = await f.token.balanceOf(f.seller.address);
  assert.equal(await f.token.balanceOf(f.buyer.address), 100n);
  t.diagnostic(JSON.stringify({ case: "timely-certificate-loses-to-expiry", certifiedAt,
    deadline: f.deadline, refundedAt: await f.now(), paid: String(paid), refunded: "100" }));
  // Deliberate negative calibration of the stronger F1 promise, not a production switch.
  assert.equal(paid, process.env.CHIO_F1_REQUIRE_TIMELY_CLAIM === "1" ? 100n : 0n);
});

test("administrative pause blocks release while an expired refund remains possible", async (t) => {
  const f = await fixture(t);
  const id = await f.create();
  const cert = await f.certificate(id);
  await (await f.escrow.setPaused(true)).wait();
  await reverted(f.escrow, "Paused", () => f.escrow.connect(f.seller).releaseWithSignature.staticCall(...cert));
  await f.expire();
  await (await f.escrow.connect(f.outsider).refund(id)).wait();
  assert.equal(await f.token.balanceOf(f.buyer.address), 100n);
  assert.equal(await f.token.balanceOf(f.seller.address), 0n);
});

test("changing the registered operator key does not migrate an existing escrow pin", async (t) => {
  const f = await fixture(t);
  const id = await f.create();
  const cert = await f.certificate(id);
  await f.escrow.connect(f.seller).releaseWithSignature.staticCall(...cert);
  await (await f.identity.deactivateOperator(f.operator.address)).wait();
  await f.register(digest("replacement operator identity"));
  await reverted(f.escrow, "OperatorKeyHashMismatch", () => f.escrow.connect(f.seller).releaseWithSignature.staticCall(...cert));
  assert.equal((await f.escrow.getEscrow(id))[2], 0n);
});

test("a separately funded child stays paid when its unpaid parent expires", async (t) => {
  const f = await fixture(t);
  const parent = await f.create();
  // B provides its own child backing; its expected revenue from A is untouched.
  await (await f.token.mint(f.seller.address, 60)).wait();
  await (await f.token.connect(f.seller).approve(await f.escrow.getAddress(), 60)).wait();
  const child = await f.create({ capabilityId: digest("child capability"), depositor: f.seller.address,
    beneficiary: f.outsider.address, maxAmount: 60n }, f.seller);
  const cert = await f.certificate(child, "child checked result", 60n);
  await (await f.escrow.connect(f.outsider).releaseWithSignature(...cert)).wait();
  await f.expire();
  await (await f.escrow.refund(parent)).wait();
  assert.equal(await f.token.balanceOf(f.buyer.address), 100n);
  assert.equal(await f.token.balanceOf(f.seller.address), 0n);
  assert.equal(await f.token.balanceOf(f.outsider.address), 60n);
  assert.equal((await f.escrow.getEscrow(parent))[2], 0n);
  assert.equal((await f.escrow.getEscrow(child))[2], 60n);
});
