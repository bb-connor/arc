// Private development-chain utilities. Never accepts an external RPC or key.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ethers } from "ethers";
import ganache from "ganache";
import solc from "solc";

const root = fileURLToPath(new URL("..", import.meta.url));
const sources = {};
function read(directory) {
  if (!fs.existsSync(directory)) return;
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) read(full);
    else if (entry.name.endsWith(".sol")) sources[path.relative(root, full)] = { content: fs.readFileSync(full, "utf8") };
  }
}
read(path.join(root, "src"));
read(path.join(root, "scripts/fixtures"));
export const mutation = process.env.CHIO_CLAIM_MUTATION ?? "";
if (mutation) {
  assert.equal(mutation, "expire-payable", "unknown negative calibration");
  const source = sources["src/experimental/ChioWorkClaimEscrow.sol"];
  const before = "if (work.state != State.Funded && work.state != State.Submitted) revert WrongState();";
  assert.equal(source.content.split(before).length, 2, "mutation must select exactly the expiry guard");
  source.content = source.content.replace(before,
    "if (work.state != State.Funded && work.state != State.Submitted && work.state != State.Payable) revert WrongState();");
}
const compiled = JSON.parse(solc.compile(JSON.stringify({
  language: "Solidity", sources,
  settings: { optimizer: { enabled: true, runs: 200 }, evmVersion: "paris",
    outputSelection: { "*": { "*": ["abi", "evm.bytecode.object", "evm.deployedBytecode.object"] } } },
})));
assert.deepEqual((compiled.errors ?? []).filter((e) => e.severity === "error"), []);
export const artifacts = compiled.contracts;
export const digest = (value) => ethers.keccak256(ethers.toUtf8Bytes(value));
export const decisionTypes = { ChioWorkDecision: [
  { name: "allocationId", type: "bytes32" },
  { name: "agreementDigest", type: "bytes32" },
  { name: "commitment", type: "bytes32" },
  { name: "decisionDigest", type: "bytes32" },
  { name: "accepted", type: "bool" },
  { name: "beneficiary", type: "address" },
  { name: "token", type: "address" },
  { name: "amount", type: "uint256" },
] };
export const states = ["Missing", "Funded", "Submitted", "Payable", "Paid", "Rejected", "TimedOut", "Refunded"];

export async function rejected(contract, expected, fn) {
  await assert.rejects(fn, (error) => {
    assert.equal(contract.interface.parseError(error.data)?.name, expected, error.shortMessage);
    return true;
  });
}

export async function fixture(t, { testToken = false } = {}) {
  const artifact = artifacts["src/experimental/ChioWorkClaimEscrow.sol"]?.ChioWorkClaimEscrow;
  assert.ok(artifact?.evm.bytecode.object, "experimental work claim escrow is not implemented");
  const rpc = ganache.provider({ logging: { quiet: true },
    chain: { chainId: 31337, hardfork: "shanghai", time: new Date("2026-09-14T00:00:00Z") },
    miner: { timestampIncrement: 0 }, wallet: { deterministic: true, totalAccounts: 7, defaultBalance: 1000 } });
  const provider = new ethers.BrowserProvider(rpc, undefined, { cacheTimeout: -1 });
  t.after(async () => { provider.destroy(); await rpc.disconnect(); });
  const [admin, A, B, V, C, X, V2] = await Promise.all([0, 1, 2, 3, 4, 5, 6].map((i) => provider.getSigner(i)));
  const actors = { admin, A, B, V, C, X, V2 };
  const accounts = rpc.getInitialAccounts();
  const wallet = (signer) => new ethers.Wallet(accounts[signer.address.toLowerCase()].secretKey);
  async function deploy(source, name, ...args) {
    const artifact = artifacts[source][name];
    const value = await new ethers.ContractFactory(artifact.abi, artifact.evm.bytecode.object, admin).deploy(...args);
    await value.waitForDeployment();
    return value;
  }
  const escrow = await deploy("src/experimental/ChioWorkClaimEscrow.sol", "ChioWorkClaimEscrow", admin.address);
  const token = testToken
    ? await deploy("scripts/fixtures/WorkClaimTestToken.sol", "WorkClaimTestToken")
    : await deploy("src/mocks/MockERC20.sol", "MockERC20", "Claim test units", "TEST", 0);
  await (await escrow.setTokenAllowed(await token.getAddress(), true)).wait();
  await (await escrow.setVerifierAllowed(V.address, true)).wait();
  for (const who of [A, B]) {
    await (await token.mint(who.address, 1000)).wait();
    await (await token.connect(who).approve(await escrow.getAddress(), ethers.MaxUint256)).wait();
  }
  const now = async () => Number((await provider.send("eth_getBlockByNumber", ["latest", false])).timestamp);
  const start = await now();
  const terms = { agreementDigest: digest("agreement"), payer: A.address, beneficiary: B.address,
    verifier: V.address, token: await token.getAddress(), amount: 100n,
    submitBy: start + 2, challengeUntil: start + 4, resolveBy: start + 6, refundAfter: start + 8 };
  async function at(relative) {
    const desired = start + relative;
    assert.ok(desired >= await now(), "test clock cannot move backwards");
    await provider.send("evm_increaseTime", [desired - await now()]);
    await provider.send("evm_mine", []);
    assert.equal(await now(), desired);
  }
  async function fund(overrides = {}, payer = A) {
    const selected = { ...terms, ...overrides };
    const id = await escrow.deriveAllocationId(selected);
    await (await escrow.connect(payer).fund(selected)).wait();
    return id;
  }
  async function sign(id, accepted = true, label = "decision", signer = V, overrides = {}, domain = {}) {
    const work = await escrow.getWork(id);
    const decisionDigest = digest(label);
    const body = { allocationId: id, agreementDigest: work.terms.agreementDigest,
      commitment: work.commitment, decisionDigest, accepted, beneficiary: work.terms.beneficiary,
      token: work.terms.token, amount: work.terms.amount, ...overrides };
    const signature = await wallet(signer).signTypedData({ name: "ChioWorkClaimEscrow", version: "1",
      chainId: 31337, verifyingContract: await escrow.getAddress(), ...domain }, decisionTypes, body);
    return [id, decisionDigest, accepted, signature];
  }
  async function submit(id, providerActor = B, commitment = "output") {
    await (await escrow.connect(providerActor).submitClaim(id, digest(commitment))).wait();
  }
  async function authorizeChecked(body) {
    assert.deepEqual(Object.keys(body).sort(), decisionTypes.ChioWorkDecision.map((v) => v.name).sort());
    assert.match(body.decisionDigest, /^0x[0-9a-f]{64}$/);
    assert.equal(typeof body.accepted, "boolean");
    const work = await escrow.getWork(body.allocationId);
    assert.equal(work.state, 2n, "checked authorization requires a submitted claim");
    for (const field of ["agreementDigest", "commitment", "beneficiary", "token", "amount"]) {
      const expected = field === "commitment" ? work.commitment : work.terms[field];
      assert.equal(String(body[field]).toLowerCase(), String(expected).toLowerCase(), `changed ${field}`);
    }
    assert.equal(work.terms.verifier, V.address);
    const signature = await wallet(V).signTypedData({ name: "ChioWorkClaimEscrow", version: "1",
      chainId: 31337, verifyingContract: await escrow.getAddress() }, decisionTypes, body);
    return [body.allocationId, body.decisionDigest, body.accepted, signature];
  }
  async function signRawCall(actor, data, overrides = {}) {
    return wallet(actor).signTransaction({ type: 2, chainId: 31337, to: await escrow.getAddress(),
      data, value: 0, nonce: await provider.getTransactionCount(actor.address, 'pending'),
      gasLimit: 1000000, maxFeePerGas: 2000000000, maxPriorityFeePerGas: 1000000000, ...overrides });
  }
  return { ...actors, actors, rpc, provider, escrow, token, terms, start, now, at, fund, sign, submit, deploy, authorizeChecked, signRawCall };
}
