// Reproducible financial scenario using only a fresh private development chain.
// Certifications are synthetic. This does not execute W0 work or a native kernel.
import assert from "node:assert/strict";
import fs from "node:fs";
import { ethers } from "ethers";
import { fixture, digest, states, artifacts, mutation } from "./work-claim-fixture.mjs";

assert.equal(mutation, "", "the demonstration must use the unmodified contract");
assert.equal(process.argv.length, 4, "usage: node work-claim-demo.mjs --output FILE");
assert.equal(process.argv[2], "--output");
const cleanups = [];
const receipts = [];
try {
  const f = await fixture({ after: (fn) => cleanups.push(fn) });
  const record = async (label, pending) => {
    const receipt = await (await pending).wait();
    receipts.push({ label, receipt: receipt.toJSON() });
  };
  const parent = await f.fund();
  const child = await f.fund({ agreementDigest: digest("child"), payer: f.B.address,
    beneficiary: f.C.address, amount: 60n }, f.B);
  const observe = async (label) => {
    const obligations = {};
    for (const [name, id] of Object.entries({ parent, child })) {
      const work = await f.escrow.getWork(id);
      obligations[name] = { allocationId: id, state: states[Number(work.state)],
        agreementDigest: work.terms.agreementDigest, payer: work.terms.payer,
        beneficiary: work.terms.beneficiary, verifier: work.terms.verifier,
        token: work.terms.token, amount: work.terms.amount,
        submitBy: work.terms.submitBy, challengeUntil: work.terms.challengeUntil,
        resolveBy: work.terms.resolveBy, refundAfter: work.terms.refundAfter,
        commitment: work.commitment, decisionDigest: work.decisionDigest,
        accepted: work.accepted, paid: work.paid, refunded: work.refunded };
    }
    const balances = {};
    for (const [name, address] of Object.entries({ A: f.A.address, B: f.B.address,
      C: f.C.address, escrow: await f.escrow.getAddress() })) balances[name] = await f.token.balanceOf(address);
    return { label, chainTime: await f.now(), obligations, balances };
  };
  const observations = [await observe("funded_parent_and_child")];
  await f.at(2);
  await record("child_submitted", f.escrow.connect(f.C).submitClaim(child, digest("child-output")));
  await f.at(5);
  const certificate = await f.sign(child);
  await record("child_accepted", f.escrow.connect(f.X).recordDecision(...certificate));
  observations.push(await observe("child_earned_but_unpaid"));
  assert.equal(observations.at(-1).obligations.child.state, "Payable");
  assert.equal(observations.at(-1).balances.C, 0n);
  await f.at(9);
  await record("unsubmitted_parent_refunded", f.escrow.connect(f.X).withdrawRefund(parent));
  observations.push(await observe("parent_refunded_child_still_payable"));
  assert.equal(observations.at(-1).obligations.parent.refunded, 100n);
  assert.equal(observations.at(-1).obligations.child.state, "Payable");
  await f.at(30);
  await record("child_withdrawn_after_parent_refund", f.escrow.connect(f.C).withdrawPayment(child));
  observations.push(await observe("child_paid_after_all_deadlines"));
  const final = observations.at(-1);
  assert.deepEqual(final.balances, { A: 1000n, B: 940n, C: 60n, escrow: 0n });
  assert.equal(final.obligations.parent.paid, 0n);
  assert.equal(final.obligations.child.refunded, 0n);
  const runtime = await f.provider.getCode(await f.escrow.getAddress());
  const artifact = artifacts["src/experimental/ChioWorkClaimEscrow.sol"].ChioWorkClaimEscrow;
  const result = { schema: "chio.experimental.work-claim-demo.v1", chainId: 31337,
    scope: "One administrator, synthetic certificates, mock tokens, no work checker or process-failure claim.",
    initialBalances: { A: "1000", B: "1000", C: "0" },
    escrow: await f.escrow.getAddress(), runtimeCodeKeccak256: ethers.keccak256(runtime),
    runtimeCodeBytes: (runtime.length - 2) / 2,
    creationCodeKeccak256: ethers.keccak256("0x" + artifact.evm.bytecode.object),
    certificate, observations, receipts,
    escrowEvents: (await f.provider.getLogs({ address: await f.escrow.getAddress(), fromBlock: 0 })).map((log) => log.toJSON()),
    tokenEvents: (await f.provider.getLogs({ address: await f.token.getAddress(), fromBlock: 0 })).map((log) => log.toJSON()),
    limitations: ["Local development-chain reads, not a public chain finality proof.",
      "Custody and predicate correctness are trusted synthetic inputs in this financial-only scenario.",
      "The parent submits no work; no native parent process was killed.",
      "Gas usage is retained in receipts; mock-token transfer amounts are not economic profit."] };
  fs.writeFileSync(process.argv[3], JSON.stringify(result, (_, value) => typeof value === "bigint" ? String(value) : value, 2) + "\n");
  console.log(JSON.stringify({ output: process.argv[3], parentRefund: "100", childPaid: "60",
    intermediaryLoss: "60", runtimeCodeKeccak256: result.runtimeCodeKeccak256 }));
} finally {
  for (const cleanup of cleanups.reverse()) await cleanup();
}
