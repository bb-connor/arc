import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { ethers } from "ethers";
import { fixture, digest, rejected, states } from "./work-claim-fixture.mjs";

test("accepted claim survives deadlines, funding pause and future verifier rotation", async (t) => {
  const f = await fixture(t);
  const id = await f.fund();
  await f.at(2);
  await f.submit(id);
  await f.at(5);
  const decision = await f.sign(id);
  await (await f.escrow.connect(f.X).recordDecision(...decision)).wait();
  assert.equal(states[Number((await f.escrow.getWork(id)).state)], "Payable");
  await (await f.escrow.setPaused(true)).wait();
  await (await f.escrow.setVerifierAllowed(f.V.address, false)).wait();
  await (await f.escrow.setVerifierAllowed(f.V2.address, true)).wait();
  await (await f.escrow.setTokenAllowed(await f.token.getAddress(), false)).wait();
  await f.at(20);
  await rejected(f.escrow, "WrongState", () => f.escrow.withdrawRefund.staticCall(id));
  // Force the actual forbidden transaction through mining as a second control.
  await assert.rejects(async () => (await f.escrow.withdrawRefund(id, { gasLimit: 500000 })).wait());
  await (await f.escrow.connect(f.B).withdrawPayment(id)).wait();
  assert.equal(await f.token.balanceOf(f.A.address), 900n);
  assert.equal(await f.token.balanceOf(f.B.address), 1100n);
  assert.equal(await f.token.balanceOf(await f.escrow.getAddress()), 0n);
  await rejected(f.escrow, "WrongState", () => f.escrow.connect(f.B).withdrawPayment.staticCall(id));
  const replay = await (await f.escrow.recordDecision(...decision)).wait();
  assert.equal(replay.logs.length, 0);
  assert.equal((await f.escrow.getWork(id)).paid, 100n);
});

test("only a timely provider commitment opens the verifier decision window", async (t) => {
  const f = await fixture(t);
  const id = await f.fund();
  await rejected(f.escrow, "UnauthorizedCaller", () => f.escrow.connect(f.A).submitClaim.staticCall(id, digest("output")));
  await rejected(f.escrow, "InvalidCommitment", () => f.escrow.connect(f.B).submitClaim.staticCall(id, ethers.ZeroHash));
  await f.at(2);
  await f.submit(id);
  await rejected(f.escrow, "ConflictingClaim", () => f.escrow.connect(f.B).submitClaim.staticCall(id, digest("other")));
  const decision = await f.sign(id);
  await f.at(4);
  await rejected(f.escrow, "OutsideResolutionWindow", () => f.escrow.recordDecision.staticCall(...decision));
  await f.at(6);
  await (await f.escrow.recordDecision(...decision)).wait();
  await f.at(9);
  await f.submit(id); // Exact acknowledgment does not renew any deadline.
  const changed = await f.sign(id, false);
  await rejected(f.escrow, "ConflictingDecision", () => f.escrow.recordDecision.staticCall(...changed));
});

test("verifier outage and absent submission reach refund only strictly after timeout", async (t) => {
  for (const submitted of [false, true]) await t.test(String(submitted), async (t) => {
    const f = await fixture(t);
    const id = await f.fund();
    if (submitted) await f.submit(id);
    await f.at(7);
    const decision = await f.sign(id);
    await rejected(f.escrow, submitted ? "OutsideResolutionWindow" : "WrongState",
      () => f.escrow.recordDecision.staticCall(...decision));
    if (!submitted) await rejected(f.escrow, "SubmissionExpired", () => f.escrow.connect(f.B).submitClaim.staticCall(id, digest("late")));
    await f.at(8);
    await rejected(f.escrow, "RefundNotDue", () => f.escrow.withdrawRefund.staticCall(id));
    await f.at(9);
    await (await f.escrow.expire(id)).wait();
    assert.equal(states[Number((await f.escrow.getWork(id)).state)], "TimedOut");
    await (await f.escrow.connect(f.X).withdrawRefund(id)).wait();
    assert.equal(await f.token.balanceOf(f.A.address), 1000n);
    assert.equal((await f.escrow.getWork(id)).refunded, 100n);
    await rejected(f.escrow, "WrongState", () => f.escrow.withdrawRefund.staticCall(id));
  });
});

test("rejected work refunds without creating a payment right", async (t) => {
  const f = await fixture(t);
  const id = await f.fund();
  await f.submit(id);
  await f.at(5);
  await (await f.escrow.recordDecision(...await f.sign(id, false))).wait();
  await rejected(f.escrow, "WrongState", () => f.escrow.connect(f.B).withdrawPayment.staticCall(id));
  await (await f.escrow.withdrawRefund(id)).wait();
  assert.equal(await f.token.balanceOf(f.A.address), 1000n);
  const changed = await f.sign(id, true);
  await rejected(f.escrow, "ConflictingDecision", () => f.escrow.recordDecision.staticCall(...changed));
});

test("still-unpaid earned child withdraws after the parent is refunded", async (t) => {
  const f = await fixture(t);
  const parent = await f.fund();
  const child = await f.fund({ agreementDigest: digest("child"), payer: f.B.address,
    beneficiary: f.C.address, amount: 60n }, f.B);
  await f.submit(child, f.C);
  await f.at(5);
  await (await f.escrow.recordDecision(...await f.sign(child))).wait();
  assert.equal(await f.token.balanceOf(f.C.address), 0n);
  await f.at(9);
  await (await f.escrow.withdrawRefund(parent)).wait();
  assert.equal(states[Number((await f.escrow.getWork(child)).state)], "Payable");
  await f.at(30);
  await (await f.escrow.connect(f.C).withdrawPayment(child)).wait();
  assert.equal(await f.token.balanceOf(f.A.address), 1000n);
  assert.equal(await f.token.balanceOf(f.B.address), 940n);
  assert.equal(await f.token.balanceOf(f.C.address), 60n);
  t.diagnostic(JSON.stringify({ case: "unpaid-earned-child-survives-parent-refund",
    parentRefunded: "100", childPaidAfterParentRefund: "60", intermediaryLoss: "60" }));
});

test("funding binds every term and cannot allocate the same agreement twice", async (t) => {
  const f = await fixture(t);
  await rejected(f.escrow, "UnauthorizedCaller", () => f.escrow.connect(f.X).fund.staticCall(f.terms));
  const original = await f.escrow.deriveAllocationId(f.terms);
  for (const change of [
    { agreementDigest: digest("changed") }, { payer: f.X.address }, { beneficiary: f.X.address },
    { verifier: f.V2.address }, { token: f.X.address }, { amount: 101n },
    { submitBy: f.start + 1 }, { challengeUntil: f.start + 3 },
    { resolveBy: f.start + 7 }, { refundAfter: f.start + 9 },
  ]) assert.notEqual(await f.escrow.deriveAllocationId({ ...f.terms, ...change }), original);
  const encoded = ethers.AbiCoder.defaultAbiCoder().encode([
    "uint256", "address", "tuple(bytes32 agreementDigest,address payer,address beneficiary,address verifier,address token,uint256 amount,uint64 submitBy,uint64 challengeUntil,uint64 resolveBy,uint64 refundAfter)",
  ], [31337, await f.escrow.getAddress(), f.terms]);
  assert.equal(original, ethers.keccak256(encoded));
  await f.fund();
  await rejected(f.escrow, "AgreementAlreadyFunded", () => f.escrow.connect(f.A).fund.staticCall({ ...f.terms, amount: 101n }));
  await rejected(f.escrow, "AgreementAlreadyFunded", () => f.escrow.connect(f.A).fund.staticCall(f.terms));
  assert.equal(await f.token.balanceOf(await f.escrow.getAddress()), 100n);
  assert.equal(await f.escrow.allocationForAgreement(f.A.address, f.terms.agreementDigest), original);
});

test("another payer cannot squat a publicly known agreement digest", async (t) => {
  const f = await fixture(t);
  await f.escrow.connect(f.A).fund.staticCall(f.terms);
  await (await f.token.mint(f.X.address, 1)).wait();
  await (await f.token.connect(f.X).approve(await f.escrow.getAddress(), 1)).wait();
  // The attacker knows the digest but cannot authorize funding as A.
  const attacker = await f.fund({ payer: f.X.address, amount: 1n }, f.X);
  const legitimate = await f.fund();
  assert.notEqual(attacker, legitimate);
  assert.equal((await f.escrow.getWork(legitimate)).terms.payer, f.A.address);
  assert.equal((await f.escrow.getWork(legitimate)).terms.amount, 100n);
  assert.equal(await f.token.balanceOf(await f.escrow.getAddress()), 101n);
});

test("fixed allocation and authorization vectors are accepted by the deployed bytecode", async (t) => {
  const f = await fixture(t);
  const vector = JSON.parse(fs.readFileSync(new URL("./fixtures/work-claim-vectors.json", import.meta.url), "utf8"));
  assert.equal((await f.escrow.getAddress()).toLowerCase(), vector.domain.verifyingContract);
  assert.equal(await f.escrow.deriveAllocationId(vector.terms), vector.allocationId);
  const id = await f.fund(vector.terms);
  await f.submit(id);
  await f.at(5);
  const signed = await f.sign(id);
  // Verify the actual fixture signature against a frozen independently encoded digest.
  assert.equal(ethers.recoverAddress(vector.decisionAuthorizationHash, signed[3]).toLowerCase(), vector.terms.verifier);
  await (await f.escrow.recordDecision(...signed)).wait();
  await (await f.escrow.connect(f.B).withdrawPayment(id)).wait();
  assert.equal(await f.token.balanceOf(f.B.address), 1100n);
});

test("invalid amounts, roles, deadlines and administrative callers cannot create backing", async (t) => {
  const f = await fixture(t);
  for (const change of [
    { amount: 0n }, { amount: 2n ** 53n }, { amount: 2n ** 64n - 1n },
    { agreementDigest: ethers.ZeroHash }, { payer: ethers.ZeroAddress },
    { beneficiary: ethers.ZeroAddress }, { beneficiary: f.A.address },
    { beneficiary: await f.escrow.getAddress() }, { verifier: f.A.address },
    { verifier: f.B.address }, { verifier: ethers.ZeroAddress },
    { submitBy: f.start }, { challengeUntil: f.terms.submitBy },
    { resolveBy: f.terms.challengeUntil }, { refundAfter: f.terms.resolveBy },
    { refundAfter: 2n ** 53n },
  ]) await rejected(f.escrow, "InvalidTerms", () => f.escrow.connect(f.A).fund.staticCall({ ...f.terms, ...change }));
  await rejected(f.escrow, "TokenNotAllowed", () => f.escrow.connect(f.A).fund.staticCall({ ...f.terms, token: f.X.address }));
  await rejected(f.escrow, "VerifierNotAllowed", () => f.escrow.connect(f.A).fund.staticCall({ ...f.terms, verifier: f.V2.address }));
  await rejected(f.escrow, "NotAdmin", () => f.escrow.connect(f.X).setPaused.staticCall(true));
  await rejected(f.escrow, "NotAdmin", () => f.escrow.connect(f.X).setVerifierAllowed.staticCall(f.X.address, true));
  await rejected(f.escrow, "NotAdmin", () => f.escrow.connect(f.X).setTokenAllowed.staticCall(f.X.address, true));
  await (await f.escrow.setPaused(true)).wait();
  await rejected(f.escrow, "Paused", () => f.escrow.connect(f.A).fund.staticCall(f.terms));
  assert.equal(await f.token.balanceOf(f.A.address), 1000n);
  assert.equal(await f.token.balanceOf(await f.escrow.getAddress()), 0n);
});

test("maximum supported integer deposits and refunds without rounding", async (t) => {
  const f = await fixture(t);
  const amount = 2n ** 53n - 1n;
  await (await f.token.mint(f.A.address, amount)).wait();
  const id = await f.fund({ amount });
  assert.equal((await f.escrow.getWork(id)).terms.amount, amount);
  assert.equal(await f.token.balanceOf(await f.escrow.getAddress()), amount);
  await f.at(9);
  await (await f.escrow.withdrawRefund(id)).wait();
  assert.equal(await f.token.balanceOf(f.A.address), 1000n + amount);
});

test("a release signature cannot substitute its domain, claim, decision, asset or beneficiary", async (t) => {
  const f = await fixture(t);
  const id = await f.fund();
  await f.submit(id);
  await f.at(5);
  const bad = [
    await f.sign(id, true, "decision", f.V2),
    await f.sign(id, true, "decision", f.V, {}, { chainId: 1 }),
    await f.sign(id, true, "decision", f.V, {}, { verifyingContract: f.X.address }),
    await f.sign(id, true, "decision", f.V, {}, { version: "2" }),
  ];
  for (const changed of [
    { allocationId: ethers.ZeroHash }, { agreementDigest: digest("foreign") },
    { commitment: digest("other") }, { decisionDigest: digest("other") },
    { accepted: false }, { beneficiary: f.X.address }, { token: f.X.address }, { amount: 101n },
  ]) bad.push(await f.sign(id, true, "decision", f.V, changed));
  const good = await f.sign(id);
  const parsed = ethers.Signature.from(good[3]);
  const order = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
  const highS = ethers.concat([parsed.r, ethers.toBeHex(order - BigInt(parsed.s), 32), ethers.toBeHex(parsed.v === 27 ? 28 : 27, 1)]);
  for (const signature of ["0x", "0x1234", highS, "0x" + "00".repeat(65)]) bad.push([...good.slice(0, 3), signature]);
  for (const decision of bad) await rejected(f.escrow, "InvalidSignature", () => f.escrow.recordDecision.staticCall(...decision));
  await rejected(f.escrow, "InvalidDecision", () => f.escrow.recordDecision.staticCall(id, ethers.ZeroHash, true, good[3]));
  assert.equal(states[Number((await f.escrow.getWork(id)).state)], "Submitted");
  await (await f.escrow.recordDecision(...good)).wait();
});

test("future verifier rotation does not replace a funded agreements decision key", async (t) => {
  const f = await fixture(t);
  const id = await f.fund();
  await f.submit(id);
  await (await f.escrow.setVerifierAllowed(f.V.address, false)).wait();
  await (await f.escrow.setVerifierAllowed(f.V2.address, true)).wait();
  await f.at(5);
  const replacement = await f.sign(id, true, "decision", f.V2);
  await rejected(f.escrow, "InvalidSignature", () => f.escrow.recordDecision.staticCall(...replacement));
  await (await f.escrow.recordDecision(...await f.sign(id))).wait();
  assert.equal((await f.escrow.getWork(id)).terms.verifier, f.V.address);
});

test("competing mined withdrawals produce one payment and no refund", async (t) => {
  const f = await fixture(t);
  const id = await f.fund();
  await f.submit(id);
  await f.at(5);
  await (await f.escrow.recordDecision(...await f.sign(id))).wait();
  await f.at(9);
  const nonce = await f.provider.getTransactionCount(f.B.address, "pending");
  await f.provider.send("miner_stop", []);
  const txs = await Promise.all([
    f.escrow.connect(f.B).withdrawPayment(id, { nonce, gasLimit: 500000 }),
    f.escrow.connect(f.B).withdrawPayment(id, { nonce: nonce + 1, gasLimit: 500000 }),
    f.escrow.connect(f.X).withdrawRefund(id, { gasLimit: 500000 }),
  ]);
  await f.provider.send("evm_mine", []);
  await f.provider.send("miner_start", [1]);
  const receipts = await Promise.allSettled(txs.map((tx) => tx.wait()));
  assert.equal(receipts.filter((r) => r.status === "fulfilled").length, 1);
  assert.equal(receipts.filter((r) => r.status === "rejected").length, 2);
  assert.equal(await f.token.balanceOf(f.B.address), 1100n);
  assert.equal(await f.token.balanceOf(f.A.address), 900n);
  assert.equal((await f.escrow.getWork(id)).paid, 100n);
});

test("failed, taxed or malformed token transfers cannot consume a payable claim", async (t) => {
  const f = await fixture(t, { testToken: true });
  const id = await f.fund();
  await f.fund({ agreementDigest: digest("padding"), amount: 10n });
  await f.submit(id);
  await f.at(5);
  await (await f.escrow.recordDecision(...await f.sign(id))).wait();
  for (const mode of [1, 2, 3, 5, 6]) {
    await (await f.token.setMode(mode)).wait();
    await rejected(f.escrow, "TransferFailed", () => f.escrow.connect(f.B).withdrawPayment.staticCall(id));
    await assert.rejects(async () => (await f.escrow.connect(f.B).withdrawPayment(id, { gasLimit: 500000 })).wait());
    assert.equal(states[Number((await f.escrow.getWork(id)).state)], "Payable");
    assert.equal((await f.escrow.getWork(id)).paid, 0n);
    assert.equal(await f.token.balanceOf(await f.escrow.getAddress()), 110n);
  }
  await (await f.token.setMode(7)).wait(); // A standard no-return token remains supported.
  await (await f.escrow.connect(f.B).withdrawPayment(id)).wait();
  assert.equal(await f.token.balanceOf(f.B.address), 1100n);
});

test("inexact deposits and failed refunds roll back allocation and terminal state", async (t) => {
  const f = await fixture(t, { testToken: true });
  for (const mode of [1, 2, 3, 5, 6]) {
    await (await f.token.setMode(mode)).wait();
    await rejected(f.escrow, "TransferFailed", () => f.escrow.connect(f.A).fund.staticCall(f.terms));
    await assert.rejects(async () => (await f.escrow.connect(f.A).fund(f.terms, { gasLimit: 1000000 })).wait());
    assert.equal(await f.escrow.allocationForAgreement(f.A.address, f.terms.agreementDigest), ethers.ZeroHash);
    assert.equal(await f.token.balanceOf(f.A.address), 1000n);
  }
  await (await f.token.setMode(0)).wait();
  const id = await f.fund();
  await f.at(9);
  await (await f.token.setMode(5)).wait();
  await assert.rejects(async () => (await f.escrow.withdrawRefund(id, { gasLimit: 500000 })).wait());
  assert.equal(states[Number((await f.escrow.getWork(id)).state)], "Funded");
  assert.equal(await f.token.balanceOf(f.A.address), 900n);
  await (await f.token.setMode(0)).wait();
  await (await f.escrow.withdrawRefund(id)).wait();
  assert.equal(await f.token.balanceOf(f.A.address), 1000n);
});

test("token callbacks cannot reenter the financial transition", async (t) => {
  const f = await fixture(t, { testToken: true });
  const id = await f.fund();
  await f.submit(id);
  await f.at(5);
  await (await f.escrow.recordDecision(...await f.sign(id))).wait();
  await (await f.token.setCallback(await f.escrow.getAddress(), f.escrow.interface.encodeFunctionData("withdrawPayment", [id]))).wait();
  await (await f.token.setMode(4)).wait();
  await (await f.escrow.connect(f.B).withdrawPayment(id)).wait();
  assert.equal(await f.token.reentryOk(), false);
  assert.equal(await f.token.reentryError(), f.escrow.interface.getError("ReentrantCall").selector);
  assert.equal(await f.token.balanceOf(f.B.address), 1100n);
  assert.equal((await f.escrow.getWork(id)).paid, 100n);
});
