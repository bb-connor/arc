// Replay bounded model transitions against independently compiled contract bytecode.
import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { ethers } from "ethers";
import { fixture, digest, states } from "./work-claim-fixture.mjs";

const corpus = JSON.parse(fs.readFileSync(new URL("../../examples/funded-work-model/claim-traces.json", import.meta.url), "utf8"));

test("model edge representatives agree with actual claim states and token balances", async (t) => {
  assert.equal(corpus.counterexample, null);
  const f = await fixture(t);
  const parent = await f.fund({ amount: 3n });
  const child = await f.fund({ agreementDigest: digest("child"), payer: f.B.address,
    beneficiary: f.C.address, amount: 2n }, f.B);
  const ids = { parent, child };
  let checkpoint = await f.provider.send("evm_snapshot", []);
  for (const [index, trace] of corpus.traces.entries()) {
    await t.test(`${index}: ${trace.op} ${trace.before} -> ${trace.after} (${trace.ok})`, async () => {
      for (const step of trace.steps) {
        if (step.op === "advance") { await f.at(step.time); continue; }
        const id = ids[step.job];
        const actor = f.actors[step.actor] ?? f.X;
        let method, args;
        switch (step.op) {
          case "submit": method = f.escrow.connect(actor).submitClaim; args = [id, digest(step.commitment)]; break;
          case "decide": method = f.escrow.connect(f.X).recordDecision; args = await f.sign(id, step.accepted, step.decision, actor); break;
          case "pay": method = f.escrow.connect(actor).withdrawPayment; args = [id]; break;
          case "refund": method = f.escrow.connect(f.X).withdrawRefund; args = [id]; break;
          case "expire": method = f.escrow.expire; args = [id]; break;
          case "unknown": break; // Journal-only metadata is deliberately outside the rail.
          default: assert.fail(`unknown model action: ${step.op}`);
        }
        if (method) {
          if (step.ok) await (await method(...args)).wait();
          else await assert.rejects(() => method.staticCall(...args));
        }
        for (const [name, expected] of Object.entries(step.expected)) {
          const actual = await f.escrow.getWork(ids[name]);
          assert.equal(states[Number(actual.state)], expected.state, name);
          assert.equal(actual.commitment, expected.commitment ? digest(expected.commitment) : ethers.ZeroHash);
          assert.equal(actual.decisionDigest, expected.decision ? digest(expected.decision) : ethers.ZeroHash);
          assert.equal(actual.accepted, expected.accepted);
          assert.equal(actual.paid, BigInt(expected.paid));
          assert.equal(actual.refunded, BigInt(expected.refunded));
        }
        const a = step.expected.parent, b = step.expected.child;
        assert.equal(await f.token.balanceOf(f.A.address), 997n + BigInt(a.refunded));
        assert.equal(await f.token.balanceOf(f.B.address), 998n + BigInt(a.paid + b.refunded));
        assert.equal(await f.token.balanceOf(f.C.address), BigInt(b.paid));
        assert.equal(await f.token.balanceOf(await f.escrow.getAddress()), BigInt(a.locked + b.locked));
      }
    });
    assert.equal(await f.provider.send("evm_revert", [checkpoint]), true);
    checkpoint = await f.provider.send("evm_snapshot", []);
  }
  t.diagnostic(JSON.stringify({ modelStates: corpus.states, modelTransitions: corpus.transitions,
    bytecodeTraceRepresentatives: corpus.traces.length }));
});
