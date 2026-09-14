// Real W0 artifacts on a private chain. No native admission or public finality.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { performance } from 'node:perf_hooks';
import { ethers } from 'ethers';
import { fixture, states, mutation } from './work-claim-fixture.mjs';

const root = fileURLToPath(new URL('../..', import.meta.url));
const python = process.env.CHIO_W0_PYTHON ?? 'python3';
const binary = process.env.CHIO_W0_BINARY ?? path.join(root, 'target/debug/chio-federated-work');
const fixtureScript = path.join(root, 'examples/funded-work/fixture.py');
const stringify = (value) => JSON.stringify(value, (_, v) => typeof v === 'bigint' ? String(v) : v, 2);

export async function runW0(scenario, directory) {
  assert.equal(mutation, '', 'W0 requires the unmodified claim contract');
  assert.ok(['accepted', 'rejected', 'missing-custody', 'child'].includes(scenario));
  const state = path.resolve(directory);
  assert.equal(fs.statSync(state).mode & 0o777, 0o700, 'state must be mode 0700');
  const source = path.join(root, 'examples/federated-work/fixtures/openapi.json');
  const cleanups = [];
  const receipts = [];
  let serial = 0;
  function command(command, request, allowFailure = false) {
    const args = ['-B', fixtureScript, command, state];
    if (request) {
      const requestPath = path.join(state, `${++serial}-${command}.json`);
      fs.writeFileSync(requestPath, stringify(request), { flag: 'wx', mode: 0o600 });
      args.push(requestPath);
    }
    const result = spawnSync(python, args, { encoding: 'utf8', maxBuffer: 512 * 1024, timeout: 30000 });
    if (allowFailure) return result;
    assert.equal(result.status, 0, `${command}: ${result.stderr || result.error}`);
    return JSON.parse(result.stdout);
  }
  command('init');
  try {
    const f = await fixture({ after: (fn) => cleanups.push(fn) });
    const escrowAddress = await f.escrow.getAddress();
    const codeHash = ethers.keccak256(await f.provider.getCode(escrowAddress));
    const rail = { chainId: '31337', escrow: escrowAddress.toLowerCase(), runtimeKeccak256: codeHash,
      token: (await f.token.getAddress()).toLowerCase(), payer: f.A.address.toLowerCase(),
      beneficiary: f.B.address.toLowerCase(), verifier: f.V.address.toLowerCase(), amount: '100' };
    const deadlines = Object.fromEntries(['submitBy', 'challengeUntil', 'resolveBy', 'refundAfter'].map((key) => [key, f.terms[key]]));
    const record = async (label, pending) => {
      const receipt = await (await pending).wait();
      assert.equal(receipt.status, 1);
      receipts.push({ label, receipt: receipt.toJSON() });
    };
    const prepare = (workId, selectedRail, parent = null) => command('prepare', {
      workId, rail: selectedRail, deadlines, parentAgreementSha256: parent, inputPath: source,
      parties: parent ? { buyer: 'B', provider: 'C' } : { buyer: 'A', provider: 'B' } });
    async function fund(prepared, actor) {
      const { agreement, agreementDigest } = prepared;
      const rail = agreement.body.rail;
      const terms = { agreementDigest, payer: rail.payer, beneficiary: rail.beneficiary,
        verifier: rail.verifier, token: rail.token, amount: BigInt(rail.amount), ...agreement.body.deadlines };
      const id = await f.escrow.deriveAllocationId(terms);
      await record('fund_' + agreement.body.workId, f.escrow.connect(actor).fund(terms));
      return id;
    }
    let parent = null;
    let parentAgreement = null;
    if (scenario === 'child') {
      parentAgreement = prepare('unsubmitted-parent', rail);
      parent = await fund(parentAgreement, f.A);
    }
    const selectedRail = scenario === 'child' ? { ...rail, payer: f.B.address.toLowerCase(),
      beneficiary: f.C.address.toLowerCase(), amount: '60' } : rail;
    const prepared = prepare(scenario + '-w0', selectedRail, parentAgreement?.agreementDigest.slice(2) ?? null);
    const allocation = await fund(prepared, scenario === 'child' ? f.B : f.A);
    const seller = scenario === 'child' ? f.C : f.B;
    async function inspect(id) {
      const work = await f.escrow.getWork(id);
      return { allocationId: id, agreementDigest: work.terms.agreementDigest,
        state: states[Number(work.state)], commitment: work.commitment, decisionDigest: work.decisionDigest,
        accepted: work.accepted, paid: String(work.paid), refunded: String(work.refunded), amount: String(work.terms.amount) };
    }
    async function observe(label) {
      const balances = {};
      for (const [name, address] of Object.entries({ A: f.A.address, B: f.B.address, C: f.C.address, escrow: escrowAddress })) {
        balances[name] = String(await f.token.balanceOf(address));
      }
      return { label, chainTime: await f.now(), work: await inspect(allocation),
        parent: parent ? await inspect(parent) : null, balances };
    }
    const observations = [await observe('funded')];
    const checkerStarted = performance.now();
    const checked = spawnSync(binary, ['check-openapi', source], { encoding: 'utf8', maxBuffer: 128 * 1024, timeout: 30000 });
    const providerCheckerMs = performance.now() - checkerStarted;
    assert.equal(checked.status, 0, checked.stderr || checked.error);
    const output = { schema: 'chio.experimental.funded-w0-output.v1', operations: JSON.parse(checked.stdout) };
    if (scenario === 'rejected') output.operations[0].authenticationRequired = !output.operations[0].authenticationRequired;
    const submitted = command('submit', { agreement: prepared.agreement, allocationId: allocation, inputPath: source, output });
    await f.at(2);
    await record('submit_exact_artifact', f.escrow.connect(seller).submitClaim(allocation, submitted.commitment));
    observations.push(await observe('submitted'));
    await f.at(5);
    const work = await f.escrow.getWork(allocation);
    const observed = { allocationId: allocation, agreementDigest: work.terms.agreementDigest,
      commitment: work.commitment, state: states[Number(work.state)], chainTime: await f.now(),
      rail: { chainId: String((await f.provider.getNetwork()).chainId), escrow: escrowAddress.toLowerCase(),
        runtimeKeccak256: ethers.keccak256(await f.provider.getCode(escrowAddress)), token: work.terms.token.toLowerCase(),
        payer: work.terms.payer.toLowerCase(), beneficiary: work.terms.beneficiary.toLowerCase(),
        verifier: work.terms.verifier.toLowerCase(), amount: String(work.terms.amount) },
      deadlines: Object.fromEntries(Object.keys(deadlines).map((key) => [key, Number(work.terms[key])])) };
    const verificationRequest = { agreement: prepared.agreement, submission: submitted.submission, observed };
    let certificate = null;
    let evmCertificate = null;
    let verifierFailure = null;
    if (scenario === 'missing-custody') {
      const db = path.join(state, 'custody.sqlite');
      fs.renameSync(db, db + '.offline');
      try {
        const failure = command('authorize', verificationRequest, true);
        assert.equal(failure.status, 1);
        assert.equal(failure.stdout, '');
        verifierFailure = failure.stderr.trim();
      } finally { fs.renameSync(db + '.offline', db); }
      await f.at(9);
      await record('uncertified_timeout_refund', f.escrow.connect(f.X).withdrawRefund(allocation));
    } else {
      certificate = command('authorize', verificationRequest);
      // Same state reopened in a second verifier process must retain the exact decision.
      const retry = command('authorize', verificationRequest);
      assert.deepEqual(retry.decision, certificate.decision);
      assert.deepEqual(retry.authorization, certificate.authorization);
      evmCertificate = await f.authorizeChecked(certificate.authorization);
      await record('record_checked_decision', f.escrow.connect(f.X).recordDecision(...evmCertificate));
      observations.push(await observe('decided_unwithdrawn'));
      if (scenario === 'rejected') {
        await record('rejected_refund', f.escrow.connect(f.X).withdrawRefund(allocation));
      } else {
        if (parent) {
          await f.at(9);
          await record('unsubmitted_parent_refund', f.escrow.connect(f.X).withdrawRefund(parent));
          observations.push(await observe('parent_refunded'));
        }
        await f.at(30);
        await record('earned_payment_after_deadlines', f.escrow.connect(seller).withdrawPayment(allocation));
      }
    }
    observations.push(await observe('financial_terminal'));
    const logs = await f.provider.getLogs({ address: await f.token.getAddress(), fromBlock: 0 });
    let funded = 0n;
    let withdrawn = 0n;
    const deltas = new Map();
    for (const log of logs) {
      const event = f.token.interface.parseLog(log);
      if (event?.name !== 'Transfer') continue;
      const { from, to, value } = event.args;
      if (to === escrowAddress) funded += value;
      if (from === escrowAddress) withdrawn += value;
      deltas.set(from, (deltas.get(from) ?? 0n) - value);
      deltas.set(to, (deltas.get(to) ?? 0n) + value);
    }
    for (const address of [f.A.address, f.B.address, f.C.address, escrowAddress]) {
      assert.equal(deltas.get(address) ?? 0n, await f.token.balanceOf(address), 'token events do not reconstruct balance');
    }
    assert.equal(funded - withdrawn, await f.token.balanceOf(escrowAddress));
    const terminal = observations.at(-1);
    const recordedPaid = BigInt(terminal.work.paid) + BigInt(terminal.parent?.paid ?? '0');
    const recordedRefunded = BigInt(terminal.work.refunded) + BigInt(terminal.parent?.refunded ?? '0');
    assert.equal(recordedPaid + recordedRefunded, withdrawn);
    return JSON.parse(stringify({ schema: 'chio.experimental.funded-w0-run.v1', scenario,
      scope: 'One host, actual Rust/Python W0 predicate, local SQLite custody, private chain and mock tokens.',
      pins: prepared.pins, agreement: prepared.agreement, agreementDigest: prepared.agreementDigest, parentAgreement,
      input: fs.readFileSync(source, 'utf8'), output, submission: submitted.submission,
      observationForVerifier: observed, certificate, evmCertificate, verifierFailure,
      providerCheckerMs, observations, receipts, runtimeCodeKeccak256: codeHash,
      accounting: { escrowFunded: funded, paid: recordedPaid, refunded: recordedRefunded, remaining: funded - withdrawn },
      escrowEvents: (await f.provider.getLogs({ address: escrowAddress, fromBlock: 0 })).map((log) => log.toJSON()),
      tokenEvents: logs.map((log) => log.toJSON()),
      limitations: ['No native funding admission, Finding assurance or crash recovery.',
        'Private-chain observations are not a public-chain finality proof.',
        'All keys and custody share one administrative host; no remote or independent custody claim.',
        'No challenge court, fee/bond backing, sustained retention or deployed API security claim.',
        'The child case leaves the parent unsubmitted; it does not kill a native parent process.',
        'Gas and checker time are functional costs, not evidence of economic advantage.'] }));
  } finally {
    for (const cleanup of cleanups.reverse()) await cleanup();
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  assert.equal(process.argv.length, 6, 'usage: work-claim-w0.mjs SCENARIO STATE --output FILE');
  assert.equal(process.argv[4], '--output');
  const result = await runW0(process.argv[2], process.argv[3]);
  fs.writeFileSync(process.argv[5], stringify(result) + '\n', { flag: 'wx' });
  console.log(stringify({ scenario: result.scenario, output: process.argv[5], accounting: result.accounting }));
}
