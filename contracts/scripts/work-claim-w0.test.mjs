// Real Rust/Python/SQLite/bytecode integration, with literal monetary expectations.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { runW0 } from './work-claim-w0.mjs';

for (const [scenario, expected] of [
  ['accepted', { A: '900', B: '1100', C: '0', escrow: '0' }],
  ['rejected', { A: '1000', B: '1000', C: '0', escrow: '0' }],
  ['missing-custody', { A: '1000', B: '1000', C: '0', escrow: '0' }],
  ['child', { A: '1000', B: '940', C: '60', escrow: '0' }],
]) {
  test(`real W0 ${scenario} has exact retained authority and balances`, async () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'chio-w0-test-'));
    try {
      const result = await runW0(scenario, directory);
      assert.deepEqual(result.observations.at(-1).balances, expected);
      if (scenario === 'missing-custody') {
        assert.equal(result.certificate, null);
        assert.equal(result.observations.at(-1).work.state, 'Refunded');
        assert.match(result.verifierFailure, /custody missing/);
      } else {
        assert.equal(result.certificate.decision.body.accepted, scenario !== 'rejected');
        assert.equal(result.certificate.decision.body.assurance, 'artifact-only-v1');
        assert.equal(result.observations.at(-1).work.state, scenario === 'rejected' ? 'Refunded' : 'Paid');
      }
      if (scenario === 'child') {
        assert.equal(result.agreement.body.buyerKey, result.parentAgreement.agreement.body.providerKey,
          'the parent provider must be the child buyer');
        assert.notEqual(result.agreement.body.providerKey, result.parentAgreement.agreement.body.providerKey);
        const afterParent = result.observations.find((o) => o.label === 'parent_refunded');
        assert.equal(afterParent.work.state, 'Payable');
        assert.equal(afterParent.balances.C, '0');
        assert.equal(afterParent.parent.refunded, '100');
      }
      assert.equal(result.accounting.escrowFunded, scenario === 'child' ? '160' : '100');
      assert.equal(result.accounting.remaining, '0');
      assert.ok(result.providerCheckerMs > 0);
      assert.ok(result.receipts.length >= 3);
      if (process.env.CHIO_W0_EVIDENCE) {
        fs.mkdirSync(process.env.CHIO_W0_EVIDENCE, { recursive: true });
        fs.writeFileSync(path.join(process.env.CHIO_W0_EVIDENCE, scenario + '.json'), JSON.stringify(result, null, 2) + '\n');
      }
    } finally {
      fs.rmSync(directory, { recursive: true, force: true });
    }
  });
}
