import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { canonical, transactions } from './work-claim-native-transactions.mjs';

test('native signer canonical bytes agree with all four Rust artifact vectors', () => {
  for (const family of ['agreement', 'submission', 'dependency', 'decision']) {
    const raw = readFileSync(new URL(`../../examples/federated-work/fixtures/registered-work/${family}.json`, import.meta.url), 'utf8');
    assert.equal(canonical(JSON.parse(raw)), raw, family);
  }
});

test('one settlement signer retains distinct immutable verifier pins per allocation', () => {
  // This boundary precedes any RPC or signing; the integrated native run
  // additionally exercises the pins against actual decisions and bytecode.
  const signer = transactions({ domain: {} });
  const a = '0x' + 'a'.repeat(64);
  const b = '0x' + 'b'.repeat(64);
  const first = '1'.repeat(64);
  const second = '2'.repeat(64);
  signer.pin(first, a);
  signer.pin(second, b);
  signer.pin(first, a);
  assert.throws(() => signer.pin(second, a), /immutable/);
  assert.throws(() => signer.pin(first, b), /immutable/);
  assert.throws(() => signer.pin(first), /immutable/);
  assert.throws(() => signer.pin(second, 'unbound-allocation'));
  const legacy = transactions({ domain: {} });
  legacy.pin(first);
  legacy.pin(first, a);
  assert.throws(() => legacy.pin(second, b), /immutable/);
});

test('native signer preserves facet order and rejects unsupported scalar encodings', () => {
  assert.equal(canonical({ facets: [{ required: true }, { required: false }] }),
    '{"facets":[{"required":true},{"required":false}]}');
  assert.notEqual(canonical(['artifact_integrity', 'guarantee_consistency']),
    canonical(['guarantee_consistency', 'artifact_integrity']));
  for (const value of [null, undefined, 0.5, NaN, Infinity, 9007199254740992, { facets: [null] }]) {
    assert.throws(() => canonical(value));
  }
});
