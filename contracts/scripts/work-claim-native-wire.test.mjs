import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { canonical } from './work-claim-native-transactions.mjs';

test('native signer canonical bytes agree with all four Rust artifact vectors', () => {
  for (const family of ['agreement', 'submission', 'dependency', 'decision']) {
    const raw = readFileSync(new URL(`../../examples/federated-work/fixtures/registered-work/${family}.json`, import.meta.url), 'utf8');
    assert.equal(canonical(JSON.parse(raw)), raw, family);
  }
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
