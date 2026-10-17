import assert from 'node:assert/strict';
import { Miniflare } from 'miniflare';

const mf = new Miniflare({
  modules: true,
  scriptPath: 'test/worker.mjs',
  compatibilityDate: '2026-04-27',
  modulesRules: [
    { type: 'ESModule', include: ['**/*.js', '**/*.mjs'], fallthrough: true },
    { type: 'CompiledWasm', include: ['**/*.wasm'], fallthrough: true },
  ],
});

try {
  const smokeRes = await mf.dispatchFetch('https://workers.test/__chio_workers_smoke');
  const smoke = await smokeRes.json();
  assert.ok(smokeRes.ok, JSON.stringify(smoke));
  assert.equal(smoke.package, '@chio-protocol/workers');
  assert.equal(smoke.wasmTarget, 'bundler');
  assert.equal(smoke.verifyReceipt, true);

  const res = await mf.dispatchFetch('https://workers.test/__chio_workers_roundtrip');
  const out = await res.json();
  assert.ok(res.ok, JSON.stringify(out));
  assert.match(out.seedA, /^[0-9a-f]{64}$/);
  assert.notEqual(out.seedA, '0'.repeat(64));
  assert.notEqual(out.seedA, out.seedB);
  assert.match(out.kernelKey, /^[0-9a-f]{64}$/);
  assert.deepEqual(out.parameters, { mode: 'read', path: '/workspace/docs/roadmap.md' });
  assert.equal(out.trusted.signature_valid, true);
  assert.equal(out.trusted.signer_trusted, true);
  assert.equal(out.trusted.ok, true);
  assert.equal(out.trusted.signer_key_hex, out.kernelKey);
  assert.equal(out.untrusted.signature_valid, true);
  assert.equal(out.untrusted.signer_trusted, false);
  assert.equal(out.untrusted.ok, false);
  console.log('miniflare workers: 2 passed');
} finally {
  await mf.dispose();
}
