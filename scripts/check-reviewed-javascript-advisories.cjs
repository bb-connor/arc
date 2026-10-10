#!/usr/bin/env node
'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const repoRoot = path.resolve(__dirname, '..');
const sdkRoot = path.join(repoRoot, 'sdks/typescript');
const expectedLock = path.join(sdkRoot, 'package-lock.json');
const argumentsByName = new Map();
for (let i = 2; i < process.argv.length; i += 2) {
  assert.ok(['--input', '--output', '--scanner-status'].includes(process.argv[i]));
  assert.ok(process.argv[i + 1] && !argumentsByName.has(process.argv[i]));
  argumentsByName.set(process.argv[i], process.argv[i + 1]);
}
const input = argumentsByName.get('--input');
const output = argumentsByName.get('--output');
const scannerStatus = Number(argumentsByName.get('--scanner-status'));
assert.ok(input && output && [0, 1].includes(scannerStatus),
  'a complete scanner report with status 0 or 1 is required');

// These dispositions cover exact owned payloads and the advisory text reviewed
// on October 7, 2026. A changed advisory or source requires a new review.
const reviews = {
  'GHSA-vfj7-8cjw-p6xm': {
    name: 'braces', version: '3.0.3',
    modified: '2026-10-02T22:45:04.328737432Z',
    archiveSha256: '1cd18e862c8640b4568b1425a7df4ee030ff201d45b2da8f9f222d2987494ffc',
    patchSha256: '9a02264e38f9ecfe00978f73b01d5d6433b91f66b570dd120055d084cf7bc088',
    hashManifestSha256: 'c055f799ad2eb915502c3d5658bed683e31e9fe09a39adbcad64a7fe746eb88f'
  },
  'GHSA-86w9-cpqp-85rv': {
    name: 'node-forge', version: '1.4.0',
    modified: '2026-10-01T21:40:55.016251436Z',
    archiveSha256: 'bf9d7ca0d774235354697bd4b5e642af6505e7ce2066762c3b855138cf870820',
    patchSha256: 'e0fe41c5047bd44ed5004ab896d07934c96ef19c26fa49984342ccfbcd44cfe2',
    hashManifestSha256: '9b12dab1a7b4c694347a75f12e043fd64b04717e60456e95ffaf19d62988a6e7'
  }
};

const proofEnvironment = { ...process.env };
// A nested Node test runner otherwise substitutes its binary reporter protocol.
delete proofEnvironment.NODE_TEST_CONTEXT;
const proof = spawnSync(process.execPath,
  ['--test-reporter=tap', path.join(__dirname, 'check-vendored-javascript.cjs')],
  { cwd: repoRoot, env: proofEnvironment, encoding: 'utf8', maxBuffer: 1024 * 1024 });
process.stdout.write(proof.stdout || '');
process.stderr.write(proof.stderr || '');
assert.equal(proof.status, 0, 'reviewed source and regression proof must pass');
assert.match(proof.stdout, /^# tests 22$/m);
assert.match(proof.stdout, /^# pass 22$/m);
assert.match(proof.stdout, /^# fail 0$/m);

const lock = JSON.parse(fs.readFileSync(expectedLock, 'utf8'));
const sdkManifest = JSON.parse(fs.readFileSync(path.join(sdkRoot, 'package.json'), 'utf8'));
const raw = JSON.parse(fs.readFileSync(input, 'utf8'));
assert.ok(Array.isArray(raw.results), 'scanner did not produce a complete results array');
const reviewed = [];
const remaining = [];
const seen = new Set();
const sha256 = file => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');

for (const result of raw.results) {
  assert.ok(result.source && Array.isArray(result.packages));
  for (const finding of result.packages) {
    for (const advisory of finding.vulnerabilities || []) {
      assert.equal(typeof advisory.id, 'string');
      const review = Object.hasOwn(reviews, advisory.id) ? reviews[advisory.id] : undefined;
      const pkg = finding.package;
      const sameSource = result.source.type === 'lockfile' &&
        path.resolve(result.source.path) === expectedLock;
      if (!review || !sameSource || pkg.ecosystem !== 'npm' ||
          pkg.name !== review.name || pkg.version !== review.version ||
          advisory.modified !== review.modified || seen.has(advisory.id)) {
        remaining.push({ source: result.source, package: pkg,
          advisory: advisory.id, modified: advisory.modified });
        continue;
      }

      const workspace = `vendor/${review.name}`;
      const sourceRoot = path.join(sdkRoot, workspace);
      const manifest = JSON.parse(fs.readFileSync(path.join(sourceRoot, 'package.json'), 'utf8'));
      const installed = lock.packages[`node_modules/${review.name}`];
      assert.equal(installed.link, true);
      assert.equal(installed.resolved, workspace);
      assert.ok(sdkManifest.workspaces.includes(workspace));
      assert.equal(manifest.private, true);
      assert.equal(manifest.name, review.name);
      assert.equal(manifest.version, review.version);
      assert.equal(sha256(path.join(sourceRoot, 'CHIO-SOURCE-HASHES.sha256')),
        review.hashManifestSha256);
      assert.equal(sha256(path.join(sourceRoot, 'CHIO-PATCH.patch')), review.patchSha256);
      seen.add(advisory.id);
      reviewed.push({ source: result.source, package: pkg, advisory: advisory.id,
        advisoryModified: advisory.modified, disposition: 'repaired-owned-source',
        upstreamReleaseRemainsAffected: true, ownedSource: workspace,
        archiveSha256: review.archiveSha256,
        hashManifestSha256: review.hashManifestSha256,
        patchSha256: sha256(path.join(sourceRoot, 'CHIO-PATCH.patch')),
        proof: '22 regressions passed; complete payload hashes and transitive resolution verified' });
    }
  }
}

assert.equal(scannerStatus, reviewed.length + remaining.length === 0 ? 0 : 1,
  'scanner exit status and advisory report disagree');
const report = { scannerStatus, reviewed, remaining,
  status: remaining.length === 0 ? 'passed' : 'unreviewed-findings' };
fs.writeFileSync(output, JSON.stringify(report, null, 2) + '\n');
for (const entry of reviewed) {
  console.log(`${entry.advisory}: repaired only in reviewed ${entry.ownedSource}; upstream remains affected`);
}
if (remaining.length > 0) {
  console.error(`${remaining.length} findings require remediation or source review`);
  process.exitCode = 1;
}
