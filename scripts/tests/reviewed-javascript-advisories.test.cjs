'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { test } = require('node:test');

const root = path.resolve(__dirname, '../..');
const script = path.join(root, 'scripts/check-reviewed-javascript-advisories.cjs');
const sdkLock = path.join(root, 'sdks/typescript/package-lock.json');

function currentFindings() {
  return { results: [{ source: { type: 'lockfile', path: sdkLock }, packages: [
    { package: { name: 'braces', version: '3.0.3', ecosystem: 'npm' },
      vulnerabilities: [{ id: 'GHSA-vfj7-8cjw-p6xm', modified: '2026-10-02T22:45:04.328737432Z' }] },
    { package: { name: 'node-forge', version: '1.4.0', ecosystem: 'npm' },
      vulnerabilities: [{ id: 'GHSA-86w9-cpqp-85rv', modified: '2026-10-01T21:40:55.016251436Z' }] }
  ] }] };
}

function evaluate(report, scannerStatus = 1) {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'chio-source-audit-'));
  try {
    const input = path.join(temporary, 'scanner.json');
    const output = path.join(temporary, 'dispositions.json');
    fs.writeFileSync(input, JSON.stringify(report));
    const child = spawnSync(process.execPath,
      [script, '--input', input, '--output', output, '--scanner-status', String(scannerStatus)],
      { encoding: 'utf8', maxBuffer: 1024 * 1024 });
    return { status: child.status, stderr: child.stderr,
      report: fs.existsSync(output) ? JSON.parse(fs.readFileSync(output, 'utf8')) : undefined };
  } finally {
    fs.rmSync(temporary, { recursive: true, force: true });
  }
}

test('closes only the current two reviewed owned-source revisions', () => {
  const result = evaluate(currentFindings());
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.report.reviewed.length, 2);
  assert.deepEqual(result.report.remaining, []);
  assert.ok(result.report.reviewed.every(entry => entry.upstreamReleaseRemainsAffected));
});

test('a new advisory on the same package remains blocking', () => {
  const raw = currentFindings();
  raw.results[0].packages[1].vulnerabilities.push({ id: 'GHSA-test-only-unknown', modified: 'fixture' });
  const result = evaluate(raw);
  assert.equal(result.status, 1);
  assert.equal(result.report.remaining.length, 1);
});

test('a changed revision of an approved advisory requires new review', () => {
  const raw = currentFindings();
  raw.results[0].packages[0].vulnerabilities[0].modified = '2026-10-08T00:00:00Z';
  const result = evaluate(raw);
  assert.equal(result.status, 1);
  assert.equal(result.report.reviewed.length, 1);
  assert.equal(result.report.remaining.length, 1);
});

test('the same package and advisory in another lock remains blocking', () => {
  const raw = currentFindings();
  raw.results[0].source.path = path.join(root, 'sdks/typescript/packages/fastify/package-lock.json');
  const result = evaluate(raw);
  assert.equal(result.status, 1);
  assert.equal(result.report.reviewed.length, 0);
  assert.equal(result.report.remaining.length, 2);
});

test('a duplicate occurrence requires inspection instead of a broad waiver', () => {
  const raw = currentFindings();
  raw.results[0].packages.push(structuredClone(raw.results[0].packages[0]));
  const result = evaluate(raw);
  assert.equal(result.status, 1);
  assert.equal(result.report.remaining.length, 1);
});

test('an incomplete scanner report cannot produce an accepted disposition', () => {
  const result = evaluate({});
  assert.notEqual(result.status, 0);
  assert.equal(result.report, undefined);
});

test('scanner failure status cannot be converted into source acceptance', () => {
  const result = evaluate(currentFindings(), 2);
  assert.notEqual(result.status, 0);
  assert.equal(result.report, undefined);
});

test('a clean scanner report still requires the complete source proof', () => {
  const result = evaluate({ results: [] }, 0);
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(result.report.reviewed, []);
  assert.deepEqual(result.report.remaining, []);
});
