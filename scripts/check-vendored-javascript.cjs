#!/usr/bin/env node
'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { createRequire } = require('node:module');
const { test } = require('node:test');

const repoRoot = path.resolve(__dirname, '..');
const sdkRoot = path.join(repoRoot, 'sdks/typescript');
const sdkRequire = createRequire(path.join(sdkRoot, 'package.json'));
const reviewedHashManifests = {
  braces: 'c055f799ad2eb915502c3d5658bed683e31e9fe09a39adbcad64a7fe746eb88f',
  'node-forge': '9b12dab1a7b4c694347a75f12e043fd64b04717e60456e95ffaf19d62988a6e7'
};
assert.equal(process.argv.length, 2, 'the source proof gate takes no bypass options');

function verifySource(name) {
  const sourceRoot = path.join(sdkRoot, 'vendor', name);
  const records = fs.readFileSync(path.join(sourceRoot, 'CHIO-SOURCE-HASHES.sha256'), 'utf8');
  assert.equal(crypto.createHash('sha256').update(records).digest('hex'),
    reviewedHashManifests[name], `${name}: source review must be refreshed`);
  const reviewed = new Set();
  for (const line of records.trim().split('\n')) {
    const [expected, relative] = line.split(/  /);
    assert.ok(relative && !path.isAbsolute(relative) && !relative.split('/').includes('..'));
    assert.match(expected, /^[a-f0-9]{64}$/);
    assert.ok(!reviewed.has(relative), `${name}: duplicate reviewed path`);
    reviewed.add(relative);
    const actual = crypto.createHash('sha256')
      .update(fs.readFileSync(path.join(sourceRoot, relative))).digest('hex');
    assert.equal(actual, expected, `${name}: reviewed source hash changed: ${relative}`);
  }
  const metadata = new Set(['CHIO-PATCH.md', 'CHIO-PATCH.patch', 'CHIO-SOURCE-HASHES.sha256']);
  function inspect(directory, prefix = '') {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const relative = prefix + entry.name;
      assert.ok(!entry.isSymbolicLink(), `${name}: unexpected source symlink ${relative}`);
      if (entry.isDirectory()) {
        inspect(path.join(directory, entry.name), relative + '/');
      } else {
        assert.ok(reviewed.has(relative) || metadata.has(relative),
          `${name}: unreviewed source payload ${relative}`);
      }
    }
  }
  inspect(sourceRoot);
  const entry = name === 'braces' ? 'index.js' : 'lib/index.js';
  const installed = sdkRequire.resolve(name);
  assert.equal(fs.realpathSync(installed), fs.realpathSync(path.join(sourceRoot, entry)),
    `${name}: npm resolved a different implementation`);
  const lock = JSON.parse(fs.readFileSync(path.join(sdkRoot, 'package-lock.json'), 'utf8'));
  let consumers = 0;
  for (const [location, manifest] of Object.entries(lock.packages)) {
    if (manifest.dependencies && Object.hasOwn(manifest.dependencies, name)) {
      const requester = createRequire(path.join(sdkRoot, location, 'package.json'));
      assert.equal(fs.realpathSync(requester.resolve(name)), fs.realpathSync(installed),
        `${name}: ${location} resolves an unreviewed transitive copy`);
      consumers++;
    }
  }
  assert.ok(consumers > 0, `${name}: no actual dependency consumer was checked`);
  return sourceRoot;
}

{
  const sourceRoot = verifySource('braces');
  const braces = require(path.join(sourceRoot, 'index.js'));
  const bounded = { name: 'RangeError', message: 'Maximum nesting depth exceeded' };

  test('brace lists, ranges, escaping and stringify retain ordinary behavior', () => {
    assert.deepEqual(braces('{a,b}/{1..3}', { expand: true }),
      ['a/1', 'a/2', 'a/3', 'b/1', 'b/2', 'b/3']);
    assert.equal(braces.compile('{a,b}'), '(a|b)');
    assert.equal(braces.stringify(braces.parse('foo/{a,b}')), 'foo/{a,b}');
    for (const input of ['{x}', '${x,y}', 'foo/{x}']) {
      assert.equal(braces.stringify(braces.parse(input), { escapeInvalid: true }), input);
    }
    assert.equal(braces.compile('\\{'.repeat(1500) + 'x'), '{'.repeat(1500) + 'x');
    assert.equal(braces.compile('"' + '{'.repeat(4000) + '"'), '{'.repeat(4000));
    assert.doesNotThrow(() => braces.compile('{'.repeat(100) + 'x' + '}'.repeat(100)));
  });

  for (const method of ['parse', 'compile', 'expand']) {
    test(`${method} rejects excessive brace and parenthesis depth before stack exhaustion`, () => {
      assert.throws(() => braces[method]('{'.repeat(4500) + 'x' + '}'.repeat(4500)), bounded);
      assert.throws(() => braces[method]('('.repeat(4500) + 'x' + ')'.repeat(4500)), bounded);
    });
  }

  for (const method of ['compile', 'expand', 'stringify']) {
    test(`${method} also bounds caller-supplied AST depth`, () => {
      const root = { type: 'root', nodes: [] };
      let parent = root;
      for (let i = 0; i < 4000; i++) {
        const node = { type: 'brace', open: true, close: true, commas: 1,
          ranges: 0, nodes: [], parent };
        parent.nodes.push(node);
        parent = node;
      }
      parent.nodes.push({ type: 'text', value: 'x', parent });
      assert.throws(() => braces[method](root), bounded);
    });
  }
}

{
  const sourceRoot = verifySource('node-forge');
  const forge = require(path.join(sourceRoot, 'lib/index.js'));
  const pair = crypto.generateKeyPairSync('rsa', { modulusLength: 1024, publicExponent: 3 });
  const privatePem = pair.privateKey.export({ type: 'pkcs1', format: 'pem' });
  const publicPem = pair.publicKey.export({ type: 'spki', format: 'pem' });
  const privateKey = forge.pki.privateKeyFromPem(privatePem);
  const digest = forge.md.sha256.create().update('digest-algorithm-binding').digest().getBytes();
  const asn1 = forge.asn1;
  const primitive = (type, value) => asn1.create(asn1.Class.UNIVERSAL, type, false, value);
  const nullValue = value => primitive(asn1.Type.NULL, value);
  const signatures = [];

  for (const [name, parameters, valid] of [
    ['absent optional NULL', [], true],
    ['empty optional NULL', [nullValue('')], true],
    ['extra child after NULL', [nullValue(''), primitive(asn1.Type.OCTETSTRING, 'garbage')], false],
    ['non-NULL second child', [primitive(asn1.Type.OCTETSTRING, 'garbage')], false],
    ['nonempty NULL payload', [nullValue('garbage')], false]
  ]) {
    const algorithm = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true,
      [primitive(asn1.Type.OID, asn1.oidToDer(forge.oids.sha256).getBytes()), ...parameters]);
    const info = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true,
      [algorithm, primitive(asn1.Type.OCTETSTRING, digest)]);
    const signature = privateKey.sign(asn1.toDer(info).getBytes(), 'NONE');
    signatures.push({ name, signature, valid });
  }

  const backends = [['CommonJS', forge]];
  for (const file of ['forge.min.js', 'forge.all.min.js']) {
    // Supply the host's WebCrypto API and bind the unused jQuery external.
    const context = { Uint8Array, setTimeout, clearTimeout, crypto: crypto.webcrypto, jQuery: undefined };
    context.self = context;
    context.window = context;
    vm.runInNewContext(fs.readFileSync(path.join(sourceRoot, 'dist', file), 'utf8'), context,
      { timeout: 5000, filename: file });
    backends.push([file, context.forge]);
  }

  for (const [backendName, backend] of backends) {
    const publicKey = backend.pki.publicKeyFromPem(publicPem);
    for (const fixture of signatures) {
      test(`${backendName} ${fixture.valid ? 'accepts' : 'rejects'} ${fixture.name}`, () => {
        if (fixture.valid) {
          assert.equal(publicKey.verify(digest, fixture.signature), true);
          assert.equal(publicKey.verify('wrong digest', fixture.signature), false);
        } else {
          assert.throws(() => publicKey.verify(digest, fixture.signature), /DigestInfo/);
        }
      });
    }
  }
}
