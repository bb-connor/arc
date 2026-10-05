// Run against the installed peer-tooling packages. The same tests must fail
// against the original registry packages before accepting a source repair.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const path = require('node:path');
const { createRequire } = require('node:module');
const test = require('node:test');
const vm = require('node:vm');

const requireTooling = createRequire(path.resolve(
  process.env.CHIO_TOOLING_TEST_ROOT || 'sdks/typescript', 'package.json'));
const braces = requireTooling('braces');
const forge = requireTooling('node-forge');

test('braces bounds strings and every public AST walker', () => {
  assert.deepEqual(braces.expand('src/{a,b}.js'), ['src/a.js', 'src/b.js']);
  for (const [open, close] of [['{', '}'], ['(', ')']]) {
    const pattern = open.repeat(101) + 'a,b' + close.repeat(101);
    for (const options of [{}, { maxDepth: 10000 }, { maxDepth: Infinity }]) {
      assert.throws(() => braces.parse(pattern, options), /exceeds max depth/);
    }
  }
  for (const method of ['compile', 'expand', 'stringify']) {
    let ast = { type: 'text', value: 'a' };
    for (let level = 0; level < 101; level++) ast = { type: 'brace', nodes: [ast] };
    ast = { type: 'root', nodes: [ast] };
    assert.throws(() => braces[method](ast), /exceeds max depth/);
  }
  assert.doesNotThrow(() => braces.parse('{{a,b},c}', { maxDepth: 2 }));
  assert.throws(() => braces.parse('{{a,b},c}', { maxDepth: 1 }), /exceeds max depth/);
});

test('braces rejects cyclic parent chains within a bounded time', () => {
  const ast = { type: 'paren', nodes: [{ type: 'text', value: 'a' }] };
  ast.parent = ast;
  assert.throws(
    () => vm.runInNewContext('braces.expand(ast)', { braces, ast }, { timeout: 500 }),
    /AST parent chain contains a cycle/);
  assert.deepEqual(braces.expand('foo/({a,b})'), ['foo/(a)', 'foo/(b)']);
});

test('RSA rejects extra nested DigestAlgorithm fields and accepts valid signatures', () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 1024 });
  const publicForge = forge.pki.publicKeyFromPem(publicKey.export({ type: 'spki', format: 'pem' }));
  const message = Buffer.from('Chio tooling signature boundary');
  const digest = crypto.createHash('sha256').update(message).digest();
  const signature = crypto.sign('sha256', message, privateKey);
  assert.equal(publicForge.verify(digest.toString('binary'), signature.toString('binary')), true);
  assert.equal(publicForge.verify('\0'.repeat(32), signature.toString('binary')), false);
  const asn = forge.asn1;
  const node = (type, constructed, value) => asn.create(asn.Class.UNIVERSAL, type, constructed, value);
  for (const includeNull of [false, true]) {
    const algorithm = [node(asn.Type.OID, false, asn.oidToDer(forge.pki.oids.sha256).getBytes())];
    if (includeNull) algorithm.push(node(asn.Type.NULL, false, ''));
    algorithm.push(node(asn.Type.OCTETSTRING, false, 'unconsumed nested bytes'));
    const der = asn.toDer(node(asn.Type.SEQUENCE, true, [
      node(asn.Type.SEQUENCE, true, algorithm),
      node(asn.Type.OCTETSTRING, false, digest.toString('binary')),
    ])).getBytes();
    const malformed = crypto.privateEncrypt(
      { key: privateKey, padding: crypto.constants.RSA_PKCS1_PADDING }, Buffer.from(der, 'binary'));
    assert.throws(
      () => publicForge.verify(digest.toString('binary'), malformed.toString('binary')),
      /does not contain a valid RSASSA-PKCS1-v1_5 DigestInfo/);
  }
});
