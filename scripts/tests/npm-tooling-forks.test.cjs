// Run against the installed peer-tooling packages. Each regression must fail
// against its vulnerable registry package before accepting a repair or release.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { once } = require('node:events');
const http = require('node:http');
const path = require('node:path');
const { createRequire } = require('node:module');
const test = require('node:test');
const vm = require('node:vm');
const zlib = require('node:zlib');

const requireTooling = createRequire(path.resolve(
  process.env.CHIO_TOOLING_TEST_ROOT || 'sdks/typescript', 'package.json'));
const braces = requireTooling('braces');
const forge = requireTooling('node-forge');
const compression = requireTooling('compression');
const proxyaddr = requireTooling('proxy-addr');
const { SourceMapConsumer } = requireTooling('source-map-js');

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

test('compression releases its native stream after a client aborts', { timeout: 10000 }, async (t) => {
  const descriptor = Object.getOwnPropertyDescriptor(zlib, 'createGzip');
  let stream;
  Object.defineProperty(zlib, 'createGzip', {
    ...descriptor,
    value(...args) {
      stream = descriptor.value(...args);
      return stream;
    },
  });
  t.after(() => {
    Object.defineProperty(zlib, 'createGzip', descriptor);
    stream?.destroy();
  });

  let responseClosed;
  const closed = new Promise((resolve) => { responseClosed = resolve; });
  const middleware = compression({ threshold: 0 });
  const server = http.createServer((req, res) => {
    middleware(req, res, () => {
      res.once('close', responseClosed);
      res.setHeader('Content-Type', 'text/plain');
      res.write('Chio compressed response\n'.repeat(1024));
      res.flush();
    });
  });
  t.after(async () => {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  });
  const listening = once(server, 'listening');
  server.listen(0, '127.0.0.1');
  await listening;
  const request = http.get({
    host: '127.0.0.1', port: server.address().port,
    headers: { 'Accept-Encoding': 'gzip' },
  }, (response) => {
    response.once('data', () => response.destroy());
    response.on('error', () => {});
  });
  request.on('error', () => {});
  t.after(() => request.destroy());
  await closed;
  await new Promise(setImmediate);
  assert.ok(stream, 'the real response must create a native compression stream');
  assert.equal(stream.destroyed, true);
  assert.equal(stream.closed, true);
});

test('proxy trust cannot cross address families through short IPv6 prefixes', () => {
  for (const subnets of [
    ['::ffff:10.0.0.0/8'], ['::/1'],
    ['::ffff:10.0.0.0/8', '10.0.0.0/8'],
  ]) {
    const trust = proxyaddr.compile(subnets);
    for (const address of ['203.0.113.9', '::ffff:203.0.113.9']) {
      assert.equal(trust(address), false, `${subnets}: ${address}`);
    }
    const request = {
      socket: { remoteAddress: '203.0.113.9' },
      headers: { 'x-forwarded-for': '10.0.0.8' },
    };
    assert.equal(proxyaddr(request, subnets), '203.0.113.9');
  }
  for (const subnet of ['10.0.0.0/8', '::ffff:10.0.0.0/104']) {
    const trust = proxyaddr.compile(subnet);
    assert.equal(trust('10.0.0.8'), true);
    assert.equal(trust('::ffff:10.0.0.8'), true);
    assert.equal(trust('203.0.113.9'), false);
  }
  assert.equal(proxyaddr.compile('2001:db8::/32')('2001:db8::1'), true);
});

test('indexed source maps reject invalid and amplifying section offsets', () => {
  const flat = { version: 3, sources: ['a.js'], names: [], mappings: 'AAAA' };
  const indexed = (map, line, column = 0) => ({
    version: 3, sections: [{ offset: { line, column }, map }],
  });
  const ordinary = new SourceMapConsumer(indexed(flat, 1));
  assert.equal(ordinary.originalPositionFor({ line: 2, column: 1 }).source, 'a.js');
  for (const value of [-1, 1.5, NaN, Infinity, '1']) {
    assert.throws(() => new SourceMapConsumer(indexed(flat, value)));
    assert.throws(() => new SourceMapConsumer(indexed(flat, 0, value)));
  }
  assert.throws(() => new SourceMapConsumer(indexed(flat, 1e15)));
  const nested = indexed(indexed(indexed(flat, 5e6), 5e6), 5e6);
  assert.throws(() => new SourceMapConsumer(nested));
});
