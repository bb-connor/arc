'use strict';

const assert = require('node:assert/strict');
const { createRequire } = require('node:module');
const path = require('node:path');
const test = require('node:test');

const workspace = createRequire(path.join(__dirname, '../../../sdks/typescript/package.json'));
const forge = workspace('node-forge');
const { asn1 } = forge;

const keys = forge.pki.rsa.generateKeyPair({ bits: 1024, e: 0x10001 });
const message = forge.md.sha256.create().update('chio');
const digest = message.digest().getBytes();

const sign = digestAlgorithm => {
  const digestInfo = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, digestAlgorithm),
    asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, digest)
  ]);
  const der = asn1.toDer(digestInfo).getBytes();
  return keys.privateKey.sign(der, 'NONE');
};

const sha256 = () =>
  asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(forge.pki.oids.sha256).getBytes());
const nullValue = bytes => asn1.create(asn1.Class.UNIVERSAL, asn1.Type.NULL, false, bytes);

test('the installed node-forge is the Chio repair', () => {
  assert.equal(workspace('node-forge/package.json').version, '1.4.1-chio.1');
});

test('canonical DigestInfo with and without NULL parameters verifies', () => {
  assert.equal(keys.publicKey.verify(digest, keys.privateKey.sign(message)), true);
  assert.equal(keys.publicKey.verify(digest, sign([sha256()])), true);
});

test('extra DigestAlgorithm elements are rejected', () => {
  const garbage = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OCTETSTRING, false, 'garbage');
  assert.throws(() => keys.publicKey.verify(digest, sign([sha256(), nullValue(''), garbage])), /DigestInfo/);
  assert.throws(() => keys.publicKey.verify(digest, sign([sha256(), garbage])), /DigestInfo/);
});

test('nonempty NULL parameters are rejected', () => {
  assert.throws(() => keys.publicKey.verify(digest, sign([sha256(), nullValue('garbage')])), /DigestInfo/);
});
