# node-forge 1.4.0 PKCS#1 v1.5 DigestInfo repair

Path fork of node-forge 1.4.0 (BSD-3-Clause OR GPL-2.0), repairing
GHSA-86w9-cpqp-85rv (CVE-2026-85393, upstream issue digitalbazaar/forge#1149).
`sdks/typescript` reaches node-forge through Expo CLI and
`@expo/code-signing-certificates`, the required peers of `@chio-protocol/mobile`.

## Provenance

- Archive: `https://registry.npmjs.org/node-forge/-/node-forge-1.4.0.tgz`,
  SHA-512 `LarFH0+6VfriEhqMMcLX2F7SwSXeWwnEAJEsYm5QKWchiVYVvJyV9v7UDvUv+w5HO23ZpQTXDv/GxdDdMyOuoQ==`
  (registry integrity), SHA-256
  `bf9d7ca0d774235354697bd4b5e642af6505e7ce2066762c3b855138cf870820`.
- Patched archive: `node-forge-1.4.1-chio.1.tgz`, SHA-256
  `53d1ca30c88e93e08fac51befa6d44e440e426083998631a53932de12dd5abeb`.
- All 59 published files are retained.

## Delta

1. RSASSA-PKCS1-v1_5 verification rejects a DigestInfo unless DigestAlgorithm
   holds exactly the algorithm identifier and, when present, one NULL. A
   present NULL must be empty. `asn1.validate` ignores extra children, so
   1.4.0 accepted attacker bytes inside DigestAlgorithm, which allows signature
   forgery against low-exponent RSA keys.
2. `package.json` version is `1.4.1-chio.1`.

## Tests

`CHIO-PATCH.test.cjs` signs crafted DigestInfo values with a test key and
checks that canonical encodings, with and without NULL parameters, verify,
that extra DigestAlgorithm elements fail, and that nonempty NULL parameters
fail. Against the registry archive, the two rejection tests fail.
