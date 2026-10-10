# Owned Forge DigestInfo repair

This private workspace preserves the upstream name, version 1.4.0, public
entry points and BSD-3-Clause/GPL-2.0 license choices. It is a modified local
source package, not a newly fixed upstream release.

The npm archive at
<https://registry.npmjs.org/node-forge/-/node-forge-1.4.0.tgz> has SHA-256
`bf9d7ca0d774235354697bd4b5e642af6505e7ce2066762c3b855138cf870820`.
The npm metadata identifies upstream commit
`fa385f92440879601240020f158bed68e444e83a`.

GHSA-86w9-cpqp-85rv remains unfixed in the latest published upstream package
as checked October 7, 2026. The report and proposed repair are
<https://github.com/digitalbazaar/forge/issues/1149> and
<https://github.com/digitalbazaar/forge/pull/1152>.

`CHIO-PATCH.patch` records the source/manifest delta. RSA PKCS#1 v1.5
verification now validates the complete DigestInfo algorithm child count and
optional NULL payload. It accepts an OID alone or an OID plus empty NULL;
it rejects extra children, a non-NULL second child and nonempty NULL. The
existing digest algorithm and digest value validation remain in place.
The validation succeeds before the new nested access, preserving the
structural precondition on each accessed child.

Both browser bundles and their maps were rebuilt from the modified source
using the original commit's webpack configuration and upstream package
development dependencies. The prime-worker bundles were rebuilt by the
same command. `CHIO-SOURCE-HASHES.sha256` covers all runtime sources,
bundles, maps, manifest, license and upstream readme. Development scripts
and dependencies are removed from this installed private runtime package;
the separate source review retains the original build harness.

The restored upstream Node suite passes 828 tests with four pre-existing
pending tests. Its checked-in `describe.only` was removed only in the
restored test harness so all suites actually run. The focused regressions
use ephemeral test RSA keys to encode malformed DigestInfo values. They
exercise the CommonJS verifier and both minified browser verifiers. All six
positive controls pass against the original source, while all nine malformed
DigestInfo negatives reproduce acceptance there. These tests establish the
verifier defect directly; they do not claim to construct a private-key-free
RSA forgery.

`scripts/check-vendored-javascript.cjs` checks the reviewed payload hashes
and actual npm resolution before executing those cases. Source review and
regression evidence close this finding only for this exact owned workspace
implementation. Other upstream Forge vulnerabilities retain normal audit
coverage.
