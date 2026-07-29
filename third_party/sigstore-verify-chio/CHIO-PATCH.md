# Chio Sigstore Verifier Patch

This directory contains the crates.io source for `sigstore-verify` 0.6.3 with
one Chio security patch.

- Upstream repository: `https://github.com/prefix-dev/sigstore-rust`
- Upstream source commit: `490f9231ff81b3269f4316a98b95059691d49593`
- Crates.io checksum: `6d751d608afd334fb9d8c037ad9efef69f1954494eff99cd79a0a6fc8af34ccb`
- Upstream fixed commit: `c9d76063833cb58a06483b181096294524d2dbf1`
- License: BSD-3-Clause

Version 0.6.3 checked identity and issuer only when the certificate exposed the
corresponding claim. A policy that required a claim therefore succeeded when
the claim was absent. The patch applies the fail-closed matching behavior
released upstream in version 0.6.6: an absent required identity or issuer is a
verification error. Focused unit tests cover exact match, mismatch, and missing
claim behavior.

Chio cannot select `sigstore-verify` 0.6.6 while `nono` 0.53.0 pins
`sigstore-trust-root` 0.6.3. The workspace uses `[patch.crates-io]` so the
patched verifier replaces only the affected 0.6.3 package without changing the
rest of the Sigstore dependency graph.
