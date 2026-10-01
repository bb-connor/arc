# Chio Sigstore Verifier Patch

This directory contains the crates.io source for `sigstore-verify` 0.6.3 with
the Chio fail-closed verification patch set used by `nono` 0.53.0.

- Upstream repository: `https://github.com/prefix-dev/sigstore-rust`
- Upstream source commit: `490f9231ff81b3269f4316a98b95059691d49593`
- Crates.io checksum: `6d751d608afd334fb9d8c037ad9efef69f1954494eff99cd79a0a6fc8af34ccb`
- Upstream fixed commit: `c9d76063833cb58a06483b181096294524d2dbf1`
- License: BSD-3-Clause

The patch set closes security gaps found while qualifying Chio's enterprise
enforcement path:

- required identity and issuer claims fail when absent or mismatched;
- clock-skew policy is bounded and validated before verification;
- artifact and DSSE content are bound to the authenticated log entry;
- V1 and V2 validation times come only from authenticated, content-bound
  transparency-log or RFC 3161 evidence;
- multiple DSSE signatures and redundant time or log proofs must be
  unambiguous and mutually consistent;
- transparency-log entries, checkpoints, inclusion proofs, SET signatures,
  and logged certificate keys are bound to the same verified entry;
- SCT verification is bound to the trusted signing time; and
- skip-policy combinations fail closed when they remove the trusted time or
  verification authority required by another enabled check.

The package's test coverage exercises successful paths and the missing,
mismatched, ambiguous, untrusted, and cross-entry cases above.

Chio cannot select `sigstore-verify` 0.6.6 while `nono` 0.53.0 pins
`sigstore-trust-root` 0.6.3. The workspace uses `[patch.crates-io]` so the
patched verifier replaces only the affected 0.6.3 package without changing the
rest of the Sigstore dependency graph.

## Standalone qualification

The declared upstream integration target and both examples are restored from
the checksum-verified 0.6.3 archive. Two fixtures previously referenced through
a sibling package are retained locally from the checksum-verified
sigstore-bundle 0.6.6 archive
(`0e7dc53c8a941858d01479622dbb7650aaa2ee0ca1fb58fb6cdddbfc3064abbb`).
Only those include paths change in the upstream integration test. All 37
original test cases remain, including parsing-only cases; this is not a claim
that every case exercises full authentication. Example targets compile but
contain no tests.

The package is unpublished and has a standalone workspace/lockfile selecting
the same owned crypto, Merkle, trust-root, CMP and CRMF repairs as Chio. This
makes the complete target suite reproducible without an external validation
copy or missing sibling checkout:

```sh
cargo test --locked --all-targets --all-features --manifest-path third_party/sigstore-verify-chio/Cargo.toml
cargo clippy --locked --all-targets --all-features --manifest-path third_party/sigstore-verify-chio/Cargo.toml -- -D warnings
```

Timestamp authority regression coverage includes a real embedded signer:
upstream signature-only verification accepts it, while Chio rejects removal
of the configured authority. The initial missing-certificate diagnostic and
restoration evidence are retained under
`output/process-security-20260915/sigstore-tsa-audit-769f796a6/` in the primary
checkout.
