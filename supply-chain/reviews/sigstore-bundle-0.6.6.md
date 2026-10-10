# sigstore-bundle 0.6.6 source review

Reviewed September 16, 2026 by the executing Codex agent. Confidence is high
for source identity and the tested separation between bundle validation and
authentication. This is direct source review, not independent human
certification.

Registry archive SHA-256:
`0e7dc53c8a941858d01479622dbb7650aaa2ee0ca1fb58fb6cdddbfc3064abbb`.
Release source is `c9d76063833cb58a06483b181096294524d2dbf1` in
prefix-dev/sigstore-rust, under `crates/sigstore-bundle`.

## Source and behavior

Reviewed both manifests, all four production modules, both upstream integration
test modules and their fixture inventory. There is no unsafe code, build script,
filesystem or network IO, environment inspection or process execution in this
package. Its transport feature flags forward to dependencies requiring their
own audits.

The package builds bundle data and checks version-specific shape, evidence
presence and Merkle membership against the root parsed from a checkpoint.
Negative proof positions reject through checked conversion. Chio selects the
repaired owned Merkle implementation beneath the unmodified bundle package.

`validate_bundle` is not an authenticity verifier. It does not verify artifact
signatures, certificates, timestamps, signed-entry timestamps or checkpoint
signatures. It also does not join the proof's duplicate root and tree size to
the checkpoint's fields. An audit regression deliberately supplies invalid
certificate/signature bytes and then mismatched duplicate fields; this API
accepts both. A changed leaf and invalid proof positions reject. These tests
record the actual boundary rather than interpreting the function name as a
security guarantee.

Upstream subsequently clarified this distinction in
[commit 4ec634fed02216f45d2b7f30c5c62b5812fec2d4](https://github.com/prefix-dev/sigstore-rust/commit/4ec634fed02216f45d2b7f30c5c62b5812fec2d4).
Chio's already-owned `sigstore-verify` separately verifies the checkpoint
signature and key validity, requires equal root hashes and tree sizes, and
checks the canonicalized entry's Merkle path. Source references are
`third_party/sigstore-verify-chio/src/verify_impl/tlog.rs` and `src/verify.rs`.
The bundle audit does not replace those checks.

The Rekor-response builder is also not a validator: it falls back on malformed
log-ID/root conversions and drops malformed proof hashes. Its output must pass
the complete cryptographic verifier. This review does not approve treating
constructed or shape-valid bundles as trusted evidence.

## Validation and conclusion

All 24 upstream tests pass with all features. The one upstream documentation
example remains explicitly ignored. Strict Clippy passes for all targets and
features with warnings denied. Two added audit tests retain the authentication
boundary and proof-rejection cases in `sigstore-bundle-0.6.6-boundaries.rs`.
Six existing Chio log-verifier tests also pass on the selected dependency graph,
covering entry binding, unsigned chronology, key validity windows, redundant
signatures and colliding key hints. An additional owned regression keeps a valid
signed checkpoint unchanged and proves that substituted root hashes and tree
sizes both reject. These are focused checks, not a complete integration
qualification. The retained fork manifest also names absent upstream integration
tests/examples, so an all-target standalone invocation remains unqualified;
the focused library targets above are the actual executed inventory.

The exact registry package receives a `safe-to-deploy` audit with these explicit
limits. No imported authority, criterion or exemption changes. Production and
upstream test bytes remain unchanged. Evidence, archive checksums, selected
lockfiles and complete test/lint logs are retained in the primary checkout under
`output/process-security-20260915/sigstore-data-audit-7ff6ba3bd/`.
