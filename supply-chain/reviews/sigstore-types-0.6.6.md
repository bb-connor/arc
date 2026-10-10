# sigstore-types 0.6.6 source review

Reviewed September 16, 2026 by the executing Codex agent. Confidence is high
for the exact source and tested encoding boundaries. This is direct source
review, not independent human certification.

Registry archive SHA-256:
`f8d870c9bcfdf83396ac2bd2d6a23c5d09ec02cc9fda50fa1cbb3dd71a9bee53`.
Release source is `c9d76063833cb58a06483b181096294524d2dbf1` in
prefix-dev/sigstore-rust, under `crates/sigstore-types`.

## Scope and boundary

Reviewed both manifests and all nine source modules, including their tests.
The package has no unsafe code, build script, filesystem or network IO,
environment inspection or process execution. It supplies Serde data models,
base64/hex and PEM wrappers, fixed-size hashes and key hints, DSSE
pre-authentication encoding, and checkpoint text parsing. It does not implement
cryptographic primitives or establish trust.

SHA-256 values and checkpoint key hints enforce lengths of 32 and four bytes
before copying into arrays. DSSE pre-authentication encoding includes the byte
lengths and exact bytes of both the payload type and payload. A checkpoint
parsed from text preserves its original signed body separately from normalized
fields. Chio verifies that preserved body after parsing the original envelope.

The following are caller obligations, not properties of decoded types:

- Certificates, keys, signatures, canonicalized bodies and timestamps are byte
  wrappers. Their names do not establish validity, canonical form or identity.
- Media-type support is checked by `version()`, not by JSON decoding alone.
  In-toto digest strings and predicate types also require semantic validation.
- Negative log positions can deserialize. Unsigned numeric values above
  `i64::MAX` wrap to negative values in this release. Callers must use the
  checked `as_u64()` boundary; Chio's proof and signed-entry verification do so.
- Checkpoint JSON serialization omits the preserved signed body. A JSON
  round-trip is therefore unsuitable for reconstructing signed verification
  bytes. Public field mutation likewise cannot update an existing signature.
- The checkpoint parser tolerates some formatting and trailing material;
  parsing does not authenticate a log, key hint or signature. Input-size and
  collection limits remain the caller's responsibility.

## Validation and conclusion

All 27 upstream unit tests and three documentation tests pass. Strict Clippy
passes for all targets and features with warnings denied. Five retained audit
tests additionally check malformed fixed sizes, UTF-8 and binary DSSE encoding,
signed/unsigned integer boundaries, exact signed checkpoint bytes and malformed
checkpoint rejection. See `sigstore-types-0.6.6-boundaries.rs` beside this report.

The checksum-verified registry package receives a `safe-to-deploy` audit for
this encoding/data-model boundary with the stated limitations. The certificate
does not cover dependencies or replace Chio's cryptographic verification.
Production and upstream test bytes remain unchanged; validation adds only
standalone metadata, a selected lockfile and the separate audit test target.

Evidence is retained in the primary checkout under
`output/process-security-20260915/sigstore-data-audit-7ff6ba3bd/`.
