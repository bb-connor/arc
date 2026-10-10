# cms 0.2.3 source review

Reviewed September 16, 2026 by the executing Codex agent. Confidence is high
for source identity and the reviewed data-model boundary, and moderate for
complete CMS interoperability. This is direct source review, not independent
human certification.

## Source and selected role

Registry archive SHA-256:
`7b77c319abfd5219629c45c34c89ba945ed3c5e49fcde9d16b6c3885f118a730`.
The archive identifies RustCrypto/formats source
`5821a21553509dbd03eae593b0a1fad4e2083d4e`, under `cms`.

The review covers both manifests, all 13 production modules, all seven test
modules and the fixture inventory. Chio selects the default, alloc and std
features. It uses CMS types in its Sigstore timestamp verification chain and
CRMF data model; the optional `builder` feature is not selected.

## Production boundary

The crate forbids unsafe Rust and has no build script, filesystem or network
access, environment inspection or process execution. The selected modules
define DER sequences, tagged choices and ordered sets through the separately
reviewed dependency APIs. Conversions from certificates to certificate-only
SignedData encode caller-supplied certificates; they do not authenticate them.

Parsing ContentInfo, SignedData, a certificate choice or signed attributes does
not verify a signature, chain, identity, digest, timestamp, algorithm policy or
revocation status. Callers must perform those checks and impose input-size and
resource limits. DER decoding alone does not establish RFC semantic validity.
The less commonly used alternative certificate and revocation forms also have
schema/interoperability limitations; this audit does not claim full RFC 5652
coverage.

## Optional builder review and limits

The optional builder was reviewed even though the selected graph disables it.
It accepts a caller-provided signer and cryptographic RNG, hashes content using
an explicit supported digest identifier, and signs DER-encoded signed
attributes. Envelope construction uses fresh caller-RNG keys and IVs with
AES-CBC and RSA PKCS#1 v1.5 key wrapping. This crate does not implement envelope
decryption or a remotely callable padding oracle. Encryption alone does not
authenticate CMS content.

The builder is not a general validator for hostile construction inputs:

- Several ordered-set conversions unwrap errors; duplicate or invalid builder
  collections can panic. Unsupported recipient construction paths return errors
  or explicitly panic.
- Its check for an explicitly supplied content-type attribute compares the
  attribute identifier rather than its value. Callers cannot rely on that check
  as semantic validation, and normal explicit attributes can be rejected.
- The generated content-encryption key is zeroized after successful recipient
  construction. Early error paths do not guarantee that cleanup.

These are explicit audit-discretion limits. They do not add authority or IO to
the data-model role, and this review does not approve using the optional builder
as an untrusted-input service or claim complete key-memory erasure. A future
Chio feature change enabling it requires a separate integration review.

## Validation and conclusion

All 26 retained upstream tests pass with every feature enabled on Rust 1.94.1:
five builder cases, one compressed-data case, one digested-data case, one
encrypted-data case, five enveloped-data cases, eight signed-data cases and
five PKCS#7 fixture cases. None failed or were ignored. Strict Clippy passes
for all targets and features with warnings denied.

The validation copy adds only standalone-workspace metadata and a resolved
lockfile. Production source, upstream tests and fixtures remain identical to
the checksum-verified registry archive. Tests use included public fixtures;
they do not read user credentials or invoke external programs.

The exact registry package receives a `safe-to-deploy` audit with the limits
above recorded. This certifies the reviewed package, not its dependencies or
Chio's complete CMS verification composition. No exemption, criterion or
imported audit authority changes.

Evidence is retained in the primary checkout under
`output/process-security-20260915/cms-audit-9dc12ff1c/`: the original archive,
source hashes, selected feature graph, unchanged-source comparison, test output
and lint output.
