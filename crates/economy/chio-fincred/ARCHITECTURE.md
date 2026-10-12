# chio-fincred architecture

## Responsibility and boundary

This crate owns wire-neutral financial credential contracts shared by issuers
and verifiers. Its public surface consists of schema constants, family and
subject enums, policy structures, source evidence structures, and signed
source-envelope aliases. The implementation has no network, storage, policy
evaluation, or financial source verification service.

The five families are credit scorecard, exposure history, settlement
reliability, premium history, and loss history. Issuance projections in
`chio-credit` and credential consumers in `chio-credentials` reuse these types
so their field names and identity domains agree.

## Structure

`lib.rs` holds the public contract definitions. The private `domains` module
exports two byte-string digest domains and contains the shared-identifier
fixture test. There are no optional Cargo features.

`FinancialVerifierPolicyV1` carries tenant and verifier identity, accepted
issuers and families, thresholds, maximum age, a validity interval,
configuration generation, and body digest. Thresholds include score,
exposure ratio, settlement reliability, loss count, and premiums by currency.
These fields describe a policy without evaluating it.

`FinancialCredentialSubjectV1` tags each subject with its family. Scorecard
subjects carry band, confidence, score, probation, and imported-signal counts.
Exposure subjects carry positions containing governed, reserved, settled,
pending, failed, loss, and recovered amounts. Settlement subjects carry counts
and an on-time basis-point ratio. Premium and loss subjects carry their
corresponding event counts and monetary lists.

## Data and control flow

A caller builds a subject variant and obtains its identity through `id()` and
its family through `family()`. Family methods supply a schema, label, and
credential type; `from_schema` maps recognized schema strings back to variants.
Serde serializes the subject with `family` and `claims` fields.

`FinancialCredentialEvidenceV1` combines a time window, a source disclosure,
and signed completeness attestations. Disclosure is either bundled canonical
artifact strings or resolver references. Each artifact is labeled as a claim
or member and carries a schema and digest.

Source members bind a query key to canonical artifact content. Checkpoints
carry authority epoch and key, store generation, sequence, cutoff, window,
index size, roots, and lower/upper completeness boundaries. Attestations bind
those values to a subject and family, committed leaf proofs, artifact digests,
a disclosure digest, validity times, and an evidence class.

## Trust and invariants

Serde contracts use camelCase fields and reject unknown fields. Enums use
explicit snake_case tags. BTreeMap and BTreeSet give policy collections an
ordered representation. None of these mechanisms proves that a schema field,
amount, ratio, digest, window, or authority declaration is semantically valid.

`SignedFinancialSourceMemberV1`, `SignedFinancialSourceCheckpointV1`, and
`SignedFinancialSourceCompletenessAttestationV1` are aliases over the shared
signed envelope. Constructing or decoding them does not pin a trusted signer,
verify completeness, or grant credit. Those checks belong to consumers that
have authenticated source and policy context.

The exported artifact and disclosure domains terminate with a NUL byte.
Digest consumers must use the exact domain bytes and canonical payload.
`MAX_I_JSON_SAFE_INTEGER` names the portable integer limit; merely storing a
`u64` in these public structs does not enforce that limit.

## Dependencies

`chio-core-types` supplies `MonetaryAmount`, public keys, provenance evidence
classes, and `SignedExportEnvelope`. Serde supplies derived serialization and
deserialization. `serde_json` is a development dependency for fixture tests;
the runtime type crate does not choose a JSON transport implementation.

## Verification

`cargo test -p chio-fincred` runs the identity fixture test in `domains.rs`.
It loads `spec/fixtures/shared-security-identifiers.json`, recomputes canonical
payload bytes, prefixes each exported domain, and checks the SHA-256 digest.
The README sample exercises subject helpers and Serde round-tripping.

Source proof authentication, completeness, policy thresholds, and credential
presentation are checked in downstream crates. This crate's fixture test
checks the shared digest identities and their canonical example preimages.
