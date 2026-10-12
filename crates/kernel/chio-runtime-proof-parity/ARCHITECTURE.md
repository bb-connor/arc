# chio-runtime-proof-parity architecture

## Responsibility and boundary

This crate owns typed parity report schemas and consistency validation for
runtime proof regeneration artifacts. `RuntimeProofParityReport` and
`RuntimeProofParityMismatch` describe declarations. `RuntimeProofRegenerationArtifacts`
borrows seven byte slices, allowing the caller to retain artifact ownership.
The two public validators return `RuntimeProofParityError::Rejected` with a
stable code and a detail string when a checked condition fails.

The boundary is evidence consistency. Callers supply artifacts and obtain
trusted provenance themselves. Validation does not invoke a proof engine,
verify workflow signatures, fetch evidence, or grant runtime authority.
Proof-model conclusions and actual host enforcement require their own evidence.

## Structure

`src/lib.rs` reexports schema constants from shared core types, defines report
records and errors, and implements both validators. Private helpers enforce
schema tags, fields, hash syntax, canonical hashing, manifest binding, and
workflow-step matching. `src/tests.rs` contains fixtures and regressions.
The crate has no Cargo feature switches and no platform-specific modules.

## Data and control flow

`validate_runtime_proof_parity_report` receives an already decoded report.
It validates schema, four lowercase 64-character hashes, acceptance/failure-code
consistency, and a nonempty compared-fields collection. Accepted reports must
have equal static/runtime package hashes, equal verifier-report hashes, and
no mismatches. Each mismatch requires a nonblank field and two valid hashes.

`validate_runtime_proof_regeneration_artifacts` parses four JSON records,
checks their schema tags and matching nonempty run IDs, and requires accepted
regeneration and workflow reports without failure-code fields. It computes
canonical JSON hashes for reports, manifest, proof package, verifier report,
and workflow receipt, then checks their declared cross-links.

The source-record arrays in the input and report must match. Every source
record must identify a workflow step and match its admission report, tool
receipt, bilateral DSSE, and workflow-step binding strings. Required arrays
must be nonempty. Required manifest roles are found by role and compared to
raw byte SHA-256 hashes and byte counts for supplied artifacts.

## Trust and invariants

Typed parity structs use camelCase Serde names and deny unknown fields.
The regeneration path parses generic JSON values with serde_json and checks
specific fields; this path does not promise duplicate-key rejection or a
closed vocabulary for every evidence record.

Canonical hashes bind decoded JSON content; manifest entry hashes bind exact
bytes. These checks have different purposes and both must remain coherent.
Parity report validation checks declared hashes without receiving the underlying
packages. Bundle validation recomputes selected hashes but cannot establish
that a proof verifier executed honestly or that a workflow signer is trusted.

The parity validator does not validate `run_id` contents, timestamp freshness,
or individual compared-field strings. Callers apply any required policy to
those fields. A rejected parity declaration can be structurally valid and
return success from validation; consumers must inspect its `accepted` flag.

## Dependencies

`chio-core-types` provides schema constants, canonical JSON bytes, and SHA-256.
Serde derives the typed wire records. serde_json supplies the generic evidence
value tree. thiserror formats the stable rejected error surface.
All evidence is supplied in memory; no persistence or network layer is owned
by this crate.

## Verification

Tests exercise uppercase digest rejection, accepted package-hash drift,
a valid regeneration bundle, source/workflow binding mismatch, omitted binding
hash fields, accepted reports carrying failure codes, and run-ID mismatch.
Fixtures synthesize JSON and hash links to check validator behavior.

```bash
cargo test -p chio-runtime-proof-parity
```

These regressions establish the checked consistency rules when executed.
They do not execute a theorem prover or qualify the host runtime's isolation,
receipt persistence, or authorization enforcement.
