# chio-transaction-passport architecture

## Responsibility and boundary

`TransactionPassport` carries root identity, optional validity bounds,
self-certifying issuer, graph/claim-set/policy digests and relative paths,
omission policy, and signature. `TransactionVerifierReport` records
machine-readable result state, claims, and transparency state. Report
constructors create data; callers use actual verifier entrypoints to
establish evidence.

Root-signature entrypoints require independently selected `PublicKey` pins.
Runtime-security and cognition-market verifiers accept additional
deployment-owned evidence and trust objects. This library evaluates supplied
artifacts, with caller-owned persistence only through explicit status-store
interfaces.

## Structure

`minimal.rs` handles root schemas, validity, signatures, scoped graph
subsets, claim-set bindings, omissions, and transparency tiers.
`evidence_graph.rs` validates graph/claim artifacts and domain bindings.
`verifier_policy.rs` validates selected claims and gates. `input.rs` owns
original-byte budgets and decoding; `validation.rs`, `ids.rs`, `types.rs`,
and `error.rs` hold shared helpers and vocabulary.

`runtime_security.rs` and its private submodules evaluate execution leases,
acknowledgments, trusted time, revocation, sandbox, and terminal evidence.
`cognition_market.rs` evaluates Finding, profile, purchase, and status
evidence with deployment trust.

## Data and control flow

`sign_transaction_passport` requires the issuer key to match the signing key
and signs the canonical body without the signature field. Signature
verification checks root shape/validity, nonempty trusted pins, issuer
membership, and signature validity. The graph-aware signature function
authenticates the signed root graph and checks that a disclosed graph is a
literal node/edge subset.

`validate_transaction_evidence_graph` checks graph identity, node ID/digest
agreement, bounds, references, cycles, and advisory authority edges. It
accepts a lighter JSON projection than the typed artifact-verification
paths, which also validate node roles, schemas, and paths.

Artifact entrypoints check digests and decode the committed documents,
validate graph/policy/claim bindings, and return a report. Root and
claim-set verification adds authentication and loaded artifact bytes.
External claim variants accept caller-supplied family results, whose origin
the caller must verify.

## Trust and invariants

Original JSON decoding is bounded to 16 MiB/document; bundle work is bounded
to 64 MiB and 4096 documents. Graph traversal has independent node/edge
limits. These checks establish input admissibility before signature/domain
evaluation.

`verify_minimal_passport_artifacts` validates commitments and policy shape
without verifying the root signature. Explicit unchecked-signature functions
likewise need authenticated upstream context. Root issuer pins and
checkpoint signer pins are separate in `TransactionTrustAnchors`; anchored
transparency requires checkpoint evidence and independent keys. Schema
validity defaults to `Utc::now`; the `_at` helper uses supplied time.
Cognition-market status trust includes an authenticated operator envelope,
checked time, freshness policy, and a caller-owned state store that prevents
status rollback.

## Dependencies

`chio-core-types` supplies canonical JSON, cryptographic keys, Merkle
proofs, and original JSON boundaries. `chio-finding`,
`chio-finding-verifier`, and `chio-open-market` supply authenticated
Finding/profile/purchase evidence. `chrono` parses validity and evidence
times; `sha2`/`hex` compute commitments, and serde represents artifact
types.

## Verification

Integration tests cover root tampering/untrusted signers, claim-set digest
checks, graph closure/cycles, transparency anchor cases, runtime bindings,
cognition-market profile governance, status floors, and delivery evidence.
`original_input.rs` covers duplicate fields, lossy numbers, byte budgets,
and deep graph traversal. Run `cargo test -p chio-transaction-passport`. The
README verifies a local root signature under default features; it does not
claim artifact closure.
