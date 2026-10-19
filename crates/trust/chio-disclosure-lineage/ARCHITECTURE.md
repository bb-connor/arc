# chio-disclosure-lineage architecture

## Responsibility and boundary

The crate owns typed capsule, lineage, ledger, privacy-profile, crypto-context,
and verifier-report artifacts. Its public bundle verifier accepts these supplied
objects and a `DisclosureLineageVerifierTrust` containing pinned signer keys.

Its proof boundary is signed artifact consistency. A crypto-context report
carries a producer's verified verdict and claims. This crate authenticates that
report and binds its references; BBS proof computation lives in the sibling
selective-disclosure crate.

## Structure

| Source | Responsibility |
| --- | --- |
| `src/types.rs` | Strict Serde artifact shapes, schema constants, verdicts, errors. |
| `src/verifier.rs` | Digests, signatures, graph and privacy checks, report assembly. |
| `src/lib.rs` | Re-exports the public artifact and verifier surface. |
| `tests/disclosure_lineage.rs` | Signed fixtures and adversarial bundle mutations. |

There are no Cargo feature switches. The library unit-test target is disabled;
integration tests exercise the exported surface.

## Data and control flow

The bundle verifier validates capsule and profile, checks lineage and ledger,
binds their references, applies reveal policy, and verifies leakage coverage.
It then authenticates the required crypto-context report and returns a report
containing counts and the accepted claim identifiers.

Lineage validation checks unique nodes, roots, edges, declared parent closure,
increasing depths, maximum depth, supported kinds, and node evidence floors.
It checks redaction reasons, recomputes frontier and subgraph digests, and
verifies the subgraph signature against the trusted lineage keys.

Ledger validation checks classification, duplicate entries, audience, total
score, maximum score, and residual-inference notes for sensitive entries.
Coverage requires entries for each disclosed field and hidden predicate.
When either is present, three derived crypto facts must also be recorded.

## Trust and invariants

Lineage signing covers the SHA-256 digest of canonical selected subgraph fields.
The signature string carries a key and signature under `sig-ed25519:`.
Crypto-context signing clears its signature field and signs canonical report
bytes. Empty trust lists accept no signer.

Node artifact and source-ID digests are hashes of `receipt_ref` strings.
Edge digests hash edge IDs and `from|to|kind` strings. Checkpoint inclusion is a
hash of `checkpoint_ref|frontier_sha256`. These checks do not load receipt bodies
or authenticate an external Merkle checkpoint.

The evidence floor applies to nodes. Edge evidence labels are checked against
supported values, without applying that floor to each edge.
The accepted labels are `asserted`, `observed`, `verified`, and `derived`.

The hidden-predicate validator recognizes the fixed `amount_lte_100` descriptor,
including USD, slot 2, and a true result. It checks descriptor equality without
computing a cryptographic range proof.
Profile key, epoch, timing, replay, and transparency requirements need a trusted
crypto-context producer; this verifier does not retrieve those inputs.

## Dependencies

`chio-core-types` supplies canonical bytes, SHA-256, and signature primitives.
Serde rejects unknown artifact fields; semantic checks remain in the verifier.
`thiserror` exposes `DisclosureLineageError::InvalidArtifact` and, for a recomputed
digest that does not match, `DisclosureLineageError::DigestMismatch`, each with failure detail.

## Verification

Run `cargo test -p chio-disclosure-lineage --test disclosure_lineage` for budget,
sensitivity, reference, depth, digest, redaction, trust, and signature cases.
Fixtures test supplied graph consistency and report signatures. Source receipt
validation and externally authenticated checkpoint membership need integration
at the consumer boundary.
