# chio-finding-verifier architecture

## Responsibility and boundary

`verify_finding_evidence` accepts raw finding JSON, `FindingVerifierTrustRoots`,
and a `FindingEvidenceBundle`. It produces a `FindingVerifierDraft` whose
finding, facets, and evidence commitments have read-only accessors.
`sign_finding_verifier_report` serializes that evaluation into an authority-signed
report. A venue admission remains a separate market artifact.

Resolution belongs to the caller: this verifier does not fetch receipts,
checkpoint transparency records, replay attachments, status feeds, or bond
state. Trusted time and snapshot digests are explicit inputs. A verifier report
records the evaluated inputs and cannot supply its own deployment trust roots.

## Structure

| Module | Responsibility |
|--------|----------------|
| `verify` | Trust inputs, thirteen facets, raw ingress, report signing |
| `verify/draft` | Read-only accessors and required-facet acceptance |
| `verify/bond` | Requirement and collateral-authority verification |
| `receipts` | Embedded-key strict receipt authenticity |
| `checkpoints` | Signed log, transparency, full inclusion-wrapper binding |
| `cost` | Nonce resolution, metered exposure and settled spend |
| `error` | Typed ingress, profile, authority, and report failures |

## Data and control flow

1. Bound raw finding size, canonicalize strictly, compare original bytes, and
   deserialize with an additional typed-canonical equality check.
2. Require authenticated governance standing, the pinned profile signature,
   supported semantics, active profile/finding windows, and admitted kernel keys.
3. Enforce independent verifier, collateral, fee-schedule, status, attestation,
   and appraisal roles at the relevant checks.
4. Evaluate ordered facets for artifact integrity, receipt authenticity,
   checkpoint membership, kernel/revocation trust, issuer lineage, recipe and
   intent binding, metered exposure, settled spend, runtime assurance, bond,
   status liveness, and guarantee consistency.
5. Commit the resolved evidence bundle and attachment digests into the draft.
6. Sign a report only under the same evaluated profile and its live report key.

Production receipt references are compared in order and cardinality. Optional
post-purchase delivery evidence has a separate checkpoint path because a
finding's publication cannot commit a later delivery receipt.

## Trust and invariants

`verify_receipt_strict` proves authenticity against the embedded kernel key.
It supplies neither external key authorization nor lifecycle standing.
`verify_checkpoint_membership` verifies full wrapper offsets, both leaf indexes,
tree size, checkpoint identity, canonical envelope leaves, profile log pins,
signatures, and transparency. Its public helper does not add the full verifier's
production issuance ceiling or fresh signer-status context.

The full production path checks checkpoint existence at finding issuance and
fresh independently signed receipt/checkpoint standing at evaluation.
Status liveness uses a separately authorized status operator, freshness policy,
and exact raw portable proof attachment. Runtime assurance requires separately
pinned attestation/appraisal authorities and a local trust policy.

A bond facet needs authority-signed allocation, terms, fee schedule, and a fresh
signed store snapshot that binds the exact allocation. A seller boolean cannot
establish collateral liveness. Missing evidence yields an unavailable or failed
facet according to the check; every failed facet denies acceptance, and required
facets must be verified. Optional assertions remain visible in the report.

## Dependencies

`chio-finding` owns artifact schemas, required facets, and status-proof checks.
`chio-kernel` supplies checkpoints and transparency primitives.
`chio-core-types` supplies canonical JSON, strict signatures, and receipt
semantics. `chio-fiscal` supplies signed fee schedules; `chio-appraisal` supplies
runtime attestation appraisal and effective assurance evaluation.

## Verification

Run `cargo test -p chio-finding-verifier` from the workspace root.
`tests/verifier.rs` builds real signed findings, receipts, and checkpoints.
Its regression modules exercise authority separation, bond timing, inclusion
wrapper tampering, status freshness, and revoked or expired receipt signers.
The README runs embedded-key receipt verification only; full finding evaluation
requires the resolved bundle and external authority configuration above.
