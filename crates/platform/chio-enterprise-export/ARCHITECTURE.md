# chio-enterprise-export architecture

## Responsibility and boundary

`EnterpriseExportBundle` supplies a transaction passport, scoped graph,
optional signed root graph, verifier policy, artifact map, and separate
trusted key sets for passport, receipt kernel, approval, and risk
authorities. `verify_enterprise_export` returns `EnterpriseVerifierReport`
and section references for governance, export, telemetry, approval, and
control mapping.

This verifier owns evidence consistency and selected authentication checks.
Storage retention, regional access enforcement, legal-hold enforcement,
actual export delivery, and telemetry emission occur in the producing
systems. Digest-bound governance claims remain supplied evidence.

## Structure

`lib.rs` composes the verification stages and report. `evidence.rs` parses
graphs, resolves roles, hashes artifact bytes, and authenticates risk
reports. `artifacts.rs` defines private
governance/export/approval/telemetry/control shapes and domain checks.
`policy.rs` parses enterprise required claims; `claims.rs` names supported
family claims. The lib test target is disabled; integration tests exercise
the composed entrypoint.

## Data and control flow

Verification bounds graph, policy, root, and artifact inputs before work. It
authenticates the passport against selected root keys, allowing a literal
scoped subset of the signed graph, then checks minimal graph/policy
commitments. Enterprise graph role lookup obtains required section artifacts
and all risk reports.

Risk reports undergo signature, consistency, evidence-reference, and
portfolio checks. Section references select their risk report. The verifier
checks governance, recomputed export index digest, telemetry, approval, and
controls, then ensures supported required family claims were established
before building the report.

## Trust and invariants

Artifact bytes must match graph digests and expected schemas before
projection. Risk authorities, receipt kernels, and approval signers use
separately supplied pin sets. Governance checks compare allowed/observed
region, legal-hold status, retention floor, and field-classification export
actions. These fields describe supplied system evidence.

Export artifacts include required roles and an index digest over canonical
role/path/hash entries. Approval must bind that digest, meet a positive
quorum of distinct identities, and have a coherent validity window. Export
issuance must fall within the approval window; the check uses artifact
timestamps. Telemetry receipts are authenticated and content-bound. Control
claims must resolve to appropriate evidence gate roles.

## Dependencies

`chio-transaction-passport` supplies root authentication, strict
original-byte decoding, budgets, and minimal proof checks.
`chio-risk-comptroller` supplies report/portfolio/reference validation.
`chio-core-types` supplies signatures, receipts, canonical bytes, and
hashes. `chrono` compares evidence timestamps; `serde`/`serde_json` project
strict artifacts. No optional features are declared.

## Verification

`tests/enterprise_export.rs` constructs a signed valid bundle and mutates
approval, governance, export digests, telemetry, controls, and risk
accounting. Its `original_input.rs` cases cover oversized artifact
collections and schema-only telemetry receipts. Run `cargo test -p
chio-enterprise-export --test enterprise_export`. The README intentionally
exercises missing root-pin rejection with a compile-time passport fixture;
it performs no enterprise operation and establishes no complete-bundle
success claim.
