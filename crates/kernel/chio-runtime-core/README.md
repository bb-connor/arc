# chio-runtime-core

`chio-runtime-core` is the implementation crate behind Chio's live runtime admission layer: kernel-mediated admission, trust-floor enforcement, treaty and swarm evidence verification, buyer-attestation review, and orchestration bookkeeping for cross-vendor, cross-kernel workflows. It implements `chio_kernel::RuntimeAdmissionHook`, the extension point `chio-kernel` calls into during tool-call dispatch to decide runtime-level admission. `chio-runtime` is the public facade over this crate and the one most callers should depend on; `chio-kernel-core` is an unrelated crate, the portable single-request capability/scope/guard evaluation kernel.

## Responsibilities

- Evaluate a runtime admission request (`evaluate_runtime_admission`) against a `RuntimeAdmissionProfile`, an admission bundle, a runtime trust bundle, and an optional pheromone-policy decision, returning a structured, receipt-embeddable `RuntimeAdmissionReport`.
- Implement `ChioRuntimeAdmissionHook`, the `chio_kernel::RuntimeAdmissionHook` the kernel calls: extracts `chioAdmission` / `chioTreaty` / `chioSwarm` governed-intent context from a tool-call request, verifies treaty and swarm-authority evidence against a store, and reserves/releases destructive leases and continuations.
- Own the federation treaty and governance-ladder data model and validators: treaty scope, governance ladder manifest, ladder intersection, cross-boundary admission, receipt lineage, bilateral invocation.
- Verify buyer-attestation packets and the 14-artifact buyer-attestation review package end to end (lineage, continuation, admission report, bilateral invocation/DSSE, workflow and proof-regeneration reports, evidence manifest).
- Build and validate orchestration artifacts: run contracts, orchestration plans, run/resume/status reports, run leases, scheduler ticks, recovery drills, evidence-sink health, proof-drift and proof-parity reports, provider health, artifact retention plans.
- Provide four `RuntimeAdmissionStore` backends behind one trait (in-memory, JSON file, SQLite, plus a JSON trust-floor-only store), and a `LayeredRuntimeAdmissionStore` that composes an admission store with a separate trust-floor store.

## Public API

| Area | Key items |
|------|-----------|
| Admission | `evaluate_runtime_admission`, `RuntimeAdmissionInput`, `ChioRuntimeAdmissionHook` |
| Buyer attestation | `verify_buyer_attestation_packet`, `verify_buyer_attestation_review_package`, `verify_buyer_attestation_review_package_with_trust`, `verify_receipt_lineage_bundle` |
| Treaty / federation | `evaluate_cross_boundary_admission`, `compute_ladder_intersection`, `validate_treaty_scope`, `validate_governance_ladder_manifest`, `validate_ladder_intersection`, `validate_cross_boundary_admission_report`, and `*_sha256` binding helpers |
| Orchestration | `build_runtime_orchestration_plan`, `load_runtime_orchestration_evidence`, `validate_runtime_orchestration_evidence_binding`, `validate_runtime_orchestration_evidence_integrity`, `RuntimeOrchestrationEvidence` |
| Ops | `generate_runtime_artifact_retention_plan`, `generate_runtime_evidence_sink_health_report`, `generate_runtime_provider_health_report` (+ `_with_model_cards` / `_with_model_card_evidence`), `generate_runtime_proof_drift_report` |
| Stores | `InMemoryRuntimeAdmissionStore`, `JsonRuntimeAdmissionStore`, `SqliteRuntimeOrchestrationStore`, `JsonRuntimeTrustFloorStateStore`, `LayeredRuntimeAdmissionStore`, traits `RuntimeAdmissionStore` / `RuntimeTrustFloorStore` |
| Serde I/O | Matched `*_from_json` / `*_json` pairs for every artifact type; `sign_runtime_admission_report`, `verify_signed_runtime_admission_report` |
| Validation | `validate_runtime_*` for every profile, plan, and report type |
| Types | `Runtime*`, `BuyerAttestation*`, and treaty/federation structs (`types.rs`); `CHIO_RUNTIME_*_SCHEMA` constants and `CHIO_RUNTIME_FAILURE_CODES` (`schema.rs`) |
| Errors | `ChioRuntimeError` |

## Usage

```rust
use chio_runtime_core::{ChioRuntimeAdmissionHook, InMemoryRuntimeAdmissionStore};

let hook = ChioRuntimeAdmissionHook::new(profile, InMemoryRuntimeAdmissionStore::new())
    .with_runtime_trust_input(runtime_trust_bundle, trusted_verifier_keys);
// register `hook` with the kernel as a `chio_kernel::RuntimeAdmissionHook`
```

## Treaty presentation records

Live bilateral admission requires locally activated records for the lease and
governance identifiers in its admission bundle. Older stores containing only
the identifiers fail closed until the receiver provisions these records:

| Artifact kind | Artifact id | Record type |
| --- | --- | --- |
| `capability_lease` | `lease.lease_id` | `RuntimeTreatyLeaseRecord` |
| `governance_receipt` | `receipt.receipt_id` | `RuntimeTreatyGovernanceRecord` |

Use the existing `insert_treaty_runtime_artifact` API on the receiver's trusted
provisioning path. A lease record pins its issuer, optional scope digest, and
expiry, with a local activation start. A governance record pins the verified
receipt's issuer and digest with a local validity interval. These are local
activation records, not a new credential that an incoming request may install.
The governance reference alone does not prove that its receipt is authentic;
provisioning must validate that receipt under the receiver's policy.

To revoke an activation, insert an artifact of kind
`capability_lease_revocation` or `governance_receipt_revocation` under the same
identifier. The payload can record the operator's reason; its presence closes
the activation. The default store implementation checks this tombstone on every
resolution, including after SQLite reopen, and immutable artifact insertion
prevents widening an existing activation. Renewal uses a new activation
identifier and a new admission bundle. Custom store implementations must preserve these
fail-closed semantics.

The hook checks the intersection of treaty, continuation, lease, and governance
validity at admission and again during dispatch revalidation. A statement may
shorten its lease expiry but cannot extend the receiver's issuer window. These
are point-in-time checks, not a transaction with an external revocation service.

## Experimental outcome continuations

`outcome_continuation` adds receiver-owned, single-use effect slots backed by
SQLite. A trusted provisioning path activates an `OutcomeEffectRule` that pins
a workflow step, predecessor, verifier key, test-contract digest, target tool,
resource, and validity interval. Signed artifact outcomes can satisfy that
rule; they cannot provision or change it. Slot identity excludes candidate
artifact, evidence, request, capability, and agent identifiers.

Call `preview_outcome_effect` for a non-consuming check and
`claim_outcome_effect` at the protected tool's final dispatch boundary. The
latter verifies current state and commits the claim in one immediate SQLite
transaction before the external effect. Register only the protected adapter
with the kernel. This API does not automatically gate other registered tools.
Kernel capability, guard, and runtime admission checks remain necessary.

`complete_outcome_effect` records the trusted adapter's result. A crash or
ambiguous error after claiming leaves `DispatchClaimed`, including when no
effect happened. No timeout, fresh agent, re-signature, or identical rule
activation resets it. Revocation prevents new claims; it does not undo effects
already authorized. External writes and kernel receipts are outside this
SQLite transaction. The result record is not a signed kernel receipt or a
proof of external truth. Rollback or cloning of the trusted database is outside
this local guarantee.

Run the native capability-policy repair demonstration:

```bash
cargo run --locked -p chio-runtime-core --example outcome_artifact_workflow
```

It writes a reviewable scope artifact, owner-selected contract, verification
evidence, kernel receipts, and summary to a fresh temporary directory. Two
local kernels verify and publish; a replacement agent cannot publish twice.
The scope verifier parses data and uses Chio's attenuation validator. It never
executes proposed code. This is an experimental local composition, with no
claim of remote deployment or advantage over a matched durable ledger.

The same example accepts `--verify DIRECTORY PUBLISHER_PUBLIC_KEY
VERIFIER_PUBLIC_KEY` to check an exported run without starting kernels. Supply
trusted keys independently of the bundle. The checker recomputes the native
scope contract and verifies the outcome, effect claim and both kernel receipts.
It checks artifact bindings, not global non-duplication.

## Testing

`cargo test -p chio-runtime-core`

## See also

- `chio-runtime` - the public facade; wraps this crate's error type and re-exports a narrowed admission/orchestration/validation surface (no buyer attestation, no treaty/federation, no store trait).
- `chio-kernel` - supplies the `RuntimeAdmissionHook` trait, `ToolCallRequest`, and `KernelError` this crate implements against.
- `chio-kernel-core` - unrelated: the portable `no_std + alloc` single-request evaluation and receipt-signing kernel.
- `chio-swarm-authority` - supplies `SwarmAuthorityBundle` and the delegation-chain verification the swarm admission path calls.
- `chio-federation` - supplies `bilateral_dsse` / `bilateral_verifier` used by treaty and buyer-attestation verification.
- `chio-attest-buyer-core` - supplies proof-package/trust-bundle parsing and `verify_package_report` used by buyer review verification.
- `chio-runtime-proof-parity` - supplies the `RuntimeProofParityReport` type and validator re-exported here.
