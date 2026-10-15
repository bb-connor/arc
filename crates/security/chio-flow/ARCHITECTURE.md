# chio-flow architecture

## Responsibility and boundary

The crate owns label comparisons, taint joins, classification-result binding,
and declassification-grant validation, including recovery authority coverage.
`InformationFlowLattice` implements the security-types label order. `authorize_egress` evaluates one destination.
`prepare_pre_invocation` produces `PreparedFlowAdmission`; its public admission
contains a `FlowJoinRequest` and an optional `EgressFencePlan`.

The runtime supplies resolved identities, stored labels, operator floors,
manifest declarations, clearances, trusted authorities, and clock observations.
It also owns persistence, connector entry, and output delivery. A successful
admission calculation alone installs no network control or durable taint.

## Structure

- `lattice.rs` implements joins and explicit egress rejection reasons.
- `engine.rs` combines request state, policy, manifests, and verified grants;
  it prepares fences and evaluates post-invocation taint.
- `classification.rs` maps bounded classifier categories into labels and
  exposes immutable `VerifiedClassification` evidence when `std` is enabled.
- `declassification.rs` hashes canonical request and label representations,
  verifies signed grants, and records one-shot consumption and dispatch outcomes.
- `recovery_authority.rs` authenticates reviewed actions and conjunctive issuer
  coverage, then binds recovery grants to that verified context.

The default library is `no_std` with `alloc`. Classification, post-invocation
processing, and store-backed grant consumption require `std`. Grant verification
and pure label operations remain exported without that feature.

## Data and control flow

Pre-invocation evaluation joins payload label, operator input floor, and the
principal, lineage, and session labels. Effective egress is the union of the
runtime's egress flag and the manifest's declaration. Egress requires at least
one policy clearance and checks every supplied policy clearance. A manifest
input clearance is checked when present.

`ResolvedFlowRequest::observed_input_taint` supplies a transition for input the
principal already observed, including when subsequent egress checks reject.
An unrepresentable observed-input join becomes `Top`; admission independently
rejects the overflowing join. Callers must retain this taint on denial.

A verified grant changes the label evaluated for egress while preserving the
original taint transition. `PreparedFlowAdmission::into_admission` refuses a
pending grant. With `std`, `consume_declassification_at` checks a fresh time
observation before invoking `DeclassificationUseStore::consume`.

After the taint transition is persisted, `prepare_egress_fence` compares its key
and joined label with the admission and uses the persisted context generation.
The caller acquires and enforces that fence through its runtime store.

Post-invocation evaluation validates classifier tenant, request, and payload
bindings, then joins classification with state, operator output floor, and
optional manifest output label. Overflow becomes `Top` in this output join.

## Trust and invariants

`authorize_egress` rejects `Top` at both ends and missing clearances.
`verify_declassification` binds capability, tenant, subject, agent, session,
request hash, source-label hash, destination, tool, and purpose to a trusted
signature and validity window. Policy and manifest must permit the purpose;
the target must be a strict downgrade. Pre-invocation preparation rechecks
current bindings, authority membership, purposes, and time.

Recovery verification recomputes the canonical action and requirements digests
and checks the action's scope, source basis and embedded requirements against
independently selected inputs. The grant must match the action-derived binding,
approval, coverage window and native expected binding. The native isolation
epoch is selected independently because an unsigned action may carry epoch zero.

Coverage requires exactly the owner and compartment releases derived from the
source-to-target restriction change. Endorsement and user acceptance are distinct
authority classes. Each attestation must bind the same action, review, challenge,
requirements, scope and basis, and match an operator-installed issuer, principal,
key and obligation assignment. Duplicate principals or issuers refuse. A key
confers no assignments by itself; the operator determines which principals and
obligations each issuer may represent.

The coverage digest uses the `AuthorityCoverage` domain over canonical signed
attestations ordered by principal, then issuer. At most 16 attestations and 64
obligations are admitted. Before each signature and per-obligation allocation,
checked arithmetic charges 32 work units per attestation, 3 per attested obligation
and one per assigned obligation. Cumulative work above 4096 refuses.

Verified coverage may be reused within its validity window; it provides no
one-shot execution authority. Retained verification uses the same bounded v1
shape at an independently authenticated preparation time and returns only a
digest. Native materialization, authority freshness and grant consumption remain
caller responsibilities.

`CategoryLabelMap` holds at most 256 categories and disallows `Top` mappings.
Classification verification hashes the actual payload and checks classifier
identity/version, result bindings, confidence, and exactly one finding location.
Byte ranges must be nonempty and in bounds. Field paths resolve through one
lazy, strict signed-JSON decode of a payload bounded to 16 MiB.

One-shot atomicity and outcome durability belong to `DeclassificationUseStore`.
The crate rejects returned replay and storage failure outcomes; it contains no
concrete durable implementation of that trait.

## Dependencies

`chio-security-types` supplies labels, manifests, bounded inputs, and port
contracts. `chio-core-types` supplies canonical JSON and signed grants.
`sha2` binds classifier requests to payload bytes; `serde_json` supports field
path lookup after strict decoding. `proptest` generates lattice test cases.

## Verification

Unit tests cover lattice laws, label overflow, classification
locations and rebinding, grant tampering and replay, and fence/state mismatch.
Recovery integration tests cover conjunctive coverage, action and grant binding,
retained-time verification, bounded work and exact refusal errors. Compile-fail
doctests check that retained digests and wire data cannot forge coverage.
Run `cargo test -p chio-flow` for the default surface and
`cargo test -p chio-flow --features std` for the standard-library composition.
The README example uses default-feature `authorize_egress` and joins only.

[README](README.md) | [Manifest contract](../../../spec/PROTOCOL.md#7-manifest-contract)
