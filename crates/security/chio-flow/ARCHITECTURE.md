# chio-flow architecture

## Responsibility and boundary

The crate owns label comparisons, taint joins, classification-result binding,
and declassification-grant validation. `InformationFlowLattice` implements the
security-types label order. `authorize_egress` evaluates one destination.
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

Unit tests in the four modules cover lattice laws, label overflow, classification
locations and rebinding, grant tampering and replay, and fence/state mismatch.
Run `cargo test -p chio-flow --lib` for the default surface and
`cargo test -p chio-flow --features std` for the standard-library composition.
The README example uses default-feature `authorize_egress` and joins only.

[README](README.md) | [Manifest contract](../../../spec/PROTOCOL.md#7-manifest-contract)
