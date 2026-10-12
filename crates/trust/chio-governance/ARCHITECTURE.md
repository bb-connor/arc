# chio-governance architecture

## Responsibility and boundary

The crate owns operator-scoped charter and case artifacts plus verification
helpers for capability leases and destructive workflow receipts.
It re-exports `chio-listing` as `listing` and core canonical, crypto, and receipt
namespaces for envelope construction.

Evaluation returns evidence for local admission policy. It does not change a
registry, persist case transitions, revoke a capability, or execute an action.
The caller supplies trusted signer policy and enforces accepted case results.

## Structure

| Module | Responsibility |
| --- | --- |
| `generic` | Charter/case types, request validation, artifact builders, findings. |
| `evaluation` | Signature and identity checks, effective state computation. |
| `lease` | Capability lease contract and verification. |
| `authorization` | Destructive governance receipt and step boundary helpers. |
| `error` | Typed authorization errors. |
| `validation` | Internal text and digest checks. |

## Data and control flow

Generic builders validate issue requests before producing unsigned bodies.
Callers sign these bodies with `SignedExportEnvelope`.
`evaluate_generic_governance_case` validates the request, chooses its supplied
`evaluated_at` override or the `now` argument, and verifies carried signatures.

It matches charter and case to normalized listing namespace, listing ID, and
governing operator. It checks expiration, authorized case kinds, publisher and
actor scope, and references to activation or prior cases.
Freeze and sanction require a local trust activation with matching operator
and activation ID. Appeal and supersession require matching prior case targets.

Resolved, denied, and superseded cases produce a clear state.
Open or escalated cases can be disputed, appealed, frozen, or sanctioned without
blocking admission. Enforced freeze and sanction produce blocking results.

## Trust and invariants

`SignedExportEnvelope` verifies canonical body bytes against its carried key.
These helpers do not pin that key to `issuer`, `authorizing_kernel`, or a registry
operator. The caller establishes signer authority before using verified data.

Lease and destructive receipt verification reject future issuance and accept
only times strictly before expiration. Their digest checks accept 64 hex
characters; matching compares the supplied strings exactly.

`verify_destructive_authorization` binds lease ID, workflow ID, and step digest.
`verify_step_governance_boundary` checks the presence, contract, signature, and
lifetime of a receipt for destructive steps. It has no expected identity inputs
and performs no lease, workflow, or step comparison. Non-destructive steps
return success immediately.

Generic evaluation failures can be findings inside a successful Rust result.
Such results use clear state and `blocks_admission: false`; admission must check
the findings as well as the blocking flag. Evaluation does not fetch revocation
state or prove that the supplied activation remains current.

## Dependencies

`chio-core-types` supplies canonical signing envelopes and key operations.
`chio-listing` supplies listing and activation contracts and namespace
normalization. Serde encodes artifacts; `thiserror` defines authorization errors.
There are no crate-level Cargo features.

## Verification

Run `cargo test -p chio-governance` for enforced freezes, scope mismatch,
activation authority, invalid signatures, appeal/supersession, lease expiration,
and exact destructive receipt bindings.
`tests/integration_smoke.rs` exercises the public authority-scope validator.
The fixtures use local signed artifacts without network registry enforcement.
