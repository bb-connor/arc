# chio-web3 architecture

## Responsibility and boundary

The crate owns portable web3 artifact types and synchronous validators.
Its inputs cover identity bindings, contract packages, chain configuration,
checkpoint/anchor proofs, oracle conversion evidence, settlement dispatch and
execution receipts, and public-settlement bundles. It owns no RPC transport,
transaction sender, scheduler, or durable ledger.

Low-level validators check a particular artifact's shape and internal links.
`verify_public_settlement_proof` adds independently supplied trust and chain
observations. Applications collect those observations through their chosen
adapter and persist authoritative receipt/reconciliation state elsewhere.

## Structure

| Module | Responsibility |
| --- | --- |
| `identity` | Scoped key-binding certificates and canonical signature verification. |
| `anchors` | Versioned checkpoint/inclusion proofs and oracle evidence signatures. |
| `chain`, `contracts` | Chain deployment configuration and compiled contract package shape. |
| `settlement` | Dispatch, lifecycle receipts, execution and identity-evidence binding. |
| `settlement_proof` | Public proof verification and explicit verified-claim reports. |
| `settlement_proof_types` | Bundle, trust, snapshot, witness and event types. |
| `settlement_proof_event_validation` | Release/dispute event and registry snapshot checks. |
| `trust_profile`, `qualification` | Trust-profile shape and qualification-case inventory. |
| `validation`, `error` | Address/money/uniqueness checks and typed failures. |

Proof type/event modules are private children of `settlement_proof`; their
exported types are re-exported there. Other named artifact modules are public.
Shared canonical/crypto/Merkle/receipt modules and `credit` are re-exported.

## Data and control flow

`verify_anchor_inclusion_proof` validates proof/checkpoint version agreement,
shape, tree size, optional chain/super-root fields, and binding scope.
It verifies receipt, identity certificate, and reconstructed checkpoint-body
signatures, requires the same kernel key across them, and recomputes receipt
Merkle inclusion from canonical receipt body bytes.

`validate_web3_settlement_dispatch` binds capital instructions, optional bonds,
amounts, addresses, and completion-flow context. Execution-receipt validation
then binds lifecycle and observed execution to that dispatch. Optional anchor,
oracle, and identity-registry evidence receives its specific local checks.

`verify_public_settlement_proof` requires v2 dispatch/receipt schemas and a
trusted canonical bundle signature. It validates deployment provenance,
registry identity, order/amount context, chain/block snapshots, independently
provided chain head, finality, dispute posture/events, and public witness.
If oracle evidence is present, it must verify under the configured oracle pins.
The report lists only claims reached through successful checks.

## Trust and invariants

`verify_web3_identity_binding` checks schema, nonempty scope/purpose/identity,
unique entries, interval ordering, and the certificate's carried-key signature.
It accepts no current-time or independent-key argument. A caller must establish
key authorization, settlement-address ownership, and current validity separately.
Local anchor verification likewise does not query an external chain.

`PublicSettlementVerifierTrust` supplies bundle/capital/checkpoint/beneficiary
keys, runtime code hashes, verifier clock, expected policy/context, and
independent chain/event observations. Trusted inputs must come from outside
the submitted bundle. The verifier rejects missing trust pins and mismatched
runtime/deployment evidence. Carried finality assertions alone cannot replace
the independent chain-head checks.

Versioned checkpoint bodies preserve every signed field, including `chain_root`.
V1 forbids that field; v2 enforces covered-entry tree size and the first
checkpoint's chain-root commitment. Optional anchor/checkpoint fields reject
explicit JSON null where their custom deserializer applies.

`validate_web3_qualification_matrix` checks schema, identifiers, nonempty cases,
unique case IDs, and cited requirement IDs. It does not compare expected and
observed outcomes or establish current contract deployment acceptance.
Persistence order and transaction submission are responsibilities of the runtime
that consumes these artifacts.

## Dependencies

`chio-core-types` supplies canonical bytes, signatures, monetary amounts,
receipts, and Merkle primitives. `chio-credit` supplies capital instructions,
bonds, and exposure evidence. Alloy primitives supply Keccak hashing for EVM
operator key bindings. Serde/JSON define the wire records and signature-body
projections; `thiserror` supplies `Web3ContractError`.
`default` enables no extra features. Kani harnesses use `cfg(kani)`.

## Verification

Use `cargo test -p chio-web3`.
`tests.rs` checks artifact examples, oracle math/signatures, settlement bindings,
and public proof rejection. Anchor-versioning tests cover v1/v2 shape and
canonical round trips. Dedicated identity/event tests mutate registry evidence,
release/refund/dispute logs, deployment pins, and trust inputs.
The integration smoke test covers the public dispute-window shape.
Kani harnesses require their toolchain and are distinct from ordinary unit tests.

[README](README.md) · [Anchor runtime](../chio-anchor/README.md)
