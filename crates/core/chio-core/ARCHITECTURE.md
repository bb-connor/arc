# chio-core architecture

## Responsibility and boundary

The crate owns a unified Rust import surface and three local contract modules.
`src/lib.rs` re-exports portable primitives from `chio-core-types` and domain
APIs from appraisal, autonomy, credit, federation, governance, listing, market,
open-market, underwriting, and web3 crates.
Re-exporting preserves each dependency's implementation and error semantics.
The facade does not implement tool execution, receipt persistence, or runtime
admission for those domains.
Consumers needing the small portable substrate can depend on `chio-core-types`.
Local contract modules use standard-library collections.

## Structure

`extension/model.rs` defines inventory, stack, manifest, and qualification data.
`extension/validation.rs` checks structural rules and guardrails.
`extension/negotiation.rs` compares validated contracts and builds a report.
`extension/error.rs` preserves contract failure categories.
`identity_network/types.rs` defines public identity and wallet artifacts.
Its `validation.rs` and `validators.rs` check profiles, references, URLs,
binding policies, and routing guardrails.
`standards.rs` owns portable claim catalogs and identity/auth binding contracts.
Module-local tests exercise extension and identity validation.

## Data and control flow

A caller constructs or deserializes an artifact and invokes its validator.
Extension negotiation first validates the inventory, official stack, and custom
manifest, collecting malformed-input reasons into the resulting report.
It then resolves the named extension point and checks compatibility inputs.
The returned report describes compatibility; runtime policy activation remains
a separate responsibility.
Public identity profile validation checks declared methods and families before
accepting the profile's contract.
The canonical signing example uses a re-exported substrate API:
serialize the typed value, sign the canonical buffer, and retain both outputs.

## Trust and invariants

`validate_extension_inventory` forbids extensions from writing canonical truth.
It rejects duplicate IDs and missing allowed modes or privileges.
Evidence-capable modes require consistent local policy activation declarations.
`validate_public_identity_profile` requires `did:chio` provenance support
for subjects and issuers and at least one additional identity method.
Artifact validation establishes the rules checked by that function.
Callers still select trusted signers and verify signatures where required.
Typed canonical serialization assumes earlier parsing preserved the intended
value; strict raw JSON readers belong at untrusted signing boundaries.

## Dependencies

`chio-core-types` supplies canonical bytes, hashes, signing, and protocol data.
Dedicated domain crates supply their own artifact and evaluation surfaces.
Serde and serde_json support local serializable contract representations.
`url` supports identity endpoint validation; `thiserror` supplies local errors.
The `pq` feature forwards to the substrate and gates additional re-exports.
There is no facade feature for disabling `std`.

## Verification

`src/extension/tests.rs` and `src/identity_network/tests.rs` exercise local rules.
`tests/unknown_fields.rs` checks ignored members on receipts and the closed
capability and signed-manifest boundaries.
`tests/property_invariants.rs` exercises protocol invariant properties.
`benches/core_primitives.rs` measures canonicalization, signing, capabilities,
and Merkle operations through the facade.
Run `cargo test -p chio-core` for the default implementation.
Run `cargo test -p chio-core --features pq` for gated PQ coverage.
These checks validate crate behavior; runtime deployment acceptance requires
its own evidence.
