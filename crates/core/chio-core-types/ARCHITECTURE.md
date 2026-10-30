# chio-core-types architecture

## Responsibility and boundary

This crate owns shared protocol representations and their data/crypto helpers.
Its public surface includes capability tokens, scopes, receipts, manifests,
session messages, canonical JSON, signing backends, hashes, and Merkle proofs.
It also exports shared evidence families consumed by runtime and domain crates.
The implementation is `no_std + alloc` when default features are disabled.
The default `std` feature enables hosted dependency features and error derives.
The substrate does not own a runtime, durable database, or trusted issuer set.

## Structure

`canonical.rs` implements serialization and immutable canonical-byte witnesses.
Its `signed_json.rs`, `untrusted.rs`, and `secret.rs` support distinct parsing
and secret-buffer paths.
`crypto.rs` and `crypto/` implement backends, encoding, and verification helpers.
`capability/` splits scope, token, attenuation, validation, approval, identity,
and trust-policy concerns into separate modules.
`receipt/` splits bodies, decisions, signing, validation, metadata, lineage,
checkpoints, security, and economics.
`session/` separates identifiers, operations, payloads, ownership, and roots.
`manifest.rs`, `hashing.rs`, `merkle.rs`, and `merkle_steps.rs` supply shared
contract and digest primitives.
`src/_generated/` holds schema-derived artifacts outside crate-root exports.

## Data and control flow

Typed values pass through `serde_json::to_value` into canonical serialization.
Raw signing text instead enters `canonical_json_bytes_from_str`, which validates
input constraints before canonicalization.
`CanonicalBytes` wraps the resulting immutable buffer with a witness.
`Keypair::sign_wrapped` and `SigningBackend::sign_wrapped` sign the 88-byte
signing wrapper over that buffer under a registered schema id; an unregistered
id refuses before any signing call. `verify_wrapped` and `verify_wrapped_bytes`
take the pinned key and the expected schema id from the caller. JWS signing
inputs and DSSE pre-authentication encoding are the only bytes signed without
the wrapper, through `SigningMessage::exempt` and `verify_exempt` with a named
`ExemptFormat`.
Consumers can retain the canonical body without rebuilding it.
Capability attenuation compares a child scope with the parent scope.
Delegation-chain helpers additionally operate on signed link sequences.
Receipt and manifest consumers choose the applicable validation and signature
APIs before admitting artifacts to their own runtime.

## Trust and invariants

Canonical object keys use UTF-16 code-unit ordering.
Raw signing readers reject duplicate keys and unsafe number representations.
The typed-value serializer cannot detect keys an earlier parser discarded.
The witness constructor is private outside serializer-backed constructors.
`validate_attenuation` accepts only `child.is_subset_of(parent)`.
Signature validity and authority selection are separate caller concerns.
A valid signature does not establish revocation status or enforce invocation
budgets without runtime state.
Backends gated by `fips` and `pq` provide concrete algorithm implementations.
Feature selection alone supplies no certification or operational acceptance.

## Dependencies

Serde represents typed wire data; serde_json parses and constructs JSON values.
Ed25519-Dalek supplies default signatures, and SHA-2 supplies digest operations.
Ryu supports canonical number formatting; hex supplies wire digest encoding.
Zeroize supports secret-buffer handling.
`chio-security-types` supplies shared security contract types.
AWS-LC is optional behind `fips`; fips204 is optional behind `pq`.
The `kani` feature selects software SHA-256 for verification work.
The delegation feature names remain compatibility switches with no gating effect.

## Verification

`tests/canonical_signature_boundary.rs` checks byte stability and signed-body
boundaries, including tampering cases.
`tests/signed_json.rs` exercises existing writers and strict signing readers.
`tests/untrusted_json.rs` exercises the separate untrusted JSON representation.
`tests/property_capability_algebra.rs` exercises scope algebra properties.
`tests/_generated_check.rs` checks generated artifact consistency.
Run `cargo test -p chio-core-types` for default coverage.
Run `cargo check -p chio-core-types --no-default-features` for portable source.
Run feature-specific tests for `pq` and `fips` when validating those backends.
These tests exercise the substrate's encoding, signing, and scope rules.
Complete kernel deployments require their own integration evidence.
