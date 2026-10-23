# chio-binding-helpers architecture

## Responsibility and boundary

The public surface in `src/lib.rs` re-exports artifact parsers, canonical body
serializers, verification reports, hashing, and signing functions. Inputs are
borrowed Rust strings, byte slices, or typed artifacts; outputs are owned
strings, artifacts, and serializable reports. The crate forbids unsafe code.
Foreign pointer handling belongs to `chio-bindings-ffi`.

`CapabilityVerification`, `ReceiptVerification`, and `ManifestVerification`
retain individual check outcomes so SDKs can expose them without reproducing
Rust cryptographic logic. These reports do not store policy or trust decisions
between calls. Applications supply time and trusted receipt signers explicitly.

## Structure

| Module | Responsibility |
| --- | --- |
| `canonical` | Parse raw JSON into a value and emit RFC 8785 canonical JSON. |
| `hashing` | SHA-256 lowercase hex for byte slices and UTF-8 strings. |
| `signing` | Seed-based Ed25519 signing-wrapper signing and verification under a registered schema id, and hex helpers. |
| `capability` | Token parsing, body canonicalization, signature/chain-shape/time report. |
| `receipt` | Strict signed-wire parsing, body canonicalization, identity/hash/trust report. |
| `manifest` | Signed-manifest parsing, body canonicalization, structure and key report. |
| `error` | `Error`, `ErrorCode`, and `Result` conversion across dependencies. |

## Data and control flow

JSON signing parses a `serde_json::Value`, constructs a `Keypair` from the seed,
and invokes `sign_wrapped` under the caller's schema id. The returned
`WrappedJsonSignature` carries the schema id, the canonical bytes as UTF-8, the
public key, and the hex signature. Verification reconstructs the value and
key/signature objects before `verify_wrapped`, which returns an error on any
refusal.

Capability verification calls `validate_time(now)` and converts its expiry or
not-yet-valid outcome to `CapabilityTimeStatus`. Signature verification remains
fallible. `validate_delegation_chain` receives the optional maximum depth; its
failure becomes a false `delegation_chain_shape_valid` field. The validator checks
link signatures, adjacent delegator/delegatee continuity, timestamp order, and
optional depth; authenticated scope-root binding is outside this helper.

Receipt JSON takes a distinct ingress path through
`UntrustedJsonText::decode_signed`. Verification recomputes the ID from the body,
checks `action.verify_hash`, and verifies the signature. It compares the embedded
kernel key to the supplied trusted signer slice, then combines those outcomes
with the receipt's decision/kind/boundary semantics for `authorized`.

Manifest verification calls `validate_manifest`, parses the manifest's embedded
public key, and verifies the signature with `signer_key`. Structure and embedded
key failures appear as report fields; decoding and cryptographic operation
errors return `Err`. The body serializers expose unsigned bodies, while artifact
signature verification uses the corresponding underlying signing contract.

## Trust and invariants

Generic canonicalization, JSON signing, capability parsing, and manifest parsing
use ordinary Serde JSON decoding. Duplicate-aware signed-wire rejection is an
explicit guarantee of receipt JSON ingress. Callers requiring strict admission
of other raw signed artifacts must use the appropriate authoritative parser.

`verify_capability` checks chain shape, signatures, and time. It has no trusted
issuer parameter, trust-root resolver, request, or persistent budget registry.
An application accepting delegated authority needs the kernel's full verifier
and admission state. A successfully returned report may contain false fields.

Receipt `ok` requires signature, parameter hash, ID, and signer trust. `authorized`
also requires the semantic authorization predicate. An empty trusted signer list
always makes both fields false. Output content is absent from this API, so it
cannot recompute a receipt's content hash against the delivered output.

`public_key_hex_matches` strips a lowercase `0x` prefix and compares text ignoring
ASCII case; it performs no key parsing. Use `is_valid_public_key_hex` to check key
encoding separately. Signing seeds and their handling remain caller concerns.

## Dependencies

`chio-core` supplies artifact types, canonicalization, hash functions, signatures,
receipt semantics, and delegation validation. `chio-manifest` supplies the signed
manifest and structural validator. `serde` and `serde_json` provide report/wire
serialization. `thiserror` preserves dependency error messages behind `Error`.
`chio-test-support` supplies test assertion helpers.

## Verification

Run `cargo test -p chio-binding-helpers`. Module tests cover known hashes,
canonical ordering, signature round trips, report construction, and error codes.
`tests/vector_fixtures.rs` reads the cross-language corpus in
`tests/bindings/vectors`, checks public API results, rejects duplicate receipt
members at original bytes, and exercises full-width integers and nested values.

Fixture generation and signature reblessing helpers are ignored tests with file
write effects. Ordinary tests read the checked-in corpus. The obsolete manifest
fixture test expects rejection under the current manifest admission shape.
