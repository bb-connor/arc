# chio-did architecture

## Responsibility and boundary

The crate owns canonical `did:chio` identifiers and deterministic DID document
construction. Its public surface is `DidChio`, `DidDocument`, verification-method
and service structs, `ResolveOptions`, and the resolver `resolve_did_arc`.
The resolver's exported name retains the legacy project spelling.

An identifier binds an Ed25519 key representation to a DID string. A resolved
document does not establish possession of its private key or admission to a
kernel. Consumers verify signatures and apply their own authority policy.

## Structure

| Source | Responsibility |
| --- | --- |
| `src/lib.rs` | DID parsing, document construction, service constructors, errors, unit tests. |
| `src/fuzz.rs` | Feature-gated parser and document fuzz entry point. |
| `tests/integration_smoke.rs` | Public resolver with service metadata. |

`DidChio` keeps its public key and Ed25519 bytes private. In contrast,
`DidDocument`, `DidVerificationMethod`, and `DidService` expose serializable
fields so consumers can exchange documents.

## Data and control flow

`from_public_key` checks the key algorithm before retaining its 32-byte key.
`FromStr` checks the exact prefix, lowercase hex alphabet, and suffix length,
then delegates key decoding to `chio-core-types`.

Resolution creates the W3C DID context, one `Ed25519VerificationKey2020`, and
matching authentication and assertion references. The multibase representation
prefixes the key bytes with the Ed25519 multicodec bytes `0xed, 0x01`, encodes
that buffer as base58btc, and adds the `z` prefix.

`ResolveOptions::with_service` appends service objects in caller order.
`DidService::receipt_log` and `passport_status` derive fragment identifiers and
call the HTTPS URL constructor. Ordinal zero has no numeric suffix; subsequent
ordinals use one-based suffixes beginning with `-2`.

## Trust and invariants

Only the `did:chio` method is parsed here. P-256, P-384, hybrid keys, and other
DID methods fail the `DidChio` constructor or parser.
The protocol permits broader methods as compatibility inputs elsewhere.

HTTPS validation proves URL scheme and syntax. It does not contact the endpoint,
verify its owner, or bind the service to a signed document.
`resolve_with_options` clones supplied services without revalidation.
A caller can construct or deserialize a service with arbitrary public fields;
use constructors when their checks are required.

Document deserialization is schema decoding through Serde. The crate has no
public verifier for a received document's method references, service identities,
or consistency with an externally trusted DID.

## Dependencies

`chio-core-types` provides key decoding and algorithm identity.
`bs58` renders the multibase key, `url` parses service URLs, and Serde supplies
document serialization. `thiserror` names parser and constructor failures.
`fuzz` adds `arbitrary` and JSON decoding for fuzz inputs.

## Verification

Run `cargo test -p chio-did` for parser, unsupported-key, multibase, service
fragment, HTTPS rejection, and public resolver cases.
The tests operate locally with deterministic keys and inspect emitted metadata.
They exercise neither remote DID discovery nor endpoint ownership.
