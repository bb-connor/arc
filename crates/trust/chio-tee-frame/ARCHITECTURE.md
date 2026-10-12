# Architecture

## Responsibility and boundary

The crate owns the typed `Frame` capture format and its validation routines.
It exports construction, canonicalization, parsing, signing preimages, and
tenant-signature verification. It has no file writer, redactor, encrypted
store, tenant-key resolver, or kernel policy evaluator.

A frame commits metadata about redacted request and response blobs. The
consumer supplies the trusted public key and independently verifies the blobs
and their provenance before relying on them during replay.

## Structure

| Module | Responsibility |
| --- | --- |
| `frame` | `Frame`, `FrameInputs`, upstream/provenance/verdict types, codec |
| `schema` | Version/id constants, patterns, reason gate, Ed25519 checks |
| `lib` | Public re-exports and `FRAME_VERSION` label |
| `tests/property_roundtrip` | Property-based canonical codec invariants |

`UpstreamSystem` enumerates OpenAI, Anthropic, AWS Bedrock, MCP, A2A, and ACP.
`Provenance` carries trace/span identifiers plus optional opaque supply-chain
JSON. `Verdict` carries allow, deny, or rewrite.

## Data and control flow

`Frame::build` supplies schema version `1` and calls `validate`.
`canonicalize` validates before RFC 8785 encoding. `parse` runs signed
original-input decoding with a 16 MiB limit, then validates the typed frame.
It accepts structurally valid JSON without requiring the input to already
be canonical. Re-encoding produces the canonical representation.

`signing_payload` serializes the frame, removes `tenant_sig`, and canonicalizes
the remaining object. `verify_tenant_sig` reconstructs that payload, decodes
the standard-base64 Ed25519 signature, and checks it with the supplied raw
32-byte public key. `validate_signed` runs structural validation first.

## Trust and invariants

Structural validation requires exact schema version, uppercase Crockford
base32 event-id characters, UTC millisecond timestamp, deployment id pattern,
operation/api-version bounds, object invocation, lowercase trace/span ids,
and lowercase 64-character blob hashes. The event id is checked as a string
pattern; the validator does not compare its embedded time with `ts`.

Deny and rewrite must carry a bounded lowercase namespaced reason.
Allow must omit that reason. `would_have_blocked` is carried as a boolean;
the crate does not know the mode needed to derive its semantic value.
Supply-chain provenance remains opaque.

`validate` checks the signature's prefix, base64 character shape, and encoded
length. It does not decode or cryptographically authenticate the signature.
`verify_tenant_sig` additionally requires exactly 64 decoded bytes and an
Ed25519 signature accepted under the provided key.
Callers choose that key independently of untrusted frame material.

The signed frame commits claimed hashes. No function retrieves redacted
blobs or recomputes those hashes here. Timestamp format validation also adds
no age or replay-consumption policy.

## Dependencies

The aliased `chio-core-types` dependency supplies canonical encoding,
original-input JSON, and Ed25519 types. Serde carries wire types and opaque
JSON values. Chrono validates real RFC 3339 dates; Base64 decodes signatures.
Proptest generates codec cases for development tests.

## Verification

Run `cargo test -p chio-tee-frame` and
`cargo test -p chio-tee-frame --doc`.
Schema unit tests cover field patterns, invalid dates, reason gates, valid
signatures, tampered signed fields, and wrong keys. Codec unit tests cover
bounded/ambiguous input. Property tests exercise frame round trips and verdict
combinations. The README example signs and verifies one fixture frame locally.

[README](README.md) | [Serialization](../../../spec/PROTOCOL.md#41-canonical-json)
