# Architecture

## Responsibility and boundary

The crate implements synchronous remote Ed25519 signing behind Chio's
`SigningBackend` trait. It owns client configuration, request/response
binding, bounded response decoding, and local signature verification.
The service owns private signing material and authentication policy.

`RemoteSigningKey` carries a handle, nonzero version, and nonweak Ed25519
public key. Client `public_key()` always returns this configured pin.
The client never replaces it from a remote response.

## Structure

All implementation and unit tests live in `src/lib.rs`.

| Type or helper | Responsibility |
| --- | --- |
| `RemoteSigningKey` | Validated handle/version/public-key configuration |
| `RemoteSecret` | Shared credential and redacted debug formatting |
| `HttpSigningBackend` | Chio HTTP key preflight and signing contract |
| `VaultTransitSigningBackend` | Transit key version, namespace, signing |
| `read_json` | Bounded read and duplicate-aware external JSON decoding |
| `verified_signature`, `binding_digest` | Strict verification and canonical hash |
| `validate_base_url`, `build_agent` | URL constraints, timeout, redirect policy |

## Data and control flow

HTTP `sign_bytes` rejects empty or oversized messages, builds a binding
containing handle, version, Ed25519 algorithm, SHA-256, and base64 message,
then derives the request id from canonical binding bytes.
The POST response must echo the request id and all required binding fields.
Only a signature verified against the exact input and pinned key is returned.

`HttpSigningBackend::verify_key` fetches the key endpoint and checks schema,
handle, version, algorithm, and encoded public key. This is an explicit
preflight call. Signing independently checks its response and signature.

Vault signing sends base64 input, configured `key_version`, and
`prehashed: false`. The response prefix must name that version. Decoded
signature bytes must have Ed25519 length and verify locally.
Vault preflight selects the configured entry from the returned key map,
decodes its 32-byte public key, and compares it with the local pin.

## Trust and invariants

Canonicalization applies to HTTP binding metadata. The signing backend signs
the caller's exact bytes; artifact canonicalization and receipt content-hash
validation belong to the calling Chio signing path. The protocol's WYSIWYS
receipt requirement must be enforced before requesting remote signing.

Base URLs reject credentials, query strings, fragments, absent hosts, and
non-HTTPS transport except recognized loopback HTTP. Agent redirects are
zero, and connect/read/write timeouts default to five seconds. Optional
Vault namespaces must be nonempty, bounded, and free of control characters.

Response reading is bounded during I/O to 64 KiB plus a sentinel byte.
The external JSON reader rejects duplicate and lossy original fields.
HTTP response shapes deny unknown fields; Vault projections accept extra
service metadata while the original-input checks still cover the whole JSON.
Remote secrets are shared in memory and hidden by `Debug`; they are not
represented as zeroizing secret buffers.

## Dependencies

`chio-core` supplies signing traits, canonical metadata, hashes, and strict
Ed25519 verification. `ureq` supplies HTTP/TLS transport; `url` validates
transport addresses. Base64 and Serde encode the protocol shapes.
`chio-test-support` supports local endpoint tests.

## Verification

Run `cargo test -p chio-signing-remote` and
`cargo test -p chio-signing-remote --doc`.
Unit tests use loopback HTTP fixtures for exact-message signing, key preflight,
response substitution, Vault version pinning, and mismatched public keys.
Additional cases cover HTTPS policy and duplicate/lossy response rejection.
They exercise client behavior against local fixtures; a deployed signer needs
its own credential, key lifecycle, transport, and availability acceptance.

[README](README.md) | [Receipt contract](../../../spec/PROTOCOL.md#wysiwys-signing-invariant)
