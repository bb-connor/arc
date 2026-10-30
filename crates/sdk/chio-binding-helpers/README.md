# chio-binding-helpers

`chio-binding-helpers` provides Rust functions that language bindings share for
canonical JSON, SHA-256, Ed25519 signing, and artifact verification. It wraps
`chio-core` and `chio-manifest`; `chio-bindings-ffi` exports these operations to
C callers. The crate owns no session, transport, revocation store, or tool
execution state.

## Usage

Sign a JSON value under a registered schema id and verify the signature over
the same canonical value:

```rust
use chio_binding_helpers::{sign_wrapped_json_ed25519, verify_wrapped_json};

fn main() -> chio_binding_helpers::Result<()> {
    // Fixed seeds are useful for examples; applications must protect real keys.
    let signed =
        sign_wrapped_json_ed25519("chio.receipt.v1", r#"{"z":1,"a":2}"#, &"09".repeat(32))?;
    assert_eq!(signed.canonical_json, r#"{"a":2,"z":1}"#);
    verify_wrapped_json(
        "chio.receipt.v1",
        r#"{"a":2,"z":1}"#,
        &signed.public_key_hex,
        &signed.signature_hex,
    )?;
    Ok(())
}
```

The sample uses the crate's existing dependencies and runs offline. JSON signing
canonicalizes a `serde_json::Value` and signs the signing wrapper over it under
the schema id; an id outside the signed-artifact registry is refused. Seed input
is a hex-encoded Ed25519 seed.

## Guarantees

| API | Enforced check or returned evidence |
| --- | --- |
| `canonicalize_json_str` | Bounds input to 1 MiB, refuses duplicate keys, and normalizes numeric spellings through RFC 8785 canonicalization. |
| `verify_capability` | Returns signature validity, delegation-chain shape validity, and validity at the caller's `now` timestamp. |
| `parse_receipt_json` | Uses `UntrustedJsonText::decode_signed` to reject duplicate members and number tokens that change representation. |
| `verify_receipt_with_trusted_signers` | Recomputes receipt ID and action parameter hash, verifies signature, and checks membership in the supplied signer set. |
| `verify_signed_manifest` | Reports manifest structure, signature validity, embedded-key validity, and equality with the signing key separately. |
| `Error::code` | Maps core, JSON, and manifest errors to the serializable `ErrorCode` vocabulary. |

`ReceiptVerification::ok` requires all cryptographic/hash checks and a trusted
signer. `authorized` additionally requires receipt semantics that authorize the
decision. `verify_receipt` supplies an empty trust set, so both fields remain
false. The `result` label alone is insufficient for an authorization decision.

Capability verification supplies evidence about the token. The caller must
establish issuer trust, request scope, subject binding, revocation, and durable
budgets through the appropriate kernel path. Manifest reports likewise require
the caller to examine every relevant validity field and establish signer trust.

## Status

Implemented as an internal library with `publish = false`. Its manifest declares
no Cargo features. Module tests exercise canonicalization, signing, key matching,
and reports; `tests/vector_fixtures.rs` checks shared vector cases and receipt
JSON rejection. Run `cargo test -p chio-binding-helpers` for these checks.

## Related

- [Architecture](ARCHITECTURE.md)
- [Canonical JSON contract](../../../spec/PROTOCOL.md#41-canonical-json)
- [Receipt contract](../../../spec/PROTOCOL.md#6-receipt-contract)
- [C ABI facade](../chio-bindings-ffi/README.md)
- [Core types and cryptography](../../core/chio-core/README.md)
- [License](../../../LICENSE)
