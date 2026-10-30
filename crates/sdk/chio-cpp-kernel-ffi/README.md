# chio-cpp-kernel-ffi

`chio-cpp-kernel-ffi` exposes offline capability evaluation and verification,
receipt signing, and portable-passport verification to `sdks/cpp/chio-cpp-kernel`.
It adapts `chio-kernel-core` to JSON C strings and Rust-owned result buffers.
Its ABI version is 2; the library produces `staticlib`, `cdylib`, and `rlib`.

## Usage

Verify a signed direct capability through the exported Rust-accessible C ABI:

```rust
use std::ffi::CString;
use chio_core_types::capability::{
    scope::{ChioScope, Operation, ToolGrant},
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core_types::crypto::Keypair;
use chio_cpp_kernel_ffi::{
    chio_kernel_buffer_free, chio_kernel_ffi_abi_version,
    chio_kernel_verify_capability_json, CHIO_KERNEL_FFI_STATUS_OK,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(chio_kernel_ffi_abi_version(), 1);
    let issuer = Keypair::from_seed(&[9; 32]);
    let subject = Keypair::from_seed(&[10; 32]);
    let token = CapabilityToken::sign(CapabilityTokenBody {
        id: "example-cap".into(), issuer: issuer.public_key(),
        subject: subject.public_key(), issued_at: 100, expires_at: 200,
        delegation_chain: vec![], aggregate_invocation_budget: None,
        scope: ChioScope {
            grants: vec![ToolGrant {
                server_id: "echo-server".into(), tool_name: "echo".into(),
                operations: vec![Operation::Invoke], constraints: vec![],
                max_invocations: None, max_cost_per_invocation: None,
                max_total_cost: None, dpop_required: None,
            }],
            resource_grants: vec![], prompt_grants: vec![],
        },
    }, &issuer)?;
    let input = CString::new(serde_json::to_string(&token)?)?;
    let authority = CString::new(issuer.public_key().to_hex())?;
    let result = chio_kernel_verify_capability_json(
        input.as_ptr(), authority.as_ptr(), 150,
    );
    // SAFETY: the live result buffer has exactly result.data.len bytes.
    let output = unsafe {
        std::slice::from_raw_parts(result.data.ptr, result.data.len).to_vec()
    };
    chio_kernel_buffer_free(result.data);
    assert_eq!(result.status, CHIO_KERNEL_FFI_STATUS_OK);
    let verified: serde_json::Value = serde_json::from_slice(&output)?;
    assert_eq!(verified["id"], "example-cap");
    Ok(())
}
```

The sample runs offline with existing dependencies. Fixed seeds are example
keys. Foreign callers include [chio_kernel_ffi.h](include/chio/chio_kernel_ffi.h)
and link the matching target library after checking the ABI version.

## Guarantees

`chio_kernel_evaluate_json` uses `evaluate_with_full_floor` to check
issuer trust, signature/time, negotiated capability features, chain binding,
subject/request scope, and sibling-share admission against supplied snapshots.
It uses `AllowClassical`, an empty guard list, and no session filesystem roots.
`PendingApproval` maps to a deny verdict. Governed approval and supplemental
authorization request fields reject before evaluation.

`chio_kernel_sign_receipt_json(body, content_hex, seed)` recomputes the content
hash from supplied bytes and checks the kernel key before signing. The explicit
`chio_kernel_sign_receipt_relaying_trusted_body_json` trusts the body's content
hash. Callers using the relay must establish trust in its upstream producer.
Relay signing is permitted only when forwarding an upstream-trusted body
without its content preimage. Paths holding evaluated content must use
`chio_kernel_sign_receipt_json` with that preimage, as required by the
protocol. The relay export cannot enforce this caller obligation.

Callers supply valid readable NUL-terminated UTF-8 inputs. Null and UTF-8 checks
do not establish pointer validity. Results contain length-delimited UTF-8 and
must be freed once with `chio_kernel_buffer_free`, preserving pointer and length.
Independent calls have local state; callers synchronize shared buffers and frees.
`run_ffi` catches unwinding panics during wrapped processing, after input reads.

## Status

Implemented as an internal offline SDK bridge with `publish = false` and no
Cargo features. Each call creates a fresh budget registry from caller snapshots.
Tool dispatch, persistent invocation/spend accounting, revocation lookup, DPoP
replay checks, receipt storage, and guards require the integrating runtime.
Run `cargo test -p chio-cpp-kernel-ffi` for its focused Rust tests.

## Related

- [Architecture](ARCHITECTURE.md)
- [Capability verification contract](../../../spec/PROTOCOL.md#53-verification-rules)
- [WYSIWYS signing contract](../../../spec/PROTOCOL.md#wysiwys-signing-invariant)
- [Portable kernel core](../../kernel/chio-kernel-core/README.md)
- [Invariant C ABI](../chio-bindings-ffi/README.md)
- [C++ kernel consumer](../../../sdks/cpp/chio-cpp-kernel/README.md)
- [License](../../../LICENSE)
