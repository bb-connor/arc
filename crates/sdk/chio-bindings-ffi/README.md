# chio-bindings-ffi

`chio-bindings-ffi` exposes `chio-binding-helpers` through a synchronous C ABI
for SDKs such as `sdks/cpp/chio-cpp`. It accepts UTF-8 C strings or explicit byte
ranges and returns Rust-allocated UTF-8 buffers. The library builds as a
`staticlib`, `cdylib`, and `rlib`; its checked-in C declarations are in
[chio_ffi.h](include/chio/chio_ffi.h).

## Usage

Rust callers can exercise the same exported canonicalization entrypoint:

```rust
use std::ffi::CString;
use chio_bindings_ffi::{
    chio_buffer_free, chio_canonicalize_json, chio_ffi_abi_version,
    CHIO_FFI_STATUS_OK,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(chio_ffi_abi_version(), 1);
    let input = CString::new(r#"{"z":1,"a":2}"#)?;
    let result = chio_canonicalize_json(input.as_ptr());
    // SAFETY: this live Rust-owned result contains result.data.len bytes.
    let output = unsafe {
        std::slice::from_raw_parts(result.data.ptr, result.data.len).to_vec()
    };
    chio_buffer_free(result.data);
    assert_eq!(result.status, CHIO_FFI_STATUS_OK);
    assert_eq!(String::from_utf8(output)?, r#"{"a":2,"z":1}"#);
    Ok(())
}
```

This example runs offline using the `rlib`. Foreign callers include
`include/chio/chio_ffi.h`, link the library for their target, and check
`chio_ffi_abi_version()` before calling the ABI.

## Guarantees

`read_c_str` rejects null arguments and invalid UTF-8. The caller must supply a
live, readable NUL-terminated string and prevent mutation while it is borrowed.
`read_bytes` accepts a null pointer only when length is zero; otherwise the whole
range must be readable and valid for a Rust slice. These checks cannot validate
arbitrary pointer addresses.

`ChioFfiResult` carries status `0` (success), `1` (error), `2` (caught panic), or
`3` (null argument), plus a numeric error code and data buffer. Success data may
be canonical text, a hex digest, a boolean string, or a JSON report. A successful
verification call can return false validity fields. Always inspect its payload.

Every returned nonempty buffer, including an error message, must be released
exactly once with `chio_buffer_free`, retaining the original pointer and length.
Buffers have no NUL terminator. Callers must coordinate access and deallocation
across threads; the ABI owns no shared session or callback state.

`run_ffi` catches unwinding panics in wrapped helper calls. String reads, buffer
release, and the two hash functions execute outside that wrapper; invalid pointer
use and aborting panics remain outside its containment guarantee.

## Status

Implemented as an internal library with `publish = false` and no declared Cargo
features. Capability checks return signature, chain-shape, and time evidence.
Receipt verification needs the trusted-signers entrypoint for `ok` or
`authorized` to become true. Run `cargo test -p chio-bindings-ffi` for ABI buffer,
error, signing, receipt-trust, and symbol-snapshot tests.

## Related

- [Architecture](ARCHITECTURE.md)
- [Canonical JSON contract](../../../spec/PROTOCOL.md#41-canonical-json)
- [Invariant helpers](../chio-binding-helpers/README.md)
- [Offline kernel ABI](../chio-cpp-kernel-ffi/README.md)
- [C++ consumer](../../../sdks/cpp/chio-cpp/README.md)
- [License](../../../LICENSE)
