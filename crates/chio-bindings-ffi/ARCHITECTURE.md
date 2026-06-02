# chio-bindings-ffi Architecture

## Owner

`chio-bindings-ffi` owns the stable C ABI for deterministic SDK invariant helpers. It is a thin ABI layer over `chio-binding-helpers`, not a runtime, transport, session, or kernel crate.

## Module Boundaries

This crate has one Rust module because the surface is intentionally small:

- exported C functions accept UTF-8 C strings or raw byte buffers
- helper code validates pointers and UTF-8 before crossing into `chio-binding-helpers`
- all successful outputs are UTF-8 buffers allocated by Rust
- all failures return `ChioFfiResult` with stable status and error-code integers
- callers must release non-empty returned buffers with `chio_buffer_free`

The checked-in C header under `include/chio/chio_ffi.h` is an ABI artifact generated from this crate's Rust exports and `cbindgen.toml`. The symbol snapshot under `tests/abi/` is the review gate for exported names.

## Pain Points

- Receipt verification over the C ABI currently cannot accept trusted signer keys, so C and C++ callers can only observe cryptographic validity, not authoritative receipt trust.
- Passing arrays through C would create ownership and lifetime hazards. This ABI deliberately prefers JSON-string parameters for structured inputs.
- Header and symbol artifacts must move with the Rust export to avoid ABI drift.

## Security And API Constraints

- Receipt authorization must require an explicit trusted signer set.
- Malformed trusted signer input must fail closed with a stable FFI error result.
- Existing ABI v1 symbols and numeric status/error-code values must remain stable.
- Do not expose async flows, callbacks, session state, transport state, or kernel execution.
- Do not hand-edit generated header semantics independently from the Rust export and cbindgen config.

## Affected Dependents

The C++ SDK consumes this crate through `sdks/cpp/chio-cpp/src/invariants.cpp`. A new trusted-signer receipt ABI needs a minimal C++ wrapper so the dependent can exercise the authoritative local verification path without reaching into Rust internals.

## Planned Improvement

Add a receipt-verification ABI entrypoint that accepts a receipt JSON string plus a trusted-signer JSON array. This makes authoritative receipt verification available over the C ABI while preserving the narrow string-buffer boundary.
