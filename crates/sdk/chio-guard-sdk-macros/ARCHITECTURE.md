# chio-guard-sdk-macros architecture

## Responsibility and boundary

This proc-macro crate owns compile-time signature validation and token
generation for `#[chio_guard]`. Its public surface is the attribute.
The generated code calls `chio_guard_sdk` at the consumer's call site;
the macro manifest contains no dependency on that SDK.

Guard authors provide policy logic as a Rust function. The SDK owns raw
memory decoding, deny-reason storage, allocator exports, and host imports.
The WASM runtime owns isolation, memory bounds, and host resources.
The attribute does not inspect the policy body or certify its decisions.

## Structure and dependencies

All implementation and inline tests live in `src/lib.rs`:

| Item | Role |
|------|------|
| `chio_guard` | Parse the item, validate it, then emit the guest ABI tokens. |
| `validate_guard_fn` | Reject unsupported names, qualifiers, arguments, and return types. |
| `type_path_ends_with_ident` | Compare the last identifier in an unqualified-self type path. |

`syn` with its `full` feature parses `ItemFn` and produces spanned errors.
`quote` builds the expansion and internal function name. `proc-macro2`
supports the token representation. No Cargo features are declared.

## Data and control flow

`chio_guard` parses the annotated item as a `syn::ItemFn`.
An invalid signature produces `syn::Error::to_compile_error` immediately.
Attribute arguments are received as `_attr` and ignored.

For a valid function, the expansion preserves its attributes, visibility,
arguments, return type, and body under `__chio_guard_user_evaluate`.
It re-exports `chio_alloc`, `chio_free`, and `chio_deny_reason` from the SDK
and creates `#[no_mangle] pub extern "C" fn evaluate(ptr, len) -> i32`.

The entry point calls unsafe `chio_guard_sdk::read_request`.
An error returns `VERDICT_DENY` directly. Success passes the owned request
to user logic, then forwards the verdict to `encode_verdict`.
The host retrieves any structured reason through the SDK export afterward.

## Trust and invariants

Validation requires the name `evaluate`, one typed input ending in
`GuardRequest`, and an explicit return type ending in `GuardVerdict`.
It rejects async, const, unsafe, explicit ABI, generic parameters, where
clauses, variadic arguments, and receivers. Type references and qualified
self forms fail the path check. The helper checks identifiers syntactically;
ordinary compiler type checking resolves whether the generated calls match.

The generated unsafe read assumes a live guest-memory region supplied by
the host. The SDK rejects invalid signed bounds, but positive pointers and
lengths require host validation. Function signature validation cannot
establish this memory invariant.

Decode errors skip `encode_verdict`, so they do not clear or replace its
thread-local deny reason. Hosts must interpret the returned deny code even
when structured evidence is absent or reflects a preceding evaluation.
User logic is invoked synchronously without a generated panic handler.

Every expansion emits the same exported names. Multiple expansions in one
module collide in Rust; exports across modules must also remain unique
in the linked guest. The macro does not generate resource limits or
capability admission checks.

## Verification

Run `cargo test -p chio-guard-sdk-macros` for the two inline validator tests:
one accepts the plain signature and one rejects an incorrect function name.
These tests do not cover every rejection branch or execute the expansion.

`examples/guards/tool-gate` and `examples/guards/enriched-inspector` are
workspace consumers that apply the attribute with SDK dependencies.
`cargo test -p chio-example-tool-gate` tests the tool-name policy; WASM host
tests load compiled guest examples. The [README](README.md) demonstrates
the real attribute and a deny return for invalid signed memory bounds.
