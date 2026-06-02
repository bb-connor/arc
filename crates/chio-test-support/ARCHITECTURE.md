# chio-test-support Architecture

## Module Boundaries

`src/lib.rs` owns the full public surface. The `plain` module provides the
default context-free helper family re-exported by `prelude`; the `ctx` module
provides context-carrying helpers for call sites that want the context argument
on every unwrap. The crate intentionally has no runtime dependencies and is
consumed only as a dev-dependency across the workspace.

## Pain Points

These helpers replace banned `unwrap` and `expect` calls in test code. If a
helper panic reports the implementation line inside `chio-test-support`, the
failure loses the most important diagnostic: the actual test assertion call
that made the bad assumption. The `ctx` family also currently uses
`unwrap_or_else` internally, which makes call-site location tracking harder to
reason about than a direct match at the assertion boundary.

## Security And API Constraints

The public trait names, method names, module names, and prelude exports must
stay source-compatible. The crate must stay dependency-free and test-only.
Helper failure must remain an explicit panic, not a production error type.
Trait implementations must not add `Debug` or `Display` bounds for payloads
that are not rendered in the panic message, because several downstream tests
unwrap opaque handles.

## Affected Dependents

No transitive source edits are planned. Existing downstream imports from
`chio_test_support::prelude::*` and `chio_test_support::ctx::*` should keep
compiling. A representative context-family dependent and a representative
prelude-family dependent should be checked after the change.

## Planned Material Improvement

Make each helper method preserve the test call site with `#[track_caller]`,
replace context-family `unwrap_or_else` calls with direct matches, and add
unit tests that capture panic hook metadata to prove panics report the caller
line rather than the helper implementation. Also strengthen native coverage for
payload-bound behavior so future edits do not reintroduce unnecessary bounds.
