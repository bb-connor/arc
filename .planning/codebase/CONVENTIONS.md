# Coding Conventions

**Analysis Date:** 2026-03-19

## Naming Patterns

**Files:**
- Rust module files use `snake_case.rs`
- Integration tests use descriptive `snake_case.rs` names under `tests/`
- Crates use `arc-*` naming for product modules

**Functions:**
- Rust functions and methods use `snake_case`
- Test helpers are small free functions near the tests that use them
- CLI subcommands are represented as enum variants in `main.rs`

**Variables:**
- Local bindings use `snake_case`
- Constants use `SCREAMING_SNAKE_CASE`
- Types and enums use `PascalCase`

**Types:**
- Structs, enums, and traits use `PascalCase`
- Error types are explicit and usually backed by `thiserror`
- IDs and domain values are strongly typed where practical (`SessionId`, `RequestId`, etc.)

## Code Style

**Formatting:**
- `rustfmt` is the formatter of record
- Standard Rust formatting conventions apply
- Comments are used sparingly and usually explain protocol/runtime intent, not obvious mechanics

**Linting:**
- Clippy warnings are denied in CI
- Multiple crates explicitly deny `unwrap_used` and `expect_used`
- Run: `cargo clippy --workspace -- -D warnings`

## Import Organization

**Order:**
1. Standard library imports
2. External crate imports
3. Workspace/local crate imports

**Grouping:**
- Blank lines between logical groups
- Imports are usually grouped by source and kept stable rather than aggressively reordered

**Path Aliases:**
- No alias system; standard Rust crate/module paths are used

## Error Handling

**Patterns:**
- Use `Result` and typed errors instead of panicking in production code
- Fail security-sensitive paths closed when invariants are not provable
- Convert low-level failures into protocol-appropriate error outputs at boundaries

**Error Types:**
- `thiserror` is the common error abstraction
- Tests use `expect`/`unwrap` where setup clarity matters; production code generally does not
- Boundary code logs context with `tracing` before returning or surfacing failures

## Logging

**Framework:**
- `tracing` and `tracing-subscriber`
- Levels used include `debug`, `info`, `warn`, and `error`

**Patterns:**
- Log state transitions and transport/service boundaries rather than every helper
- Hosted/trust-control code increasingly relies on explicit diagnostics for cluster or lifecycle issues

## Comments

**When to Comment:**
- Explain protocol or security rationale
- Clarify tricky edge/transport semantics
- Avoid restating obvious Rust code

**Docs:**
- Public-facing modules and CLI entrypoints may use doc comments
- Planning and epic docs carry the higher-level design narrative

**TODO Comments:**
- Prefer tracked epic/task docs over ad hoc TODO accumulation

## Function Design

**Size:**
- Core modules often use helper functions to keep protocol and session code factored

**Parameters:**
- Domain structs are preferred when multiple related fields travel together
- CLI parsing uses `clap` structs/enums instead of manual argument plumbing

**Return Values:**
- Explicit return types and early exits are common
- Security and transport boundaries should return enough context to produce receipts or actionable errors

## Module Design

**Exports:**
- Each crate exposes a focused public API from `lib.rs` or a small module surface
- Product entrypoints stay in the crate most responsible for the behavior rather than a catch-all utils layer

**Barrel Files:**
- Rust crate/module exports are used instead of JavaScript-style barrel files
- Avoid circular dependencies by keeping shared domain types in `arc-core`

---
*Convention analysis: 2026-03-19*
*Update when patterns change*
