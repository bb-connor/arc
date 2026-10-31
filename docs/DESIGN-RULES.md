# Chio Code Design and Quality Rules

These rules bind every Chio change. A reviewer from a different lane than the author checks the PR against the R1-R15 table in section 13, and any FAIL blocks the merge. Code that predates a rule is tracked as debt; new and touched code follows the rule.

Rule numbers are stable. Reviews, receipts and design notes cite them by number.

## 1. Crate boundaries and layering

1. **No storage code in `chio-control-plane`, the kernel or the CLI.** These crates hold no SQL text, schema, migrations, row mapping, store types or `rusqlite` usage. Persistence lives in a store crate (`chio-store-sqlite`, `chio-*-store-postgres`) behind a port. The service layer orchestrates; it does not own persistence. *Ref:* `docs/architecture/WORKSPACE_STRUCTURE.md`.
2. **Respect the four layers:** domain and protocol core, then enforcement and persistence, then adapter and edge, then service and operator. A lower layer never depends on a higher one. Domain and protocol crates never depend on `clap`, `axum`, `reqwest`, `chio-cli` or `chio-control-plane`. *Enforced by:* `scripts/check-workspace-layering.sh`.
3. **Rules leave before tables do.** A domain rule (refusal kinds, consume-once, status transitions, capacity caps) lives in the crate that owns its vocabulary. A store keeps rows, transactions and referential integrity, and every backend inherits the rule. *Ref:* ADR-0022 §3 (`FindingStatusSource`).
4. **One store per aggregate.** Each store has its own module, its own closed error enum and its own `.sql` schema file loaded with `include_str!`. Queries are named constants grouped with the aggregate they serve. There is no shared queries file. *Ref:* ADR-0022 §1, `chio-store-sqlite` (`*_store.rs` with `include_str!` schemas).
5. **Decompose god types by lane.** New kernel behaviour is a type that borrows exactly what it needs (`struct SettlementDrain<'a> { .. }`), and the kernel delegates to it in a few lines. Another `impl ChioKernel` block in a new file is not decomposition. *Ref:* ADR-0022 §4.
6. **New crates go in `crates/<group>/chio-<name>`** in the right functional group, with `publish = false` unless registered as a public entrypoint. *Ref:* `AGENTS.md` crate map, `docs/architecture/RUST_PUBLIC_SURFACE.md`.
7. **Wire changes agree with `spec/PROTOCOL.md` in the same PR.**
30. **Functional core, imperative shell.** Core and kernel crates are pure: no file, network or database IO, no clock reads, no ambient randomness, no environment reads and no global mutable state. Effects enter through ports passed in by the caller. Crates that build `no_std + alloc` today keep doing so.
31. **Concrete adapters are built only at the composition root.** Binaries and service wiring construct the SQLite store, HTTP clients and key custody, then hand them down as `Arc<dyn Port>` or a generic parameter. A library never opens its own backend, and a missing adapter is a typed construction error, not a runtime branch.

## 2. Abstractions and traits

8. **Every abstraction pays for itself.** A new trait, type or module removes duplication, encodes an invariant or cuts a dependency, and the PR body says which. A pass-through wrapper, or a trait with one implementation and no seam, is rejected. A second implementation that exists only for tests is a seam only when domain tests actually run against it.
9. **Ports are owned by the consumer's domain crate.** The trait and its vocabulary live in the lowest crate that owns the concepts and that the adapter crate already depends on, so no cycle forms. Adapters implement it in store and edge crates.
10. **No legacy or compatibility code.** Chio has not shipped. Change every caller and delete the old path in the same PR: no deprecated aliases, dual APIs, compat default trait methods, `Legacy*` doubles or migrations from unshipped formats. Every schema and version family is v1 and is edited in place. The only exception is interop with a named external protocol revision.
11. **Use the type system for invariants.** Newtypes for identifiers and units. Typestate or sealed traits for lifecycles and authority. Builders for wide constructors. Enums for closed sets, never booleans or strings.
32. **Traits carry required methods only.** A capability is expressed by a type (a subtrait or a separate port, `trait SettlementReceiptStore: ReceiptStore`), never by `supports_x() -> bool` flags or default bodies that return "unsupported". Seal a trait when an outside implementation could break an invariant. Keep port traits object-safe. Use generics on hot paths and `dyn` at composition boundaries.
33. **Minimal public surface.** Items are `pub(crate)` unless another crate needs them. Fields are private whenever the type has an invariant, and construction goes through a validating constructor. No glob re-exports. Public items document their invariants and their error cases.

## 3. Idiomatic Rust

12. **No `unwrap` or `expect` outside tests.** Propagate typed errors. In a fail-closed kernel a panic is an availability fault. *Enforced by:* workspace clippy `unwrap_used` and `expect_used` = deny.
13. **Fail closed.** Any error during evaluation denies. Invalid policy is rejected at load. No error path widens authority, and no fallback substitutes a default for a missing security input.
14. **Checked arithmetic on money, budget, quota and exposure.** Use `chio-fixed` (Q16.16) or `checked_*`, and turn `None` into a typed refusal. `overflow-checks = true` stays on in every shipping profile, because a wrap reads as unlimited authority. *Enforced by:* `Cargo.toml` profiles, `scripts/check-release-overflow.sh`.
15. **`unsafe` needs a `// SAFETY:` comment and does one unsafe operation per block.** Prefer a safe abstraction from a reviewed crate. *Enforced by:* workspace lints `unsafe_op_in_unsafe_fn`, `undocumented_unsafe_blocks` and `multiple_unsafe_ops_per_block` = deny.
16. **Library errors are closed enums.** Each crate defines `thiserror` enums that carry structured context. Backend errors (`rusqlite`, `reqwest`, `std::io`) are mapped at the adapter and never appear in a port signature. No `String` catch-all variant, no `anyhow` and no `Box<dyn Error>` in library APIs. Keep `#[source]` chains, and log an error once, at the boundary that handles it.
17. **Borrow by default.** No `.clone()`, `.to_string()` or `Arc` added to satisfy the borrow checker. Take `&str`, `&[T]`, `impl AsRef<_>` or `impl IntoIterator` at boundaries, and use `Cow` when a value is borrowed on the common path and owned on the rare one.
18. **Make illegal states unrepresentable.** Parse, don't validate: constructors return `Result`, and a value that exists is valid. No raw `String` or `u64` for identifiers, keys, handles or amounts.
19. **Canonical JSON (RFC 8785) for every signed payload.**
20. **Clippy clean at `-D warnings`, `cargo fmt` clean, no em dashes (U+2014), no narrative comments.** Comments state invariants, contracts and field semantics. They never narrate history, plans or alternatives.
34. **Panic-free on untrusted input.** Use `get` rather than `[]` indexing on lengths that come from input. Use `TryFrom` rather than a narrowing `as` cast. No `unreachable!`, `todo!` or `unimplemented!` in production code, and no recursion whose depth an input controls.
35. **`#[must_use]` where dropping a value is a bug:** guards, builders, refusal-carrying results and functions whose return value is the effect.
36. **Exhaustive matches on crate-owned enums.** No `_` arm, so a new variant forces every site to make a decision.
37. **Secrets are typed.** Key material, seeds and bearer tokens live in types that redact `Debug` and `Display`, zeroize on drop and compare in constant time. They never appear in error messages, logs, panics or test snapshots.

## 4. Modularity and file size

21. **Production files stay under 2,000 lines (warn at 1,200), `lib.rs` under 1,000 (warn at 900), test files under 2,000.** New code never grows an allowlisted file, and a file over its cap is split, not re-capped. *Enforced by:* `scripts/check-rust-file-hygiene.py`.
22. **One responsibility per module, split by domain concept.** No `queries.rs`, `utils.rs` or `helpers.rs` dumping grounds.
23. **Decomposition lands in steps that each keep the suite green.** *Ref:* ADR-0022 §5.
24. **PRs are focused.** Unrelated work goes in its own PR, and a remediation PR reports its measured net line change.

## 5. Concurrency and async

38. **No blocking work on an async executor thread.** File IO, `std::thread::sleep`, blocking HTTP and SQLite calls run in `spawn_blocking` or on a dedicated thread.
39. **No lock guard lives across `.await`.** Use `std::sync::Mutex` for short critical sections, and use an async mutex only when the guard must cross an await. Where two locks nest, the acquisition order is documented at both sites.
40. **Bounded channels, owned tasks.** Every queue and channel has a capacity, so backpressure is explicit. Every spawned task has an owner (`JoinSet` or a stored handle) and a shutdown path. No fire-and-forget tasks.
41. **Cancellation safety.** A future used in `select!` is cancellation-safe or documented as not. A state change that must be atomic never straddles an `.await`.
42. **Minimize shared state.** Prefer owned state per task and message passing over `Arc<Mutex<_>>`. Hand-written synchronization and lock-free code gets `loom` tests.

## 6. Resource bounds, IO and time

43. **Bound every input that crosses a trust boundary before allocating for it:** byte size, element count, nesting depth and string length. Readers use the bounded, no-follow helpers in `chio-secure-ipc`, and every trust-boundary decoder is registered. *Enforced by:* `scripts/check-trust-boundaries.py`.
44. **Every external call has a timeout and a bounded retry budget with backoff.** Outbound HTTP goes through `chio-egress-contract` and never through a hand-built client.
45. **Durable writes are atomic:** write a temp file in the same directory, fsync it, rename it, then fsync the directory. Opening an operator-controlled path refuses symlinks and checks owner and mode.
46. **Time is injected.** Domain code takes a clock port and never calls `SystemTime::now`. Elapsed time uses a monotonic clock. Fixtures use fixed timestamps (`chio-test-support` `ClockScope`). *Enforced by:* `scripts/check-security-clocks.py`.
47. **Deterministic output.** Anything that is hashed, signed, compared or snapshotted uses ordered collections (`BTreeMap`, `BTreeSet`) or an explicit sort. `HashMap` iteration order never reaches output. Randomness comes only from an injected RNG.

## 7. Persistence

48. **A transaction is the invariant boundary.** A multi-statement invariant commits in one transaction. SQLite write transactions use `BEGIN IMMEDIATE`. No read-modify-write spans two transactions.
49. **Queries are index-backed and bounded.** A lookup on a hot or unbounded path has a test asserting that `EXPLAIN QUERY PLAN` shows `SEARCH`, not `SCAN`. List APIs take a limit of at least 1 and a cursor, and a limit of 0 is refused, not clamped.
50. **Schema is v1 and lives in the store's `.sql` file.** Changing an unshipped schema edits v1 in place.

## 8. Wire formats

51. **Wire inputs deserialize strictly:** `deny_unknown_fields`, no `#[serde(default)]` on a security-relevant field, and explicitly tagged enums. One concept has one parser. A second textual form of the same data is rejected.

## 9. Dependencies

52. **Every new dependency justifies itself:** the PR states why `std` or an existing dependency cannot do the job. Enable only the features you use, with `default-features = false` on heavy crates, and add no new duplicate versions. Core crates take no async runtime, HTTP client or database driver. *Enforced by:* `cargo deny` and its duplicate baseline.

## 10. Testing

25. **Tests cover behaviour:** the happy path, every deny and error path, and boundary values (zero, maximum, overflow, expiry, revocation, replay). A refusal test asserts the exact error variant.
26. **Property tests and fuzz targets for parsers, canonical JSON, arithmetic and policy evaluation,** in place of piles of hand-written examples.
27. **No testing churn.** Reject tests of tests, scripts that verify scripts, assertions on fixtures or harness internals, snapshot or golden files with no behavioural assertion, and near-duplicate cases that differ only in name.
28. **Tests live beside the code they cover** (`*_tests.rs` or `tests/`) and use `chio-test-support`. Test doubles stay out of production builds: a double used only inside its own crate lives under `#[cfg(test)]`, and a double or shared suite used by other crates sits behind a feature enabled only from their `[dev-dependencies]`. A new CI hygiene script names the defect it would have caught.
29. **The full gate passes before ready:** `make gate` (build, all tests, clippy `-D warnings`, fmt check), plus `cargo check --workspace --locked`.
53. **Tests are deterministic:** a fixed clock and fixed seeds, no sleeps used for synchronization and no network. A flaky test is a bug.
54. **Fixes land RED first.** A bug fix or new refusal comes with a test that fails on the base and passes on the head.
55. **Formal artifacts move with the code.** A change to a symbol tracked in `formal/proof-manifest.toml` re-blesses its mirror in the same PR. `docs/formal/COVERAGE.md` is regenerated as the last commit.

## 11. Review receipt

A receipt counts only when the reviewer ran it on a real checkout of the PR head. It records:
- the head SHA;
- the output of `git rev-parse HEAD`;
- the output of `ls crates/`;
- the R1-R15 table below with PASS, FAIL or N/A and file:line evidence;
- the verdict.

A new head invalidates the receipt. A receipt carries to a new head only when the code diff is identical and the only addition is a COVERAGE regeneration.

## 12. Escalation

When a rule cannot be met, the PR says which rule, why, and the follow-up row that removes the exception. A reviewer never waives a rule silently.

## 13. PR review checklist

Each line is PASS, FAIL or N/A with evidence. Any FAIL blocks the merge.

| # | Check | Rules |
|---|---|---|
| R1 | No SQL, schema, row mapping, store types or `rusqlite` in control-plane, kernel or CLI. Adapters are built only at the composition root. | 1, 31 |
| R2 | No layer inversion. New crates sit in the right group. Core stays pure. New dependencies are justified and minimal. | 2, 6, 30, 52 |
| R3 | Domain rules live in the domain crate behind a consumer-owned port. Stores hold only persistence. New kernel behaviour is a borrowing type, not another `impl ChioKernel` block. | 3, 5, 9 |
| R4 | One store per aggregate, with its own `.sql`. Transactions bound the invariants. Queries are indexed and bounded. | 4, 22, 48, 49, 50 |
| R5 | Every new trait, type or module states its payoff. Traits have required methods only, with no capability flags. Visibility is minimal. | 8, 32, 33 |
| R6 | No legacy or compat code. The old path is deleted in the same PR. Everything is v1. | 10 |
| R7 | Fail-closed on every path. No panic on untrusted input. Errors are typed with no backend leakage. Inputs are bounded and external calls have timeouts. | 12, 13, 16, 34, 43, 44 |
| R8 | Checked arithmetic on money, budget, quota and exposure. | 14 |
| R9 | Types encode invariants (newtypes, typestate, `#[must_use]`, exhaustive matches). No needless clones. Secrets are typed. Output is deterministic. Wire parsing is strict. | 11, 17, 18, 35, 36, 37, 47, 51 |
| R10 | Sound concurrency and IO: `unsafe` is justified, nothing blocks in async, no guard crosses `.await`, channels are bounded, tasks are owned, writes are atomic and time is injected. | 15, 38, 39, 40, 41, 42, 45, 46 |
| R11 | File-size limits hold, no allowlisted file grew, modules are split by concept, decomposition lands in green steps, and the PR is focused with its net line change measured. | 21, 22, 23, 24 |
| R12 | Tests cover deny, error and boundary behaviour. Property or fuzz tests exist where input is parsed or arithmetic is done. Tests are deterministic and RED first. | 25, 26, 53, 54 |
| R13 | No test churn. Test doubles are dev-only. | 27, 28 |
| R14 | The gate is green at the exact head. Spec and canonical JSON agree with the wire. Formal mirrors are re-blessed and COVERAGE is last. Clippy and fmt pass, with no em dashes. | 7, 19, 20, 29, 55 |
| R15 | The reviewer is a different lane from the author and posted this table from a real checkout. | section 11 |
