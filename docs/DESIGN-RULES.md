# Chio Code Design and Quality Rules

Status: authoritative for every Chio PR. Compiled 2026-10-30 from the repo at `936ecc1e1` and from maintainer directives.
Tags: **[C]** = maintainer directive; **[D]** = in the repo docs/config (enforced or stated); **[I]** = inferred from docs/code, not stated verbatim.


## 1. Crate boundaries and layering

1. **[C][D] No storage code in `chio-control-plane`.** No new SQL strings, schema, migrations, row mapping or store types in the control-plane crate; persistence lives in a store crate (`chio-store-sqlite`, `chio-*-store-postgres`) behind a port trait. *Why:* service layer orchestrates, it does not own persistence. *Src:* maintainer directive 2026-10-30 (#2001); `docs/architecture/WORKSPACE_STRUCTURE.md` ("Concrete SQLite storage belongs in `chio-store-sqlite`, not back in the kernel or the CLI").
2. **[D] Respect the four layers:** domain/protocol core -> enforcement/persistence -> adapter/edge -> service/operator. Lower layers never depend on higher ones; domain crates never pull `clap`, `axum`, `reqwest`, `chio-cli` or `chio-control-plane`. *Why:* keeps the TCB small and pure. *Src:* `WORKSPACE_STRUCTURE.md`; gate `scripts/check-workspace-layering.sh`.
3. **[D] Rules leave before tables do.** Domain rules live in the crate owning the vocabulary, behind a trait (e.g. `FindingStatusSource` in `chio-finding`); stores keep only rows and referential integrity. *Why:* the next backend inherits the rule instead of re-writing it. *Src:* `docs/adr/ADR-0022-store-and-kernel-decomposition.md` §3.
4. **[D] One store per domain, its own error type, its own module/crate.** Queries are grouped by aggregate, never one "all queries" file. *Why:* ADR-0022 measured that per-store helpers are duplication, not coupling, and travel with their store. *Src:* ADR-0022 Context/§1; maintainer directive on #2001.
5. **[D] Decompose god types by lane, not by adding `impl ChioKernel` blocks.** New kernel behaviour is a type that borrows what it needs; the kernel delegates thinly. *Why:* 30-file `impl` sprawl is named structural debt. *Src:* ADR-0022 §4.
6. **[D] New crates go in `crates/<group>/chio-<name>`** in the right functional group; `publish = false` unless registered as a public entrypoint. *Src:* `AGENTS.md` Crate Map; `docs/architecture/RUST_PUBLIC_SURFACE.md`.
7. **[D] Wire changes agree with `spec/PROTOCOL.md` in the same PR.** *Src:* `CLAUDE.md`, `CONTRIBUTING.md`.

## 2. Abstractions and traits

8. **[C] Every abstraction must improve the overall design.** A new trait/type/module must remove duplication, encode an invariant, or cut a dependency; a pass-through wrapper or single-use trait with no seam is rejected. *Src:* maintainer directive 2026-10-30.
9. **[D][I] Ports are traits owned by the consumer's domain crate; adapters implement them in store/edge crates.** *Why:* that is how the control plane talks to storage without owning it. *Src:* ADR-0022 §3 (`FindingStatusSource`); inferred for general use.
10. **[D] No legacy or compatibility shims.** Change every caller and delete the old path in the same PR; no deprecated aliases, dual APIs, compat default trait methods, `Legacy*` doubles, or migrations from unshipped schemas. Only exception: a named external protocol revision. *Src:* `AGENTS.md` Conventions; `CLAUDE.md`.
11. **[C][I] Use expert Rust patterns where they pay:** newtypes for IDs/units, typestate or sealed traits for state machines and authority, builders for wide constructors, enums over boolean/stringly flags. *Src:* maintainer directive 2026-10-30; `chio-decision-model` "sealed" projection (`AGENTS.md`).

## 3. Idiomatic Rust

12. **[D] No `unwrap`/`expect`** outside tests; propagate typed errors. *Why:* in a fail-closed kernel a panic is an availability fault. *Src:* `Cargo.toml` `[workspace.lints.clippy]`; `CONTRIBUTING.md`.
13. **[D] Fail closed.** Any error in evaluation denies; invalid policy rejects at load; no error path may widen authority. *Src:* `AGENTS.md`, `CONTRIBUTING.md`.
14. **[D] Checked arithmetic on money, budget, quota, exposure** (`chio-fixed` Q16.16 or `checked_*`); `overflow-checks = true` stays on in shipping profiles. *Why:* a wrap reads as unlimited authority. *Src:* `Cargo.toml` profile comment.
15. **[D] `unsafe` only with a `// SAFETY:` comment, one unsafe op per block.** *Src:* `Cargo.toml` lints (`undocumented_unsafe_blocks`, `multiple_unsafe_ops_per_block`, `unsafe_op_in_unsafe_fn` = deny).
16. **[C][I] Errors are typed enums per crate (`thiserror`-style, `chio-errors` vocabulary), not `String` or catch-all boxes in library code.** *Src:* maintainer directive 2026-10-30; `chio-errors` crate (`AGENTS.md`).
17. **[C][I] Ownership: borrow by default, no needless `.clone()`/`to_string()`/`Arc` to satisfy the borrow checker; take `&str`/`&[T]`/`impl AsRef` at boundaries.** *Src:* maintainer directive 2026-10-30; clippy `-D warnings`.
18. **[C][I] Make illegal states unrepresentable:** parse, don't validate; constructors return `Result`; no raw `String`/`u64` for identifiers. *Src:* maintainer directive 2026-10-30; `require_identifier` patterns cited in ADR-0022.
19. **[D] Canonical JSON (RFC 8785) for every signed payload.** *Src:* `AGENTS.md`.
20. **[D] Clippy clean at `-D warnings`, `cargo fmt` clean, no em dashes (U+2014).** *Src:* `CLAUDE.md`, `CONTRIBUTING.md`.

## 4. Modularity and file size

21. **[D] Production file hard limit 2,000 lines (warn 1,200); `lib.rs` 1,000 (warn 900); test file 2,000.** New code must not grow an allowlisted file. *Src:* `scripts/check-rust-file-hygiene.py`.
22. **[C][I] One responsibility per module; split by domain concept, not by "kind" (no `queries.rs`, `utils.rs`, `helpers.rs` dumping grounds).** *Src:* maintainer directive on #2001.
23. **[D] Decomposition lands in steps that each keep the suite green.** *Src:* ADR-0022 §5.
24. **[D] PRs are focused; unrelated work is split.** *Src:* `CONTRIBUTING.md` Pull requests.

## 5. Testing

25. **[C] Bulletproof means meaningful coverage of behaviour:** happy path, every deny/error path, and boundary values (zero, max, overflow, expiry, revocation, replay). *Src:* maintainer directive 2026-10-30; fail-closed rule 13.
26. **[C][I] Use property tests (`proptest`) and fuzz targets (`fuzz/`) for parsers, canonical JSON, arithmetic and policy evaluation** rather than piles of hand-written examples. *Src:* maintainer directive 2026-10-30; repo `fuzz/`, `formal/`.
27. **[C] No testing churn.** Reject: tests of tests, scripts that verify scripts, tests asserting on test fixtures/harness internals, snapshot or golden files with no behavioural assertion, and near-duplicate test cases that differ only in naming. *Src:* maintainer directive 2026-10-30.
28. **[I] Tests live beside the code they cover (`*_tests.rs`/`tests/`) and use `chio-test-support`;** a new CI hygiene script requires a stated defect it would have caught. *Src:* crate layout; `chio-test-support` (`AGENTS.md`).
29. **[D] Full gate passes before ready:** `cargo build/test/clippy -D warnings/fmt --check` (`make gate`). *Src:* `CONTRIBUTING.md`, `CLAUDE.md`.

## 6. PR review checklist (each line PASS/FAIL; any FAIL blocks merge)

| # | Check | Rule |
|---|---|---|
| R1 | No SQL/schema/row-mapping/store types added to `chio-control-plane` (or kernel/CLI) | 1 |
| R2 | No layer inversion; `check-workspace-layering.sh` passes | 2 |
| R3 | Domain rules in domain crate behind a trait; store holds only persistence | 3, 9 |
| R4 | Queries grouped per aggregate in a store module/crate, not one file | 4, 22 |
| R5 | Every new trait/type/module has a stated design payoff (dedup, invariant, or cut dep) | 8 |
| R6 | No legacy/compat shims; old path deleted in same PR | 10 |
| R7 | No `unwrap`/`expect`/panics in non-test code; typed errors; fail-closed on every error path | 12, 13, 16 |
| R8 | Checked arithmetic on money/budget/quota | 14 |
| R9 | No needless clones/`Arc`/stringly types; newtypes for IDs | 17, 18 |
| R10 | `unsafe` has SAFETY comment | 15 |
| R11 | File-size limits respected; no allowlisted file grew | 21 |
| R12 | Tests cover deny/error/boundary behaviour; property/fuzz where input is parsed or arithmetic | 25, 26 |
| R13 | No test-of-test, script-verifies-script, or duplicate-case churn | 27 |
| R14 | `make gate` green; spec updated if wire changed; clippy/fmt/no em dash | 7, 20, 29 |
| R15 | Reviewer is a different lane than author, and posts this table in the PR | Maintainer order 2026-10-30 |

## Known conflicts and debt (as of `936ecc1e1`)
- `chio-control-plane/Cargo.toml` already depends on `rusqlite` and `chio-finding-market-store-postgres`, and ~75 files under its `src/` contain SQL strings (mostly tests; production hits include `passport_revocation_mirror.rs`, `passport_verifier.rs`, `security/adapters/native_evidence.rs`). Rule 1 applies to new code now; existing debt needs an extraction plan sequenced per ADR-0022.
- `chio-store-sqlite` is itself 188k lines / 228 files (ADR-0022), on the hygiene allowlist until decomposed.
- `WORKSPACE_STRUCTURE.md` says the workspace "is currently flat"; it is now grouped into 11 folders (`AGENTS.md`). Doc is stale on that point; its layering rules still hold.
- `CONTRIBUTING.md` "Add or update tests that cover the change" can be read as "always add tests"; rule 27 narrows it: add behavioural tests, not churn.
