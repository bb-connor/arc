# M04 P0 Implementation Notes

Scope: Wave 2 M04 P0 opener only. These notes cover
`.planning/trajectory-2/tickets/M04/P0.yml` and the P0 section of
`.planning/trajectory-2/04-recursive-delegation-revocation-oracle.md`.
Do not implement oracle logic, delegation logic, formal proofs, or runtime
integration in P0.

## Source Inputs

- Milestone narrative: `.planning/trajectory-2/04-recursive-delegation-revocation-oracle.md`
- P0 tickets: `.planning/trajectory-2/tickets/M04/P0.yml`
- Decisions: `.planning/trajectory-2/decisions.yml`
- Freezes: `.planning/trajectory-2/freezes.yml`
- Current dependency and workspace layout: `Cargo.toml`, `Cargo.lock`
- Current ownership surface: `.github/CODEOWNERS`

## Ticket Notes

### M04.P0.T1 - Pin `rs_merkle = "1.5"` and refresh lockfile

Expected files:

- `Cargo.toml`
- `Cargo.lock`

Inspect first:

- `Cargo.toml` workspace member list near the identity and federation group.
- `Cargo.toml` `[workspace.dependencies]` near the existing shared dependency pins.
- `Cargo.lock` after resolution, only to confirm the dependency graph is the expected lockfile bump.

Implementation notes:

- Add `rs_merkle = "1.5"` under `[workspace.dependencies]`.
- Do not add `crates/chio-revocation-oracle` in this ticket unless the branch owner intentionally bundles T2, because T2 depends on T1 and owns the crate scaffold.
- Refresh the lockfile with Cargo, not manual editing.
- Keep the workspace dependency pin at the root. The milestone says both the oracle crate and later SQLite-adjacent work consume the same version.

Gate command:

```bash
grep -q 'rs_merkle' Cargo.toml && cargo metadata --quiet --format-version 1 >/dev/null
```

Risk notes:

- Lockfile churn can hide unrelated dependency upgrades. Review the lockfile diff for `rs_merkle` and its direct transitive additions only.
- The milestone text says to re-check the latest patch when work opens, but the P0 ticket title explicitly pins `1.5`. If a newer compatible patch exists, update the audit trail before changing the ticket intent.

Reviewer focus:

- Confirm `rs_merkle` is pinned once at workspace scope.
- Confirm no oracle code or unrelated workspace member was added in T1.
- Confirm `cargo metadata` succeeds from a clean worktree.

### M04.P0.T2 - Scaffold `crates/chio-revocation-oracle`

Expected files:

- `Cargo.toml`
- `Cargo.lock`
- `crates/chio-revocation-oracle/Cargo.toml`
- `crates/chio-revocation-oracle/src/lib.rs`
- `crates/chio-revocation-oracle/tests/scaffold.rs`

Inspect first:

- Neighbor crate manifests for local style: `crates/chio-federation/Cargo.toml`, `crates/chio-credentials/Cargo.toml`, and `crates/chio-kernel-core/Cargo.toml`.
- Current revocation trait surface: `crates/chio-kernel/src/revocation_runtime.rs`.
- Current revocation error surface: `crates/chio-kernel/src/revocation_store.rs`.
- Existing SQLite revocation persistence for later compatibility only: `crates/chio-store-sqlite/src/revocation_store.rs`.

Implementation notes:

- Add `"crates/chio-revocation-oracle"` to root workspace members near the identity, credentials, and federation group unless the team wants a separate new grouping.
- The crate manifest should follow the workspace package fields and `publish = false` pattern.
- Use `lib.name = "chio_revocation_oracle"` to match crate naming conventions.
- Keep `src/lib.rs` intentionally minimal. P0 asks for an empty library scaffold, not sparse-Merkle primitives.
- Add a placeholder integration test that proves the package builds and test discovery works. Avoid asserting future oracle behavior.
- Initial dependencies should be just enough to compile the scaffold. If dependencies are added now, prefer only milestone-declared dependencies and workspace pins. Do not import from kernel internals unless the public API shape is needed.

Gate command:

```bash
test -f crates/chio-revocation-oracle/Cargo.toml && cargo build -p chio-revocation-oracle --quiet && cargo test -p chio-revocation-oracle --quiet
```

Risk notes:

- The existing `RevocationStore` trait currently lives in `chio-kernel`, which is not a good public dependency direction for a lower-level oracle crate. P0 should avoid locking in that dependency inversion.
- `chio-kernel-core` is documented as portable `no_std + alloc`; do not assume oracle code can be pulled into kernel-core without a later portability decision.
- Do not add SQLite-backed sparse-Merkle storage in P0. The milestone scope explicitly defers the SQLite backend.

Reviewer focus:

- Confirm the crate is a scaffold only.
- Confirm clippy lint settings match local crate convention.
- Confirm the root workspace member order is intentional.
- Confirm the placeholder test is not masking missing implementation by overclaiming behavior.

### M04.P0.T3 - Open audit doc with starting counts

Expected files:

- `.planning/audits/M04-delegation-revocation.md`

Inspect first:

- Hard counts in `.planning/trajectory-2/04-recursive-delegation-revocation-oracle.md`.
- `formal/rust-verification/kani-public-harnesses.toml`, where `covered_symbols` currently records the public Kani harness set.
- `formal/tla/RevocationPropagation.tla` and current `formal/tla/` inventory.
- `formal/lean4/Chio/Chio/Core/Revocation.lean` and `formal/lean4/Chio/Chio/Proofs/Revocation.lean`.
- Existing revocation implementation files:
  - `crates/chio-kernel/src/revocation_runtime.rs`
  - `crates/chio-kernel/src/revocation_store.rs`
  - `crates/chio-store-sqlite/src/revocation_store.rs`

Implementation notes:

- Record the required starting counts from the P0 ticket and milestone:
  - 10 Kani harnesses.
  - 1 TLA module, `RevocationPropagation.tla`.
  - 0 Lean delegation theorems.
  - 254 LoC of revocation surface across the three implementation files named by the milestone.
- Include the exact reproduction commands for counts so later P1-P5 agents can update the audit doc without guesswork.
- Keep this audit doc factual. Do not claim oracle, gossip, recursive delegation, or acceptance behavior is implemented.

Gate command:

```bash
test -f .planning/audits/M04-delegation-revocation.md && grep -q '10 Kani' .planning/audits/M04-delegation-revocation.md && grep -q 'RevocationPropagation.tla' .planning/audits/M04-delegation-revocation.md
```

Risk notes:

- Counts in the milestone are measured on 2026-04-29. If live counts differ, the audit doc should state both the planned baseline and the measured value with date and command.
- The requested audit path is `.planning/audits/`, not `.planning/trajectory-2/audits/`. Do not relocate it unless tickets are amended.

Reviewer focus:

- Confirm the document does not overstate implementation status.
- Confirm all count claims are either reproduced or explicitly labeled as milestone baseline counts.
- Confirm the audit doc names the freeze windows and P0 opening state clearly enough for later closure review.

### M04.P0.T4 - Wire freeze on capability and federation paths

Expected files:

- `.github/CODEOWNERS`
- `.planning/trajectory-2/freezes.yml`

Inspect first:

- Current generated ownership header in `.github/CODEOWNERS`.
- Current M04 freeze entries in `.planning/trajectory-2/freezes.yml`.
- Any generator or trajectory tooling referenced by the repo before hand-editing ownership files. The P0 ticket header says to regenerate the manifest after edits with `cargo xtask trajectory regen-manifest`.

Implementation notes:

- The ticket owns `.github/CODEOWNERS` and `.planning/trajectory-2/freezes.yml`; both are protected coordination surfaces. Keep the diff minimal.
- Existing freeze entries already name:
  - `m04-revocation-oracle-pivot`
  - `m04-delegation-pivot`
- The P0 ticket says to cover `crates/chio-core-types/src/capability.rs` and `crates/chio-federation/src/lib.rs` for P3-P4. The current freeze register uses globbed capability paths and revocation-specific federation paths. Resolve that mismatch explicitly in the implementation PR rather than silently broadening or narrowing coverage.
- `.github/CODEOWNERS` says it is generated from `.planning/trajectory/OWNERS.toml`, while this wave uses trajectory-2 ticketing. Before editing, find the current generator path and source of truth. If CODEOWNERS must be regenerated from a protected owner file, record that in the PR and avoid hand edits that will drift.
- The milestone prose mentions wiring freeze on `crates/chio-core-types/src/capability.rs` and `crates/chio-federation/src/lib.rs`; do not edit those code files in P0.

Gate command:

```bash
grep -q 'crates/chio-core-types/src/capability.rs' .github/CODEOWNERS && grep -q 'crates/chio-federation/src/lib.rs' .github/CODEOWNERS && grep -q 'm04-' .planning/trajectory-2/freezes.yml
```

Risk notes:

- The gate checks exact file paths, but current CODEOWNERS contains `crates/chio-core-types/src/capability*.rs`, not an exact `capability.rs` line, and no visible `crates/chio-federation/src/lib.rs` line in the opening state.
- A generated CODEOWNERS file can drift if edited by hand. Prefer the repository generator if it can produce the required exact lines.
- The freeze register currently scopes `m04-delegation-pivot` to P3-P5, while the P0 ticket header says P3-P4. Treat this as an explicit review item, not a cleanup opportunity.

Reviewer focus:

- Confirm freeze coverage matches the ticket and the freeze-register semantics.
- Confirm generated ownership files are updated through the repo-approved path.
- Confirm no code files are modified as part of freeze wiring.

## Cross-Ticket Order

1. T1 must land before T2 because the new scaffold may depend on the workspace `rs_merkle` pin.
2. T2 must land before T3 because the audit doc should include the opened oracle crate state.
3. T3 must land before T4 because the audit doc should record the freeze opening baseline.
4. After any planning or ownership edits, run `cargo xtask trajectory regen-manifest` if the edited surface requires manifest regeneration.

## Gate Bundle For P0 Close

Run ticket gates individually first. A practical P0 close bundle is:

```bash
cargo metadata --quiet --format-version 1 >/dev/null
cargo build -p chio-revocation-oracle --quiet
cargo test -p chio-revocation-oracle --quiet
test -f .planning/audits/M04-delegation-revocation.md
grep -q '10 Kani' .planning/audits/M04-delegation-revocation.md
grep -q 'RevocationPropagation.tla' .planning/audits/M04-delegation-revocation.md
grep -q 'm04-' .planning/trajectory-2/freezes.yml
```

If T4 keeps the exact-path gate from the ticket, also run the two CODEOWNERS
grep checks from T4 and verify they pass for exact paths, not only globs.

## Known Surfaces To Inspect First

- `Cargo.toml`: workspace members and `[workspace.dependencies]`.
- `.github/CODEOWNERS`: generated ownership and current capability owner line.
- `.planning/trajectory-2/freezes.yml`: current M04 freeze IDs, path globs, and overlap notes.
- `crates/chio-core-types/src/capability.rs`: existing `DelegationLink`, `DelegationLinkBody`, `DelegationLink::sign`, and `validate_delegation_chain`.
- `crates/chio-kernel/src/revocation_runtime.rs`: current `RevocationStore` trait and in-memory store.
- `crates/chio-kernel/src/revocation_store.rs`: current revocation error and record types.
- `crates/chio-store-sqlite/src/revocation_store.rs`: current SQLite persistence surface.
- `crates/chio-credentials/src/passport.rs`: current passport lifecycle revocation status.
- `formal/rust-verification/kani-public-harnesses.toml`: starting public harness inventory.
- `formal/tla/RevocationPropagation.tla`: starting TLA revocation model.

## General Risk Notes

- P0 is opener plumbing. Avoid importing P1-P5 implementation decisions into scaffold code.
- Fail-closed behavior belongs in later oracle verifier implementation, not in placeholder tests.
- The current milestone has soft dependencies on M03 PQ signing and M06 canonical bytes. P0 should not block on those surfaces unless dependency resolution directly requires them.
- Keep exact wording free of em dash characters in docs and comments.

## Reviewer Checklist

- One ticket, one narrow diff.
- No implementation code beyond the requested scaffold.
- No edits to `crates/chio-core-types/src/capability.rs` or `crates/chio-federation/src/lib.rs` in P0.
- No hand-edited generated ownership drift.
- All gate commands in the ticket pass.
- Any mismatch between ticket text, milestone prose, and current freeze register is called out in the PR, not hidden by a broad diff.
