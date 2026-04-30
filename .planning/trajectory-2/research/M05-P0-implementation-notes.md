# M05 P0 Implementation Notes

Scope: Wave 2 pre-flight notes for M05.P0.T1 only. These notes are read-only with respect to milestone narratives, ticket YAML, decisions, freezes, owners, board files, style files, and code.

Sources read:

- `.planning/trajectory-2/05-adversarial-escape-threat-model.md`
- `.planning/trajectory-2/tickets/M05/P0.yml`
- `.planning/trajectory-2/decisions.yml`
- `.planning/trajectory-2/freezes.yml`
- `.planning/trajectory-2/WAVE-OPENER-STRATEGY.md`
- `.planning/trajectory-2/EXECUTION-BOARD.md`
- `.planning/trajectory-2/audits/M05-AUDIT.md`
- `.planning/trajectory-2/ci-stubs/threat-model-coverage.yml`
- `spec/security/chio-threat-model.v1.json`
- `Cargo.toml`
- `Cargo.lock`
- `crates/chio-attest-verify/Cargo.toml`
- `crates/chio-attest-verify/src/lib.rs`
- `crates/chio-wasm-guards/Cargo.toml`
- `crates/chio-wasm-guards/src/fuzz.rs`
- `crates/chio-wasm-guards/src/error.rs`
- `crates/chio-wasm-guards/src/host.rs`

## Ticket M05.P0.T1

Title: Pin `toml` direct dep on `chio-attest-verify` and `arbitrary` on `chio-wasm-guards` tests.

Intent: remove dependency and lockfile churn from later M05 trust-boundary phases. P4 needs TOML policy parsing in `chio-attest-verify`; P3 needs structured adversarial inputs for WASM guard escape fixtures and fuzz-adjacent tests.

Expected write set for the implementation PR:

- `crates/chio-attest-verify/Cargo.toml`
- `crates/chio-wasm-guards/Cargo.toml`
- `Cargo.lock`

Shared path:

- `Cargo.lock`

Do not include in this P0 PR:

- `crates/chio-attest-verify/src/policy.rs`
- `crates/chio-wasm-guards/tests/escape/**`
- `fuzz/fuzz_targets/wasm_guard_escape.rs`
- `spec/security/chio-threat-model.v1.json`
- `crates/chio-conformance/tests/threats/**`
- any adversarial corpus crate genesis

## Same-Day Opener Checklist

Run this as the handoff checklist for the P0 opener after Wave 1 gates drain:

- Verify Wave 1 has fully drained. All `M01`, `M02`, and `M06` rows in
  `.planning/trajectory-2/tickets/manifest.yml` must be `merged`, and the Wave
  2 pre-flight gate in `.planning/trajectory-2/WAVE-OPENER-STRATEGY.md` must be
  green or replaced by the current local executor gate.
- Check out `wave/W2/m05/p0.t1-cargo-lock-bump-toml-arbitrary` from the current
  integration base. Do not start from a stale research branch.
- Re-read `M05.P0.T1`, the two crate manifests, and `Cargo.lock` before editing.
  The live manifest state is authoritative.
- Apply only the dependency bump: `toml = "0.8"` in
  `crates/chio-attest-verify/Cargo.toml`; `crates/chio-wasm-guards/Cargo.toml`
  changes only if Cargo metadata proves the existing optional direct
  `arbitrary` edge is insufficient for tests.
- Refresh `Cargo.lock` through Cargo. Do not hand-edit the lockfile.
- Run the ticket gate exactly, then the focused hygiene gates below.
- Regenerate trajectory manifest output only if the orchestrator requires it.
  Include generated output in the same PR only if the command emits a diff.
- Confirm `git diff --name-only` excludes crate source, `decisions.yml`,
  `freezes.yml`, `OWNERS.toml`, ticket YAML, execution state, and the P1..P5
  M05 protected paths.
- Open the PR as `[M05] chore(m05): pin P0 dependency surface` or an equivalent
  conventional title. The body should say P0 did not implement adversarial
  suite code, threat-model coverage, a WASM escape harness, or policy loader
  code.
- Schedule security x2 review before merge: two independent security reviewers
  with different seeds and no shared scratchpad, plus `@bb-connor`. If the
  path-scoped freeze guard does not request security x2 for this manifest-only
  P0 diff, manually request it or record the explicit audit override before
  merge.

## Current Surface Notes

`crates/chio-attest-verify` currently has no direct `toml` dependency. Its manifest includes `sigstore`, `serde`, `serde_json`, `thiserror`, `sha2`, `regex`, `tokio`, `tracing`, x509 and webpki dependencies, plus `tempfile` for tests. The P4 target surface is the existing `ExpectedIdentity` struct in `src/lib.rs`, whose fields are `certificate_identity_regexp` and `certificate_oidc_issuer`. P0 should not change that API.

`crates/chio-wasm-guards` already has optional production dependency `arbitrary = { version = "1", features = ["derive"], optional = true }` gated by the `fuzz` feature. It is not present in `[dev-dependencies]`. P0 should add a direct test/dev dependency only if the implementation ticket owner confirms the intended interpretation of "on chio-wasm-guards tests" is a dev dependency rather than relying on the existing optional feature. Keep the existing `fuzz` feature shape intact.

`fuzz/Cargo.toml` already pins `arbitrary = { version = "1", features = ["derive"] }`. `Cargo.lock` already contains `arbitrary 1.4.2` and multiple `toml` versions, including `toml 0.8.23`. The likely P0 lockfile diff should be limited to package dependency lists, not new registry package entries, unless Cargo resolution shifts.

## Decision And Corpus Readiness Notes

Reference M05 corpus decisions by ID only: `D13`, `D14`. Do not paste or
paraphrase their decision text into the implementation PR as if this research
note were the source of truth. The opener should link or mention the IDs and
leave `decisions.yml` unchanged.

Corpus readiness assumptions for later phases:

- P1 should be able to add JSON corpus cases without changing the encoding
  choice again. P0's TOML dependency is for P4 policy files only.
- P1/P2 should reserve room for `threat_id`, `pending`, `source`, and
  content-addressing metadata so P5 coverage and P2 corpus metadata can join
  vectors to registry rows.
- The current registry baseline has six threat IDs:
  `capability_token_theft`, `kernel_impersonation`, `tool_server_escape`,
  `native_channel_replay`, `resource_exhaustion_dos`, and
  `delegation_chain_abuse`.
- P0 must not create `crates/chio-adversarial-suite`, corpus files,
  `fuzz/corpus_metadata.toml`, generated threat tests, or
  `docs/security/threat-coverage.md`.

Threat-model coverage gate assumptions:

- `threat-model-coverage` is still a CI stub at P0. It becomes load-bearing in
  M05 P5 after the registry coverage linkage and checker script exist.
- Once active, coverage is 100 percent required: every registered threat ID must
  have a green test mapping.
- `coverage_state: covered` and `coverage_state: partial` count as pass per the
  execution board. `coverage_state: pending` without `deferred_to` fails closed.
- Less than 100 percent active coverage is halt trigger 13. Recovery is to add a
  green test mapping under `crates/chio-conformance/tests/threats/` or revert
  the uncovered threat row. Do not merge by marking the gate advisory.

## APIs And Files To Inspect First

For `chio-attest-verify`:

- `crates/chio-attest-verify/Cargo.toml`
- `crates/chio-attest-verify/src/lib.rs`
- `crates/chio-attest-verify/src/sigstore.rs`
- `crates/chio-attest-verify/tests/integration.rs`
- `crates/chio-attest-verify/README.md`

Reviewer reason: confirm the direct TOML dependency does not accidentally start policy-loader work, introduce direct Sigstore use elsewhere, or weaken the crate-level `forbid(unsafe_code)`, `forbid(clippy::unwrap_used)`, and `forbid(clippy::expect_used)` posture.

For `chio-wasm-guards`:

- `crates/chio-wasm-guards/Cargo.toml`
- `crates/chio-wasm-guards/src/fuzz.rs`
- `crates/chio-wasm-guards/src/error.rs`
- `crates/chio-wasm-guards/src/host.rs`
- `crates/chio-wasm-guards/src/runtime.rs`
- `fuzz/Cargo.toml`

Reviewer reason: preserve the split between production builds, the optional `fuzz` feature, and test-only structured input support. `src/fuzz.rs` already documents that production builds should not pull in `arbitrary` through fuzz instrumentation.

## Suggested Implementation Shape

For `crates/chio-attest-verify/Cargo.toml`, add:

```toml
toml = "0.8"
```

or, if the workspace owner prefers dependency centralization before P0, add `toml = "0.8"` to `[workspace.dependencies]` and use:

```toml
toml = { workspace = true }
```

The milestone narrative says "No new workspace-level pins beyond the TOML direct-dep promotion and the `arbitrary` reuse." The least invasive reading is a crate-local direct dependency in `chio-attest-verify`, using the already resolved `toml 0.8.23`.

For `crates/chio-wasm-guards/Cargo.toml`, keep the existing optional dependency and `fuzz` feature unchanged. Add a dev dependency only if tests will import `arbitrary` without enabling the `fuzz` feature:

```toml
[dev-dependencies]
arbitrary = { version = "1", features = ["derive"] }
```

If Cargo rejects having `arbitrary` in both `[dependencies]` and `[dev-dependencies]`, prefer moving the existing `arbitrary` declaration to workspace dependencies and referencing it from both locations, but keep it optional in production and test-only in dev. Do not remove the `fuzz = ["dep:arbitrary", "wasmtime-runtime"]` feature contract.

After manifest edits, run Cargo once to refresh `Cargo.lock`. Because both packages are already present in the lockfile, expect a small diff adding `toml 0.8.23` to `chio-attest-verify` and possibly `arbitrary` to `chio-wasm-guards`.

## Gate Commands

Ticket gate from `P0.yml`:

```bash
cargo build -p chio-attest-verify --quiet && cargo build -p chio-wasm-guards --quiet && cargo tree -p chio-attest-verify --depth 1 | grep -q '^[├└]── toml '
```

Additional focused checks recommended for the P0 branch:

```bash
cargo tree -p chio-wasm-guards --depth 1
cargo test -p chio-attest-verify --no-run
cargo test -p chio-wasm-guards --no-run --features wasmtime-runtime
cargo fmt --all -- --check
cargo clippy -p chio-attest-verify -- -D warnings
cargo clippy -p chio-wasm-guards --features wasmtime-runtime -- -D warnings
```

If the implementer adds a dev dependency that only exists for future tests, `cargo tree -p chio-wasm-guards --edges dev --depth 1` should show `arbitrary` without requiring the `fuzz` feature.

## Risk Notes

- Dependency scope risk: adding `arbitrary` as a normal non-optional production dependency would violate the documented split in `crates/chio-wasm-guards/src/fuzz.rs`. Keep production builds free of fuzz instrumentation.
- Lockfile churn risk: later M05 phases touch trust-boundary crates and frozen paths. P0 should isolate `Cargo.lock` changes now and keep the diff minimal.
- Freeze sequencing risk: the M05 freeze starts at M05.P1.T1, not P0, but P0 still touches trust-adjacent manifests. Avoid opening P1, P3, P4, or P5 files in the same PR.
- M03 overlap risk: `freezes.yml` says M05.P4 `crates/chio-attest-verify/src/policy.rs` lands after M03.P3 closes. P0 must not create or edit `policy.rs`.
- API drift risk: do not replace `ExpectedIdentity` construction or add policy loader APIs in P0. P4 owns that work.
- Cargo resolution risk: `toml 0.8.23` is already in `Cargo.lock`, but if Cargo selects a different version, the reviewer should ask why before accepting expanded churn.

## Reviewer Focus

- Confirm the diff includes only the two crate manifests and `Cargo.lock`.
- Confirm `chio-attest-verify` has a direct `toml` edge visible in `cargo tree -p chio-attest-verify --depth 1`.
- Confirm `chio-wasm-guards` keeps `arbitrary` optional for production and available for tests or fuzz as intended.
- Confirm no code, ticket YAML, milestone narrative, decisions, freezes, owner files, execution board, or style files changed.
- Confirm the conventional commit message is docs-free only if this research file is the current PR. For the actual implementation branch, use a `build:` or `chore:` conventional message because Cargo manifests and lockfile are changed.
