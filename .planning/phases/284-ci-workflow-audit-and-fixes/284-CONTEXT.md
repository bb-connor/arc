# Phase 284: CI Workflow Audit and Fixes - Context

**Gathered:** 2026-04-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Repair the repo-owned GitHub Actions workflow failures that currently stop the
hosted `CI` and `Release Qualification` lanes from reaching a clean pass on
GitHub-hosted runners, without widening into release tagging, milestone
lifecycle actions, or unrelated product behavior changes.

</domain>

<decisions>
## Implementation Decisions

### Hosted Failure Scope
- Use the current hosted failures on `main` as the source of truth for this phase: `CI` run `24311566689` and `Release Qualification` run `24311566699` from 2026-04-12.
- Keep scope limited to actionable repo-owned failures surfaced by those runs: the `rg` prerequisite in workspace-layering checks, release-workflow `pnpm` setup ordering, and the MSRV warning promoted to an error in `arc-core` tests.
- Treat the GitHub Actions Node 20 deprecation warning as non-blocking unless it becomes a hard failure during a later rerun.

### Verification Mode
- Reproduce and validate each hosted failure with the closest practical local command before changing broader workflow structure.
- Prefer small script or workflow repairs over introducing new CI infrastructure.
- Defer final hosted-green confirmation until the updated workflow definitions are published and rerun on GitHub.

### Claude's Discretion
- Workflow caching optimizations are optional; correctness and hosted passability are the priority.
- Use the smallest patch that preserves the current lane intent and artifact flow.

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- [.github/workflows/ci.yml](/Users/connor/Medica/backbay/standalone/arc/.github/workflows/ci.yml) already owns the stable, MSRV, and coverage hosted lanes.
- [.github/workflows/release-qualification.yml](/Users/connor/Medica/backbay/standalone/arc/.github/workflows/release-qualification.yml) already owns the hosted release qualification flow and artifact upload.
- [scripts/ci-workspace.sh](/Users/connor/Medica/backbay/standalone/arc/scripts/ci-workspace.sh) and [scripts/check-workspace-layering.sh](/Users/connor/Medica/backbay/standalone/arc/scripts/check-workspace-layering.sh) are the earliest repo-script gate in hosted CI.
- [scripts/qualify-release.sh](/Users/connor/Medica/backbay/standalone/arc/scripts/qualify-release.sh) stages the release artifact tree consumed by the release workflow.
- [crates/arc-core/tests/monetary_types.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-core/tests/monetary_types.rs) is the concrete MSRV warning target promoted to failure by `-D warnings`.

### Established Patterns
- Hosted workflows prefer shell scripts over large inline YAML commands.
- Jobs upload artifacts with `if: always()` so post-failure evidence survives.
- Workflow setup stays explicit in YAML rather than hidden in bootstrap scripts.

### Integration Points
- The `check` job in `ci.yml` calls `./scripts/ci-workspace.sh`.
- The `msrv` job in `ci.yml` runs `cargo build --workspace && cargo test --workspace` under Rust `1.93.0`.
- The `qualify` job in `release-qualification.yml` sets up Node, Python, Go, SDK parity, release qualification, hosted web3 checks, and MSRV validation in a single hosted lane.

</code_context>

<specifics>
## Specific Ideas

Hosted failure details driving this phase:

- `CI` run `24311566689` failed in `./scripts/ci-workspace.sh` because `check-workspace-layering.sh` exits early with `check-workspace-layering.sh requires rg on PATH` on GitHub's Ubuntu runner.
- The same `CI` run later failed in the MSRV lane because `crates/arc-core/tests/monetary_types.rs` defines `make_grant_no_monetary`, which is unused and becomes an error under `RUSTFLAGS="-D warnings"`.
- `Release Qualification` run `24311566699` failed in `actions/setup-node@v4` because the step enables `cache: pnpm` before `pnpm` exists on `PATH`, producing `Unable to locate executable file: pnpm`.

</specifics>

<deferred>
## Deferred Ideas

- Final hosted rerun of the updated workflows after the local fixes are published.
- Release candidate tagging and milestone archive/cleanup remain outside this phase.

</deferred>
