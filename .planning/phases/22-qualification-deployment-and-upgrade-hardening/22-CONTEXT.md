# Phase 22: Qualification, Deployment, and Upgrade Hardening - Context

**Gathered:** 2026-03-25
**Status:** Completed

<domain>
## Phase Boundary

Phase 22 closes the operational proof gap in `v2.3`. The repo already had
release-oriented tests and docs, but the actual production qualification lane
and operator procedure were still fragmented across old `v1` wording, partial
runtime assumptions, and local tribal knowledge.

</domain>

<decisions>
## Implementation Decisions

### Release Qualification
- Keep one top-level `./scripts/qualify-release.sh` entrypoint as the canonical
  production lane rather than documenting separate manual sequences.
- Treat dashboard build/test, TypeScript package build/pack/smoke install,
  Python wheel/sdist validation, Go consumer-module smoke, live conformance
  waves, and repeat-run clustered trust proof as first-class release evidence.

### Packaging And CI
- Make the TypeScript SDK self-describing by declaring its own build-time
  dependencies instead of relying on ambient workspace tools.
- Add explicit Python and Go setup to the hosted CI and release-qualification
  workflows so local and hosted gates fail on missing runtimes instead of
  silently narrowing coverage.

### Operator Procedures
- Document trust-control and remote MCP deployment as file-backed, SQLite-backed
  self-hosted surfaces with explicit backup, restore, upgrade, and rollback
  steps.
- Keep the dashboard optional at process startup while still requiring it for
  release qualification.

### Qualification Reliability
- Fix release-lane blockers inside the lane instead of narrowing the gate.
- Harden the `receipt_query` startup harness so transient trust-service startup
  races do not make the release lane flaky or opaque.

</decisions>

<canonical_refs>
## Canonical References

- `.planning/ROADMAP.md` -- Phase 22 goal and success criteria
- `.planning/REQUIREMENTS.md` -- `PROD-09`, `PROD-10`
- `scripts/qualify-release.sh` -- canonical production qualification lane
- `scripts/ci-workspace.sh` -- baseline workspace gate
- `scripts/check-dashboard-release.sh` -- dashboard clean-install proof
- `scripts/check-arc-ts-release.sh` -- TypeScript SDK build/pack/smoke proof
- `scripts/check-arc-py-release.sh` -- Python SDK wheel/sdist proof
- `scripts/check-arc-go-release.sh` -- Go SDK module-release proof
- `docs/release/QUALIFICATION.md` -- qualification contract
- `docs/release/OPERATIONS_RUNBOOK.md` -- deploy/backup/restore/upgrade contract
- `.github/workflows/ci.yml` -- hosted CI runtime prerequisites
- `.github/workflows/release-qualification.yml` -- hosted release lane
- `packages/sdk/arc-ts/package.json` -- TypeScript SDK package metadata
- `packages/sdk/arc-ts/package-lock.json` -- deterministic TS SDK install plan
- `crates/arc-cli/tests/receipt_query.rs` -- release-lane startup reliability

</canonical_refs>

<code_context>
## Existing Code Insights

- The dashboard qualification path was not explicitly isolated from local
  `node_modules` and `dist` state.
- The TypeScript SDK built inside the repo but did not declare `typescript` or
  `@types/node`, which broke the clean package-release lane.
- The hosted workflows assumed Python and Go availability instead of declaring
  them explicitly.
- `arc trust serve` correctly tolerated missing dashboard assets at runtime,
  but the `receipt_query` integration harness could still fail opaquely on
  transient startup issues during the full qualification run.

</code_context>

<deferred>
## Deferred Ideas

- Add explicit artifact signing and retention policy for hosted release
  qualification outputs.
- Fold trust-service startup retry diagnostics into a shared integration-test
  helper instead of leaving the stronger logic only in `receipt_query.rs`.
- Expand operator runbooks with metrics/alert examples once the Phase 23
  observability contract exists.

</deferred>

---

*Phase: 22-qualification-deployment-and-upgrade-hardening*
*Context gathered: 2026-03-25*
