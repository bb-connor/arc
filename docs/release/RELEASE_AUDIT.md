# Release Audit

## Scope

This audit closes the `E14` release-hardening phase for the scoped `v1` release candidate described in [RELEASE_CANDIDATE.md](RELEASE_CANDIDATE.md).

It is a repo-local go/no-go record, not a substitute for observing the hosted GitHub Actions workflows after merge.

## Decision

**Decision:** Conditional go for the scoped `v1` release candidate.

Meaning:

- the local workspace and release-qualification gates are green
- the supported guarantees, limits, non-goals, and migration story are now documented explicitly
- no remaining post-review finding is left in an undefined hardening bucket
- the hosted `CI` and `Release Qualification` workflows should be green before tagging a release from `main`

**Local qualification date:** 2026-03-20

## Evidence

Primary local qualification commands:

- `./scripts/ci-workspace.sh`
- `./scripts/qualify-release.sh`

Primary release artifacts:

- `target/release-qualification/conformance/wave1/report.md`
- `target/release-qualification/conformance/wave2/report.md`
- `target/release-qualification/conformance/wave3/report.md`
- `target/release-qualification/conformance/wave4/report.md`
- `target/release-qualification/conformance/wave5/report.md`
- `target/release-qualification/logs/trust-cluster-repeat-run.log`

Primary release docs:

- [RELEASE_CANDIDATE.md](RELEASE_CANDIDATE.md)
- [QUALIFICATION.md](QUALIFICATION.md)
- [README.md](../../README.md)

## Findings Closure

| Former finding | Release disposition |
| --- | --- |
| HA trust-control determinism | closed through the normal workspace lane plus the repeat-run trust-cluster qualification lane |
| Roots not enforced | closed through signed deny-evidence coverage for tools and filesystem-backed resources |
| Split policy surface | closed through canonical HushSpec guidance, YAML compatibility coverage, and native adoption docs/examples |
| Remote runtime not deployment-hard | closed for the supported surface through reconnect, GET/SSE, shared-owner, lifecycle, and tombstone coverage |
| Transport-dependent long-running semantics | closed for the supported surface through transport-neutral ownership, cancellation, and late-async coverage plus live conformance waves |

## Remaining Non-Goals

These are intentionally not blockers for the scoped `v1` release candidate:

- multi-region or consensus trust replication
- full OS sandbox management
- theorem-prover completion for the full protocol draft
- production networking and federation breadth beyond the currently supported hosted edge
- performance-first rewrite work

## Procedural Note

This audit was produced from the local development environment.

It does not claim that GitHub Actions has already run on the updated workflows. The repo is ready for that hosted verification, and release tagging should wait for those workflow results.
