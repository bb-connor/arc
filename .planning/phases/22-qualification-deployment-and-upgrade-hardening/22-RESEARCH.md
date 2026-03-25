# Phase 22 Research

## Key Findings

- The existing release docs were still anchored to the older `v1` release
  candidate framing and did not fully describe the broader `v2.3` surface.
- Dashboard release proof needed a clean-install copy because the checked-in UI
  build output is intentionally not tracked.
- The TypeScript SDK release lane needed to verify three distinct properties:
  clean install, package build, and consumer installation from the packed
  tarball.
- CI setup needed explicit `setup-python` and `setup-go` steps to make runtime
  availability part of the contract rather than an ambient environment detail.
- The full `./scripts/qualify-release.sh` run surfaced two real blockers:
  missing TS package build-time dependencies and a flaky trust-service startup
  path in `receipt_query`.

## Chosen Approach

- Encode the release contract in scripts first, then document those exact
  scripts in the qualification guide and runbook.
- Fix every blocker found by the end-to-end lane rather than weakening the
  proof surface.
