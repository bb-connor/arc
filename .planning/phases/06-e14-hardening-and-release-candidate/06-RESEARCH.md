---
phase: 06-e14-hardening-and-release-candidate
focus:
  - qualification
  - release-docs
  - failure-modes
  - audit
---

# Phase 6 Research

## What Already Existed

- strong semantic coverage from `E9` through `E13`
- live JS/Python conformance waves in `crates/pact-conformance/tests/`
- the ignored five-run trust-cluster qualifier in `crates/pact-cli/tests/trust_cluster.rs`
- draft close-out intent in `docs/epics/E14-hardening-and-release-candidate.md`

## What Was Missing

- one repo-level release-qualification command
- one hosted workflow for the heavy qualification lane
- release-facing docs naming the supported surface and its limits
- a final audit doc tying the release claims to proving artifacts

## Chosen Approach

- `./scripts/ci-workspace.sh` is the ordinary workspace gate
- `./scripts/qualify-release.sh` is the release gate
- `docs/release/` holds the qualification matrix, release-candidate surface, and final audit
- the release workflow uploads generated qualification artifacts rather than only printing them
- the trust-cluster repeat lane remains explicit and slower than normal CI, but it is now part of the named release proof

## Risks

- the release lane is intentionally heavier than day-to-day CI
- trust-cluster proof still depends on timing-sensitive integration behavior, so the qualification test must prefer strong diagnostics over brittle short timeouts
- GitHub-hosted CI cannot be observed directly from this local execution environment, so the audit must call that out explicitly
