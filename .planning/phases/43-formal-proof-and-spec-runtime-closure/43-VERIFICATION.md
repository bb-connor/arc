---
phase: 43
slug: formal-proof-and-spec-runtime-closure
status: passed
completed: 2026-03-27
---

# Phase 43 Verification

Phase 43 passed the formal/spec closure gate for `v2.8`.

## Automated Verification

- `cargo test -p arc-formal-diff-tests`
- `cargo test -p arc-conformance`
- `cargo test -p arc-control-plane certification_discovery_network_normalizes_registry_urls -- --nocapture`
- `cargo test --workspace`
- `./scripts/qualify-release.sh`

## Result

Passed. Phase 43 now satisfies `RISK-03`:

- ARC has an explicit launch evidence boundary covering executable diff-tests,
  empirical runtime verification, and full release qualification
- the executable reference model now covers the shipped scope-attenuation
  surface across tools, resources, prompts, DPoP, monetary caps, governed
  constraints, and runtime assurance
- the protocol and release docs no longer overclaim theorem-prover closure
  while standalone Lean modules remain outside the shipped release gate
- the broader release lane passed cleanly, including dashboard and SDK package
  checks, conformance waves 1-5, and the five-run trust-cluster repeat proof
