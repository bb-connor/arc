---
phase: 06-e14-hardening-and-release-candidate
plan: 04
status: passed
requirements:
  - REL-01
  - REL-02
  - REL-03
  - REL-04
---

# Phase 6 Verification

## Verified Truths

1. The repo now has one normal workspace gate and one explicit release-qualification gate.
2. Hosted HTTP negative-path coverage now includes malformed JSON-RPC bodies and wrapped-stream interruption.
3. The release story is documented explicitly through qualification, release-candidate, and audit docs.
4. The former closing findings now map to concrete proving artifacts rather than an undefined hardening bucket.
5. The release lane generates conformance artifacts for waves 1 through 5 and replays the repeat-run clustered trust-control proof.

## Primary Commands

- `cargo fmt --all -- --check`
- `cargo clippy --workspace -- -D warnings`
- `cargo test -p arc-cli --test mcp_serve_http -- --nocapture`
- `cargo test -p arc-cli --test trust_cluster trust_control_cluster_repeat_run_qualification -- --ignored --nocapture`
- `./scripts/qualify-release.sh`
