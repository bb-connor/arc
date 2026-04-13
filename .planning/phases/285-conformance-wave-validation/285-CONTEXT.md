# Phase 285 Context

## Goal

Validate all five bounded conformance waves across the shipped JS, Python, and
Go peers from the release-qualification lane, then preserve the resulting
evidence for the hosted CI hold.

## Existing Coverage

The repo already ships the live conformance harnesses needed for this phase:

- `crates/arc-conformance/tests/wave1_live.rs` and `wave1_go_live.rs`
- `crates/arc-conformance/tests/wave2_tasks_live.rs` and `wave2_go_live.rs`
- `crates/arc-conformance/tests/wave3_auth_live.rs` and `wave3_go_live.rs`
- `crates/arc-conformance/tests/wave4_notifications_live.rs` and
  `wave4_go_live.rs`
- `crates/arc-conformance/tests/wave5_nested_flows_live.rs` and
  `wave5_go_live.rs`

`scripts/qualify-release.sh` already drives the same bounded wave scenarios in
`tests/conformance/scenarios/wave1` through `wave5` and stages per-wave
reports under `target/release-qualification/conformance/`.

## Code Surface

- `scripts/qualify-release.sh` for the release lane that exercises the waves
- `crates/arc-conformance/tests/` for the JS/Python and Go live harnesses
- `tests/conformance/scenarios/wave*/` for the actual scenario definitions
- `target/release-qualification/conformance/` and
  `target/release-qualification/logs/coverage.log` for the staged evidence

## Execution Direction

- run the full release-qualification lane once so every wave is exercised in
  the same end-to-end qualification pass
- take JS/Python evidence from the staged compatibility matrices under
  `target/release-qualification/conformance/wave*/report.md`
- take Go evidence from the dedicated `wave*_go_live` harness results captured
  in the qualification coverage log
- keep the requirement blocked until the same evidence is observed on hosted
  GitHub Actions
