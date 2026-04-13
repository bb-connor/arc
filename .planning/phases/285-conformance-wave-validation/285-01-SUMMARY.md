# Summary 285-01

Phase `285-01` proved the repo-side portion of CI-03 from one full
`./scripts/qualify-release.sh` run:

- The staged compatibility matrices under `target/release-qualification/conformance/wave1` through `wave5` all passed for the shipped JS/Python peers:
  wave 1 `10/10`, wave 2 `4/4`, wave 3 `10/10`, wave 4 `4/4`, and wave 5
  `8/8`
- The same qualification run also exercised all five Go live harnesses from
  [wave1_go_live.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-conformance/tests/wave1_go_live.rs),
  [wave2_go_live.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-conformance/tests/wave2_go_live.rs),
  [wave3_go_live.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-conformance/tests/wave3_go_live.rs),
  [wave4_go_live.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-conformance/tests/wave4_go_live.rs),
  and [wave5_go_live.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-conformance/tests/wave5_go_live.rs); the staged `coverage.log` shows each harness passing in that same run
- The evidence is now staged under `target/release-qualification/conformance/`, which keeps the wave reports and the later phase-286 certification bundle on the same execution path

Verification:

- `./scripts/qualify-release.sh`
- inspected `target/release-qualification/conformance/wave1/report.md` through `wave5/report.md`
- `rg -n "wave1_remote_http_harness_runs_against_live_|wave2_task_harness_runs_against_live_|wave3_auth_harness_runs_against_live_|wave4_notification_harness_runs_against_live_|wave5_nested_flow_harness_runs_against_live_" target/release-qualification/logs/coverage.log`

Remaining gap:

- CI-03 is still blocked on hosted GitHub observation because this evidence came from a local release lane, not a green GitHub Actions run on a published commit.
