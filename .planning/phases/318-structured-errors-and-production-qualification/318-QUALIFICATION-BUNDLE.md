---
phase: 318
artifact: qualification-bundle
created: 2026-04-15T01:21:21Z
status: current
---

# v2.83 Qualification Bundle

This bundle records the current production-readiness snapshot for the
`v2.83` lane. It is intentionally honest rather than promotional: the bundle
captures what is measured locally today, what prior checked-in qualification
artifacts still show, and which gaps remain open in phase `316`.

## Test Inventory

| Metric | Value | Evidence |
| --- | --- | --- |
| Source-counted Rust test functions | `2364` | `rg -n '^\\s*#\\[(tokio::)?test\\]' crates --glob '!**/target/**' \| wc -l` |
| Integration test files under crate `tests/` directories | `88` | `find crates -path '*/tests/*.rs' \| wc -l` |
| Workspace crate integration-test floor | satisfied | Phase `315` verification confirms every crate under `crates/` now has at least one integration-test file. |

## Coverage Snapshot

| Metric | Value | Evidence |
| --- | --- | --- |
| Full-workspace line coverage | `73.40%` (`109397/149044`) | `.planning/phases/316-coverage-push-and-store-hardening/316-VERIFICATION.md` |
| Coverage target | `80%+` | Phase `316` roadmap requirement `PROD-04` |
| Storage hardening status | satisfied | Phase `316` verified pooled SQLite writes and concurrent-writer coverage. |

Interpretation: the production-readiness story is materially improved over the
earlier baseline, but the workspace still fails the explicit coverage gate.

## Benchmark Baselines

Fresh benchmark baseline gathered on `2026-04-14`:

- Command:
  `CARGO_TARGET_DIR=/tmp/arc-phase318-bench cargo bench -p arc-core --bench core_primitives -- --noplot`

| Benchmark | Observed time range |
| --- | --- |
| `arc_core/signature_verification` | `33.827 µs` to `36.519 µs` |
| `arc_core/canonical_json_bytes` | `5.0837 µs` to `5.3783 µs` |
| `arc_core/merkle/build_tree_1024_leaves` | `789.10 µs` to `796.03 µs` |
| `arc_core/merkle/generate_proof_1024_leaves` | `119.13 ns` to `120.91 ns` |
| `arc_core/merkle/verify_proof_1024_leaves` | `4.2515 µs` to `4.3681 µs` |
| `arc_core/capability_validation_path` | `120.27 µs` to `121.67 µs` |

Interpretation: the repository now has at least one measured `v2.83`
microbenchmark baseline captured in the qualification bundle. The broader gap
is scope, not absence: this is still a core-primitives baseline, not an
end-to-end CLI/kernel latency suite.

## Conformance Snapshot

Checked-in generated conformance reports under
`tests/conformance/reports/generated/` currently show:

| Report | Timestamp | Result |
| --- | --- | --- |
| `wave1-live.md` | `2026-03-19 08:35:56` | `10/10` pass |
| `wave2-tasks.md` | `2026-03-19 09:40:06` | `2/4` pass, `2` expected failures |
| `wave3-auth.md` | `2026-03-19 09:53:03` | `10/10` pass |
| `wave4-notifications.md` | `2026-03-19 09:57:51` | `4/4` pass |
| `wave5-nested-flows.md` | `2026-03-19 10:46:03` | `8/8` pass |

Aggregate checked-in conformance posture:

- `34/36` scenarios pass
- `2/36` remain documented expected failures in the remote `tasks-cancel` path

## Known Gaps

### Phase 316

- Full-workspace coverage is still `73.40%`, below the `80%+` bar.
- The latest comparable rerun showed that new wrapper tests under excluded
  `arc-control-plane` acreage do not move the measured phase gate.
- The next counted coverage acreage is still the trust-control handler/config
  surface in `arc-cli`, led by `http_handlers_a.rs`, `http_handlers_b.rs`, and
  `config_and_public.rs`.

### Broader Qualification Envelope

- The benchmark evidence in this bundle is currently limited to the
  `arc-core` microbenchmark lane.
- The conformance snapshot comes from checked-in generated reports dated
  `2026-03-19`, not a fresh rerun on today’s tree.
- The milestone cannot be called production-ready overall until the `316`
  coverage gap is closed.

## Conclusion

Phase `318` closes the structured-error and qualification-bundle requirements:
the error surface is now actionable, the CLI has a real JSON error object path,
and the repo has one consolidated readiness artifact for `v2.83`.

The bundle also makes the release hold explicit: `v2.83` is better qualified
than before, but it is not fully ready to graduate while phase `316` remains
open.
