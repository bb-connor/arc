---
id: "WORK-SLICE-B.4"
title: "Beta: S1 runtime store and live-swarm evolution"
severity: "P2"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["WORK-SLICE-B.3"]
paths: ["crates/kernel/chio-runtime-core/src/store/traits.rs", "crates/kernel/chio-runtime-core/src/store/sqlite/swarm_authority_bundles.rs", "crates/kernel/chio-runtime-core/src/store/sqlite/schema_migrations.rs", "crates/kernel/chio-runtime-core/src/store/sqlite/admission_replay.rs", "crates/kernel/chio-runtime-core/src/admission_hook/swarm_authority.rs", "crates/kernel/chio-runtime-core/tests/runtime_admission.rs", "crates/kernel/chio-runtime-core/tests/runtime_admission/swarm_evolution.rs", "crates/kernel/chio-runtime-core/tests/runtime_admission/operation_owned.rs", "crates/kernel/chio-runtime-core/tests/runtime_admission/operation_owned/**", "crates/kernel/chio-runtime-core/tests/lease_boundaries.rs", "crates/kernel/chio-runtime-core/tests/support/dispatch_counter.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 10.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Method: #1173 (ref `origin/work/verifiable-work-session-20261003`, head cafdc970e) is split by path, not by commit. Diff against its real PR base 75d679670 (not `git merge-base`, which picks the criss-cross base and inflates the diff to 26,621 files); the PR changes 6,637 files. Bring the slice's paths over with `git checkout cafdc970e -- <paths>` onto `integration/beta-next`, then repair against #1160. The slice manifest from WORK-SLICE-0.1 (`docs/research/work-abstraction/SLICES.json`) is the authoritative path list. Slice beta (D1 dynamic delegation, S1 swarm evolution, A2A v1 edge; lands right after Gate 0; 2 conflicts). None of the beta paths reference alpha or delta symbols. Take only the `runtime_swarm_authority_versions` DDL (`extend_swarm_authority_bundle`). Exclude #1162's `runtime_outcome_effect_slots` and outcome continuation (parked UR-PK-1162-OUTCOME). chio-runtime-core creates tables with `CREATE TABLE IF NOT EXISTS` and no version bump; record that in the slot ledger's planned section if a version is later introduced.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test -p chio-runtime-core --test runtime_admission swarm_evolution` (4 tests, including `swarm_evolution_serializes_competing_writers`) passes.

## Log
- 2026-10-09T04:51:58Z connor: created
