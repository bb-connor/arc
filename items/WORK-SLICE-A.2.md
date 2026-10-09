---
id: "WORK-SLICE-A.2"
title: "Alpha: tool-outcome execution evidence on #1160's v4 store (tool-outcome collision fix)"
severity: "P2"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["WORK-SLICE-A.1", "UR-G0-LEDGER.4"]
paths: ["crates/kernel/chio-kernel/src/tool_outcome.rs", "crates/kernel/chio-kernel/src/tool_outcome/execution_evidence.rs", "crates/platform/chio-store-sqlite/src/tool_outcome_store.rs", "crates/platform/chio-store-sqlite/src/tool_outcome_projection.rs", "crates/platform/chio-store-sqlite/src/tool_outcome_security_release_tests.rs", "crates/platform/chio-store-sqlite/src/tool_outcome_execution_evidence.rs", "crates/platform/chio-store-sqlite/src/tool_outcome_execution_evidence.sql", "crates/platform/chio-store-sqlite/src/tool_outcome_execution_evidence_tests.rs", "crates/platform/chio-store-sqlite/src/tool_outcome_store/payload_compaction.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 14.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Method: #1173 (ref `origin/work/verifiable-work-session-20261003`, head cafdc970e) is split by path, not by commit. Diff against its real PR base 75d679670 (not `git merge-base`, which picks the criss-cross base and inflates the diff to 26,621 files); the PR changes 6,637 files. Bring the slice's paths over with `git checkout cafdc970e -- <paths>` onto `integration/beta-next`, then repair against #1160. The slice manifest from WORK-SLICE-0.1 (`docs/research/work-abstraction/SLICES.json`) is the authoritative path list. Slice alpha (execution evidence and checked output; lands right after Gate 0; drops #1173's own sweep edit in favour of #1160's classifier). Collision (G0.2): both #1160 (payload compaction) and #1173 (execution evidence) claimed tool-outcome v4. Re-base execution evidence as the next tool-outcome slot (symbolic, via the ledger lock) on top of #1160's v4; `verify_pre_migration` must accept the compaction v4 predecessor. Semantic interaction: compaction must keep any raw blob referenced by `tool_outcome_execution_evidence`. Rename #1173's v3-to-v4 migration tests to v4-to-next.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- The seven ported tests (for example `execution_schema_prevents_replacement_mutation_deletion_and_wrong_owner`) plus new `exact_v4_migration_preserves_compaction_and_creates_empty_execution_projection` and `payload_compaction_retains_execution_evidence_payload` pass: `cargo test -p chio-store-sqlite tool_outcome`.

## Log
- 2026-10-09T04:51:58Z connor: created
