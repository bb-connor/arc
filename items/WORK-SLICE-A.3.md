---
id: "WORK-SLICE-A.3"
title: "Alpha: kernel execution-evidence export (signer outside the sequencer)"
severity: "P2"
wave: 2
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["WORK-SLICE-A.2"]
paths: ["crates/kernel/chio-kernel/src/kernel/admission_coordinator/execution_evidence.rs", "crates/kernel/chio-kernel/src/admission_operation/retained_request.rs", "crates/platform/chio-store-sqlite/src/admission_operation_store/retained_request.rs", "crates/kernel/chio-kernel/src/kernel/tests/durable_admission/execution_evidence.rs", "crates/kernel/chio-kernel/tests/durable_admission_sqlite/execution_evidence.rs"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 14.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Method: #1173 (ref `origin/work/verifiable-work-session-20261003`, head cafdc970e) is split by path, not by commit. Diff against its real PR base 75d679670 (not `git merge-base`, which picks the criss-cross base and inflates the diff to 26,621 files); the PR changes 6,637 files. Bring the slice's paths over with `git checkout cafdc970e -- <paths>` onto `integration/beta-next`, then repair against #1160. The slice manifest from WORK-SLICE-0.1 (`docs/research/work-abstraction/SLICES.json`) is the authoritative path list. Slice alpha (execution evidence and checked output; lands right after Gate 0; drops #1173's own sweep edit in favour of #1160's classifier). Port the export that replays the original receipt after signer replacement and uses the federated original admission. Take only the execution-evidence hunks of `admission_coordinator.rs` (one `mod` line and a call site; the funding hunks from commit 6162bccf5 belong to delta). KernelOp 27 (`ExportExecutionEvidence`) gets its id through the ledger lock (CT-ABI census lists it as planned).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- The 11 tests in `durable_admission/execution_evidence.rs` (for example `execution_export_rejects_signer_identity_substitution`) and `sqlite_execution_evidence_precedes_payment_and_replays_after_restart` pass: `cargo test -p chio-kernel --features admission-test-support execution_export` and `--test durable_admission_sqlite execution_evidence`.

## Log
- 2026-10-09T04:51:58Z connor: created
