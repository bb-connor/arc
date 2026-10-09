---
id: "WORK-SLICE-A.1"
title: "Alpha: execution-evidence core receipt type and spec section"
severity: "P2"
wave: 2
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["CT-WIRE.1"]
paths: ["crates/core/chio-core-types/src/receipt/execution_evidence.rs", "crates/core/chio-core-types/src/receipt/mod.rs", "spec/EXECUTION_EVIDENCE_AND_PAYMENT_SUCCESSORS.md"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 5.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Method: #1173 (ref `origin/work/verifiable-work-session-20261003`, head cafdc970e) is split by path, not by commit. Diff against its real PR base 75d679670 (not `git merge-base`, which picks the criss-cross base and inflates the diff to 26,621 files); the PR changes 6,637 files. Bring the slice's paths over with `git checkout cafdc970e -- <paths>` onto `integration/beta-next`, then repair against #1160. The slice manifest from WORK-SLICE-0.1 (`docs/research/work-abstraction/SLICES.json`) is the authoritative path list. Slice alpha (execution evidence and checked output; lands right after Gate 0; drops #1173's own sweep edit in favour of #1160's classifier). Port `verify_pre_settlement_execution_receipt` and `ExecutionEvidenceMetadata` (`chio.execution_evidence.v1`, profile `chio.pre_settlement_execution.v1`). This is new receipt metadata: register it in the CT-WIRE inventory. Bring only the execution and withheld-output sections of the spec; payment-successor sections wait for slice delta.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `cargo test -p chio-core-types execution_evidence` (16 in-file tests) and clippy pass; the identifier appears in the CT-WIRE inventory and `spec/wire-schemas.lock`.

## Log
- 2026-10-09T04:51:58Z connor: created
