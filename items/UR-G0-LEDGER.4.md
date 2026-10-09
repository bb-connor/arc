---
id: "UR-G0-LEDGER.4"
title: "Register every planned slot, projection kind and KernelOp id symbolically"
severity: "P1"
wave: 1
tier: "cheap"
status: "open"
owner: ""
assignee: ""
depends_on: ["UR-G0-LEDGER.1"]
paths: ["docs/security/schema-slot-ledger.json"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 3.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: G0.2 ("Unreserved bumps. The planned bumps for KSPEC-08 phase 1, WORK-W1.2, KSPEC-10 and KSPEC-11 are allocated through the same lock"). Add a `planned` section (names only, no numbers): KSPEC-08-P1 (admission plus stop tables), KSPEC-04-P1 (closure tables), KERN-3-EXIT (process journal), WORK-W1.2 (new store keys `delegation_store`, `work_graph_store` and projection kinds), KSPEC-10 (crossing records), KSPEC-11 (admission), SHARE-1 (family cap, sibling registry), REC-P0/P1 (#1179's seven names from v35 to v41; CT-SETTLE may fold historical holds into #1160's deferrals), REC-P4 (knowledge), WORK alpha (tool_outcome execution evidence, next tool_outcome slot), WORK delta (unknown payment release, capture waiver, `payment_resolution` kind), REC `recovery` kind, and KernelOp 27 (alpha `ExportExecutionEvidence`) and 28-29 (REC). Also record the module-path collision: both #1160 and #1179 own `admission_operation_store/recovery.rs`.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- The checker passes; `--landing` refuses a fixture that lands any planned name without an assignment.

## Log
- 2026-10-09T04:51:58Z connor: created
