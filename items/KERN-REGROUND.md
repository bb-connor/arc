---
id: "KERN-REGROUND"
title: "Re-verify every KDEF row against post-#1160 main and record where each is addressed"
severity: "P1"
wave: 1
tier: "mid"
status: "open"
owner: ""
assignee: ""
depends_on: ["DOCS-1174.1"]
paths: ["docs/superpowers/specs/2026-10-04-ftl-lessons-program-design.md", "docs/superpowers/specs/2026-10-04-durable-stop-epoch-design.md", "docs/superpowers/specs/2026-10-04-unified-event-queue-design.md"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 8.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: section 13 ("re-verify every KDEF row against post-merge main"), KERN-6 (owner rows). The KDEF register is section 3 of `docs/superpowers/specs/2026-10-04-ftl-lessons-program-design.md`. Re-pin M: to post-#1160 main and update every row with a `main@<sha>:path:line` anchor. Findings already established (verify, then apply):
- open with line drift only: D2, D5 (now `crates/platform/chio-store-sqlite/src/security_state/issuance_freeze.rs:1246`), D6 (`Guard` default `kernel/mod.rs:889`, revalidation `dispatch.rs:817`; also add `EgressRestrictionGuard` and `SessionThrottleGuard`, which do not override `requires_dispatch_revalidation`), D7, D11, D12, N3, N4, N6, N22, N23 (real path `crates/platform/chio-http-core/src/emergency.rs:193`), N26, N29 (plus pre-dispatch MustPrepay discards at `validation.rs:2499,2506`);
- changed shape: D1 (non-durable disarm now in `kernel/evaluation/return_recording.rs:30`), N28 (`return_recording.rs:58-76`), D3 (lag now closes the session instead of hanging);
- fixed on #1160: N30 (`http_service.rs:795-801`), KSPEC-05 A5, the `chio_runtime` metadata reservation (part of M20);
- moved: N1 (still present on #1173 `chio-process/src/worker.rs:330`), N15 (widened on #1179 to 9 control-plane sites), N24 (#1179);
- not met: N5/GT1.
In KSPEC-08 section 2 fix the stale facts (admission schema is v36 not 34; `chio_runtime` is reserved; the sweep defers per item). Add a "Where addressed" column naming the backlog item for each row (for example D7 and N6 by REL-4.2, D11 by SHARE-4.4, D12 interim by COOP-2.4). Recompute the acceptance statistics from `docs/security/landing-ledger.json`.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- Every KDEF row has a verified anchor or "fixed in <commit>"; a reviewer spot-checks 10 rows with `git grep` (commands pasted in the PR).
- Every open row names a backlog item ID or `owner-assignment` (see parked UR-PK-KDEF-OWNERS); no U+2014.

## Log
- 2026-10-09T04:51:58Z connor: created
