---
id: "CT-WORK.1"
title: "`chio.work.v1` contract and the WORK-W1 facade mapped to #1179's real ports"
severity: "P1"
wave: 1
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["CT-ABI.2"]
paths: ["spec/CHIO_WORK.md"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 12.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: G0.3 CT-WORK ("`chio.work.v1` and the WORK-W1 facade (`WorkClient`, `WorkHandleV1`, `WorkViewV1`), mapped to #1179's real port names, not the doc-only names; includes an unpaid `Agreement` variant"). Design source on #1173 (`origin/work/verifiable-work-session-20261003`): `docs/superpowers/specs/2026-10-03-work-runtime-design.md` (`chio-runtime::work::WorkClient<T>` at 21; `WorkTransport`, `WorkRequestV1{Prepare,Submit,Query}` at 30-32; preparation variants at 57-63; `WorkHandleV1` 91; `WorkViewV1` 99; negotiate `chio.work.v1` alongside `chio.process.v1` with no second listener at 155) and `2026-10-03-work-developer-surface-design.md:21-30`. Port map (real names on #1179 at its live head f217de1fb (the roadmap's pin 491bd01b5 is stale; the local ref `origin/feat/recoverable-agent-runtime-20261002` may lag)): doc `ProcessRecoveryPort` = `RecoveryProcessReservationPort::verify_reservation` (`crates/kernel/chio-kernel/src/recovery/ports.rs:46`) plus `RecoveryAuthorityPort::acknowledge_reservation`; doc `KernelRecoveryPort` = `RecoveryProcessOriginPort::{verify_original_request, original_request_scope}` (`:56`) plus `RecoveryAuthorityPort::{load_workflow, settle, historical_release, quarantine_historical}` (`:76`); `ArtifactReleasePort`/`ConfinedReturnPort` = `RecoveryAuthorityPort::release_result` plus `NativeProcessReturnCustodyPort` (`process_return_custody.rs:166`) plus `ArtifactBlobPort` (`knowledge.rs:173`); exact-invocation custody = `RecoveryRequestCustody`; recovery commands = `RecoveryCommandBodyV1::{CreateWorkflow, InspectWorkflow, SelectOffer, SubmitApproval, ResumeWorkflow, CancelWorkflow, ReportDecision}` (there is no ExplainIntent); preparation = #1160's `InvocationPreparer` (`chio-process/src/worker.rs:55`). Bounds: 2 MiB request and 8 MiB response frames, 64-entry catalog pages. Decision gate: the Agreement section is drafted by CT-WORK.3 under D5.

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- A source-anchor table where every named type resolves with `git grep` at the pinned refs (commands included so the reviewer can re-run them).
- `bash scripts/check-chio-owned-v1-only.sh` passes; zero doc-only port names appear outside a "superseded names" table.

## Log
- 2026-10-09T04:51:58Z connor: created
