---
id: "G4-RUN"
title: "G4: complete internal HOST-M3 run across two Backbay-operated domains"
severity: "P2"
wave: 3
tier: "premium"
status: "open"
owner: ""
assignee: ""
depends_on: ["WORK-W2.4", "WORK-W2.5a", "WORK-W1.7", "WORK-W3.2b", "WORK-W3.2c", "WORK-W3.3a", "WORK-W3.1", "REC-EXIT", "COOP-3.1", "COOP-3.2", "COOP-3.3a", "COOP-3.3b", "COOP-4.1", "COOP-4.2", "KSPEC-05.A.4b", "KSPEC-04.P2.2", "G2-REHEARSAL", "G3-REHEARSAL"]
paths: ["tests/integration/host-m3/**", "docs/records/g4/**"]
branch: ""
commits: []
author_vendor: ""
estimate_hours: 16.0
review: {"verdict": "", "reviewer": "", "round": 0}
attempts: {"started": "", "ci_failures": 0}
evidence: []
---
## Brief

Roadmap: G4 ("two Backbay-operated domains on separate hosts, with independent keys and no shared keys; a complete run satisfying section 1 criteria (a) to (e); the requester verifies the package offline"). Script a full HOST-M3 run: A's agent proposes work (WORK-W3 client); B admits it at its own door under a co-signed, attenuated work commitment (COOP-3 receiver-owned admission, CT-CROSS co-signer, no party holds both co-signer keys); B runs it in its HOST-M2 process tree under one root grant with holds; a named evaluator accepts or rejects against the commitment's predicate (WORK-W1.5a); the run includes at least one out-of-scope deny; every decision carries a signed receipt; A verifies the whole package offline against B's pinned partner card including B's door receipts. File an independent-operation record. Claims follow the G4 rows in `docs/records/gate-claims.yaml` (lost-reply recovery stays `blocked_by_adr` until CT-SETTLE and D2 are recorded).

Work on a `lane/<ID>-<slug>` branch off `integration/beta-next` (post-#1160 main). House rules: no em dashes, fail-closed on error, no `unwrap`/`expect` (clippy `unwrap_used` and `expect_used` are denied workspace-wide), conventional commits. Run `cargo fmt --all -- --check` and clippy with `-D warnings` on every crate you touch.

## Acceptance

- `tests/integration/host-m3/run.sh` completes on two hosts and emits a machine-readable result mapping each of criteria (a) to (e) to evidence paths.
- Offline verification of the package by A passes; the record passes `check-independent-operation-record.py`.

## Log
- 2026-10-09T04:51:58Z connor: created
